package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// OwnerInfo 资源归属信息（username → uid → gid 顺序）
type OwnerInfo struct {
	Username string
	UID      int
	GID      int
}

// OwnershipDB 容器/镜像归属持久化存储
type OwnershipDB struct {
	db *sql.DB
}

func newOwnershipDB(path string) (*OwnershipDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// WAL 模式提升并发写入性能
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return &OwnershipDB{db: db}, nil
}

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS containers (
			id             TEXT PRIMARY KEY,
			owner_username TEXT NOT NULL,
			owner_uid      INT  NOT NULL,
			owner_gid      INT  NOT NULL,
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS images (
			image_id       TEXT PRIMARY KEY,
			owner_username TEXT NOT NULL,
			owner_uid      INT  NOT NULL,
			owner_gid      INT  NOT NULL,
			is_public      INTEGER DEFAULT 0,
			source         TEXT,
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS image_access (
			image_id TEXT NOT NULL,
			user_uid INT  NOT NULL,
			PRIMARY KEY (image_id, user_uid)
		);

		CREATE INDEX IF NOT EXISTS idx_containers_owner_uid ON containers(owner_uid);
		CREATE INDEX IF NOT EXISTS idx_images_owner_uid     ON images(owner_uid);
		CREATE INDEX IF NOT EXISTS idx_image_access_uid     ON image_access(user_uid);
	`)
	return err
}

// ── 容器归属 ────────────────────────────────────────────────

func (o *OwnershipDB) SetContainerOwner(id string, identity *CallerIdentity) error {
	_, err := o.db.Exec(
		`INSERT OR REPLACE INTO containers(id, owner_username, owner_uid, owner_gid, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id,
		identity.RealUsername,
		identity.RealUID,
		identity.RealGID,
		time.Now().UTC(),
	)
	return err
}

// GetContainerOwner 返回容器归属信息；第二个返回值表示是否找到
func (o *OwnershipDB) GetContainerOwner(id string) (*OwnerInfo, bool) {
	var info OwnerInfo
	err := o.db.QueryRow(
		`SELECT owner_username, owner_uid, owner_gid FROM containers WHERE id = ?`, id,
	).Scan(&info.Username, &info.UID, &info.GID)
	if err != nil {
		return nil, false
	}
	return &info, true
}

// DeleteContainer 删除容器归属记录（容器被 rm 时调用）
func (o *OwnershipDB) DeleteContainer(id string) error {
	_, err := o.db.Exec(`DELETE FROM containers WHERE id = ?`, id)
	return err
}

// GetContainerIDsByOwner 返回某用户拥有的所有容器 ID
func (o *OwnershipDB) GetContainerIDsByOwner(uid int) ([]string, error) {
	rows, err := o.db.Query(`SELECT id FROM containers WHERE owner_uid = ?`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ── 镜像归属 ────────────────────────────────────────────────

func (o *OwnershipDB) SetImageOwner(imageID string, identity *CallerIdentity, isPublic bool, source string) error {
	publicInt := 0
	if isPublic {
		publicInt = 1
	}
	// INSERT OR IGNORE: first puller keeps ownership; concurrent pulls don't overwrite
	_, err := o.db.Exec(
		`INSERT OR IGNORE INTO images(image_id, owner_username, owner_uid, owner_gid, is_public, source, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		imageID,
		identity.RealUsername,
		identity.RealUID,
		identity.RealGID,
		publicInt,
		source,
		time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	// Record per-user access: every user who pulls an image can use it (concurrent-safe)
	_, err = o.db.Exec(
		`INSERT OR IGNORE INTO image_access(image_id, user_uid) VALUES (?, ?)`,
		imageID, identity.RealUID,
	)
	return err
}

// GetImageOwner 返回镜像归属信息及是否为公共镜像
func (o *OwnershipDB) GetImageOwner(imageID string) (*OwnerInfo, bool, bool) {
	var info OwnerInfo
	var isPublicInt int
	err := o.db.QueryRow(
		`SELECT owner_username, owner_uid, owner_gid, is_public FROM images WHERE image_id = ?`, imageID,
	).Scan(&info.Username, &info.UID, &info.GID, &isPublicInt)
	if err != nil {
		return nil, false, false
	}
	return &info, isPublicInt != 0, true
}

// CanUseImage 判断用户是否有权使用某镜像（公共镜像、自己拉取的镜像）
func (o *OwnershipDB) CanUseImage(realUID int, imageID string) bool {
	// 检查镜像是否在 DB 中以及是否为公共镜像
	var isPublic int
	err := o.db.QueryRow(
		`SELECT is_public FROM images WHERE image_id = ?`, imageID,
	).Scan(&isPublic)
	if err != nil {
		// 不在 DB 中：默认拒绝（严格隔离模式）
		// 如果需要兼容存量镜像，管理员应将其标记为公共镜像
		return false
	}
	if isPublic != 0 {
		return true
	}
	// 检查 image_access 表：任何拉取过该镜像的用户都有访问权
	var count int
	_ = o.db.QueryRow(
		`SELECT COUNT(*) FROM image_access WHERE image_id = ? AND user_uid = ?`,
		imageID, realUID,
	).Scan(&count)
	return count > 0
}

// MarkImagePublic 将镜像标记为公共（管理员操作）
func (o *OwnershipDB) MarkImagePublic(imageID string, isPublic bool) error {
	publicInt := 0
	if isPublic {
		publicInt = 1
	}
	_, err := o.db.Exec(
		`UPDATE images SET is_public = ? WHERE image_id = ?`, publicInt, imageID,
	)
	return err
}

// RemoveUserImageAccess 移除用户对镜像的访问权限
// 返回：是否应该真正删除镜像（当没有任何用户访问时）
func (o *OwnershipDB) RemoveUserImageAccess(imageID string, uid int) (shouldDelete bool, err error) {
	// 从 image_access 表中移除该用户的记录
	_, err = o.db.Exec(`DELETE FROM image_access WHERE image_id = ? AND user_uid = ?`, imageID, uid)
	if err != nil {
		return false, err
	}

	// 检查是否还有其他用户访问这个镜像
	var count int
	err = o.db.QueryRow(`SELECT COUNT(*) FROM image_access WHERE image_id = ?`, imageID).Scan(&count)
	if err != nil {
		return false, err
	}

	// 如果没有任何用户访问，应该删除镜像
	return count == 0, nil
}

// EnsureImageAccess 确保用户对镜像有访问权限（幂等操作）
// 用于 build/pull 等操作，即使镜像已存在也要确保当前用户有访问权
func (o *OwnershipDB) EnsureImageAccess(imageID string, uid int) error {
	_, err := o.db.Exec(
		`INSERT OR IGNORE INTO image_access (image_id, user_uid) VALUES (?, ?)`,
		imageID, uid,
	)
	return err
}

// DeleteImage 删除镜像归属记录（同步清理 image_access）
func (o *OwnershipDB) DeleteImage(imageID string) error {
	_, _ = o.db.Exec(`DELETE FROM image_access WHERE image_id = ?`, imageID)
	_, err := o.db.Exec(`DELETE FROM images WHERE image_id = ?`, imageID)
	return err
}

// GetImageIDsByOwner 返回某用户拥有的所有镜像 ID（不含公共镜像）
func (o *OwnershipDB) GetImageIDsByOwner(uid int) ([]string, error) {
	rows, err := o.db.Query(
		`SELECT image_id FROM images WHERE owner_uid = ? AND is_public = 0`, uid,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// GetPublicImageIDs 返回所有公共镜像 ID
func (o *OwnershipDB) GetPublicImageIDs() ([]string, error) {
	rows, err := o.db.Query(`SELECT image_id FROM images WHERE is_public = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (o *OwnershipDB) Close() error {
	return o.db.Close()
}
