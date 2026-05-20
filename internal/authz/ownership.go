package authz

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"docker-authz-proxy/internal/auth"

	_ "modernc.org/sqlite"
)

// OwnerInfo 资源归属信息
type OwnerInfo struct {
	Username string
	UID      int
	GID      int
	Source   string // 镜像来源：pull / build / load / import / commit
}

// OwnershipDB 容器/镜像归属持久化存储
type OwnershipDB struct {
	DB *sql.DB
}

func NewOwnershipDB(path string) (*OwnershipDB, error) {
	db, err := sql.Open("sqlite", path+"?_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// SQLite 写操作串行化：只允许一个写连接，避免 SQLITE_BUSY
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return &OwnershipDB{DB: db}, nil
}

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS containers (
			id             TEXT PRIMARY KEY,
			owner_username TEXT NOT NULL,
			owner_uid      INT  NOT NULL,
			owner_gid      INT  NOT NULL,
			image_id       TEXT DEFAULT '',
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

		CREATE TABLE IF NOT EXISTS networks (
			network_id     TEXT PRIMARY KEY,
			name           TEXT NOT NULL,
			owner_uid      INT  NOT NULL,
			owner_username TEXT NOT NULL,
			is_shared      INTEGER DEFAULT 0,
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS network_access (
			network_id TEXT NOT NULL,
			user_uid   INT  NOT NULL,
			PRIMARY KEY (network_id, user_uid)
		);

		CREATE TABLE IF NOT EXISTS volumes (
			name           TEXT PRIMARY KEY,
			owner_uid      INT  NOT NULL,
			owner_username TEXT NOT NULL,
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		-- 端口映射记录表：全局唯一（host_port + protocol 组合唯一）
		-- 容器删除时自动清除对应记录
		CREATE TABLE IF NOT EXISTS port_mappings (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			host_port      INT  NOT NULL,
			protocol       TEXT NOT NULL DEFAULT 'tcp',
			container_port INT  NOT NULL,
			container_id   TEXT NOT NULL,
			owner_uid      INT  NOT NULL,
			owner_username TEXT NOT NULL,
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(host_port, protocol)
		);

		-- 用户网络互通记录表：记录管理员开启的跨用户网络互通
		-- container_id_a/b 为空表示用户级互通（双方所有容器），非空表示容器级互通（仅指定容器）
		CREATE TABLE IF NOT EXISTS network_peers (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			uid_a           INT  NOT NULL,
			uid_b           INT  NOT NULL,
			peer_network_id TEXT NOT NULL,  -- 共享辅助网络 ID
			container_id_a  TEXT NOT NULL DEFAULT '',  -- 用户 A 的容器 ID（空=用户级）
			container_id_b  TEXT NOT NULL DEFAULT '',  -- 用户 B 的容器 ID（空=用户级）
			created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(uid_a, uid_b, container_id_a, container_id_b)
		);

		CREATE INDEX IF NOT EXISTS idx_containers_owner_uid  ON containers(owner_uid);
		CREATE INDEX IF NOT EXISTS idx_images_owner_uid      ON images(owner_uid);
		CREATE INDEX IF NOT EXISTS idx_image_access_uid      ON image_access(user_uid);
		CREATE INDEX IF NOT EXISTS idx_networks_owner_uid    ON networks(owner_uid);
		CREATE INDEX IF NOT EXISTS idx_network_access_uid    ON network_access(user_uid);
		CREATE INDEX IF NOT EXISTS idx_volumes_owner_uid     ON volumes(owner_uid);
		CREATE INDEX IF NOT EXISTS idx_port_mappings_container ON port_mappings(container_id);
		CREATE INDEX IF NOT EXISTS idx_port_mappings_owner   ON port_mappings(owner_uid);

		-- volumes-from 授权表：管理员授权某容器可被其他用户 --volumes-from 引用
		-- grantee_uid = -1 表示授权给所有用户
		CREATE TABLE IF NOT EXISTS volumes_from_access (
			container_id TEXT NOT NULL,
			grantee_uid  INT  NOT NULL,
			granted_by   INT  NOT NULL DEFAULT 0,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (container_id, grantee_uid)
		);
		CREATE INDEX IF NOT EXISTS idx_volumes_from_container ON volumes_from_access(container_id);
	`)
	if err != nil {
		return err
	}
	// 迁移：为旧数据库添加新列/表（幂等）
	_, _ = db.Exec(`ALTER TABLE containers ADD COLUMN image_id TEXT DEFAULT ''`)
	// 迁移：为已有数据库添加 port_mappings 和 network_peers 表
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS port_mappings (
		id             INTEGER PRIMARY KEY AUTOINCREMENT,
		host_port      INT  NOT NULL,
		protocol       TEXT NOT NULL DEFAULT 'tcp',
		container_port INT  NOT NULL,
		container_id   TEXT NOT NULL,
		owner_uid      INT  NOT NULL,
		owner_username TEXT NOT NULL,
		created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(host_port, protocol)
	)`)
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS network_peers (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		uid_a           INT  NOT NULL,
		uid_b           INT  NOT NULL,
		peer_network_id TEXT NOT NULL,
		container_id_a  TEXT NOT NULL DEFAULT '',
		container_id_b  TEXT NOT NULL DEFAULT '',
		created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(uid_a, uid_b, container_id_a, container_id_b)
	)`)
	// 迁移：为已有 network_peers 表添加容器级互通列
	_, _ = db.Exec(`ALTER TABLE network_peers ADD COLUMN container_id_a TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE network_peers ADD COLUMN container_id_b TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_port_mappings_container ON port_mappings(container_id)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_port_mappings_owner ON port_mappings(owner_uid)`)
	// 迁移：volumes_from_access 表
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS volumes_from_access (
		container_id TEXT NOT NULL,
		grantee_uid  INT  NOT NULL,
		granted_by   INT  NOT NULL DEFAULT 0,
		created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (container_id, grantee_uid)
	)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_volumes_from_container ON volumes_from_access(container_id)`)
	return nil
}

// ── 容器归属 ────────────────────────────────────────────────

func (o *OwnershipDB) SetContainerOwner(id string, identity *auth.CallerIdentity, imageID string) error {
	_, err := o.DB.Exec(
		`INSERT OR REPLACE INTO containers(id, owner_username, owner_uid, owner_gid, image_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id,
		identity.RealUsername,
		identity.RealUID,
		identity.RealGID,
		imageID,
		time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("db write failed: %w", err)
	}
	return nil
}

// HasContainerUsingImage 检查某用户是否有容器使用了指定镜像
func (o *OwnershipDB) HasContainerUsingImage(uid int, imageID string) (bool, error) {
	var count int
	err := o.DB.QueryRow(
		`SELECT COUNT(*) FROM containers WHERE owner_uid = ? AND image_id = ?`, uid, imageID,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetContainerOwner 返回容器归属信息；第二个返回值表示是否找到
func (o *OwnershipDB) GetContainerOwner(id string) (*OwnerInfo, bool) {
	var info OwnerInfo
	err := o.DB.QueryRow(
		`SELECT owner_username, owner_uid, owner_gid FROM containers WHERE id = ?`, id,
	).Scan(&info.Username, &info.UID, &info.GID)
	if err != nil {
		return nil, false
	}
	return &info, true
}

// DeleteContainer 删除容器归属记录
func (o *OwnershipDB) DeleteContainer(id string) error {
	_, err := o.DB.Exec(`DELETE FROM containers WHERE id = ?`, id)
	return err
}

// CountContainersByOwner 返回某用户拥有的容器总数（含已停止）
func (o *OwnershipDB) CountContainersByOwner(uid int) (int, error) {
	var count int
	err := o.DB.QueryRow(`SELECT COUNT(*) FROM containers WHERE owner_uid = ?`, uid).Scan(&count)
	return count, err
}

// CountAccessibleImages 返回用户可访问的镜像总数（自己拥有 + 有访问权限 + 公共镜像，去重）
func (o *OwnershipDB) CountAccessibleImages(uid int) (int, error) {
	var count int
	err := o.DB.QueryRow(`
		SELECT COUNT(*) FROM (
			SELECT image_id FROM images WHERE owner_uid = ? OR is_public = 1
			UNION
			SELECT image_id FROM image_access WHERE user_uid = ?
		)`, uid, uid).Scan(&count)
	return count, err
}

// GetContainerIDsByOwner 返回某用户拥有的所有容器 ID
func (o *OwnershipDB) GetContainerIDsByOwner(uid int) ([]string, error) {
	rows, err := o.DB.Query(`SELECT id FROM containers WHERE owner_uid = ?`, uid)
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

// normalizeImageID 规范化镜像 ID：去除 "sha256:" 前缀
func normalizeImageID(id string) string {
	return strings.TrimPrefix(id, "sha256:")
}

// matchesImageID 判断两个镜像 ID 是否指向同一镜像（支持短 ID 前缀匹配）
// 规则：strip sha256: → 短 ID 是长 ID 的前缀
func matchesImageID(stored, query string) bool {
	s := normalizeImageID(stored)
	q := normalizeImageID(query)
	if s == q {
		return true
	}
	// 允许 12-char 短 ID 匹配长 ID（例如 "ba6dc382fcdc" 匹配 "ba6dc382fcdc19e3..."）
	if len(s) < len(q) {
		return strings.HasPrefix(q, s)
	}
	return strings.HasPrefix(s, q)
}

func (o *OwnershipDB) SetImageOwner(imageID string, identity *auth.CallerIdentity, isPublic bool, source string) error {
	imageID = normalizeImageID(imageID)
	publicInt := 0
	if isPublic {
		publicInt = 1
	}
	_, err := o.DB.Exec(
		`INSERT INTO images(image_id, owner_username, owner_uid, owner_gid, is_public, source, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(image_id) DO UPDATE SET
		     owner_username = excluded.owner_username,
		     owner_uid      = excluded.owner_uid,
		     owner_gid      = excluded.owner_gid,
		     source         = excluded.source,
		     created_at     = excluded.created_at
		 WHERE images.source = 'build' AND excluded.source = 'pull'`,
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
	_, err = o.DB.Exec(
		`INSERT OR IGNORE INTO image_access(image_id, user_uid) VALUES (?, ?)`,
		imageID, identity.RealUID,
	)
	return err
}

// resolveImageIDInDB 在数据库中查找镜像 ID（支持多种格式：短ID/长ID/sha256:前缀）
// 返回数据库中实际存储的 image_id（可能是短 ID）
func (o *OwnershipDB) resolveImageIDInDB(imageID string) string {
	norm := normalizeImageID(imageID)
	// 1. 精确匹配（规范化后）
	var stored string
	err := o.DB.QueryRow(`SELECT image_id FROM images WHERE image_id = ?`, norm).Scan(&stored)
	if err == nil {
		return stored
	}
	// 2. 若 norm 是长 ID（>12 char hex），尝试短 ID（前12 char）前缀匹配
	if len(norm) > 12 {
		isHex := true
		for _, c := range norm[:12] {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				isHex = false
				break
			}
		}
		if isHex {
			short := norm[:12]
			// 用 LIKE 匹配 DB 中以 short 开头的条目（短ID或长ID均可）
			err = o.DB.QueryRow(`SELECT image_id FROM images WHERE image_id = ? OR image_id LIKE ?`,
				short, short+"%").Scan(&stored)
			if err == nil {
				return stored
			}
		}
	}
	return ""
}

// GetImageOwner 返回镜像归属信息及是否为公共镜像
func (o *OwnershipDB) GetImageOwner(imageID string) (*OwnerInfo, bool, bool) {
	resolvedID := o.resolveImageIDInDB(imageID)
	if resolvedID == "" {
		return nil, false, false
	}
	var info OwnerInfo
	var isPublicInt int
	err := o.DB.QueryRow(
		`SELECT owner_username, owner_uid, owner_gid, is_public, COALESCE(source, '') FROM images WHERE image_id = ?`, resolvedID,
	).Scan(&info.Username, &info.UID, &info.GID, &isPublicInt, &info.Source)
	if err != nil {
		return nil, false, false
	}
	return &info, isPublicInt != 0, true
}

// CanUseImage 判断用户是否有权使用某镜像
func (o *OwnershipDB) CanUseImage(realUID int, imageID string) bool {
	resolvedID := o.resolveImageIDInDB(imageID)
	if resolvedID == "" {
		return realUID == 0
	}
	var isPublic int
	var ownerUID int
	err := o.DB.QueryRow(
		`SELECT is_public, owner_uid FROM images WHERE image_id = ?`, resolvedID,
	).Scan(&isPublic, &ownerUID)
	if err != nil {
		return realUID == 0
	}
	// 只有 is_public=1 的镜像对所有用户开放
	if isPublic != 0 {
		return true
	}
	// 属主本人始终可以使用自己的镜像
	if ownerUID == realUID {
		return true
	}
	var count int
	_ = o.DB.QueryRow(
		`SELECT COUNT(*) FROM image_access WHERE image_id = ? AND user_uid = ?`,
		resolvedID, realUID,
	).Scan(&count)
	return count > 0
}

// CanSeeImage 判断用户是否能在列表中看到某镜像
// 规则：is_public=1 的镜像所有人可见；否则只有属主可见
func (o *OwnershipDB) CanSeeImage(realUID int, imageID string) bool {
	resolvedID := o.resolveImageIDInDB(imageID)
	if resolvedID == "" {
		return false
	}
	var isPublic, ownerUID int
	err := o.DB.QueryRow(
		`SELECT is_public, owner_uid FROM images WHERE image_id = ?`, resolvedID,
	).Scan(&isPublic, &ownerUID)
	if err != nil {
		return false
	}
	if isPublic != 0 {
		return true
	}
	if ownerUID == realUID {
		return true
	}
	// 用户曾经 pull 过（image_access 有记录）也可见
	var count int
	_ = o.DB.QueryRow(
		`SELECT COUNT(*) FROM image_access WHERE image_id = ? AND user_uid = ?`,
		resolvedID, realUID,
	).Scan(&count)
	return count > 0
}

// MarkImagePublic 将镜像标记为公共
func (o *OwnershipDB) MarkImagePublic(imageID string, isPublic bool) error {
	imageID = normalizeImageID(imageID)
	publicInt := 0
	if isPublic {
		publicInt = 1
	}
	_, err := o.DB.Exec(
		`UPDATE images SET is_public = ? WHERE image_id = ?`, publicInt, imageID,
	)
	return err
}

// RemoveUserImageAccess 移除用户对镜像的访问权限（引用计数 -1）。
// shouldDelete=true 表示引用计数降为 0，调用方应物理删除镜像。
func (o *OwnershipDB) RemoveUserImageAccess(imageID string, uid int) (shouldDelete bool, err error) {
	imageID = normalizeImageID(imageID)
	_, err = o.DB.Exec(`DELETE FROM image_access WHERE image_id = ? AND user_uid = ?`, imageID, uid)
	if err != nil {
		return false, err
	}
	var count int
	err = o.DB.QueryRow(`SELECT COUNT(*) FROM image_access WHERE image_id = ?`, imageID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

// GetImageRefCount 返回当前引用该镜像的用户数（image_access 行数）
func (o *OwnershipDB) GetImageRefCount(imageID string) (int, error) {
	var count int
	err := o.DB.QueryRow(`SELECT COUNT(*) FROM image_access WHERE image_id = ?`, imageID).Scan(&count)
	return count, err
}

// GetImageRefUsers 返回所有引用该镜像的用户 UID 列表（用于错误提示）
func (o *OwnershipDB) GetImageRefUsers(imageID string) ([]int, error) {
	rows, err := o.DB.Query(`SELECT user_uid FROM image_access WHERE image_id = ?`, imageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var uids []int
	for rows.Next() {
		var uid int
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		uids = append(uids, uid)
	}
	return uids, rows.Err()
}

// HasUserImageAccess 检查用户是否已有该镜像的引用（用于 pull 去重）
func (o *OwnershipDB) HasUserImageAccess(imageID string, uid int) (bool, error) {
	imageID = normalizeImageID(imageID)
	var count int
	err := o.DB.QueryRow(
		`SELECT COUNT(*) FROM image_access WHERE image_id = ? AND user_uid = ?`, imageID, uid,
	).Scan(&count)
	return count > 0, err
}

// EnsureImageAccess 确保用户对镜像有访问权限（幂等）
func (o *OwnershipDB) EnsureImageAccess(imageID string, uid int) error {
	// 规范化：与 SetImageOwner 保持一致
	imageID = normalizeImageID(imageID)
	_, err := o.DB.Exec(
		`INSERT OR IGNORE INTO image_access (image_id, user_uid) VALUES (?, ?)`,
		imageID, uid,
	)
	return err
}

// DeleteImage 删除镜像归属记录
func (o *OwnershipDB) DeleteImage(imageID string) error {
	if resolved := o.resolveImageIDInDB(imageID); resolved != "" {
		imageID = resolved
	} else {
		imageID = normalizeImageID(imageID)
	}
	_, _ = o.DB.Exec(`DELETE FROM image_access WHERE image_id = ?`, imageID)
	_, err := o.DB.Exec(`DELETE FROM images WHERE image_id = ?`, imageID)
	return err
}

// GetImageIDsByOwner 返回某用户拥有的所有镜像 ID
func (o *OwnershipDB) GetImageIDsByOwner(uid int) ([]string, error) {
	rows, err := o.DB.Query(
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
	rows, err := o.DB.Query(`SELECT image_id FROM images WHERE is_public = 1`)
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
	return o.DB.Close()
}

// ── 公共镜像管理 ─────────────────────────────────────────────

// SetImagePublic 设置镜像是否为公共镜像
func (o *OwnershipDB) SetImagePublic(imageID string, isPublic bool) error {
	imageID = normalizeImageID(imageID)
	pub := 0
	if isPublic {
		pub = 1
	}
	_, err := o.DB.Exec(`UPDATE images SET is_public = ? WHERE image_id = ?`, pub, imageID)
	return err
}

// IsImagePublic 查询镜像是否为公共镜像
func (o *OwnershipDB) IsImagePublic(imageID string) (bool, error) {
	var pub int
	err := o.DB.QueryRow(`SELECT is_public FROM images WHERE image_id = ?`, imageID).Scan(&pub)
	if err != nil {
		return false, err
	}
	return pub == 1, nil
}

// ── 网络归属 ─────────────────────────────────────────────────

// SetNetworkOwner 记录网络归属
func (o *OwnershipDB) SetNetworkOwner(networkID, name string, identity *auth.CallerIdentity) error {
	_, err := o.DB.Exec(
		`INSERT OR REPLACE INTO networks(network_id, name, owner_uid, owner_username, is_shared, created_at)
		 VALUES (?, ?, ?, ?, 0, ?)`,
		networkID, name, identity.RealUID, identity.RealUsername, time.Now().UTC(),
	)
	return err
}

// SetManagedNetworkOwner 记录代理自动创建的用户专属桥接网络归属
// 与 SetNetworkOwner 的区别：不需要 CallerIdentity，直接传入 uid/username
func (o *OwnershipDB) SetManagedNetworkOwner(networkID, name string, uid int, username string) error {
	_, err := o.DB.Exec(
		`INSERT OR REPLACE INTO networks(network_id, name, owner_uid, owner_username, is_shared, created_at)
		 VALUES (?, ?, ?, ?, 0, ?)`,
		networkID, name, uid, username, time.Now().UTC(),
	)
	return err
}

// GetNetworkIDByName 按网络名称查找网络 ID
func (o *OwnershipDB) GetNetworkIDByName(name string) (string, bool) {
	var networkID string
	err := o.DB.QueryRow(
		`SELECT network_id FROM networks WHERE name = ?`, name,
	).Scan(&networkID)
	if err != nil {
		return "", false
	}
	return networkID, true
}

// GetNetworkOwner 返回网络归属信息
func (o *OwnershipDB) GetNetworkOwner(networkID string) (*OwnerInfo, bool) {
	var info OwnerInfo
	err := o.DB.QueryRow(
		`SELECT owner_username, owner_uid FROM networks WHERE network_id = ?`, networkID,
	).Scan(&info.Username, &info.UID)
	if err != nil {
		return nil, false
	}
	return &info, true
}

// DeleteNetwork 删除网络归属记录
func (o *OwnershipDB) DeleteNetwork(networkID string) error {
	_, err := o.DB.Exec(`DELETE FROM networks WHERE network_id = ?`, networkID)
	if err != nil {
		return err
	}
	_, err = o.DB.Exec(`DELETE FROM network_access WHERE network_id = ?`, networkID)
	return err
}

// SetNetworkShared 设置网络为共享，并授权指定用户访问
func (o *OwnershipDB) SetNetworkShared(networkID string, allowedUIDs []int) error {
	_, err := o.DB.Exec(`UPDATE networks SET is_shared = 1 WHERE network_id = ?`, networkID)
	if err != nil {
		return err
	}
	for _, uid := range allowedUIDs {
		if _, err := o.DB.Exec(
			`INSERT OR IGNORE INTO network_access(network_id, user_uid) VALUES (?, ?)`,
			networkID, uid,
		); err != nil {
			return err
		}
	}
	return nil
}

// CanUserAccessNetwork 检查用户是否可访问该网络
func (o *OwnershipDB) CanUserAccessNetwork(networkID string, uid int) (bool, error) {
	owner, ok := o.GetNetworkOwner(networkID)
	if ok && owner.UID == uid {
		return true, nil
	}
	var count int
	err := o.DB.QueryRow(
		`SELECT COUNT(*) FROM network_access WHERE network_id = ? AND user_uid = ?`,
		networkID, uid,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetNetworkIDsByOwner 返回用户拥有的所有网络 ID
func (o *OwnershipDB) GetNetworkIDsByOwner(uid int) ([]string, error) {
	rows, err := o.DB.Query(`SELECT network_id FROM networks WHERE owner_uid = ?`, uid)
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

// GetAccessibleNetworkIDs 返回用户可访问的所有网络 ID
func (o *OwnershipDB) GetAccessibleNetworkIDs(uid int) ([]string, error) {
	rows, err := o.DB.Query(`
		SELECT network_id FROM networks WHERE owner_uid = ?
		UNION
		SELECT network_id FROM network_access WHERE user_uid = ?
	`, uid, uid)
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

// ── Volume 归属 ──────────────────────────────────────────────

// SetVolumeOwner 记录 Volume 归属
func (o *OwnershipDB) SetVolumeOwner(name string, identity *auth.CallerIdentity) error {
	_, err := o.DB.Exec(
		`INSERT OR REPLACE INTO volumes(name, owner_uid, owner_username, created_at)
		 VALUES (?, ?, ?, ?)`,
		name, identity.RealUID, identity.RealUsername, time.Now().UTC(),
	)
	return err
}

// GetVolumeOwner 返回 Volume 归属信息
func (o *OwnershipDB) GetVolumeOwner(name string) (*OwnerInfo, bool) {
	var info OwnerInfo
	err := o.DB.QueryRow(
		`SELECT owner_username, owner_uid FROM volumes WHERE name = ?`, name,
	).Scan(&info.Username, &info.UID)
	if err != nil {
		return nil, false
	}
	return &info, true
}

// DeleteVolume 删除 Volume 归属记录
func (o *OwnershipDB) DeleteVolume(name string) error {
	_, err := o.DB.Exec(`DELETE FROM volumes WHERE name = ?`, name)
	return err
}

// GetVolumeNamesByOwner 返回用户拥有的所有 Volume 名称
func (o *OwnershipDB) GetVolumeNamesByOwner(uid int) ([]string, error) {
	rows, err := o.DB.Query(`SELECT name FROM volumes WHERE owner_uid = ?`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// ── 端口映射归属 ──────────────────────────────────────────────

// PortMappingInfo 端口映射记录
type PortMappingInfo struct {
	HostPort      int
	Protocol      string
	ContainerPort int
	ContainerID   string
	OwnerUID      int
	OwnerUsername string
}

// AddPortMappings 批量记录容器的端口映射
// 若端口已被占用（UNIQUE 约束冲突），返回冲突的端口信息
func (o *OwnershipDB) AddPortMappings(mappings []PortMappingInfo) error {
	for _, m := range mappings {
		_, err := o.DB.Exec(
			`INSERT INTO port_mappings(host_port, protocol, container_port, container_id, owner_uid, owner_username, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			m.HostPort, m.Protocol, m.ContainerPort, m.ContainerID, m.OwnerUID, m.OwnerUsername, time.Now().UTC(),
		)
		if err != nil {
			// 查询冲突记录，返回详细信息
			var existing PortMappingInfo
			_ = o.DB.QueryRow(
				`SELECT host_port, protocol, container_id, owner_uid, owner_username FROM port_mappings
				 WHERE host_port = ? AND protocol = ?`,
				m.HostPort, m.Protocol,
			).Scan(&existing.HostPort, &existing.Protocol, &existing.ContainerID,
				&existing.OwnerUID, &existing.OwnerUsername)
			return &PortConflictError{
				HostPort:          m.HostPort,
				Protocol:          m.Protocol,
				ExistingContainer: existing.ContainerID,
				ExistingOwner:     existing.OwnerUsername,
				ExistingOwnerUID:  existing.OwnerUID,
			}
		}
	}
	return nil
}

// ReleasePortMappings 释放容器的所有端口映射记录（容器删除时调用）
func (o *OwnershipDB) ReleasePortMappings(containerID string) error {
	_, err := o.DB.Exec(`DELETE FROM port_mappings WHERE container_id = ?`, containerID)
	return err
}

// GetPortMappingsByOwner 查询用户的所有端口映射
func (o *OwnershipDB) GetPortMappingsByOwner(uid int) ([]PortMappingInfo, error) {
	rows, err := o.DB.Query(
		`SELECT host_port, protocol, container_port, container_id, owner_uid, owner_username
		 FROM port_mappings WHERE owner_uid = ? ORDER BY host_port`,
		uid,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []PortMappingInfo
	for rows.Next() {
		var m PortMappingInfo
		if err := rows.Scan(&m.HostPort, &m.Protocol, &m.ContainerPort,
			&m.ContainerID, &m.OwnerUID, &m.OwnerUsername); err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

// GetPortMapping 查询指定端口的占用情况
func (o *OwnershipDB) GetPortMapping(hostPort int, protocol string) (*PortMappingInfo, bool) {
	var m PortMappingInfo
	err := o.DB.QueryRow(
		`SELECT host_port, protocol, container_port, container_id, owner_uid, owner_username
		 FROM port_mappings WHERE host_port = ? AND protocol = ?`,
		hostPort, protocol,
	).Scan(&m.HostPort, &m.Protocol, &m.ContainerPort, &m.ContainerID, &m.OwnerUID, &m.OwnerUsername)
	if err != nil {
		return nil, false
	}
	return &m, true
}

// PortConflictError 端口冲突错误，携带冲突详情
type PortConflictError struct {
	HostPort          int
	Protocol          string
	ExistingContainer string
	ExistingOwner     string
	ExistingOwnerUID  int
}

func (e *PortConflictError) Error() string {
	return fmt.Sprintf("port %d/%s already in use by container %s (owner: %s uid=%d)",
		e.HostPort, e.Protocol, truncateID(e.ExistingContainer), e.ExistingOwner, e.ExistingOwnerUID)
}

func truncateID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// ── 网络互通记录 ──────────────────────────────────────────────

// NetworkPeerInfo 用户网络互通记录
type NetworkPeerInfo struct {
	UidA          int
	UidB          int
	PeerNetworkID string // 共享辅助网络 ID
	ContainerIDA  string // 用户 A 的容器 ID（空=用户级互通）
	ContainerIDB  string // 用户 B 的容器 ID（空=用户级互通）
}

// IsUserLevel 返回 true 表示用户级互通（双方所有容器），false 表示容器级互通
func (p *NetworkPeerInfo) IsUserLevel() bool {
	return p.ContainerIDA == "" && p.ContainerIDB == ""
}

// AddNetworkPeer 记录网络互通。
// containerIDA/B 为空表示用户级互通（双方所有容器），非空表示容器级互通（仅指定容器）。
// uid 顺序按小 uid 在前规范化，容器 ID 顺序随 uid 同步交换。
func (o *OwnershipDB) AddNetworkPeer(uidA, uidB int, peerNetworkID, containerIDA, containerIDB string) error {
	if uidA > uidB {
		uidA, uidB = uidB, uidA
		containerIDA, containerIDB = containerIDB, containerIDA
	}
	_, err := o.DB.Exec(
		`INSERT OR REPLACE INTO network_peers(uid_a, uid_b, peer_network_id, container_id_a, container_id_b, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		uidA, uidB, peerNetworkID, containerIDA, containerIDB, time.Now().UTC(),
	)
	return err
}

// RemoveNetworkPeer 删除互通记录。
// containerIDA/B 为空时删除该用户对的所有互通记录（含容器级），非空时只删除指定容器级记录。
// 返回被删除的所有 peer_network_id 列表。
func (o *OwnershipDB) RemoveNetworkPeer(uidA, uidB int, containerIDA, containerIDB string) ([]string, error) {
	if uidA > uidB {
		uidA, uidB = uidB, uidA
		containerIDA, containerIDB = containerIDB, containerIDA
	}
	var rows *sql.Rows
	var err error
	if containerIDA == "" && containerIDB == "" {
		// 删除该用户对的全部记录
		rows, err = o.DB.Query(
			`SELECT peer_network_id FROM network_peers WHERE uid_a = ? AND uid_b = ?`,
			uidA, uidB,
		)
	} else {
		rows, err = o.DB.Query(
			`SELECT peer_network_id FROM network_peers WHERE uid_a = ? AND uid_b = ? AND container_id_a = ? AND container_id_b = ?`,
			uidA, uidB, containerIDA, containerIDB,
		)
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if containerIDA == "" && containerIDB == "" {
		_, err = o.DB.Exec(`DELETE FROM network_peers WHERE uid_a = ? AND uid_b = ?`, uidA, uidB)
	} else {
		_, err = o.DB.Exec(
			`DELETE FROM network_peers WHERE uid_a = ? AND uid_b = ? AND container_id_a = ? AND container_id_b = ?`,
			uidA, uidB, containerIDA, containerIDB,
		)
	}
	return ids, err
}

// GetNetworkPeer 查询用户级互通记录（container_id_a/b 均为空）
func (o *OwnershipDB) GetNetworkPeer(uidA, uidB int) (*NetworkPeerInfo, bool) {
	if uidA > uidB {
		uidA, uidB = uidB, uidA
	}
	var info NetworkPeerInfo
	err := o.DB.QueryRow(
		`SELECT uid_a, uid_b, peer_network_id, container_id_a, container_id_b
		 FROM network_peers WHERE uid_a = ? AND uid_b = ? AND container_id_a = '' AND container_id_b = ''`,
		uidA, uidB,
	).Scan(&info.UidA, &info.UidB, &info.PeerNetworkID, &info.ContainerIDA, &info.ContainerIDB)
	if err != nil {
		return nil, false
	}
	return &info, true
}

// GetContainerPeer 查询容器级互通记录
func (o *OwnershipDB) GetContainerPeer(uidA, uidB int, containerIDA, containerIDB string) (*NetworkPeerInfo, bool) {
	if uidA > uidB {
		uidA, uidB = uidB, uidA
		containerIDA, containerIDB = containerIDB, containerIDA
	}
	var info NetworkPeerInfo
	err := o.DB.QueryRow(
		`SELECT uid_a, uid_b, peer_network_id, container_id_a, container_id_b
		 FROM network_peers WHERE uid_a = ? AND uid_b = ? AND container_id_a = ? AND container_id_b = ?`,
		uidA, uidB, containerIDA, containerIDB,
	).Scan(&info.UidA, &info.UidB, &info.PeerNetworkID, &info.ContainerIDA, &info.ContainerIDB)
	if err != nil {
		return nil, false
	}
	return &info, true
}

// GetAllNetworkPeers 查询所有互通记录
func (o *OwnershipDB) GetAllNetworkPeers() ([]NetworkPeerInfo, error) {
	rows, err := o.DB.Query(
		`SELECT uid_a, uid_b, peer_network_id, container_id_a, container_id_b FROM network_peers`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []NetworkPeerInfo
	for rows.Next() {
		var info NetworkPeerInfo
		if err := rows.Scan(&info.UidA, &info.UidB, &info.PeerNetworkID, &info.ContainerIDA, &info.ContainerIDB); err != nil {
			return nil, err
		}
		result = append(result, info)
	}
	return result, rows.Err()
}

// GetNetworkPeersByContainer 查询包含指定容器 ID 的互通记录（容器级互通过滤）
func (o *OwnershipDB) GetNetworkPeersByContainer(containerID string) ([]NetworkPeerInfo, error) {
	rows, err := o.DB.Query(
		`SELECT uid_a, uid_b, peer_network_id, container_id_a, container_id_b
		 FROM network_peers WHERE container_id_a = ? OR container_id_b = ?`,
		containerID, containerID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []NetworkPeerInfo
	for rows.Next() {
		var info NetworkPeerInfo
		if err := rows.Scan(&info.UidA, &info.UidB, &info.PeerNetworkID, &info.ContainerIDA, &info.ContainerIDB); err != nil {
			return nil, err
		}
		result = append(result, info)
	}
	return result, rows.Err()
}

// GetNetworkPeersByUID 查询某用户参与的所有互通记录（含用户级和容器级）
func (o *OwnershipDB) GetNetworkPeersByUID(uid int) ([]NetworkPeerInfo, error) {
	rows, err := o.DB.Query(
		`SELECT uid_a, uid_b, peer_network_id, container_id_a, container_id_b
		 FROM network_peers WHERE uid_a = ? OR uid_b = ?`,
		uid, uid,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []NetworkPeerInfo
	for rows.Next() {
		var info NetworkPeerInfo
		if err := rows.Scan(&info.UidA, &info.UidB, &info.PeerNetworkID, &info.ContainerIDA, &info.ContainerIDB); err != nil {
			return nil, err
		}
		result = append(result, info)
	}
	return result, rows.Err()
}

// ── volumes-from 授权 ────────────────────────────────────────

// VolumesFromGrant 描述一条 volumes-from 授权记录
type VolumesFromGrant struct {
	ContainerID string
	GranteeUID  int    // -1 = 所有用户
	GrantedBy   int
	CreatedAt   string
}

// GrantVolumesFrom 授权容器可被指定用户（或所有用户）--volumes-from 引用。
// granteeUID = -1 表示授权给所有用户。
func (o *OwnershipDB) GrantVolumesFrom(containerID string, granteeUID int, grantedBy int) error {
	_, err := o.DB.Exec(
		`INSERT OR REPLACE INTO volumes_from_access(container_id, grantee_uid, granted_by, created_at)
		 VALUES (?, ?, ?, datetime('now'))`,
		containerID, granteeUID, grantedBy,
	)
	return err
}

// RevokeVolumesFrom 撤销容器的 volumes-from 授权。
// granteeUID = -1 撤销"所有用户"授权；其他值撤销指定用户授权。
// granteeUID = -999 撤销该容器的所有授权。
func (o *OwnershipDB) RevokeVolumesFrom(containerID string, granteeUID int) error {
	var err error
	if granteeUID == -999 {
		_, err = o.DB.Exec(`DELETE FROM volumes_from_access WHERE container_id = ?`, containerID)
	} else {
		_, err = o.DB.Exec(
			`DELETE FROM volumes_from_access WHERE container_id = ? AND grantee_uid = ?`,
			containerID, granteeUID,
		)
	}
	return err
}

// CanVolumesFrom 检查 uid 是否被授权引用 containerID。
// 满足以下任一条件返回 true：
//   - 存在 grantee_uid = uid 的记录
//   - 存在 grantee_uid = -1（所有用户）的记录
func (o *OwnershipDB) CanVolumesFrom(containerID string, uid int) (bool, error) {
	var count int
	err := o.DB.QueryRow(
		`SELECT COUNT(*) FROM volumes_from_access
		 WHERE container_id = ? AND (grantee_uid = ? OR grantee_uid = -1)`,
		containerID, uid,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ListVolumesFromGrants 列出所有（或指定容器的）volumes-from 授权记录
func (o *OwnershipDB) ListVolumesFromGrants(containerID string) ([]VolumesFromGrant, error) {
	query := `SELECT container_id, grantee_uid, granted_by, created_at FROM volumes_from_access`
	args := []interface{}{}
	if containerID != "" {
		query += ` WHERE container_id = ?`
		args = append(args, containerID)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := o.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []VolumesFromGrant
	for rows.Next() {
		var g VolumesFromGrant
		if err := rows.Scan(&g.ContainerID, &g.GranteeUID, &g.GrantedBy, &g.CreatedAt); err != nil {
			continue
		}
		result = append(result, g)
	}
	return result, rows.Err()
}
