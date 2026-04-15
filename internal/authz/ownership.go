package authz

import (
	"database/sql"
	"fmt"
	"time"

	"docker-authz-proxy/internal/auth"

	_ "modernc.org/sqlite"
)

// OwnerInfo 资源归属信息
type OwnerInfo struct {
	Username string
	UID      int
	GID      int
}

// OwnershipDB 容器/镜像归属持久化存储
type OwnershipDB struct {
	DB *sql.DB
}

func NewOwnershipDB(path string) (*OwnershipDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
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
		CREATE TABLE IF NOT EXISTS network_peers (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			uid_a          INT  NOT NULL,
			uid_b          INT  NOT NULL,
			peer_network_id TEXT NOT NULL,  -- 共享辅助网络 ID
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(uid_a, uid_b)
		);

		CREATE INDEX IF NOT EXISTS idx_containers_owner_uid  ON containers(owner_uid);
		CREATE INDEX IF NOT EXISTS idx_images_owner_uid      ON images(owner_uid);
		CREATE INDEX IF NOT EXISTS idx_image_access_uid      ON image_access(user_uid);
		CREATE INDEX IF NOT EXISTS idx_networks_owner_uid    ON networks(owner_uid);
		CREATE INDEX IF NOT EXISTS idx_network_access_uid    ON network_access(user_uid);
		CREATE INDEX IF NOT EXISTS idx_volumes_owner_uid     ON volumes(owner_uid);
		CREATE INDEX IF NOT EXISTS idx_port_mappings_container ON port_mappings(container_id);
		CREATE INDEX IF NOT EXISTS idx_port_mappings_owner   ON port_mappings(owner_uid);
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
		id             INTEGER PRIMARY KEY AUTOINCREMENT,
		uid_a          INT  NOT NULL,
		uid_b          INT  NOT NULL,
		peer_network_id TEXT NOT NULL,
		created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(uid_a, uid_b)
	)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_port_mappings_container ON port_mappings(container_id)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_port_mappings_owner ON port_mappings(owner_uid)`)
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

func (o *OwnershipDB) SetImageOwner(imageID string, identity *auth.CallerIdentity, isPublic bool, source string) error {
	publicInt := 0
	if isPublic {
		publicInt = 1
	}
	_, err := o.DB.Exec(
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
	_, err = o.DB.Exec(
		`INSERT OR IGNORE INTO image_access(image_id, user_uid) VALUES (?, ?)`,
		imageID, identity.RealUID,
	)
	return err
}

// GetImageOwner 返回镜像归属信息及是否为公共镜像
func (o *OwnershipDB) GetImageOwner(imageID string) (*OwnerInfo, bool, bool) {
	var info OwnerInfo
	var isPublicInt int
	err := o.DB.QueryRow(
		`SELECT owner_username, owner_uid, owner_gid, is_public FROM images WHERE image_id = ?`, imageID,
	).Scan(&info.Username, &info.UID, &info.GID, &isPublicInt)
	if err != nil {
		return nil, false, false
	}
	return &info, isPublicInt != 0, true
}

// CanUseImage 判断用户是否有权使用某镜像
func (o *OwnershipDB) CanUseImage(realUID int, imageID string) bool {
	var isPublic int
	err := o.DB.QueryRow(
		`SELECT is_public FROM images WHERE image_id = ?`, imageID,
	).Scan(&isPublic)
	if err != nil {
		return realUID == 0
	}
	if isPublic != 0 {
		return true
	}
	var count int
	_ = o.DB.QueryRow(
		`SELECT COUNT(*) FROM image_access WHERE image_id = ? AND user_uid = ?`,
		imageID, realUID,
	).Scan(&count)
	return count > 0
}

// CanSeeImage 判断用户是否能在列表中看到某镜像
func (o *OwnershipDB) CanSeeImage(realUID int, imageID string) bool {
	var isPublic int
	err := o.DB.QueryRow(
		`SELECT is_public FROM images WHERE image_id = ?`, imageID,
	).Scan(&isPublic)
	if err != nil {
		return false
	}
	if isPublic != 0 {
		return true
	}
	var count int
	_ = o.DB.QueryRow(
		`SELECT COUNT(*) FROM image_access WHERE image_id = ? AND user_uid = ?`,
		imageID, realUID,
	).Scan(&count)
	return count > 0
}

// MarkImagePublic 将镜像标记为公共
func (o *OwnershipDB) MarkImagePublic(imageID string, isPublic bool) error {
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
	var count int
	err := o.DB.QueryRow(
		`SELECT COUNT(*) FROM image_access WHERE image_id = ? AND user_uid = ?`, imageID, uid,
	).Scan(&count)
	return count > 0, err
}

// EnsureImageAccess 确保用户对镜像有访问权限（幂等）
func (o *OwnershipDB) EnsureImageAccess(imageID string, uid int) error {
	_, err := o.DB.Exec(
		`INSERT OR IGNORE INTO image_access (image_id, user_uid) VALUES (?, ?)`,
		imageID, uid,
	)
	return err
}

// DeleteImage 删除镜像归属记录
func (o *OwnershipDB) DeleteImage(imageID string) error {
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
}

// AddNetworkPeer 记录两个用户之间的网络互通
func (o *OwnershipDB) AddNetworkPeer(uidA, uidB int, peerNetworkID string) error {
	// 规范化顺序（小 uid 在前），保证 UNIQUE 约束有效
	if uidA > uidB {
		uidA, uidB = uidB, uidA
	}
	_, err := o.DB.Exec(
		`INSERT OR REPLACE INTO network_peers(uid_a, uid_b, peer_network_id, created_at)
		 VALUES (?, ?, ?, ?)`,
		uidA, uidB, peerNetworkID, time.Now().UTC(),
	)
	return err
}

// RemoveNetworkPeer 删除两个用户之间的网络互通记录
func (o *OwnershipDB) RemoveNetworkPeer(uidA, uidB int) (string, error) {
	if uidA > uidB {
		uidA, uidB = uidB, uidA
	}
	var peerNetworkID string
	_ = o.DB.QueryRow(
		`SELECT peer_network_id FROM network_peers WHERE uid_a = ? AND uid_b = ?`,
		uidA, uidB,
	).Scan(&peerNetworkID)
	_, err := o.DB.Exec(
		`DELETE FROM network_peers WHERE uid_a = ? AND uid_b = ?`, uidA, uidB,
	)
	return peerNetworkID, err
}

// GetNetworkPeer 查询两个用户之间的互通记录
func (o *OwnershipDB) GetNetworkPeer(uidA, uidB int) (*NetworkPeerInfo, bool) {
	if uidA > uidB {
		uidA, uidB = uidB, uidA
	}
	var info NetworkPeerInfo
	err := o.DB.QueryRow(
		`SELECT uid_a, uid_b, peer_network_id FROM network_peers WHERE uid_a = ? AND uid_b = ?`,
		uidA, uidB,
	).Scan(&info.UidA, &info.UidB, &info.PeerNetworkID)
	if err != nil {
		return nil, false
	}
	return &info, true
}

// GetAllNetworkPeers 查询所有互通记录（启动时恢复 iptables 规则用）
func (o *OwnershipDB) GetAllNetworkPeers() ([]NetworkPeerInfo, error) {
	rows, err := o.DB.Query(`SELECT uid_a, uid_b, peer_network_id FROM network_peers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []NetworkPeerInfo
	for rows.Next() {
		var info NetworkPeerInfo
		if err := rows.Scan(&info.UidA, &info.UidB, &info.PeerNetworkID); err != nil {
			return nil, err
		}
		result = append(result, info)
	}
	return result, rows.Err()
}
