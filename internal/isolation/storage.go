package isolation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"docker-authz-proxy/internal/audit"
	"docker-authz-proxy/internal/authz"

	"go.uber.org/zap"
)

// DefaultStorageBase 用户存储根目录默认路径
const DefaultStorageBase = "/var/docker/user-storage"

// UserStorageRoot 返回某用户的专属存储目录路径
// 格式：<base>/user-<uid>
func UserStorageRoot(base string, uid int) string {
	return filepath.Join(base, fmt.Sprintf("user-%d", uid))
}

// UserVolumePrefix 返回用户 Volume 名称前缀
// 格式：user-<uid>-volume-
func UserVolumePrefix(uid int) string {
	return fmt.Sprintf("user-%d-volume-", uid)
}

// EnsureUserStorageDir 创建用户专属存储目录（幂等），并设置归属权限
func EnsureUserStorageDir(base string, uid, gid int) error {
	dir := UserStorageRoot(base, uid)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create user storage dir %s: %w", dir, err)
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		// Windows 下 Chown 不支持，忽略错误
		return fmt.Errorf("chown user storage dir %s: %w", dir, err)
	}
	return nil
}

// BindMountViolation 描述一次挂载路径违规
type BindMountViolation struct {
	Source    string // 被拒绝的宿主机路径
	UserRoot  string // 允许的用户目录
}

func (e *BindMountViolation) Error() string {
	return fmt.Sprintf(
		"bind mount '%s' is not allowed: only paths under '%s' are permitted for non-root users",
		e.Source, e.UserRoot,
	)
}

// ValidateBindMounts 校验容器创建请求中的宿主机目录挂载路径。
// 非 root 用户（uid != 0）只能挂载自身专属存储目录下的路径；
// named volume（无 / 前缀）跳过校验，由 Volume 前缀机制约束。
// 返回第一个违规项的 *BindMountViolation，无违规则返回 nil。
func ValidateBindMounts(body []byte, storageBase string, uid int) error {
	if uid == 0 {
		return nil
	}

	entries := parseBindMounts(body)
	if len(entries) == 0 {
		return nil
	}

	userRoot := filepath.Clean(UserStorageRoot(storageBase, uid))

	for _, src := range entries {
		// named volume 不是路径，跳过
		if !strings.HasPrefix(src, "/") {
			continue
		}
		cleanSrc := filepath.Clean(src)
		// 允许精确匹配用户目录本身，或其子路径
		if cleanSrc != userRoot && !strings.HasPrefix(cleanSrc, userRoot+string(filepath.Separator)) {
			return &BindMountViolation{Source: src, UserRoot: userRoot}
		}
	}
	return nil
}

// parseBindMounts 从容器创建请求体中提取所有宿主机挂载源路径（字符串列表）
func parseBindMounts(body []byte) []string {
	var req struct {
		HostConfig struct {
			Binds  []string `json:"Binds"`
			Mounts []struct {
				Type   string `json:"Type"`
				Source string `json:"Source"`
			} `json:"Mounts"`
		} `json:"HostConfig"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}

	var sources []string

	// Binds 格式：["src:dst[:opts]", ...]
	for _, b := range req.HostConfig.Binds {
		// src 是第一个 : 之前的部分
		src := b
		if idx := strings.Index(b, ":"); idx >= 0 {
			src = b[:idx]
		}
		sources = append(sources, src)
	}

	// Mounts（新式 API）：只验证 bind 类型
	for _, m := range req.HostConfig.Mounts {
		if strings.EqualFold(m.Type, "bind") && m.Source != "" {
			sources = append(sources, m.Source)
		}
	}

	return sources
}

// ── StorageManager：定期清理孤立 Volume 和废弃空目录 ────────────────────────

// StorageManager 用户存储资源管理器
type StorageManager struct {
	storageBase string
	httpClient  *http.Client
}

// NewStorageManager 创建存储管理器，upstreamSock 为 Docker daemon Unix socket 路径
func NewStorageManager(storageBase, upstreamSock string) *StorageManager {
	return &StorageManager{
		storageBase: storageBase,
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", upstreamSock)
				},
			},
			Timeout: 30 * time.Second,
		},
	}
}

// StartCleanup 启动定期清理协程。
// interval：清理间隔（建议 5 分钟）；ctx 取消时退出。
func (m *StorageManager) StartCleanup(
	ctx context.Context,
	db *authz.OwnershipDB,
	logger *zap.Logger,
	auditLog *audit.AuditLogger,
	interval time.Duration,
) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.runCleanup(ctx, db, logger, auditLog)
			}
		}
	}()
}

// dockerVolumeItem Docker volume 列表条目
type dockerVolumeItem struct {
	Name      string `json:"Name"`
	UsageData *struct {
		RefCount int64 `json:"RefCount"`
	} `json:"UsageData"`
}

// listDanglingVolumes 调用 Docker API 列出所有未被任何容器使用的 volume
func (m *StorageManager) listDanglingVolumes(ctx context.Context) ([]dockerVolumeItem, error) {
	filter := url.QueryEscape(`{"dangling":["true"]}`)
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://docker/volumes?filters="+filter, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result struct {
		Volumes []dockerVolumeItem `json:"Volumes"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse volumes response: %w", err)
	}
	return result.Volumes, nil
}

// removeVolume 调用 Docker API 删除指定 volume（不强制，在用的不会删除）
func (m *StorageManager) removeVolume(ctx context.Context, name string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE",
		"http://docker/volumes/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// runCleanup 执行一次清理：孤立 Volume + 用户存储目录内的空子目录
func (m *StorageManager) runCleanup(
	ctx context.Context,
	db *authz.OwnershipDB,
	logger *zap.Logger,
	auditLog *audit.AuditLogger,
) {
	logger.Info("storage_cleanup_start")
	volumesRemoved := 0
	dirsRemoved := 0

	// ── 1. 清理孤立 Docker Volume（有用户前缀 且 DB 中无归属记录） ──────────
	//
	// 两阶段保护策略：
	//   阶段一（批量）：取 DB 全量快照作为主过滤，O(1) 判断，避免 N+1 查询。
	//   阶段二（逐条）：删除前再做一次点查询，将 TOCTOU 竞态窗口从
	//                  "HTTP 往返级（~50ms）"收缩到"函数调用级（~1μs）"。
	// DB 查询失败时采用保守策略：放弃本次 volume 清理，不删任何 volume。
	ownedVols, err := db.GetAllVolumeNames()
	if err != nil {
		logger.Warn("storage_cleanup_skip_volumes_db_unavailable", zap.Error(err))
	} else {
		ownedSet := make(map[string]struct{}, len(ownedVols))
		for _, n := range ownedVols {
			ownedSet[n] = struct{}{}
		}

		volumes, err := m.listDanglingVolumes(ctx)
		if err != nil {
			logger.Warn("storage_cleanup_list_volumes_failed", zap.Error(err))
		} else {
			for _, v := range volumes {
				// 只处理符合用户 volume 命名规范的 volume：user-{digits}-volume-*
				if !isUserVolumePrefix(v.Name) {
					continue
				}
				// Phase 1: snapshot filter (skip volumes owned before snapshot was taken)
				if _, owned := ownedSet[v.Name]; owned {
					continue
				}
				// Phase 2: point-query re-check to narrow TOCTOU window (skip volumes created after snapshot)
				if _, found := db.GetVolumeOwner(v.Name); found {
					logger.Debug("storage_cleanup_skip_toctou_protected",
						zap.String("volume", v.Name))
					continue
				}
				if err := m.removeVolume(ctx, v.Name); err != nil {
					logger.Warn("storage_cleanup_volume_remove_failed",
						zap.String("volume", v.Name),
						zap.Error(err))
					continue
				}
				if err := db.DeleteVolume(v.Name); err != nil {
					logger.Warn("storage_cleanup_db_delete_failed",
						zap.String("volume", v.Name),
						zap.Error(err))
				}
				volumesRemoved++
				logger.Info("storage_cleanup_orphan_volume_removed", zap.String("volume", v.Name))
				if auditLog != nil {
					auditLog.Log("system", 0, "system",
						"volume_cleanup", "/volumes/"+v.Name, "allow",
						"orphaned_volume_removed", v.Name, http.StatusNoContent)
				}
			}
		}
	}

	// ── 2. 清理用户存储目录下的空子目录 ──────────────────────────────────────
	if m.storageBase != "" {
		entries, err := os.ReadDir(m.storageBase)
		if err != nil && !os.IsNotExist(err) {
			logger.Warn("storage_cleanup_readdir_failed",
				zap.String("dir", m.storageBase), zap.Error(err))
		}
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "user-") {
				continue
			}
			userDir := filepath.Join(m.storageBase, entry.Name())
			n := removeEmptySubDirs(userDir, logger)
			dirsRemoved += n
		}
	}

	logger.Info("storage_cleanup_done",
		zap.Int("volumes_removed", volumesRemoved),
		zap.Int("empty_dirs_removed", dirsRemoved))
}

// IsUserVolumePrefix 判断 volume 名称是否匹配 user-{digits}-volume-* 模式（可被外部包调用）。
func IsUserVolumePrefix(name string) bool {
	return isUserVolumePrefix(name)
}

// isUserVolumePrefix 判断 volume 名称是否匹配 user-{digits}-volume-* 模式
func isUserVolumePrefix(name string) bool {
	if !strings.HasPrefix(name, "user-") {
		return false
	}
	rest := name[len("user-"):]
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	if i == 0 {
		return false
	}
	return strings.HasPrefix(rest[i:], "-volume-")
}

// removeEmptySubDirs 删除 dir 下的所有空子目录（非递归，只检查一层），返回删除数量
func removeEmptySubDirs(dir string, logger *zap.Logger) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(dir, e.Name())
		subEntries, err := os.ReadDir(sub)
		if err != nil {
			continue
		}
		if len(subEntries) == 0 {
			if err := os.Remove(sub); err != nil {
				logger.Warn("storage_cleanup_remove_empty_dir_failed",
					zap.String("dir", sub), zap.Error(err))
			} else {
				logger.Info("storage_cleanup_empty_dir_removed", zap.String("dir", sub))
				removed++
			}
		}
	}
	return removed
}

// ── tmpfs 限制 ────────────────────────────────────────────────────────────────

// TmpfsViolation 描述一次 tmpfs 超限违规
type TmpfsViolation struct {
	RequestedMB int
	LimitMB     int
}

func (e *TmpfsViolation) Error() string {
	return fmt.Sprintf("tmpfs size %dMB exceeds limit %dMB", e.RequestedMB, e.LimitMB)
}

// ValidateAndInjectTmpfs 校验并强制注入 tmpfs 大小上限。
// limitMB == 0 表示不限制，直接返回原 body。
// 对 HostConfig.Mounts 中 type=tmpfs 的条目：
//   - 若未指定 SizeBytes，注入上限
//   - 若已指定且超限，拒绝
//
// 对 HostConfig.Tmpfs（旧式 map 格式）：注入 size= 选项。
func ValidateAndInjectTmpfs(body []byte, limitMB int) ([]byte, error) {
	if limitMB == 0 {
		return body, nil
	}
	limitBytes := int64(limitMB) * 1024 * 1024

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, nil
	}
	hcRaw, ok := raw["HostConfig"]
	if !ok {
		return body, nil
	}
	var hostConfig map[string]json.RawMessage
	if err := json.Unmarshal(hcRaw, &hostConfig); err != nil {
		return body, nil
	}

	modified := false

	// 新式 Mounts API
	if mountsRaw, ok := hostConfig["Mounts"]; ok {
		var mounts []json.RawMessage
		if err := json.Unmarshal(mountsRaw, &mounts); err == nil {
			for i, m := range mounts {
				var mount map[string]json.RawMessage
				if err := json.Unmarshal(m, &mount); err != nil {
					continue
				}
				var mountType string
				if t, ok := mount["Type"]; ok {
					_ = json.Unmarshal(t, &mountType)
				}
				if !strings.EqualFold(mountType, "tmpfs") {
					continue
				}
				// 读取 TmpfsOptions.SizeBytes
				var sizeBytes int64
				if optsRaw, ok := mount["TmpfsOptions"]; ok {
					var opts map[string]json.RawMessage
					if err := json.Unmarshal(optsRaw, &opts); err == nil {
						if sb, ok := opts["SizeBytes"]; ok {
							_ = json.Unmarshal(sb, &sizeBytes)
						}
					}
				}
				if sizeBytes > limitBytes {
					return body, &TmpfsViolation{
						RequestedMB: int(sizeBytes / 1024 / 1024),
						LimitMB:     limitMB,
					}
				}
				// 未指定或为 0：注入上限
				if sizeBytes == 0 {
					var opts map[string]json.RawMessage
					if optsRaw, ok := mount["TmpfsOptions"]; ok {
						_ = json.Unmarshal(optsRaw, &opts)
					}
					if opts == nil {
						opts = make(map[string]json.RawMessage)
					}
					sb, _ := json.Marshal(limitBytes)
					opts["SizeBytes"] = sb
					optsB, _ := json.Marshal(opts)
					mount["TmpfsOptions"] = optsB
					newMount, _ := json.Marshal(mount)
					mounts[i] = newMount
					modified = true
				}
			}
			if modified {
				newMounts, _ := json.Marshal(mounts)
				hostConfig["Mounts"] = newMounts
			}
		}
	}

	// 旧式 Tmpfs map API：{"HostConfig":{"Tmpfs":{"/tmp":"rw,size=64m"}}}
	if tmpfsRaw, ok := hostConfig["Tmpfs"]; ok {
		var tmpfsMap map[string]string
		if err := json.Unmarshal(tmpfsRaw, &tmpfsMap); err == nil {
			tmpfsModified := false
			for target, opts := range tmpfsMap {
				// 解析 size= 选项
				reqBytes := parseTmpfsSize(opts)
				if reqBytes > limitBytes {
					return body, &TmpfsViolation{
						RequestedMB: int(reqBytes / 1024 / 1024),
						LimitMB:     limitMB,
					}
				}
				if reqBytes == 0 {
					// 注入 size 选项
					sizeOpt := fmt.Sprintf("size=%d", limitBytes)
					if opts == "" {
						tmpfsMap[target] = sizeOpt
					} else {
						tmpfsMap[target] = opts + "," + sizeOpt
					}
					tmpfsModified = true
				}
			}
			if tmpfsModified {
				newTmpfs, _ := json.Marshal(tmpfsMap)
				hostConfig["Tmpfs"] = newTmpfs
				modified = true
			}
		}
	}

	if !modified {
		return body, nil
	}

	newHC, _ := json.Marshal(hostConfig)
	raw["HostConfig"] = newHC
	out, _ := json.Marshal(raw)
	return out, nil
}

// parseTmpfsSize 从 tmpfs 选项字符串（如 "rw,size=64m,exec"）解析 size 字节数
func parseTmpfsSize(opts string) int64 {
	for _, part := range strings.Split(opts, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "size=") {
			continue
		}
		val := part[len("size="):]
		if len(val) == 0 {
			return 0
		}
		unit := val[len(val)-1]
		numStr := val[:len(val)-1]
		var n int64
		fmt.Sscanf(numStr, "%d", &n)
		switch unit {
		case 'k', 'K':
			return n * 1024
		case 'm', 'M':
			return n * 1024 * 1024
		case 'g', 'G':
			return n * 1024 * 1024 * 1024
		default:
			// 纯数字（字节）
			fmt.Sscanf(val, "%d", &n)
			return n
		}
	}
	return 0
}

// ── device mount 白名单 ───────────────────────────────────────────────────────

// DeviceViolation 描述一次设备挂载违规
type DeviceViolation struct {
	Device string
}

func (e *DeviceViolation) Error() string {
	return fmt.Sprintf("device '%s' is not allowed: not in the permitted device list", e.Device)
}

// ValidateDeviceMounts 校验容器创建请求中的设备挂载。
// allowedPatterns 为 glob 模式列表（已包含内置白名单）。
// uid == 0（root）跳过校验。
func ValidateDeviceMounts(body []byte, allowedPatterns []string, uid int) error {
	if uid == 0 {
		return nil
	}

	var req struct {
		HostConfig struct {
			Devices []struct {
				PathOnHost string `json:"PathOnHost"`
			} `json:"Devices"`
		} `json:"HostConfig"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}
	if len(req.HostConfig.Devices) == 0 {
		return nil
	}

	for _, dev := range req.HostConfig.Devices {
		path := dev.PathOnHost
		if path == "" {
			continue
		}
		if !deviceAllowed(path, allowedPatterns) {
			return &DeviceViolation{Device: path}
		}
	}
	return nil
}

// deviceAllowed 检查设备路径是否匹配任意一个允许的 glob 模式
func deviceAllowed(path string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, path)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// ── volumes-from 归属校验 ─────────────────────────────────────────────────────

// VolumesFromViolation 描述一次 volumes-from 越权违规
type VolumesFromViolation struct {
	ContainerRef string
}

func (e *VolumesFromViolation) Error() string {
	return fmt.Sprintf("volumes-from container '%s' is not owned by you", e.ContainerRef)
}

// ContainerOwnerReader 供 ValidateVolumesFrom 查询容器归属和授权
type ContainerOwnerReader interface {
	GetContainerOwner(id string) (*authz.OwnerInfo, bool)
	CanVolumesFrom(containerID string, uid int) (bool, error)
}

// ValidateVolumesFrom 校验 HostConfig.VolumesFrom 中的容器归属。
// privileged（root 或 sudo）用户跳过校验，可引用任意容器。
// resolver 将容器名/短 ID 解析为完整 Docker ID（可为 nil，此时直接使用原始引用）。
// 普通用户只能引用自己的容器，否则返回 *VolumesFromViolation。
func ValidateVolumesFrom(body []byte, uid int, privileged bool, db ContainerOwnerReader, resolver func(string) string) error {
	if uid == 0 || privileged {
		return nil
	}

	var req struct {
		HostConfig struct {
			VolumesFrom []string `json:"VolumesFrom"`
		} `json:"HostConfig"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}
	if len(req.HostConfig.VolumesFrom) == 0 {
		return nil
	}

	for _, ref := range req.HostConfig.VolumesFrom {
		// VolumesFrom 格式：<container>[:<mode>]，mode 为 ro/rw
		containerRef := ref
		if idx := strings.LastIndex(ref, ":"); idx >= 0 {
			mode := ref[idx+1:]
			if mode == "ro" || mode == "rw" {
				containerRef = ref[:idx]
			}
		}
		// 将容器名/短 ID 解析为完整 Docker ID
		resolvedID := containerRef
		if resolver != nil {
			if id := resolver(containerRef); id != "" {
				resolvedID = id
			}
		}
		owner, found := db.GetContainerOwner(resolvedID)
		if !found {
			// DB 中未找到：拒绝（未知容器不允许引用）
			return &VolumesFromViolation{ContainerRef: containerRef}
		}
		// 属主自己：允许
		if owner.UID == uid {
			continue
		}
		// 检查是否有管理员授权（用完整 ID 查询）
		granted, err := db.CanVolumesFrom(resolvedID, uid)
		if err != nil || !granted {
			return &VolumesFromViolation{ContainerRef: containerRef}
		}
	}
	return nil
}