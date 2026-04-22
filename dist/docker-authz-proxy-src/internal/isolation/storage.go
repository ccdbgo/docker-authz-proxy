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

	// ── 1. 清理孤立 Docker Volume（有用户前缀且无容器在用） ────────────────
	volumes, err := m.listDanglingVolumes(ctx)
	if err != nil {
		logger.Warn("storage_cleanup_list_volumes_failed", zap.Error(err))
	} else {
		for _, v := range volumes {
			// 只处理符合用户 volume 命名规范的 volume：user-{digits}-volume-*
			if !isUserVolumePrefix(v.Name) {
				continue
			}
			if err := m.removeVolume(ctx, v.Name); err != nil {
				logger.Warn("storage_cleanup_volume_remove_failed",
					zap.String("volume", v.Name),
					zap.Error(err))
				continue
			}
			_ = db.DeleteVolume(v.Name)
			volumesRemoved++
			logger.Info("storage_cleanup_volume_removed", zap.String("volume", v.Name))
			if auditLog != nil {
				auditLog.Log("system", 0, "system",
					"volume_cleanup", "/volumes/"+v.Name, "allow",
					"orphaned_volume_removed", v.Name, http.StatusNoContent)
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
