package main

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// PolicyConfig 对应 policy.yaml 结构
// 配置只需填写用户名/组名，后台启动时自动解析为 uid/gid
type PolicyConfig struct {
	Version       int           `yaml:"version"`
	DefaultAction string        `yaml:"default_action"` // "allow"（白名单）
	DenyRules     []DenyRule    `yaml:"deny_rules"`
	ActionMapping ActionMapping `yaml:"action_mapping"`
}

// DenyRule 禁止规则：指定用户/组不能执行哪些操作
type DenyRule struct {
	Users   []string `yaml:"users"`  // 用户名列表
	Groups  []string `yaml:"groups"` // 组名列表
	Actions []string `yaml:"actions"`
}

// ActionMapping 操作名称到 HTTP 路径模式的映射（供文档参考）
type ActionMapping map[string][]string

// resolvedDenyRule 运行期内存表示（已将 username/group → uid/gid）
type resolvedDenyRule struct {
	UIDs      []int
	GIDs      []int
	Usernames []string // 与 UIDs 一一对应，供日志展示
	Groups    []string // 与 GIDs 一一对应，供日志展示
	Actions   map[string]bool
}

// Policy 运行期策略对象
type Policy struct {
	config            PolicyConfig
	resolvedDenyRules []resolvedDenyRule
	unresolvedNames   []string // 配置中找不到的用户名/组名（用于启动时警告）
}

func loadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg PolicyConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = "allow"
	}

	p := &Policy{config: cfg}
	p.resolve()
	return p, nil
}

// resolve 启动时将 username/group → uid/gid，缓存到内存
func (p *Policy) resolve() {
	for _, rule := range p.config.DenyRules {
		r := resolvedDenyRule{
			Actions: make(map[string]bool),
		}
		for _, a := range rule.Actions {
			// "run" is an alias covering both create_container and start
			// (docker run = POST /containers/create + POST /containers/{id}/start)
			if a == "run" {
				r.Actions[ActionCreateContainer] = true
				r.Actions[ActionStartContainer] = true
			} else {
				r.Actions[a] = true
			}
		}
		for _, u := range rule.Users {
			if uid := lookupUID(u); uid >= 0 {
				r.UIDs = append(r.UIDs, uid)
				r.Usernames = append(r.Usernames, u)
			} else {
				// 用户不存在于 /etc/passwd，记录未解析名称
				p.unresolvedNames = append(p.unresolvedNames,
					"user:"+u+" (not found in /etc/passwd)")
			}
		}
		for _, g := range rule.Groups {
			if gid := lookupGroupGID(g); gid >= 0 {
				r.GIDs = append(r.GIDs, gid)
				r.Groups = append(r.Groups, g)
			} else {
				// 组不存在于 /etc/group，记录未解析名称
				p.unresolvedNames = append(p.unresolvedNames,
					"group:"+g+" (not found in /etc/group)")
			}
		}
		// 只有当规则有实际的 UID 或 GID 时才添加
		if len(r.UIDs) > 0 || len(r.GIDs) > 0 {
			p.resolvedDenyRules = append(p.resolvedDenyRules, r)
		}
	}
}

// IsDenied 检查用户是否被禁止执行某操作（白名单模式：默认允许）
// 所有用户包括 root 都要经过检查，无豁免
func (p *Policy) IsDenied(id *CallerIdentity, action string) bool {
	userGroups := getUserGroups(id.RealUID)

	for _, rule := range p.resolvedDenyRules {
		if !rule.Actions[action] {
			continue
		}
		// 检查 UID 是否匹配
		for _, uid := range rule.UIDs {
			if uid == id.RealUID {
				return true
			}
		}
		// 检查用户是否属于禁止的组
		for _, gid := range rule.GIDs {
			for _, userGID := range userGroups {
				if gid == userGID {
					return true
				}
			}
		}
	}
	return false
}

// Action 操作分类常量
// 所有标准 Docker CLI 操作均有对应分类，policy.yaml 的 deny_rules 可引用任意常量值
const (
	// ── 容器操作 ──────────────────────────────────────────────────
	ActionPS              = "ps"               // docker ps          GET  /containers/json
	ActionCreateContainer = "create_container"  // docker create      POST /containers/create
	ActionStartContainer  = "start"             // docker start       POST /containers/{id}/start
	ActionRestart         = "restart"           // docker restart     POST /containers/{id}/restart
	ActionStop            = "stop"              // docker stop/kill/pause/unpause
	ActionRemoveContainer = "rm"                // docker rm          DELETE /containers/{id}
	ActionExec            = "exec"              // docker exec/attach POST /containers/{id}/exec|attach
	ActionInspect         = "inspect"           // docker inspect     GET  /containers/{id}/json 等
	ActionLogs            = "logs"              // docker logs/stats/top/events(容器)
	ActionCp              = "cp"               // docker cp          GET|PUT /containers/{id}/archive
	ActionCommit          = "commit"            // docker commit      POST /commit

	// ── 镜像操作 ──────────────────────────────────────────────────
	ActionImages      = "images"   // docker images   GET  /images/json
	ActionPull        = "pull"     // docker pull     POST /images/create
	ActionLoad        = "load"     // docker load     POST /images/load
	ActionSave        = "save"     // docker save     GET  /images/{name}/get
	ActionBuild       = "build"    // docker build    POST /build
	ActionPush        = "push"     // docker push     POST /images/{name}/push
	ActionRemoveImage = "rmi"      // docker rmi      DELETE /images/{name}
	ActionTag         = "tag"      // docker tag      POST /images/{name}/tag
	ActionSearch      = "search"   // docker search   GET  /images/search

	// ── 清理操作（统一归类）──────────────────────────────────────
	// 覆盖：docker container/image/volume/network/builder/system prune
	ActionPrune = "prune"

	// ── 网络操作 ──────────────────────────────────────────────────
	ActionNetworkList       = "network_ls"          // docker network ls
	ActionNetworkInspect    = "network_inspect"      // docker network inspect
	ActionNetworkCreate     = "network_create"       // docker network create
	ActionNetworkConnect    = "network_connect"      // docker network connect
	ActionNetworkDisconnect = "network_disconnect"   // docker network disconnect
	ActionNetworkRemove     = "network_rm"           // docker network rm

	// ── 卷操作 ──────────────────────────────────────────────────
	ActionVolumeList    = "volume_ls"       // docker volume ls
	ActionVolumeInspect = "volume_inspect"  // docker volume inspect
	ActionVolumeCreate  = "volume_create"   // docker volume create
	ActionVolumeRemove  = "volume_rm"       // docker volume rm

	// ── 系统操作 ──────────────────────────────────────────────────
	ActionSystemInfo   = "info"    // docker info / docker version / GET /_ping
	ActionSystemDF     = "df"      // docker system df
	ActionSystemEvents = "events"  // docker events
	ActionSystemLogin  = "login"   // docker login

	// ── Swarm / Service / Node / Task 操作 ──────────────────────
	// 覆盖 /swarm、/nodes、/services、/tasks、/distribution 所有端点
	ActionSwarm = "swarm"

	// ── 插件操作 ──────────────────────────────────────────────────
	ActionPlugin = "plugin" // docker plugin *

	// ── Secret / Config 操作 ─────────────────────────────────────
	ActionSecret = "secret" // docker secret *
	ActionConfig = "config" // docker config *

	// ── 兜底（应尽可能为空；仅用于真正未知的私有/实验性端点）────
	ActionOther = "other"
)

// classifyAction 将 HTTP method + URI 映射为操作名
// 覆盖所有标准 Docker Engine API v1.41+ 端点，确保无操作落入 ActionOther
func classifyAction(method, uri string) string {
	path := stripAPIVersion(uri)
	// 去掉 query string
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}

	switch {
	// ── 容器操作 ──────────────────────────────────────────────────

	// 列表（必须在前缀匹配之前）
	case method == "GET" && pathMatches(path, "/containers/json"):
		return ActionPS
	// 清理所有停止容器
	case method == "POST" && pathMatches(path, "/containers/prune"):
		return ActionPrune
	// 创建容器
	case method == "POST" && pathMatches(path, "/containers/create"):
		return ActionCreateContainer
	// 启动
	case method == "POST" && pathMatchesN(path, "/containers/", "/start"):
		return ActionStartContainer
	// 重启
	case method == "POST" && pathMatchesN(path, "/containers/", "/restart"):
		return ActionRestart
	// 停止/杀死/暂停/恢复
	case method == "POST" && (pathMatchesN(path, "/containers/", "/stop") ||
		pathMatchesN(path, "/containers/", "/kill") ||
		pathMatchesN(path, "/containers/", "/pause") ||
		pathMatchesN(path, "/containers/", "/unpause")):
		return ActionStop
	// 改名/更新配置/等待（归类为状态变更）
	case method == "POST" && (pathMatchesN(path, "/containers/", "/rename") ||
		pathMatchesN(path, "/containers/", "/update") ||
		pathMatchesN(path, "/containers/", "/wait")):
		return ActionStop
	// 删除容器
	case method == "DELETE" && pathHasPrefix(path, "/containers/"):
		return ActionRemoveContainer
	// exec（创建 exec 实例）/ attach / 终端 resize
	case method == "POST" && (pathMatchesN(path, "/containers/", "/exec") ||
		pathMatchesN(path, "/containers/", "/attach") ||
		pathMatchesN(path, "/containers/", "/resize")):
		return ActionExec
	// attach WebSocket 升级（GET /containers/{id}/attach 或 /attach/ws）
	case method == "GET" && pathHasPrefix(path, "/containers/") &&
		strings.Contains(path, "/attach"):
		return ActionExec
	// exec 第二阶段：POST /exec/{id}/start|resize
	case method == "POST" && (pathMatchesN(path, "/exec/", "/start") ||
		pathMatchesN(path, "/exec/", "/resize")):
		return ActionExec
	// exec inspect：GET /exec/{id}/json
	case method == "GET" && pathMatchesN(path, "/exec/", "/json"):
		return ActionInspect
	// 容器详情
	case method == "GET" && pathMatchesN(path, "/containers/", "/json"):
		return ActionInspect
	// 日志/统计/进程/变更（只读）
	case method == "GET" && (pathMatchesN(path, "/containers/", "/logs") ||
		pathMatchesN(path, "/containers/", "/stats") ||
		pathMatchesN(path, "/containers/", "/top") ||
		pathMatchesN(path, "/containers/", "/changes")):
		return ActionLogs
	// docker cp：从容器复制文件（GET/HEAD）或向容器写入文件（PUT）
	case (method == "GET" || method == "HEAD") && pathMatchesN(path, "/containers/", "/archive"):
		return ActionCp
	case method == "PUT" && pathMatchesN(path, "/containers/", "/archive"):
		return ActionCp
	// docker export：导出容器文件系统（归类为 cp，属文件读取）
	case method == "GET" && pathMatchesN(path, "/containers/", "/export"):
		return ActionCp
	// docker commit
	case method == "POST" && pathMatches(path, "/commit"):
		return ActionCommit

	// ── 镜像操作 ──────────────────────────────────────────────────

	// 列表（精确匹配优先）
	case method == "GET" && pathMatches(path, "/images/json"):
		return ActionImages
	// 搜索
	case method == "GET" && pathMatches(path, "/images/search"):
		return ActionSearch
	// 批量导出多个镜像为 tar（GET /images/get?names=...）
	case method == "GET" && pathMatches(path, "/images/get"):
		return ActionSave
	// 清理无用镜像
	case method == "POST" && pathMatches(path, "/images/prune"):
		return ActionPrune
	// 拉取/导入（POST /images/create）
	case method == "POST" && pathMatches(path, "/images/create"):
		return ActionPull
	// 从 tar 加载镜像（docker load）
	case method == "POST" && pathMatches(path, "/images/load"):
		return ActionLoad
	// 构建镜像
	case method == "POST" && (pathMatches(path, "/build") ||
		pathMatches(path, "/images/build")):
		return ActionBuild
	// 清理构建缓存
	case method == "POST" && pathMatches(path, "/build/prune"):
		return ActionPrune
	// 推送镜像
	case method == "POST" && pathMatchesN(path, "/images/", "/push"):
		return ActionPush
	// 删除镜像
	case method == "DELETE" && pathHasPrefix(path, "/images/"):
		return ActionRemoveImage
	// 镜像详情 / history（需要访问权）
	case method == "GET" && (pathMatchesN(path, "/images/", "/json") ||
		pathMatchesN(path, "/images/", "/history")):
		return ActionInspect
	// 打标签
	case method == "POST" && pathMatchesN(path, "/images/", "/tag"):
		return ActionTag
	// 单个镜像导出为 tar（docker save <image>）
	case method == "GET" && pathMatchesN(path, "/images/", "/get"):
		return ActionSave
	// registry 分发信息（docker manifest inspect）
	case method == "GET" && pathMatchesN(path, "/distribution/", "/json"):
		return ActionInspect

	// ── 网络操作 ──────────────────────────────────────────────────
	case method == "GET" && pathMatches(path, "/networks"):
		return ActionNetworkList
	case method == "POST" && pathMatches(path, "/networks/create"):
		return ActionNetworkCreate
	case method == "POST" && pathMatches(path, "/networks/prune"):
		return ActionPrune
	case method == "POST" && pathMatchesN(path, "/networks/", "/connect"):
		return ActionNetworkConnect
	case method == "POST" && pathMatchesN(path, "/networks/", "/disconnect"):
		return ActionNetworkDisconnect
	case method == "DELETE" && pathHasPrefix(path, "/networks/"):
		return ActionNetworkRemove
	case method == "GET" && pathHasPrefix(path, "/networks/"):
		return ActionNetworkInspect

	// ── 卷操作 ──────────────────────────────────────────────────
	case method == "GET" && pathMatches(path, "/volumes"):
		return ActionVolumeList
	case method == "POST" && pathMatches(path, "/volumes/create"):
		return ActionVolumeCreate
	case method == "POST" && pathMatches(path, "/volumes/prune"):
		return ActionPrune
	case method == "DELETE" && pathHasPrefix(path, "/volumes/"):
		return ActionVolumeRemove
	case method == "GET" && pathHasPrefix(path, "/volumes/"):
		return ActionVolumeInspect

	// ── 系统操作 ──────────────────────────────────────────────────
	case (method == "GET" || method == "HEAD") && pathMatches(path, "/_ping"):
		return ActionSystemInfo
	case method == "GET" && (pathMatches(path, "/info") || pathMatches(path, "/version")):
		return ActionSystemInfo
	case method == "GET" && pathMatches(path, "/system/df"):
		return ActionSystemDF
	case method == "GET" && pathMatches(path, "/events"):
		return ActionSystemEvents
	case method == "POST" && pathMatches(path, "/auth"):
		return ActionSystemLogin
	case method == "POST" && pathMatches(path, "/system/prune"):
		return ActionPrune

	// ── Swarm / Service / Node / Task / Stack 操作 ───────────────
	// 覆盖所有 /swarm、/nodes、/services、/tasks、/distribution 端点
	case pathHasPrefix(path, "/swarm") ||
		pathHasPrefix(path, "/nodes") ||
		pathHasPrefix(path, "/services") ||
		pathHasPrefix(path, "/tasks"):
		return ActionSwarm

	// ── 插件操作 ──────────────────────────────────────────────────
	case pathHasPrefix(path, "/plugins"):
		return ActionPlugin

	// ── Secret / Config 操作 ─────────────────────────────────────
	case pathHasPrefix(path, "/secrets"):
		return ActionSecret
	case pathHasPrefix(path, "/configs"):
		return ActionConfig
	}
	return ActionOther
}

// stripAPIVersion 去掉 /v1.xx 前缀
func stripAPIVersion(uri string) string {
	if len(uri) > 2 && uri[0] == '/' && uri[1] == 'v' {
		rest := uri[2:]
		slash := strings.Index(rest, "/")
		if slash > 0 {
			// 验证是版本号格式（数字.数字）
			ver := rest[:slash]
			if isVersionString(ver) {
				return rest[slash:]
			}
		}
	}
	return uri
}

func isVersionString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || c == '.') {
			return false
		}
	}
	return len(s) > 0
}

// pathMatches 精确路径匹配（不含变量段）
func pathMatches(path, pattern string) bool {
	return strings.TrimRight(path, "/") == strings.TrimRight(pattern, "/")
}

// pathMatchesN 匹配形如 /containers/{id}/logs 的路径
// prefix = "/containers/", suffix = "/logs"
func pathMatchesN(path, prefix, suffix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	rest := path[len(prefix):]
	// 中间不能有额外的 /（确保只有一个 ID 段）
	// rest 形如 "abc123/logs" 或 "abc123/logs/"
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return false
	}
	tail := rest[slashIdx:]
	return strings.TrimRight(tail, "/") == strings.TrimRight(suffix, "/")
}

// pathHasPrefix 路径前缀匹配
func pathHasPrefix(path, prefix string) bool {
	return strings.HasPrefix(path, prefix)
}

// extractContainerID 从路径中提取容器 ID
// e.g. /containers/abc123def456/stop → abc123def456
func extractContainerID(uri string) string {
	path := stripAPIVersion(uri)
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}
	const prefix = "/containers/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := path[len(prefix):]
	if idx := strings.Index(rest, "/"); idx >= 0 {
		return rest[:idx]
	}
	return rest
}

// extractImageID 从路径中提取镜像 ID 或名称
// e.g. /images/sha256:abc123/json → sha256:abc123
func extractImageID(uri string) string {
	path := stripAPIVersion(uri)
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}
	const prefix = "/images/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := path[len(prefix):]
	// 去掉末尾操作段
	if idx := strings.LastIndex(rest, "/"); idx >= 0 {
		// 检查是否是操作后缀而不是 sha256: 分隔符
		candidate := rest[:idx]
		if candidate != "" && !strings.HasPrefix(candidate, "sha256:") {
			// 可能是 registry/name:tag，保留完整
		}
		return candidate
	}
	return rest
}
