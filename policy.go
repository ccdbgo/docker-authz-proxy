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
	UIDs    []int
	GIDs    []int
	Actions map[string]bool
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
			} else {
				// 用户不存在于 /etc/passwd，记录未解析名称
				p.unresolvedNames = append(p.unresolvedNames,
					"user:"+u+" (not found in /etc/passwd)")
			}
		}
		for _, g := range rule.Groups {
			if gid := lookupGroupGID(g); gid >= 0 {
				r.GIDs = append(r.GIDs, gid)
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
const (
	ActionPS              = "ps"              // 列出容器
	ActionCreateContainer = "create_container" // 创建容器
	ActionStartContainer  = "start"           // 启动容器
	ActionStop            = "stop"            // 停止/kill/pause/unpause 容器
	ActionRemoveContainer = "rm"              // 删除容器
	ActionExec            = "exec"            // 在容器内执行命令（含 attach）
	ActionInspect         = "inspect"         // 查看容器/镜像详情
	ActionLogs            = "logs"            // 查看容器日志/stats/top 等只读操作
	ActionImages          = "images"          // 列出镜像
	ActionPull            = "pull"            // 拉取镜像
	ActionBuild           = "build"           // 构建镜像
	ActionPush            = "push"            // 推送镜像
	ActionRemoveImage     = "rmi"             // 删除镜像
	ActionTag             = "tag"             // 标记镜像
	ActionCommit          = "commit"          // 从容器提交镜像
	ActionOther           = "other"           // 其他操作
)

// classifyAction 将 HTTP method + URI 映射为操作名
func classifyAction(method, uri string) string {
	path := stripAPIVersion(uri)
	// 去掉 query string
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}

	switch {
	// 容器操作
	case method == "GET" && pathMatches(path, "/containers/json"):
		return ActionPS
	case method == "POST" && pathMatches(path, "/containers/create"):
		return ActionCreateContainer
	case method == "POST" && pathMatchesN(path, "/containers/", "/start"):
		return ActionStartContainer
	case method == "POST" && (pathMatchesN(path, "/containers/", "/stop") ||
		pathMatchesN(path, "/containers/", "/kill") ||
		pathMatchesN(path, "/containers/", "/pause") ||
		pathMatchesN(path, "/containers/", "/unpause")):
		return ActionStop
	case method == "DELETE" && pathHasPrefix(path, "/containers/"):
		return ActionRemoveContainer
	case method == "POST" && (pathMatchesN(path, "/containers/", "/exec") ||
		pathMatchesN(path, "/containers/", "/attach") ||
		pathMatchesN(path, "/containers/", "/resize")):
		return ActionExec
	case method == "GET" && pathMatchesN(path, "/containers/", "/json"):
		return ActionInspect
	case method == "GET" && (pathMatchesN(path, "/containers/", "/logs") ||
		pathMatchesN(path, "/containers/", "/stats") ||
		pathMatchesN(path, "/containers/", "/top") ||
		pathMatchesN(path, "/containers/", "/changes") ||
		pathMatchesN(path, "/containers/", "/export")):
		return ActionLogs
	case method == "POST" && (pathMatchesN(path, "/containers/", "/rename") ||
		pathMatchesN(path, "/containers/", "/update") ||
		pathMatchesN(path, "/containers/", "/wait")):
		return ActionStop // 修改/等待容器状态，归属同 stop
	case method == "POST" && pathMatches(path, "/commit"):
		return ActionCommit

	// 镜像操作
	case method == "GET" && pathMatches(path, "/images/json"):
		return ActionImages
	case method == "POST" && pathMatches(path, "/images/create"):
		return ActionPull
	case method == "POST" && (pathMatches(path, "/build") ||
		pathMatches(path, "/images/build")):
		return ActionBuild
	case method == "POST" && pathMatchesN(path, "/images/", "/push"):
		return ActionPush
	case method == "DELETE" && pathHasPrefix(path, "/images/"):
		return ActionRemoveImage
	case method == "GET" && pathMatchesN(path, "/images/", "/json"):
		return ActionInspect
	case method == "GET" && pathMatchesN(path, "/images/", "/history"):
		return ActionInspect // history 需要镜像访问权
	case method == "POST" && pathMatchesN(path, "/images/", "/tag"):
		return ActionTag
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
