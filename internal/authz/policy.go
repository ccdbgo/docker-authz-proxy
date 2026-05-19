package authz

import (
	"os"
	"strings"

	"docker-authz-proxy/internal/auth"

	"gopkg.in/yaml.v3"
)

// PolicyConfig 对应 policy.yaml 结构
type PolicyConfig struct {
	Version       int           `yaml:"version"`
	DefaultAction string        `yaml:"default_action"`
	DenyRules     []DenyRule    `yaml:"deny_rules"`
	ActionMapping ActionMapping `yaml:"action_mapping"`
}

// DenyRule 禁止规则：指定用户/组不能执行哪些操作
type DenyRule struct {
	Users   []string `yaml:"users"`
	Groups  []string `yaml:"groups"`
	Actions []string `yaml:"actions"`
}

// ActionMapping 操作名称到 HTTP 路径模式的映射（供文档参考）
type ActionMapping map[string][]string

// ResolvedDenyRule 运行期内存表示（已将 username/group → uid/gid）
type ResolvedDenyRule struct {
	UIDs      []int
	GIDs      []int
	Usernames []string
	Groups    []string
	Actions   map[string]bool
}

// Policy 运行期策略对象
type Policy struct {
	Config            PolicyConfig
	ResolvedDenyRules []ResolvedDenyRule
	UnresolvedNames   []string
}

func LoadPolicy(path string) (*Policy, error) {
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

	p := &Policy{Config: cfg}
	p.resolve()
	return p, nil
}

// resolve 启动时将 username/group → uid/gid，缓存到内存
func (p *Policy) resolve() {
	for _, rule := range p.Config.DenyRules {
		r := ResolvedDenyRule{
			Actions: make(map[string]bool),
		}
		for _, a := range rule.Actions {
			switch a {
			case "run":
				r.Actions[ActionCreateContainer] = true
				r.Actions[ActionStartContainer] = true
			case "stop":
				// docker kill 是比 stop 更强制的停止方式，语义上应一并禁止
				r.Actions[ActionStop] = true
				r.Actions[ActionKill] = true
			case "plugin":
				// plugin 别名：展开为所有 plugin 子操作
				r.Actions[ActionPluginList] = true
				r.Actions[ActionPluginInspect] = true
				r.Actions[ActionPluginInstall] = true
				r.Actions[ActionPluginRemove] = true
				r.Actions[ActionPluginEnable] = true
				r.Actions[ActionPluginDisable] = true
				r.Actions[ActionPluginUpgrade] = true
				r.Actions[ActionPluginSet] = true
				r.Actions[ActionPluginPush] = true
				r.Actions[ActionPluginCreate] = true
			case "history":
				// docker image history → GET /images/{id}/history → ActionHistory
				r.Actions[ActionHistory] = true
			default:
				r.Actions[a] = true
			}
		}
		for _, u := range rule.Users {
			if uid := auth.LookupUID(u); uid >= 0 {
				r.UIDs = append(r.UIDs, uid)
				r.Usernames = append(r.Usernames, u)
			} else {
				p.UnresolvedNames = append(p.UnresolvedNames, u)
			}
		}
		for _, g := range rule.Groups {
			if gid := auth.LookupGroupGID(g); gid >= 0 {
				r.GIDs = append(r.GIDs, gid)
				r.Groups = append(r.Groups, g)
			} else {
				p.UnresolvedNames = append(p.UnresolvedNames, g)
			}
		}
		if len(r.UIDs) > 0 || len(r.GIDs) > 0 {
			p.ResolvedDenyRules = append(p.ResolvedDenyRules, r)
		}
	}
}

// IsDenied 检查用户是否被禁止执行某操作（白名单模式：默认允许）
func (p *Policy) IsDenied(id *auth.CallerIdentity, action string) bool {
	userGroups := auth.GetUserGroups(id.RealUID)

	for _, rule := range p.ResolvedDenyRules {
		if !rule.Actions[action] {
			continue
		}
		for _, uid := range rule.UIDs {
			if uid == id.RealUID {
				return true
			}
		}
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
	ActionPS              = "ps"
	ActionCreateContainer = "create_container"
	ActionStartContainer  = "start"
	ActionRestart         = "restart"
	ActionStop            = "stop"
	ActionKill            = "kill"
	ActionPause           = "pause"
	ActionUnpause         = "unpause"
	ActionRename          = "rename"
	ActionUpdate          = "update"
	ActionRemoveContainer = "rm"
	ActionExec            = "exec"
	ActionAttach          = "attach"
	ActionInspect         = "inspect"
	ActionPort            = "port"
	ActionLogs            = "logs"
	ActionDiff            = "diff"
	ActionCp              = "cp"
	ActionExport          = "export"
	ActionCommit          = "commit"
	ActionWait            = "wait"

	ActionImages      = "images"
	ActionPull        = "pull"
	ActionImport      = "import"
	ActionLoad        = "load"
	ActionSave        = "save"
	ActionBuild       = "build"
	ActionPush        = "push"
	ActionRemoveImage = "rmi"
	ActionTag         = "tag"
	ActionHistory     = "history"
	ActionSearch      = "search"

	ActionPrune = "prune"

	ActionNetworkList       = "network_ls"
	ActionNetworkInspect    = "network_inspect"
	ActionNetworkCreate     = "network_create"
	ActionNetworkConnect    = "network_connect"
	ActionNetworkDisconnect = "network_disconnect"
	ActionNetworkRemove     = "network_rm"

	ActionVolumeList    = "volume_ls"
	ActionVolumeInspect = "volume_inspect"
	ActionVolumeCreate  = "volume_create"
	ActionVolumeRemove  = "volume_rm"

	ActionSystemInfo    = "info"
	ActionSystemVersion = "version"
	ActionSystemDF      = "df"
	ActionSystemEvents  = "events"
	ActionSystemLogin   = "login"

	ActionSwarm = "swarm"

	// plugin 细粒度子操作
	ActionPlugin        = "plugin"         // 别名：禁止所有 plugin 操作
	ActionPluginList    = "plugin_ls"      // docker plugin ls
	ActionPluginInspect = "plugin_inspect" // docker plugin inspect
	ActionPluginInstall = "plugin_install" // docker plugin install
	ActionPluginRemove  = "plugin_rm"      // docker plugin rm
	ActionPluginEnable  = "plugin_enable"  // docker plugin enable
	ActionPluginDisable = "plugin_disable" // docker plugin disable
	ActionPluginUpgrade = "plugin_upgrade" // docker plugin upgrade
	ActionPluginSet     = "plugin_set"     // docker plugin set
	ActionPluginPush    = "plugin_push"    // docker plugin push
	ActionPluginCreate  = "plugin_create"  // docker plugin create

	ActionSecret = "secret"
	ActionConfig = "config"

	ActionOther = "other"
)

// cmdActionOverrides 记录"同一 API、不同命令"需要覆盖 action 的映射。
// 当 DockerCommand 在此表中时，用对应的 action 替换 ClassifyAction 的结果。
var cmdActionOverrides = map[string]string{
	"port":           ActionPort,
	"container/port": ActionPort,
}

// OverrideActionByCommand 根据 DockerCommand 将通用 action 替换为更具体的 action。
// 例如 docker port 和 docker inspect 都调用 GET /containers/{id}/json（ActionInspect），
// 但通过命令名可以区分，使 policy 能独立控制它们。
func OverrideActionByCommand(dockerCmd, action string) string {
	if override, ok := cmdActionOverrides[dockerCmd]; ok {
		return override
	}
	return action
}

// ClassifyAction 将 HTTP method + URI 映射为操作名
func ClassifyAction(method, uri string) string {
	path := StripAPIVersion(uri)
	query := ""
	if idx := strings.Index(path, "?"); idx >= 0 {
		query = path[idx+1:]
		path = path[:idx]
	}

	switch {
	case method == "GET" && pathMatches(path, "/containers/json"):
		return ActionPS
	case method == "POST" && pathMatches(path, "/containers/prune"):
		return ActionPrune
	case method == "POST" && pathMatches(path, "/containers/create"):
		return ActionCreateContainer
	case method == "POST" && pathMatchesN(path, "/containers/", "/start"):
		return ActionStartContainer
	case method == "POST" && pathMatchesN(path, "/containers/", "/restart"):
		return ActionRestart
	case method == "POST" && pathMatchesN(path, "/containers/", "/stop"):
		return ActionStop
	case method == "POST" && pathMatchesN(path, "/containers/", "/kill"):
		return ActionKill
	case method == "POST" && pathMatchesN(path, "/containers/", "/pause"):
		return ActionPause
	case method == "POST" && pathMatchesN(path, "/containers/", "/unpause"):
		return ActionUnpause
	case method == "POST" && pathMatchesN(path, "/containers/", "/rename"):
		return ActionRename
	case method == "POST" && pathMatchesN(path, "/containers/", "/update"):
		return ActionUpdate
	case method == "POST" && pathMatchesN(path, "/containers/", "/wait"):
		return ActionWait
	case method == "DELETE" && pathHasPrefix(path, "/containers/"):
		return ActionRemoveContainer
	case method == "POST" && (pathMatchesN(path, "/containers/", "/exec") ||
		pathMatchesN(path, "/containers/", "/resize")):
		return ActionExec
	case method == "POST" && pathMatchesN(path, "/containers/", "/attach"):
		return ActionAttach
	case method == "GET" && pathHasPrefix(path, "/containers/") &&
		strings.Contains(path, "/attach"):
		return ActionAttach
	case method == "POST" && (pathMatchesN(path, "/exec/", "/start") ||
		pathMatchesN(path, "/exec/", "/resize")):
		return ActionExec
	case method == "GET" && pathMatchesN(path, "/exec/", "/json"):
		return ActionInspect
	case method == "GET" && (pathMatchesN(path, "/containers/", "/json") ||
		pathMatchesN(path, "/containers/", "/processes")):
		return ActionInspect
	case method == "GET" && (pathMatchesN(path, "/containers/", "/logs") ||
		pathMatchesN(path, "/containers/", "/stats") ||
		pathMatchesN(path, "/containers/", "/top")):
		return ActionLogs
	case method == "GET" && pathMatchesN(path, "/containers/", "/changes"):
		return ActionDiff
	case (method == "GET" || method == "HEAD") && pathMatchesN(path, "/containers/", "/archive"):
		return ActionCp
	case method == "PUT" && pathMatchesN(path, "/containers/", "/archive"):
		return ActionCp
	case method == "GET" && pathMatchesN(path, "/containers/", "/export"):
		return ActionExport
	case method == "POST" && pathMatches(path, "/commit"):
		return ActionCommit

	case method == "GET" && pathMatches(path, "/images/json"):
		return ActionImages
	case method == "GET" && pathMatches(path, "/images/search"):
		return ActionSearch
	case method == "GET" && pathMatches(path, "/images/get"):
		return ActionSave
	case method == "POST" && pathMatches(path, "/images/prune"):
		return ActionPrune
	case method == "POST" && pathMatches(path, "/images/create"):
		// docker import 使用 fromSrc 参数，docker pull 使用 fromImage 参数
		if strings.Contains(query, "fromSrc=") {
			return ActionImport
		}
		return ActionPull
	case method == "POST" && pathMatches(path, "/images/load"):
		return ActionLoad
	case method == "POST" && (pathMatches(path, "/build") ||
		pathMatches(path, "/images/build") ||
		pathMatches(path, "/grpc")):
		return ActionBuild
	case method == "POST" && pathMatches(path, "/build/prune"):
		return ActionPrune
	case method == "POST" && pathMatchesN(path, "/images/", "/push"):
		return ActionPush
	case method == "DELETE" && pathHasPrefix(path, "/images/"):
		return ActionRemoveImage
	case method == "GET" && pathMatchesN(path, "/images/", "/history"):
		return ActionHistory
	case method == "GET" && pathMatchesN(path, "/images/", "/json"):
		return ActionInspect
	case method == "POST" && pathMatchesN(path, "/images/", "/tag"):
		return ActionTag
	case method == "GET" && pathMatchesN(path, "/images/", "/get"):
		return ActionSave
	case method == "GET" && pathMatchesN(path, "/distribution/", "/json"):
		return ActionInspect

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

	case (method == "GET" || method == "HEAD") && pathMatches(path, "/_ping"):
		return ActionSystemInfo
	case method == "GET" && pathMatches(path, "/info"):
		return ActionSystemInfo
	case method == "GET" && pathMatches(path, "/version"):
		return ActionSystemVersion
	case method == "GET" && pathMatches(path, "/system/df"):
		return ActionSystemDF
	case method == "GET" && pathMatches(path, "/events"):
		return ActionSystemEvents
	case method == "POST" && pathMatches(path, "/auth"):
		return ActionSystemLogin
	case method == "POST" && pathMatches(path, "/system/prune"):
		return ActionPrune

	case pathHasPrefix(path, "/swarm") ||
		pathHasPrefix(path, "/nodes") ||
		pathHasPrefix(path, "/services") ||
		pathHasPrefix(path, "/tasks"):
		return ActionSwarm

	// plugin 细粒度分类
	case method == "GET" && pathMatches(path, "/plugins"):
		return ActionPluginList
	case method == "GET" && pathMatchesN(path, "/plugins/", "/json"):
		return ActionPluginInspect
	case method == "POST" && pathMatches(path, "/plugins/pull"):
		return ActionPluginInstall
	case method == "DELETE" && pathHasPrefix(path, "/plugins/"):
		return ActionPluginRemove
	case method == "POST" && pathMatchesN(path, "/plugins/", "/enable"):
		return ActionPluginEnable
	case method == "POST" && pathMatchesN(path, "/plugins/", "/disable"):
		return ActionPluginDisable
	case method == "POST" && pathMatchesN(path, "/plugins/", "/upgrade"):
		return ActionPluginUpgrade
	case method == "POST" && pathMatchesN(path, "/plugins/", "/set"):
		return ActionPluginSet
	case method == "POST" && pathMatchesN(path, "/plugins/", "/push"):
		return ActionPluginPush
	case method == "POST" && pathMatches(path, "/plugins/create"):
		return ActionPluginCreate
	case pathHasPrefix(path, "/plugins"):
		// 兜底：未匹配的 plugin 路径归为 plugin_inspect（只读语义）
		return ActionPluginInspect

	case pathHasPrefix(path, "/secrets"):
		return ActionSecret
	case pathHasPrefix(path, "/configs"):
		return ActionConfig
	}
	return ActionOther
}

// StripAPIVersion 去掉 /v1.xx 前缀
func StripAPIVersion(uri string) string {
	if len(uri) > 2 && uri[0] == '/' && uri[1] == 'v' {
		rest := uri[2:]
		slash := strings.Index(rest, "/")
		if slash > 0 {
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

func pathMatches(path, pattern string) bool {
	return strings.TrimRight(path, "/") == strings.TrimRight(pattern, "/")
}

func pathMatchesN(path, prefix, suffix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	rest := path[len(prefix):]
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return false
	}
	// 快速路径：镜像名不含斜杠（如 /images/alpine/push）
	tail := rest[slashIdx:]
	if strings.TrimRight(tail, "/") == strings.TrimRight(suffix, "/") {
		return true
	}
	// 镜像名含斜杠（如 /images/docker.io/library/alpine/push）：
	// 检查 path 在 prefix 之后是否以 /{id...}{suffix} 结尾，且 suffix 是最后一段。
	suffixClean := "/" + strings.Trim(suffix, "/")
	pathClean := strings.TrimRight(path, "/")
	if !strings.HasSuffix(pathClean, suffixClean) {
		return false
	}
	// 确保 suffix 之前还有内容（即 ID 段非空）
	before := pathClean[:len(pathClean)-len(suffixClean)]
	return strings.HasPrefix(before+"/", prefix)
}

func pathHasPrefix(path, prefix string) bool {
	return strings.HasPrefix(path, prefix)
}

// ExtractContainerID 从路径中提取容器 ID
func ExtractContainerID(uri string) string {
	path := StripAPIVersion(uri)
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

// ExtractImageID 从路径中提取镜像 ID 或名称
func ExtractImageID(uri string) string {
	path := StripAPIVersion(uri)
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}
	const prefix = "/images/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := path[len(prefix):]
	if idx := strings.LastIndex(rest, "/"); idx >= 0 {
		candidate := rest[:idx]
		if candidate != "" && !strings.HasPrefix(candidate, "sha256:") {
			// 可能是 registry/name:tag，保留完整
		}
		return candidate
	}
	return rest
}

// DefaultAllowPolicy 策略文件缺失时的兜底策略（白名单模式，全部允许）
func DefaultAllowPolicy() *Policy {
	return &Policy{
		Config: PolicyConfig{
			Version:       1,
			DefaultAction: "allow",
		},
	}
}
