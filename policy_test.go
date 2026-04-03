package main

import (
	"os"
	"testing"
)

// ── classifyAction ────────────────────────────────────────────────────────────

func TestClassifyAction_Containers(t *testing.T) {
	tests := []struct {
		method, path string
		want         string
	}{
		// 容器列表
		{"GET", "/containers/json", ActionPS},
		{"GET", "/v1.41/containers/json", ActionPS},
		{"GET", "/containers/json?all=1", ActionPS},

		// 创建容器
		{"POST", "/containers/create", ActionCreateContainer},
		{"POST", "/v1.41/containers/create", ActionCreateContainer},

		// 启动
		{"POST", "/containers/abc123/start", ActionStartContainer},
		{"POST", "/v1.41/containers/abc123/start", ActionStartContainer},

		// 重启
		{"POST", "/containers/abc123/restart", ActionRestart},

		// 停止/杀死/暂停/恢复
		{"POST", "/containers/abc123/stop", ActionStop},
		{"POST", "/containers/abc123/kill", ActionStop},
		{"POST", "/containers/abc123/pause", ActionStop},
		{"POST", "/containers/abc123/unpause", ActionStop},
		{"POST", "/containers/abc123/rename", ActionStop},
		{"POST", "/containers/abc123/update", ActionStop},
		{"POST", "/containers/abc123/wait", ActionStop},

		// 删除
		{"DELETE", "/containers/abc123", ActionRemoveContainer},
		{"DELETE", "/containers/abc123def456", ActionRemoveContainer},

		// exec
		{"POST", "/containers/abc123/exec", ActionExec},
		{"POST", "/containers/abc123/attach", ActionExec},
		{"POST", "/containers/abc123/resize", ActionExec},
		{"GET", "/containers/abc123/attach", ActionExec},
		{"GET", "/containers/abc123/attach/ws", ActionExec},
		{"POST", "/exec/abc123/start", ActionExec},
		{"POST", "/exec/abc123/resize", ActionExec},

		// inspect
		{"GET", "/containers/abc123/json", ActionInspect},
		{"GET", "/exec/abc123/json", ActionInspect},

		// logs/stats/top/changes
		{"GET", "/containers/abc123/logs", ActionLogs},
		{"GET", "/containers/abc123/stats", ActionLogs},
		{"GET", "/containers/abc123/top", ActionLogs},
		{"GET", "/containers/abc123/changes", ActionLogs},

		// cp (archive)
		{"GET", "/containers/abc123/archive", ActionCp},
		{"HEAD", "/containers/abc123/archive", ActionCp},
		{"PUT", "/containers/abc123/archive", ActionCp},
		{"GET", "/containers/abc123/export", ActionCp},

		// commit
		{"POST", "/commit", ActionCommit},

		// prune
		{"POST", "/containers/prune", ActionPrune},
	}

	for _, tt := range tests {
		got := classifyAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("classifyAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestClassifyAction_Images(t *testing.T) {
	tests := []struct {
		method, path string
		want         string
	}{
		{"GET", "/images/json", ActionImages},
		{"GET", "/v1.41/images/json", ActionImages},
		{"GET", "/images/search", ActionSearch},
		{"GET", "/images/get", ActionSave},                      // 批量导出
		{"GET", "/images/nginx/get", ActionSave},                // 单个导出
		{"GET", "/images/nginx:latest/get", ActionSave},         // 带 tag
		{"POST", "/images/prune", ActionPrune},
		{"POST", "/images/create", ActionPull},                  // docker pull
		{"POST", "/images/load", ActionLoad},
		{"POST", "/build", ActionBuild},
		{"POST", "/images/build", ActionBuild},
		{"POST", "/build/prune", ActionPrune},
		{"POST", "/images/nginx/push", ActionPush},
		{"DELETE", "/images/nginx", ActionRemoveImage},
		{"DELETE", "/images/sha256:abc123", ActionRemoveImage},
		{"GET", "/images/nginx/json", ActionInspect},
		{"GET", "/images/nginx/history", ActionInspect},
		{"POST", "/images/nginx/tag", ActionTag},
		{"GET", "/distribution/nginx/json", ActionInspect},
	}

	for _, tt := range tests {
		got := classifyAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("classifyAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestClassifyAction_Networks(t *testing.T) {
	tests := []struct {
		method, path string
		want         string
	}{
		{"GET", "/networks", ActionNetworkList},
		{"POST", "/networks/create", ActionNetworkCreate},
		{"POST", "/networks/prune", ActionPrune},
		{"POST", "/networks/abc123/connect", ActionNetworkConnect},
		{"POST", "/networks/abc123/disconnect", ActionNetworkDisconnect},
		{"DELETE", "/networks/abc123", ActionNetworkRemove},
		{"GET", "/networks/abc123", ActionNetworkInspect},
	}

	for _, tt := range tests {
		got := classifyAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("classifyAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestClassifyAction_Volumes(t *testing.T) {
	tests := []struct {
		method, path string
		want         string
	}{
		{"GET", "/volumes", ActionVolumeList},
		{"POST", "/volumes/create", ActionVolumeCreate},
		{"POST", "/volumes/prune", ActionPrune},
		{"DELETE", "/volumes/myvolume", ActionVolumeRemove},
		{"GET", "/volumes/myvolume", ActionVolumeInspect},
	}

	for _, tt := range tests {
		got := classifyAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("classifyAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestClassifyAction_System(t *testing.T) {
	tests := []struct {
		method, path string
		want         string
	}{
		{"GET", "/_ping", ActionSystemInfo},
		{"HEAD", "/_ping", ActionSystemInfo},
		{"GET", "/info", ActionSystemInfo},
		{"GET", "/version", ActionSystemInfo},
		{"GET", "/system/df", ActionSystemDF},
		{"GET", "/events", ActionSystemEvents},
		{"POST", "/auth", ActionSystemLogin},
		{"POST", "/system/prune", ActionPrune},
	}

	for _, tt := range tests {
		got := classifyAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("classifyAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestClassifyAction_SwarmPluginSecretConfig(t *testing.T) {
	tests := []struct {
		method, path string
		want         string
	}{
		{"GET", "/swarm", ActionSwarm},
		{"POST", "/swarm/init", ActionSwarm},
		{"GET", "/nodes", ActionSwarm},
		{"GET", "/services", ActionSwarm},
		{"GET", "/tasks", ActionSwarm},
		{"GET", "/plugins", ActionPlugin},
		{"POST", "/plugins/pull", ActionPlugin},
		{"GET", "/secrets", ActionSecret},
		{"POST", "/secrets/create", ActionSecret},
		{"GET", "/configs", ActionConfig},
		{"POST", "/configs/create", ActionConfig},
	}

	for _, tt := range tests {
		got := classifyAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("classifyAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestClassifyAction_APIVersionStripping(t *testing.T) {
	// v1.xx 前缀应被自动剥离
	tests := []struct {
		method, path string
		want         string
	}{
		{"GET", "/v1.41/containers/json", ActionPS},
		{"POST", "/v1.24/containers/create", ActionCreateContainer},
		{"DELETE", "/v1.41/images/nginx", ActionRemoveImage},
		{"GET", "/v1.41/networks", ActionNetworkList},
	}
	for _, tt := range tests {
		got := classifyAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("classifyAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestClassifyAction_Unknown(t *testing.T) {
	got := classifyAction("GET", "/some/unknown/endpoint")
	if got != ActionOther {
		t.Errorf("unknown endpoint should return %q, got %q", ActionOther, got)
	}
}

// ── stripAPIVersion ───────────────────────────────────────────────────────────

func TestStripAPIVersion(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"/v1.41/containers/json", "/containers/json"},
		{"/v1.24/images/json", "/images/json"},
		{"/containers/json", "/containers/json"},     // 无版本前缀
		{"/v/containers/json", "/v/containers/json"}, // 不合法版本号
		{"/v1/containers/json", "/containers/json"},  // 只有主版本号
		{"/_ping", "/_ping"},
	}
	for _, tt := range tests {
		got := stripAPIVersion(tt.input)
		if got != tt.want {
			t.Errorf("stripAPIVersion(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── 路径辅助函数 ──────────────────────────────────────────────────────────────

func TestPathMatches(t *testing.T) {
	if !pathMatches("/containers/json", "/containers/json") {
		t.Error("exact match should be true")
	}
	if !pathMatches("/containers/json/", "/containers/json") {
		t.Error("trailing slash should match")
	}
	if pathMatches("/containers/json/extra", "/containers/json") {
		t.Error("should not match with extra segment")
	}
}

func TestPathMatchesN(t *testing.T) {
	tests := []struct {
		path, prefix, suffix string
		want                 bool
	}{
		{"/containers/abc123/start", "/containers/", "/start", true},
		{"/containers/abc123/stop", "/containers/", "/stop", true},
		{"/containers/abc123/json", "/containers/", "/json", true},
		{"/containers/json", "/containers/", "/json", false},       // json 直接跟在 prefix 后，无 ID 段
		{"/images/nginx/push", "/images/", "/push", true},
		{"/exec/abc123/start", "/exec/", "/start", true},
		{"/containers/abc/extra/start", "/containers/", "/start", false}, // 多余路径段
	}
	for _, tt := range tests {
		got := pathMatchesN(tt.path, tt.prefix, tt.suffix)
		if got != tt.want {
			t.Errorf("pathMatchesN(%q, %q, %q) = %v, want %v", tt.path, tt.prefix, tt.suffix, got, tt.want)
		}
	}
}

func TestPathHasPrefix(t *testing.T) {
	if !pathHasPrefix("/containers/abc123/start", "/containers/") {
		t.Error("should match prefix")
	}
	if pathHasPrefix("/images/json", "/containers/") {
		t.Error("should not match different prefix")
	}
}

// ── extractContainerID ────────────────────────────────────────────────────────

func TestExtractContainerID(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"/containers/abc123def456/start", "abc123def456"},
		{"/containers/abc123def456/stop", "abc123def456"},
		{"/containers/abc123def456/json", "abc123def456"},
		{"/v1.41/containers/abc123/start", "abc123"},
		{"/containers/json", "json"},   // 调用方须用 nonContainerIDs 过滤
		{"/containers/prune", "prune"}, // 同上
		{"/containers/create", "create"},
		{"/images/nginx/json", ""},     // 不是 /containers/ 路径
	}
	for _, tt := range tests {
		got := extractContainerID(tt.uri)
		if got != tt.want {
			t.Errorf("extractContainerID(%q) = %q, want %q", tt.uri, got, tt.want)
		}
	}
}

// ── extractImageID ────────────────────────────────────────────────────────────

func TestExtractImageID(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"/images/nginx/json", "nginx"},
		{"/images/nginx:latest/json", "nginx:latest"},
		{"/images/sha256:abc123/json", "sha256:abc123"},
		{"/images/nginx/push", "nginx"},
		{"/images/nginx/tag", "nginx"},
		{"/containers/abc/json", ""},
	}
	for _, tt := range tests {
		got := extractImageID(tt.uri)
		if got != tt.want {
			t.Errorf("extractImageID(%q) = %q, want %q", tt.uri, got, tt.want)
		}
	}
}

// ── Policy.IsDenied ───────────────────────────────────────────────────────────

func TestIsDenied_UID(t *testing.T) {
	// 构造一个内存策略（不通过 loadPolicy，直接构造）
	p := &Policy{
		config: PolicyConfig{DefaultAction: "allow"},
		resolvedDenyRules: []resolvedDenyRule{
			{
				UIDs:    []int{1001},
				GIDs:    nil,
				Actions: map[string]bool{ActionPS: true, ActionBuild: true},
			},
		},
	}

	alice := &CallerIdentity{RealUsername: "alice", RealUID: 1001, RealGID: 1001}
	bob := &CallerIdentity{RealUsername: "bob", RealUID: 1002, RealGID: 1002}

	if !p.IsDenied(alice, ActionPS) {
		t.Error("alice should be denied ps")
	}
	if !p.IsDenied(alice, ActionBuild) {
		t.Error("alice should be denied build")
	}
	if p.IsDenied(alice, ActionPull) {
		t.Error("alice should NOT be denied pull")
	}
	if p.IsDenied(bob, ActionPS) {
		t.Error("bob should NOT be denied ps")
	}
}

func TestIsDenied_GID(t *testing.T) {
	p := &Policy{
		config: PolicyConfig{DefaultAction: "allow"},
		resolvedDenyRules: []resolvedDenyRule{
			{
				UIDs:    nil,
				GIDs:    []int{2000},
				Actions: map[string]bool{ActionExec: true},
			},
		},
	}

	// 用一个不存在于 /etc/passwd 的 UID，getUserGroups 会返回空
	// 所以组规则不会匹配 —— 测试不存在用户时放行
	unknown := &CallerIdentity{RealUsername: "nouser", RealUID: 99999, RealGID: 99999}
	if p.IsDenied(unknown, ActionExec) {
		t.Error("user with no groups should not be denied by GID rule")
	}
}

func TestIsDenied_DefaultAllow(t *testing.T) {
	p := &Policy{
		config:            PolicyConfig{DefaultAction: "allow"},
		resolvedDenyRules: nil,
	}
	id := &CallerIdentity{RealUsername: "anyone", RealUID: 5000}
	if p.IsDenied(id, ActionPS) {
		t.Error("no deny rules: should allow everything")
	}
}

func TestPolicy_UnresolvedNames(t *testing.T) {
	// 写一个含不存在用户的 policy.yaml 临时文件
	yaml := `
version: 1
default_action: allow
deny_rules:
  - users: [nosuchuser99999]
    actions: [ps]
`
	f, err := os.CreateTemp("", "policy-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(yaml)
	f.Close()

	p, err := loadPolicy(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.unresolvedNames) == 0 {
		t.Error("expected unresolved name for nosuchuser99999")
	}
	// 规则不应被加入 resolvedDenyRules（因为无有效 UID/GID）
	if len(p.resolvedDenyRules) != 0 {
		t.Error("rule with only unresolved users should not appear in resolvedDenyRules")
	}
}

func TestPolicy_RunAlias(t *testing.T) {
	// "run" 应同时扩展为 create_container 和 start
	yaml := `
version: 1
default_action: allow
deny_rules:
  - users: []
    actions: [run]
`
	f, err := os.CreateTemp("", "policy-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(yaml)
	f.Close()

	p, err := loadPolicy(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	// 规则体中 "run" 应被展开，但因为 users 为空所以没有 resolvedDenyRules
	// 验证 PolicyConfig 中 Actions 字段记录了 "run"
	if len(p.config.DenyRules) == 0 {
		t.Fatal("expected at least one deny rule in config")
	}
	actions := p.config.DenyRules[0].Actions
	found := false
	for _, a := range actions {
		if a == "run" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'run' in config deny_rules actions")
	}
}
