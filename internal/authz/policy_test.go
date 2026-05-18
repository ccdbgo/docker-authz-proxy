package authz

import (
	"os"
	"testing"

	"docker-authz-proxy/internal/auth"
)

// ── ClassifyAction ────────────────────────────────────────────────────────────

func TestClassifyAction_Containers(t *testing.T) {
	tests := []struct {
		method, path string
		want         string
	}{
		{"GET", "/containers/json", ActionPS},
		{"GET", "/v1.41/containers/json", ActionPS},
		{"GET", "/containers/json?all=1", ActionPS},
		{"POST", "/containers/create", ActionCreateContainer},
		{"POST", "/v1.41/containers/create", ActionCreateContainer},
		{"POST", "/containers/abc123/start", ActionStartContainer},
		{"POST", "/v1.41/containers/abc123/start", ActionStartContainer},
		{"POST", "/containers/abc123/restart", ActionRestart},
		{"POST", "/containers/abc123/stop", ActionStop},
		{"POST", "/containers/abc123/kill", ActionKill},
		{"POST", "/containers/abc123/pause", ActionPause},
		{"POST", "/containers/abc123/unpause", ActionUnpause},
		{"POST", "/containers/abc123/rename", ActionRename},
		{"POST", "/containers/abc123/update", ActionUpdate},
		{"POST", "/containers/abc123/wait", ActionOther},
		{"DELETE", "/containers/abc123", ActionRemoveContainer},
		{"DELETE", "/containers/abc123def456", ActionRemoveContainer},
		{"POST", "/containers/abc123/exec", ActionExec},
		{"POST", "/containers/abc123/attach", ActionExec},
		{"POST", "/containers/abc123/resize", ActionExec},
		{"GET", "/containers/abc123/attach", ActionExec},
		{"GET", "/containers/abc123/attach/ws", ActionExec},
		{"POST", "/exec/abc123/start", ActionExec},
		{"POST", "/exec/abc123/resize", ActionExec},
		{"GET", "/containers/abc123/json", ActionInspect},
		{"GET", "/exec/abc123/json", ActionInspect},
		{"GET", "/containers/abc123/logs", ActionLogs},
		{"GET", "/containers/abc123/stats", ActionLogs},
		{"GET", "/containers/abc123/top", ActionLogs},
		{"GET", "/containers/abc123/changes", ActionLogs},
		{"GET", "/containers/abc123/archive", ActionCp},
		{"HEAD", "/containers/abc123/archive", ActionCp},
		{"PUT", "/containers/abc123/archive", ActionCp},
		{"GET", "/containers/abc123/export", ActionCp},
		{"POST", "/commit", ActionCommit},
		{"POST", "/containers/prune", ActionPrune},
	}

	for _, tt := range tests {
		got := ClassifyAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("ClassifyAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
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
		{"GET", "/images/get", ActionSave},
		{"GET", "/images/nginx/get", ActionSave},
		{"GET", "/images/nginx:latest/get", ActionSave},
		{"POST", "/images/prune", ActionPrune},
		{"POST", "/images/create", ActionPull},
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
		got := ClassifyAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("ClassifyAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
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
		got := ClassifyAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("ClassifyAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
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
		got := ClassifyAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("ClassifyAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
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
		got := ClassifyAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("ClassifyAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
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
		// plugin 细粒度
		{"GET", "/plugins", ActionPluginList},
		{"GET", "/plugins/myplugin/json", ActionPluginInspect},
		{"POST", "/plugins/pull", ActionPluginInstall},
		{"DELETE", "/plugins/myplugin", ActionPluginRemove},
		{"POST", "/plugins/myplugin/enable", ActionPluginEnable},
		{"POST", "/plugins/myplugin/disable", ActionPluginDisable},
		{"POST", "/plugins/myplugin/upgrade", ActionPluginUpgrade},
		{"POST", "/plugins/myplugin/set", ActionPluginSet},
		{"POST", "/plugins/myplugin/push", ActionPluginPush},
		{"POST", "/plugins/create", ActionPluginCreate},
		{"GET", "/secrets", ActionSecret},
		{"POST", "/secrets/create", ActionSecret},
		{"GET", "/configs", ActionConfig},
		{"POST", "/configs/create", ActionConfig},
	}

	for _, tt := range tests {
		got := ClassifyAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("ClassifyAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestClassifyAction_APIVersionStripping(t *testing.T) {
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
		got := ClassifyAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("ClassifyAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestClassifyAction_Unknown(t *testing.T) {
	got := ClassifyAction("GET", "/some/unknown/endpoint")
	if got != ActionOther {
		t.Errorf("unknown endpoint should return %q, got %q", ActionOther, got)
	}
}

// ── StripAPIVersion ───────────────────────────────────────────────────────────

func TestStripAPIVersion(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"/v1.41/containers/json", "/containers/json"},
		{"/v1.24/images/json", "/images/json"},
		{"/containers/json", "/containers/json"},
		{"/v/containers/json", "/v/containers/json"},
		{"/v1/containers/json", "/containers/json"},
		{"/_ping", "/_ping"},
	}
	for _, tt := range tests {
		got := StripAPIVersion(tt.input)
		if got != tt.want {
			t.Errorf("StripAPIVersion(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── path helpers ──────────────────────────────────────────────────────────────

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
		{"/containers/json", "/containers/", "/json", false},
		{"/images/nginx/push", "/images/", "/push", true},
		{"/exec/abc123/start", "/exec/", "/start", true},
		{"/containers/abc/extra/start", "/containers/", "/start", false},
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

// ── ExtractContainerID ────────────────────────────────────────────────────────

func TestExtractContainerID(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"/containers/abc123def456/start", "abc123def456"},
		{"/containers/abc123def456/stop", "abc123def456"},
		{"/containers/abc123def456/json", "abc123def456"},
		{"/v1.41/containers/abc123/start", "abc123"},
		{"/containers/json", "json"},
		{"/containers/prune", "prune"},
		{"/containers/create", "create"},
		{"/images/nginx/json", ""},
	}
	for _, tt := range tests {
		got := ExtractContainerID(tt.uri)
		if got != tt.want {
			t.Errorf("ExtractContainerID(%q) = %q, want %q", tt.uri, got, tt.want)
		}
	}
}

// ── ExtractImageID ────────────────────────────────────────────────────────────

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
		got := ExtractImageID(tt.uri)
		if got != tt.want {
			t.Errorf("ExtractImageID(%q) = %q, want %q", tt.uri, got, tt.want)
		}
	}
}

// ── Policy.IsDenied ───────────────────────────────────────────────────────────

func makeCallerIdentity(username string, uid, gid int) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		RealGID:           gid,
		EffectiveUsername: username,
		EffectiveUID:      uid,
		UserType:          auth.UserTypeRegular,
	}
}

func TestIsDenied_UID(t *testing.T) {
	p := &Policy{
		Config: PolicyConfig{DefaultAction: "allow"},
		ResolvedDenyRules: []ResolvedDenyRule{
			{
				UIDs:    []int{1001},
				GIDs:    nil,
				Actions: map[string]bool{ActionPS: true, ActionBuild: true},
			},
		},
	}

	alice := makeCallerIdentity("alice", 1001, 1001)
	bob := makeCallerIdentity("bob", 1002, 1002)

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
		Config: PolicyConfig{DefaultAction: "allow"},
		ResolvedDenyRules: []ResolvedDenyRule{
			{
				UIDs:    nil,
				GIDs:    []int{2000},
				Actions: map[string]bool{ActionExec: true},
			},
		},
	}

	unknown := makeCallerIdentity("nouser", 99999, 99999)
	if p.IsDenied(unknown, ActionExec) {
		t.Error("user with no groups should not be denied by GID rule")
	}
}

func TestIsDenied_DefaultAllow(t *testing.T) {
	p := &Policy{
		Config:            PolicyConfig{DefaultAction: "allow"},
		ResolvedDenyRules: nil,
	}
	id := makeCallerIdentity("anyone", 5000, 5000)
	if p.IsDenied(id, ActionPS) {
		t.Error("no deny rules: should allow everything")
	}
}

func TestPolicy_UnresolvedNames(t *testing.T) {
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

	p, err := LoadPolicy(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.UnresolvedNames) == 0 {
		t.Error("expected unresolved name for nosuchuser99999")
	}
	if len(p.ResolvedDenyRules) != 0 {
		t.Error("rule with only unresolved users should not appear in ResolvedDenyRules")
	}
}

func TestPolicy_RunAlias(t *testing.T) {
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

	p, err := LoadPolicy(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Config.DenyRules) == 0 {
		t.Fatal("expected at least one deny rule in config")
	}
	actions := p.Config.DenyRules[0].Actions
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

// ── diagnose ─────────────────────────────────────────────────────────────────

func TestDiagnose_DockerPsVsInfo(t *testing.T) {
	tests := []struct {
		method, uri string
		want        string
	}{
		{"GET", "/info", ActionSystemInfo},
		{"GET", "/v1.41/info", ActionSystemInfo},
		{"GET", "/version", ActionSystemInfo},
		{"GET", "/_ping", ActionSystemInfo},
		{"HEAD", "/_ping", ActionSystemInfo},
		{"GET", "/containers/json", ActionPS},
		{"GET", "/v1.41/containers/json", ActionPS},
		{"GET", "/containers/json?all=1", ActionPS},
		{"GET", "/v1.41/containers/json?all=1&size=1", ActionPS},
	}

	for _, tt := range tests {
		got := ClassifyAction(tt.method, tt.uri)
		if got != tt.want {
			t.Errorf("ClassifyAction(%q, %q) = %q, want %q", tt.method, tt.uri, got, tt.want)
		}
	}
}
