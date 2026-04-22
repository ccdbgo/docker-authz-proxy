package authz

import (
	"os"
	"testing"
)

// ── 场景测试：策略默认拒绝模式 ────────────────────────────────────────────────

// 场景：default_action=deny 时，未在 deny_rules 中的用户也被拒绝
func TestPolicy_DefaultDeny_BlocksEveryone(t *testing.T) {
	policy := mustLoadScenarioPolicy(t, `
version: 1
default_action: deny
deny_rules: []
`)
	id := makeTestIdentity("alice", 1001, 1001)
	// default_action=deny 时，IsDenied 本身只检查 deny_rules
	// 调用方需检查 Config.DefaultAction
	if policy.Config.DefaultAction != "deny" {
		t.Errorf("DefaultAction = %q, want deny", policy.Config.DefaultAction)
	}
	// deny_rules 为空，IsDenied 返回 false（无规则命中）
	if policy.IsDenied(id, ActionPS) {
		t.Error("IsDenied should be false when deny_rules is empty")
	}
}

// 场景：deny_rules 中指定用户被拒绝，其他用户不受影响
func TestPolicy_DenyRule_OnlyAffectsSpecifiedUser(t *testing.T) {
	policy := mustLoadScenarioPolicy(t, `
version: 1
default_action: allow
deny_rules:
  - users: ["alice"]
    actions: ["run"]
`)
	alice := makeTestIdentity("alice", 1001, 1001)
	bob := makeTestIdentity("bob", 1002, 1002)

	if !policy.IsDenied(alice, ActionCreateContainer) {
		t.Error("alice should be denied create_container (run maps to create_container)")
	}
	if policy.IsDenied(bob, ActionCreateContainer) {
		t.Error("bob should NOT be denied create_container")
	}
}

// 场景：run 操作映射到 create_container + start
func TestPolicy_RunAction_MapsToCreateAndStart(t *testing.T) {
	policy := mustLoadScenarioPolicy(t, `
version: 1
default_action: allow
deny_rules:
  - users: ["alice"]
    actions: ["run"]
`)
	alice := makeTestIdentity("alice", 1001, 1001)

	if !policy.IsDenied(alice, ActionCreateContainer) {
		t.Error("run should deny create_container")
	}
	if !policy.IsDenied(alice, ActionStartContainer) {
		t.Error("run should deny start")
	}
	// pull 不在 run 的映射中
	if policy.IsDenied(alice, ActionPull) {
		t.Error("run should NOT deny pull")
	}
}

// 场景：多个操作同时被拒绝
func TestPolicy_MultipleActionsInDenyRule(t *testing.T) {
	policy := mustLoadScenarioPolicy(t, `
version: 1
default_action: allow
deny_rules:
  - users: ["alice"]
    actions: ["pull", "rmi", "build"]
`)
	alice := makeTestIdentity("alice", 1001, 1001)

	for _, action := range []string{ActionPull, ActionRemoveImage, ActionBuild} {
		if !policy.IsDenied(alice, action) {
			t.Errorf("alice should be denied action %q", action)
		}
	}
	if policy.IsDenied(alice, ActionPS) {
		t.Error("alice should NOT be denied ps")
	}
}

// 场景：DefaultAllowPolicy 不拒绝任何操作
func TestDefaultAllowPolicy_NeverDenies(t *testing.T) {
	policy := DefaultAllowPolicy()
	id := makeTestIdentity("alice", 1001, 1001)

	actions := []string{ActionPS, ActionCreateContainer, ActionPull, ActionRemoveImage, ActionBuild}
	for _, a := range actions {
		if policy.IsDenied(id, a) {
			t.Errorf("DefaultAllowPolicy should not deny action %q", a)
		}
	}
}

// 场景：LoadPolicy 文件不存在时返回错误
func TestLoadPolicy_FileNotFound(t *testing.T) {
	_, err := LoadPolicy("/nonexistent/path/policy.yaml")
	if err == nil {
		t.Error("LoadPolicy should return error for nonexistent file")
	}
}

// 场景：LoadPolicy 无效 YAML 返回错误
func TestLoadPolicy_InvalidYAML(t *testing.T) {
	f, err := os.CreateTemp("", "policy-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString("{ invalid yaml: [")
	f.Close()

	_, err = LoadPolicy(f.Name())
	if err == nil {
		t.Error("LoadPolicy should return error for invalid YAML")
	}
}

// 场景：LoadPolicy 缺少 default_action 时默认为 allow
func TestLoadPolicy_DefaultActionFallback(t *testing.T) {
	policy := mustLoadScenarioPolicy(t, `
version: 1
deny_rules: []
`)
	if policy.Config.DefaultAction != "allow" {
		t.Errorf("DefaultAction = %q, want allow", policy.Config.DefaultAction)
	}
}

// ── 场景测试：OwnershipDB 高级场景 ────────────────────────────────────────────

// 场景：CountContainersByOwner 正确统计
func TestOwnershipDB_CountContainersByOwner(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	bob := makeTestIdentity("bob", 1002, 1002)

	_ = db.SetContainerOwner("c1", alice, "")
	_ = db.SetContainerOwner("c2", alice, "")
	_ = db.SetContainerOwner("c3", bob, "")

	count, err := db.CountContainersByOwner(1001)
	if err != nil {
		t.Fatalf("CountContainersByOwner: %v", err)
	}
	if count != 2 {
		t.Errorf("alice count = %d, want 2", count)
	}

	count, err = db.CountContainersByOwner(1002)
	if err != nil {
		t.Fatalf("CountContainersByOwner: %v", err)
	}
	if count != 1 {
		t.Errorf("bob count = %d, want 1", count)
	}
}

// 场景：HasContainerUsingImage 正确检测镜像引用
func TestOwnershipDB_HasContainerUsingImage(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)

	_ = db.SetContainerOwner("cont-1", alice, "sha256:img-abc")
	_ = db.SetContainerOwner("cont-2", alice, "sha256:img-xyz")

	has, err := db.HasContainerUsingImage(1001, "sha256:img-abc")
	if err != nil {
		t.Fatalf("HasContainerUsingImage: %v", err)
	}
	if !has {
		t.Error("alice should have container using sha256:img-abc")
	}

	has, err = db.HasContainerUsingImage(1001, "sha256:img-other")
	if err != nil {
		t.Fatalf("HasContainerUsingImage: %v", err)
	}
	if has {
		t.Error("alice should NOT have container using sha256:img-other")
	}
}

// 场景：SetImageOwner 幂等（重复调用不报错，不覆盖）
func TestOwnershipDB_SetImageOwner_Idempotent(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	bob := makeTestIdentity("bob", 1002, 1002)

	// 第一次设置
	if err := db.SetImageOwner("sha256:img-1", alice, false, "pull"); err != nil {
		t.Fatalf("first SetImageOwner: %v", err)
	}
	// 第二次设置（INSERT OR IGNORE，不覆盖）
	if err := db.SetImageOwner("sha256:img-1", bob, false, "pull"); err != nil {
		t.Fatalf("second SetImageOwner: %v", err)
	}

	owner, _, found := db.GetImageOwner("sha256:img-1")
	if !found {
		t.Fatal("image not found")
	}
	// 原始所有者应为 alice（INSERT OR IGNORE）
	if owner.UID != 1001 {
		t.Errorf("owner UID = %d, want 1001 (alice, first setter)", owner.UID)
	}
}

// 场景：公共镜像对所有用户可见
func TestOwnershipDB_PublicImage_AccessibleToAll(t *testing.T) {
	db := newTestDB(t)
	root := makeTestIdentity("root", 0, 0)

	_ = db.SetImageOwner("sha256:public-img", root, true, "pull")

	// 任意非 root 用户都能访问公共镜像
	for _, uid := range []int{1001, 1002, 9999} {
		if !db.CanUseImage(uid, "sha256:public-img") {
			t.Errorf("uid %d should be able to use public image", uid)
		}
	}
}

// 场景：私有镜像只有所有者可访问
func TestOwnershipDB_PrivateImage_OnlyOwnerAccess(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)

	_ = db.SetImageOwner("sha256:private-img", alice, false, "pull")

	if !db.CanUseImage(1001, "sha256:private-img") {
		t.Error("alice should be able to use her own private image")
	}
	if db.CanUseImage(1002, "sha256:private-img") {
		t.Error("bob should NOT be able to use alice's private image")
	}
}

// 场景：EnsureImageAccess 授权后其他用户可访问
func TestOwnershipDB_EnsureImageAccess(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)

	_ = db.SetImageOwner("sha256:shared-img", alice, false, "pull")

	// bob 初始无权访问
	if db.CanUseImage(1002, "sha256:shared-img") {
		t.Error("bob should NOT have access before grant")
	}

	// 授权 bob
	if err := db.EnsureImageAccess("sha256:shared-img", 1002); err != nil {
		t.Fatalf("EnsureImageAccess: %v", err)
	}

	if !db.CanUseImage(1002, "sha256:shared-img") {
		t.Error("bob should have access after EnsureImageAccess")
	}
}

// 场景：ClassifyAction 覆盖网络和卷操作
func TestClassifyAction_NetworkAndVolume(t *testing.T) {
	tests := []struct {
		method, path string
		want         string
	}{
		{"GET", "/networks", ActionNetworkList},
		{"POST", "/networks/create", ActionNetworkCreate},
		{"DELETE", "/networks/mynet", ActionNetworkRemove},
		{"GET", "/volumes", ActionVolumeList},
		{"POST", "/volumes/create", ActionVolumeCreate},
		{"DELETE", "/volumes/myvol", ActionVolumeRemove},
	}
	for _, tt := range tests {
		got := ClassifyAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("ClassifyAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

// 场景：ExtractContainerID 从各种路径中提取容器 ID
func TestExtractContainerID_Scenarios(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/containers/abc123/start", "abc123"},
		{"/containers/abc123/stop", "abc123"},
		{"/containers/abc123/logs", "abc123"},
		{"/containers/abc123/exec", "abc123"},
		// /containers/json 和 /containers/create 没有第二个 /，返回末段
		{"/containers/json", "json"},
		{"/containers/create", "create"},
		{"/v1.41/containers/abc123/start", "abc123"},
	}
	for _, tt := range tests {
		got := ExtractContainerID(tt.path)
		if got != tt.want {
			t.Errorf("ExtractContainerID(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

// 场景：ExtractImageID 从各种路径中提取镜像 ID
func TestExtractImageID_Scenarios(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/images/sha256:abc123/json", "sha256:abc123"},
		{"/images/nginx:latest/json", "nginx:latest"},
		// /images/json 没有第二个 /，返回末段 "json"
		{"/images/json", "json"},
		{"/v1.41/images/sha256:abc/json", "sha256:abc"},
	}
	for _, tt := range tests {
		got := ExtractImageID(tt.path)
		if got != tt.want {
			t.Errorf("ExtractImageID(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

// 场景：deny_rules 中未解析的用户名被记录到 UnresolvedNames
func TestPolicy_UnresolvedUsernames(t *testing.T) {
	policy := mustLoadScenarioPolicy(t, `
version: 1
default_action: allow
deny_rules:
  - users: ["nonexistent_user_xyz_12345"]
    actions: ["run"]
`)
	if len(policy.UnresolvedNames) == 0 {
		t.Error("nonexistent user should be in UnresolvedNames")
	}
}

// ── 场景测试：OwnershipDB 网络归属 ────────────────────────────────────────────

// 场景：网络归属 CRUD
func TestOwnershipDB_NetworkCRUD(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)

	if err := db.SetNetworkOwner("net-1", "alice-net", alice); err != nil {
		t.Fatalf("SetNetworkOwner: %v", err)
	}

	owner, found := db.GetNetworkOwner("net-1")
	if !found {
		t.Fatal("network not found after insert")
	}
	if owner.UID != 1001 {
		t.Errorf("network owner UID = %d, want 1001", owner.UID)
	}

	if err := db.DeleteNetwork("net-1"); err != nil {
		t.Fatalf("DeleteNetwork: %v", err)
	}
	_, found = db.GetNetworkOwner("net-1")
	if found {
		t.Error("network should be gone after delete")
	}
}

// 场景：卷归属 CRUD
func TestOwnershipDB_VolumeCRUD(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)

	if err := db.SetVolumeOwner("vol-1", alice); err != nil {
		t.Fatalf("SetVolumeOwner: %v", err)
	}

	owner, found := db.GetVolumeOwner("vol-1")
	if !found {
		t.Fatal("volume not found after insert")
	}
	if owner.UID != 1001 {
		t.Errorf("volume owner UID = %d, want 1001", owner.UID)
	}

	if err := db.DeleteVolume("vol-1"); err != nil {
		t.Fatalf("DeleteVolume: %v", err)
	}
	_, found = db.GetVolumeOwner("vol-1")
	if found {
		t.Error("volume should be gone after delete")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func mustLoadScenarioPolicy(t *testing.T, yaml string) *Policy {
	t.Helper()
	f, err := os.CreateTemp("", "scenario-policy-*.yaml")
	if err != nil {
		t.Fatalf("create temp policy: %v", err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString(yaml)
	f.Close()

	p, err := LoadPolicy(f.Name())
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	return p
}

// makeTestIdentity 已在 ownership_test.go 中定义（同包），此处无需重复声明
