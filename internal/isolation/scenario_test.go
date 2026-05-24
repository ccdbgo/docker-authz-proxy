package isolation

import (
	"encoding/json"
	"strings"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// ── 场景测试：QuotaManager 动态配额管理 ──────────────────────────────────────

// 场景：DefaultQuotaManager 对所有用户返回零配额（不限制）
func TestQuotaManager_Default_NoLimits(t *testing.T) {
	m := DefaultQuotaManager()
	id := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}
	q := m.GetQuota(id)
	if q.CPUCores != 0 || q.MemMB != 0 || q.StorageGB != 0 || q.MaxContainers != 0 {
		t.Errorf("DefaultQuotaManager should return zero quota, got %+v", q)
	}
}

// 场景：SetUserQuota 后 GetQuota 返回用户专属配额
func TestQuotaManager_SetUserQuota(t *testing.T) {
	m := DefaultQuotaManager()
	m.SetUserQuota("alice", QuotaEntry{CPUCores: 2.0, MemMB: 1024, MaxContainers: 5})

	id := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}
	q := m.GetQuota(id)
	if q.CPUCores != 2.0 {
		t.Errorf("CPUCores = %v, want 2.0", q.CPUCores)
	}
	if q.MemMB != 1024 {
		t.Errorf("MemMB = %d, want 1024", q.MemMB)
	}
	if q.MaxContainers != 5 {
		t.Errorf("MaxContainers = %d, want 5", q.MaxContainers)
	}
}

// 场景：DeleteUserQuota 后恢复默认配额
func TestQuotaManager_DeleteUserQuota_RestoresDefault(t *testing.T) {
	m := DefaultQuotaManager()
	m.SetDefaultQuota(QuotaEntry{CPUCores: 1.0, MemMB: 512})
	m.SetUserQuota("alice", QuotaEntry{CPUCores: 4.0, MemMB: 2048})

	m.DeleteUserQuota("alice")

	id := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}
	q := m.GetQuota(id)
	if q.CPUCores != 1.0 {
		t.Errorf("after delete, CPUCores = %v, want 1.0 (default)", q.CPUCores)
	}
}

// 场景：CheckAndInjectQuota 容器数量超限时返回错误
func TestCheckAndInjectQuota_ContainerCountExceeded(t *testing.T) {
	db := newQuotaTestDB(t)
	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001, RealGID: 1001}

	// 已有 3 个容器
	for i := 0; i < 3; i++ {
		_ = db.SetContainerOwner(strings.Repeat("a", 12)+string(rune('0'+i)), alice, "")
	}

	quota := UserQuota{MaxContainers: 3}
	body := []byte(`{"Image":"nginx"}`)

	_, _, err := CheckAndInjectQuota(body, quota, 1001, db, 0)
	if err == nil {
		t.Error("expected quota exceeded error for containers, got nil")
	}
	qErr, ok := err.(*QuotaExceededError)
	if !ok {
		t.Fatalf("expected *QuotaExceededError, got %T", err)
	}
	if qErr.Resource != "containers" {
		t.Errorf("DeniedResource = %q, want containers", qErr.Resource)
	}
}

// 场景：CheckAndInjectQuota 无配额限制时直接通过
func TestCheckAndInjectQuota_NoLimits_Passes(t *testing.T) {
	db := newQuotaTestDB(t)
	quota := UserQuota{} // 全部为 0，不限制
	body := []byte(`{"HostConfig":{"NanoCPUs":8000000000,"Memory":4294967296}}`)

	_, result, err := CheckAndInjectQuota(body, quota, 1001, db, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("should be allowed when quota is zero (unlimited)")
	}
}

// ── 场景测试：InjectContainerNamePrefix ──────────────────────────────────────

// 场景：容器名称为空时不注入前缀
func TestInjectContainerNamePrefix_EmptyName_NoChange(t *testing.T) {
	id := makeIsolationIdentity("alice", 1001, 1001)
	body := []byte(`{"Image":"nginx"}`)

	result, name, err := InjectContainerNamePrefix(body, id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "" {
		t.Errorf("name = %q, want empty", name)
	}
	// body 应保持不变（无 Name 字段）
	if string(result) != string(body) {
		t.Errorf("body changed unexpectedly: %s", result)
	}
}

// 场景：容器名称已有前缀时不重复注入
func TestInjectContainerNamePrefix_AlreadyPrefixed_NoChange(t *testing.T) {
	id := makeIsolationIdentity("alice", 1001, 1001)
	prefix := UserContainerPrefix(1001)
	body, _ := json.Marshal(map[string]string{"Image": "nginx", "Name": prefix + "myapp"})

	result, name, err := InjectContainerNamePrefix(body, id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != prefix+"myapp" {
		t.Errorf("name = %q, want %q", name, prefix+"myapp")
	}
	// 名称不应被二次前缀
	var req map[string]string
	_ = json.Unmarshal(result, &req)
	if req["Name"] != prefix+"myapp" {
		t.Errorf("Name = %q, want %q", req["Name"], prefix+"myapp")
	}
}

// 场景：容器名称无前缀时注入前缀
func TestInjectContainerNamePrefix_InjectsPrefix(t *testing.T) {
	id := makeIsolationIdentity("alice", 1001, 1001)
	body, _ := json.Marshal(map[string]string{"Image": "nginx", "Name": "myapp"})

	result, rewritten, err := InjectContainerNamePrefix(body, id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	prefix := UserContainerPrefix(1001)
	if rewritten != prefix+"myapp" {
		t.Errorf("rewritten = %q, want %q", rewritten, prefix+"myapp")
	}
	var req map[string]string
	_ = json.Unmarshal(result, &req)
	if req["Name"] != prefix+"myapp" {
		t.Errorf("Name = %q, want %q", req["Name"], prefix+"myapp")
	}
}

// ── 场景测试：InjectNetworkNamePrefix ────────────────────────────────────────

// 场景：网络名称注入用户前缀
func TestInjectNetworkNamePrefix_InjectsPrefix(t *testing.T) {
	id := makeIsolationIdentity("alice", 1001, 1001)
	body, _ := json.Marshal(map[string]string{"Name": "mynet", "Driver": "bridge"})

	result, err := InjectNetworkNamePrefix(body, id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var req map[string]string
	_ = json.Unmarshal(result, &req)
	prefix := UserResourcePrefix(id)
	if req["Name"] != prefix+"mynet" {
		t.Errorf("Name = %q, want %q", req["Name"], prefix+"mynet")
	}
}

// 场景：网络名称已有前缀时不重复注入
func TestInjectNetworkNamePrefix_AlreadyPrefixed_NoChange(t *testing.T) {
	id := makeIsolationIdentity("alice", 1001, 1001)
	prefix := UserResourcePrefix(id)
	body, _ := json.Marshal(map[string]string{"Name": prefix + "mynet"})

	result, err := InjectNetworkNamePrefix(body, id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var req map[string]string
	_ = json.Unmarshal(result, &req)
	if req["Name"] != prefix+"mynet" {
		t.Errorf("Name = %q, want %q", req["Name"], prefix+"mynet")
	}
}

// ── 场景测试：FilterNetworkListResponse ──────────────────────────────────────

// 场景：root 用户看到所有网络
func TestFilterNetworkListResponse_RootSeesAll(t *testing.T) {
	db := newFilterTestDB(t)
	alice := makeFilterIdentity("alice", 1001, 1001)
	_ = db.SetNetworkOwner("net-1", "alice_u1001_mynet", alice)

	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": "net-1", "Name": "alice_u1001_mynet"},
		{"Id": "net-2", "Name": "bridge"},
	})

	filtered, err := FilterNetworkListResponse(body, 0, true, db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	_ = json.Unmarshal(filtered, &result)
	if len(result) != 2 {
		t.Errorf("root should see all 2 networks, got %d", len(result))
	}
}

// 场景：普通用户只看到自己的网络（通过 DB 归属）
func TestFilterNetworkListResponse_UserSeesOwnNetworks(t *testing.T) {
	db := newFilterTestDB(t)
	alice := makeFilterIdentity("alice", 1001, 1001)
	bob := makeFilterIdentity("bob", 1002, 1002)

	_ = db.SetNetworkOwner("net-alice", "alice_u1001_mynet", alice)
	_ = db.SetNetworkOwner("net-bob", "bob_u1002_mynet", bob)

	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": "net-alice", "Name": "alice_u1001_mynet"},
		{"Id": "net-bob", "Name": "bob_u1002_mynet"},
	})

	filtered, err := FilterNetworkListResponse(body, 1001, false, db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	_ = json.Unmarshal(filtered, &result)
	if len(result) != 1 {
		t.Errorf("alice should see 1 network, got %d", len(result))
	}
}

// 场景：用户应能看到自己的专属 bridge 网络（user-{uid}-bridge），
// 该网络名不带用户前缀，只能通过 DB 归属匹配。
// 若 DB 中无记录，该网络会被过滤掉——这是已知 bug 的验证测试。
func TestFilterNetworkListResponse_UserBridgeVisible(t *testing.T) {
	db := newFilterTestDB(t)

	bridgeName := "user-1001-bridge"
	bridgeID := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

	// 模拟 ensureUserBridge 调用 SetManagedNetworkOwner 写入 DB
	if err := db.SetManagedNetworkOwner(bridgeID, bridgeName, 1001, "alice"); err != nil {
		t.Fatalf("SetManagedNetworkOwner: %v", err)
	}

	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": bridgeID, "Name": bridgeName},
		{"Id": "other-net-id-000000000000000000000000000000000000000000000000000", "Name": "bob_u1002_mynet"},
	})

	filtered, err := FilterNetworkListResponse(body, 1001, false, db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	_ = json.Unmarshal(filtered, &result)
	if len(result) != 1 {
		t.Errorf("alice should see her bridge network, got %d networks (want 1)", len(result))
	}
	if len(result) == 1 {
		if result[0]["Name"] != bridgeName {
			t.Errorf("network name = %q, want %q", result[0]["Name"], bridgeName)
		}
	}
}

// 场景：DB 中无记录时，user-{uid}-bridge 不应出现在列表（验证过滤严格性）
func TestFilterNetworkListResponse_UserBridgeHiddenWithoutDB(t *testing.T) {
	db := newFilterTestDB(t)
	// 不写 DB，模拟 ensureUserBridge 未执行或 DB 丢失的情况

	bridgeName := "user-1001-bridge"
	bridgeID := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": bridgeID, "Name": bridgeName},
	})

	filtered, err := FilterNetworkListResponse(body, 1001, false, db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	_ = json.Unmarshal(filtered, &result)
	// DB 无记录时，bridge 网络不可见——这是当前行为，也是 bug 的根因
	if len(result) != 0 {
		t.Errorf("bridge without DB record should be hidden, got %d networks", len(result))
	}
}

// 场景：FilterNetworkListResponse 无效 JSON 返回错误
func TestFilterNetworkListResponse_InvalidJSON(t *testing.T) {
	db := newFilterTestDB(t)
	body := []byte(`not json`)
	_, err := FilterNetworkListResponse(body, 1001, false, db)
	// 无效 JSON 应返回错误（与容器列表不同，网络列表解析失败返回 error）
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// ── 场景测试：GetLastLabelValue 边界情况 ─────────────────────────────────────

func TestGetLastLabelValue_EmptyString(t *testing.T) {
	got := GetLastLabelValue("")
	if got != "" {
		t.Errorf("GetLastLabelValue(\"\") = %q, want \"\"", got)
	}
}

func TestGetLastLabelValue_OnlyCommas(t *testing.T) {
	got := GetLastLabelValue(",,,")
	if got != "" {
		t.Errorf("GetLastLabelValue(\",,,\") = %q, want \"\"", got)
	}
}

// ── 场景测试：InjectSystemLabels 并发安全 ────────────────────────────────────

func TestInjectSystemLabels_Concurrent(t *testing.T) {
	id := makeIsolationIdentity("alice", 1001, 1001)
	id.EffectiveUID = 1001
	body := []byte(`{"Image":"nginx"}`)

	done := make(chan struct{}, 10)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			result, err := InjectSystemLabels(body, id)
			if err != nil {
				return
			}
			labels := make(map[string]string)
			var req struct {
				Labels map[string]string `json:"Labels"`
			}
			_ = json.Unmarshal(result, &req)
			labels = req.Labels
			if labels[LabelOwnerUsername] != "alice" {
				t.Errorf("concurrent: LabelOwnerUsername = %q, want alice", labels[LabelOwnerUsername])
			}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

// ── 场景测试：FilterContainerListResponse 短 ID 匹配 ─────────────────────────

func TestFilterContainerListResponse_ShortIDMatch(t *testing.T) {
	db := newFilterTestDB(t)
	alice := makeFilterIdentity("alice", 1001, 1001)

	// 存储完整 64 字符 ID
	fullID := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	_ = db.SetContainerOwner(fullID, alice, "")

	// 响应中使用短 ID（前 12 字符）
	shortID := fullID[:12]
	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": shortID, "Labels": nil},
	})

	filtered, err := FilterContainerListResponse(body, 1001, "alice", false, db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	_ = json.Unmarshal(filtered, &result)
	if len(result) != 1 {
		t.Errorf("alice should see container via short ID match, got %d", len(result))
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// newQuotaTestDB 已在 quota_network_test.go 中定义（同包），此处无需重复声明
// newFilterTestDB 已在 filter_test.go 中定义（同包），此处无需重复声明
// makeIsolationIdentity 已在 labels_test.go 中定义（同包），此处无需重复声明
// makeFilterIdentity 已在 filter_test.go 中定义（同包），此处无需重复声明
// mustMarshalFilter 已在 filter_test.go 中定义（同包），此处无需重复声明

// 确保 authz 包被引用（通过 newFilterTestDB 间接使用）
var _ *authz.OwnershipDB
