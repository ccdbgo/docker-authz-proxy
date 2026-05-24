package isolation

import (
	"encoding/json"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// ── CheckAndInjectQuota ───────────────────────────────────────────────────────

func newQuotaTestDB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCheckAndInjectQuota_NoCPULimit_Passes(t *testing.T) {
	db := newQuotaTestDB(t)
	quota := UserQuota{CPUCores: 2.0, MemMB: 512}
	body := []byte(`{"HostConfig":{}}`)

	newBody, _, err := CheckAndInjectQuota(body, quota, 1001, db, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var req containerCreateRequest
	if e := json.Unmarshal(newBody, &req); e != nil {
		t.Fatalf("unmarshal: %v", e)
	}
	// 未指定 CPU，应注入配额上限
	wantNano := int64(2.0 * 1e9)
	if req.HostConfig.NanoCPUs != wantNano {
		t.Errorf("NanoCPUs = %d, want %d", req.HostConfig.NanoCPUs, wantNano)
	}
}

func TestCheckAndInjectQuota_CPUExceeded(t *testing.T) {
	db := newQuotaTestDB(t)
	quota := UserQuota{CPUCores: 1.0}
	// 请求 4 核
	body := []byte(`{"HostConfig":{"NanoCPUs":4000000000}}`)

	_, _, err := CheckAndInjectQuota(body, quota, 1001, db, 0, 0)
	if err == nil {
		t.Error("expected quota exceeded error for CPU, got nil")
	}
}

func TestCheckAndInjectQuota_MemoryExceeded(t *testing.T) {
	db := newQuotaTestDB(t)
	quota := UserQuota{MemMB: 256}
	// 请求 1GB
	body := []byte(`{"HostConfig":{"Memory":1073741824}}`)

	_, _, err := CheckAndInjectQuota(body, quota, 1001, db, 0, 0)
	if err == nil {
		t.Error("expected quota exceeded error for memory, got nil")
	}
}

func TestCheckAndInjectQuota_MemoryInjected(t *testing.T) {
	db := newQuotaTestDB(t)
	quota := UserQuota{MemMB: 512}
	body := []byte(`{"HostConfig":{}}`)

	newBody, _, err := CheckAndInjectQuota(body, quota, 1001, db, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var req containerCreateRequest
	if e := json.Unmarshal(newBody, &req); e != nil {
		t.Fatalf("unmarshal: %v", e)
	}
	wantMem := int64(512 * 1024 * 1024)
	if req.HostConfig.Memory != wantMem {
		t.Errorf("Memory = %d, want %d", req.HostConfig.Memory, wantMem)
	}
}

func TestCheckAndInjectQuota_MaxContainersExceeded(t *testing.T) {
	db := newQuotaTestDB(t)
	quota := UserQuota{MaxContainers: 2}

	// 已有 2 个容器
	_ = db.SetContainerOwner("c1", &auth.CallerIdentity{RealUID: 1001, RealUsername: "testuser"}, "")
	_ = db.SetContainerOwner("c2", &auth.CallerIdentity{RealUID: 1001, RealUsername: "testuser"}, "")

	body := []byte(`{"HostConfig":{}}`)
	_, _, err := CheckAndInjectQuota(body, quota, 1001, db, 0, 0)
	if err == nil {
		t.Error("expected quota exceeded error for max containers, got nil")
	}
}

func TestCheckAndInjectQuota_NoLimits_Passthrough(t *testing.T) {
	db := newQuotaTestDB(t)
	// 全零配额 = 不限制
	quota := UserQuota{}
	body := []byte(`{"HostConfig":{"NanoCPUs":8000000000,"Memory":4294967296}}`)

	_, _, err := CheckAndInjectQuota(body, quota, 1001, db, 0, 0)
	if err != nil {
		t.Errorf("zero quota should not block: %v", err)
	}
}

// ── parseStorageGB ────────────────────────────────────────────────────────────

func TestParseStorageGB(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"10G", 10},
		{"10g", 10},
		{"2T", 2048},
		{"1024M", 1},
		{"512M", 0}, // < 1GB rounds to 0
		{"", 0},
		{"G", 0},
	}
	for _, tt := range tests {
		got := parseStorageGB(tt.input)
		if got != tt.want {
			t.Errorf("parseStorageGB(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

// ── InjectContainerNamePrefix ─────────────────────────────────────────────────

func TestInjectContainerNamePrefix_AddsPrefix(t *testing.T) {
	id := &auth.CallerIdentity{RealUID: 1001}
	body := []byte(`{"Image":"nginx","Name":"myapp"}`)

	newBody, rewritten, err := InjectContainerNamePrefix(body, id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rewritten != "user-1001-myapp" {
		t.Errorf("rewritten = %q, want %q", rewritten, "user-1001-myapp")
	}

	var req map[string]json.RawMessage
	_ = json.Unmarshal(newBody, &req)
	var name string
	_ = json.Unmarshal(req["Name"], &name)
	if name != "user-1001-myapp" {
		t.Errorf("body Name = %q, want %q", name, "user-1001-myapp")
	}
}

func TestInjectContainerNamePrefix_AlreadyPrefixed(t *testing.T) {
	id := &auth.CallerIdentity{RealUID: 1001}
	body := []byte(`{"Image":"nginx","Name":"user-1001-myapp"}`)

	newBody, rewritten, err := InjectContainerNamePrefix(body, id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 已有前缀，不应再次添加
	if rewritten != "user-1001-myapp" {
		t.Errorf("rewritten = %q, want %q", rewritten, "user-1001-myapp")
	}
	_ = newBody
}

func TestInjectContainerNamePrefix_EmptyName(t *testing.T) {
	id := &auth.CallerIdentity{RealUID: 1001}
	body := []byte(`{"Image":"nginx"}`)

	_, rewritten, err := InjectContainerNamePrefix(body, id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 无 Name 字段，不注入
	if rewritten != "" {
		t.Errorf("empty name should return empty rewritten, got %q", rewritten)
	}
}

// ── InjectNetworkNamePrefix ───────────────────────────────────────────────────

func TestInjectNetworkNamePrefix_AddsPrefix(t *testing.T) {
	id := &auth.CallerIdentity{RealUID: 1001, RealUsername: "alice"}
	body := []byte(`{"Name":"mynet","Driver":"bridge"}`)

	newBody, err := InjectNetworkNamePrefix(body, id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var req map[string]json.RawMessage
	_ = json.Unmarshal(newBody, &req)
	var name string
	_ = json.Unmarshal(req["Name"], &name)

	expected := "alice_u1001_mynet"
	if name != expected {
		t.Errorf("Name = %q, want %q", name, expected)
	}
}

func TestInjectNetworkNamePrefix_AlreadyPrefixed(t *testing.T) {
	id := &auth.CallerIdentity{RealUID: 1001, RealUsername: "alice"}
	body := []byte(`{"Name":"alice_u1001_mynet"}`)

	newBody, err := InjectNetworkNamePrefix(body, id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var req map[string]json.RawMessage
	_ = json.Unmarshal(newBody, &req)
	var name string
	_ = json.Unmarshal(req["Name"], &name)

	// 不应双重前缀
	if name != "alice_u1001_mynet" {
		t.Errorf("Name = %q, want %q", name, "alice_u1001_mynet")
	}
}

// ── UserContainerPrefix / UserResourcePrefix ──────────────────────────────────

func TestUserContainerPrefix(t *testing.T) {
	tests := []struct{ uid int; want string }{
		{1001, "user-1001-"},
		{0, "user-0-"},
		{65534, "user-65534-"},
	}
	for _, tt := range tests {
		got := UserContainerPrefix(tt.uid)
		if got != tt.want {
			t.Errorf("UserContainerPrefix(%d) = %q, want %q", tt.uid, got, tt.want)
		}
	}
}

func TestUserResourcePrefix(t *testing.T) {
	id := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}
	got := UserResourcePrefix(id)
	want := "alice_u1001_"
	if got != want {
		t.Errorf("UserResourcePrefix = %q, want %q", got, want)
	}
}

// ── CountJSONArray / CountVolumeList ─────────────────────────────────────────

func TestCountJSONArray(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{`[]`, 0},
		{`[{}]`, 1},
		{`[{},{},{}]`, 3},
		{`not json`, 0},
	}
	for _, tt := range tests {
		got := CountJSONArray([]byte(tt.input))
		if got != tt.want {
			t.Errorf("CountJSONArray(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestCountVolumeList(t *testing.T) {
	body := []byte(`{"Volumes":[{"Name":"v1"},{"Name":"v2"}],"Warnings":null}`)
	got := CountVolumeList(body)
	if got != 2 {
		t.Errorf("CountVolumeList = %d, want 2", got)
	}
}

func TestCountVolumeList_Empty(t *testing.T) {
	body := []byte(`{"Volumes":[],"Warnings":null}`)
	got := CountVolumeList(body)
	if got != 0 {
		t.Errorf("CountVolumeList empty = %d, want 0", got)
	}
}
