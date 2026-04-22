package forward

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// ── 场景测试：容器创建流程 ────────────────────────────────────────────────────

// 场景：容器创建成功后，归属记录写入 DB
func TestServeHTTP_ContainerCreate_RecordsOwnership(t *testing.T) {
	var capturedBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"new-cont-abc","Warnings":[]}`))
	}))
	defer upstream.Close()
	_ = capturedBody

	p := newTestProxy(t, upstream, nil)

	req := httptest.NewRequest("POST", "/containers/create", strings.NewReader(`{"Image":"nginx"}`))
	req.Header.Set("Content-Type", "application/json")
	req = injectIdentity(req, makeTestIdentityProxy("alice", 1001))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rw.Code)
	}

	// 容器归属应已写入 DB
	owner, found := p.db.GetContainerOwner("new-cont-abc")
	if !found {
		t.Error("container ownership should be recorded after create")
	} else if owner.UID != 1001 {
		t.Errorf("owner UID = %d, want 1001", owner.UID)
	}
}

// 场景：容器删除后，归属记录从 DB 移除
func TestServeHTTP_ContainerDelete_RemovesOwnership(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 预先注册容器归属
	alice := &auth.CallerIdentity{RealUID: 1001, RealUsername: "alice"}
	_ = p.db.SetContainerOwner("del-cont-1", alice, "")

	req := httptest.NewRequest("DELETE", "/containers/del-cont-1", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", 1001))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rw.Code)
	}

	// 归属记录应已删除
	_, found := p.db.GetContainerOwner("del-cont-1")
	if found {
		t.Error("container ownership should be removed after delete")
	}
}

// 场景：非容器所有者删除容器时返回 403
func TestServeHTTP_ContainerDelete_NotOwner_Returns403(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// alice 拥有容器
	alice := &auth.CallerIdentity{RealUID: 1001, RealUsername: "alice"}
	_ = p.db.SetContainerOwner("alice-cont", alice, "")

	// bob 尝试删除 alice 的容器
	req := httptest.NewRequest("DELETE", "/containers/alice-cont", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", 1002))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (bob cannot delete alice's container)", rw.Code)
	}
}

// 场景：root 用户可以操作未在 DB 中的容器（不受归属检查限制）
func TestServeHTTP_ContainerDelete_RootCanDeleteUntracked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 容器未在 DB 中（untracked）
	rootID := makeTestIdentityProxy("root", 0)
	rootID.UserType = auth.UserTypeRoot
	req := httptest.NewRequest("DELETE", "/containers/untracked-cont", nil)
	req = injectIdentity(req, rootID)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204 (root can delete untracked container)", rw.Code)
	}
}

// ── 场景测试：策略多规则 ──────────────────────────────────────────────────────

// 场景：多条 deny_rules，不同用户受不同规则约束
func TestServeHTTP_MultipleRules_IndependentDenial(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	policy := mustLoadPolicyYAML(t, `
version: 1
default_action: allow
deny_rules:
  - users: ["alice"]
    actions: ["run"]
  - users: ["bob"]
    actions: ["pull"]
`)
	p := newTestProxy(t, upstream, policy)

	// alice 被拒绝 run（POST /containers/create）
	req := httptest.NewRequest("POST", "/containers/create", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", 1001))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)
	if rw.Code != http.StatusForbidden {
		t.Errorf("alice: status = %d, want 403", rw.Code)
	}

	// bob 被拒绝 pull（POST /images/create）
	req2 := httptest.NewRequest("POST", "/images/create?fromImage=nginx", nil)
	req2 = injectIdentity(req2, makeTestIdentityProxy("bob", 1002))
	rw2 := httptest.NewRecorder()
	p.ServeHTTP(rw2, req2)
	if rw2.Code != http.StatusForbidden {
		t.Errorf("bob: status = %d, want 403", rw2.Code)
	}
}

// ── 场景测试：_ping 辅助调用直接转发 ─────────────────────────────────────────

// 场景：_ping 请求需要认证（无 identity 返回 401）
// 注意：_ping 是辅助调用（isAuxiliaryCall 返回 true），但认证检查在辅助判断之前
func TestServeHTTP_Ping_RequiresAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	req := httptest.NewRequest("GET", "/_ping", nil)
	// 不注入 identity
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	// 无 identity 时返回 401（认证检查在辅助调用判断之前）
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("_ping without identity: status = %d, want 401", rw.Code)
	}
}

// 场景：_ping 请求有 identity 时正常转发
func TestServeHTTP_Ping_WithAuth_Forwards(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	req := httptest.NewRequest("GET", "/_ping", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", 1001))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("_ping with identity: status = %d, want 200", rw.Code)
	}
}

// ── 场景测试：镜像列表过滤 ────────────────────────────────────────────────────

// 场景：普通用户只看到自己的镜像
func TestServeHTTP_ImageList_FilteredByOwner(t *testing.T) {
	images := []map[string]interface{}{
		{"Id": "sha256:alice-img"},
		{"Id": "sha256:bob-img"},
	}
	body, _ := json.Marshal(images)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 注册 alice 的镜像
	alice := &auth.CallerIdentity{RealUID: 1001, RealUsername: "alice"}
	_ = p.db.SetImageOwner("sha256:alice-img", alice, false, "pull")

	req := httptest.NewRequest("GET", "/images/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", 1001))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rw.Code)
	}

	var result []map[string]interface{}
	_ = json.Unmarshal(rw.Body.Bytes(), &result)
	if len(result) != 1 {
		t.Errorf("alice should see 1 image, got %d", len(result))
	}
}

// ── 场景测试：parseImageRefFromURI 边界情况 ───────────────────────────────────

func TestParseImageRefFromURI_Scenarios(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"/images/create?fromImage=nginx&tag=alpine", "nginx:alpine"},
		{"/images/create?fromImage=registry.io/user/img&tag=v1.0", "registry.io/user/img:v1.0"},
		{"/images/create?fromImage=nginx", "nginx"},
		{"/images/create", ""},
		{"/containers/json", ""},
	}
	for _, tt := range tests {
		got := parseImageRefFromURI(tt.uri)
		if got != tt.want {
			t.Errorf("parseImageRefFromURI(%q) = %q, want %q", tt.uri, got, tt.want)
		}
	}
}

// ── 场景测试：truncID 边界情况 ────────────────────────────────────────────────

func TestTruncID_Scenarios(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"sha256:abcdef123456789", "abcdef123456"},
		{"abcdef123456789", "abcdef123456"},
		{"short", "short"},
		{"", ""},
		{"exactly12chars", "exactly12cha"},
	}
	for _, tt := range tests {
		got := truncID(tt.input)
		if got != tt.want {
			t.Errorf("truncID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── 场景测试：容器操作所有权检查 ─────────────────────────────────────────────

// 场景：容器 stop/start/restart 需要所有权
func TestServeHTTP_ContainerStop_NotOwner_Returns403(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	alice := &auth.CallerIdentity{RealUID: 1001, RealUsername: "alice"}
	_ = p.db.SetContainerOwner("alice-cont-3", alice, "")

	// bob 尝试 stop alice 的容器
	req := httptest.NewRequest("POST", "/containers/alice-cont-3/stop", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", 1002))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (bob cannot stop alice's container)", rw.Code)
	}
}

// 场景：容器所有者可以 stop 自己的容器
func TestServeHTTP_ContainerStop_Owner_Allowed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	alice := &auth.CallerIdentity{RealUID: 1001, RealUsername: "alice"}
	_ = p.db.SetContainerOwner("alice-cont-4", alice, "")

	req := httptest.NewRequest("POST", "/containers/alice-cont-4/stop", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", 1001))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204 (alice can stop her own container)", rw.Code)
	}
}

// ── 场景测试：makeAuditEntry 字段完整性 ──────────────────────────────────────

// 场景：makeAuditEntry 正确填充所有字段
func TestMakeAuditEntry_AllFields(t *testing.T) {
	id := makeTestIdentityProxy("bob", 1002)
	id.ClientAddr = "10.0.0.1:12345"
	id.AuthSource = auth.AuthSourceOS

	req := httptest.NewRequest("POST", "/containers/create", nil)
	entry := makeAuditEntry(id, req, "run", "allow", "", "", http.StatusCreated)

	if entry.User != "bob" {
		t.Errorf("User = %q, want bob", entry.User)
	}
	if entry.UID != 1002 {
		t.Errorf("UID = %d, want 1002", entry.UID)
	}
	if entry.Method != "POST" {
		t.Errorf("Method = %q, want POST", entry.Method)
	}
	if entry.Action != "run" {
		t.Errorf("Action = %q, want run", entry.Action)
	}
	if entry.Result != "allow" {
		t.Errorf("Result = %q, want allow", entry.Result)
	}
	if entry.StatusCode != http.StatusCreated {
		t.Errorf("StatusCode = %d, want 201", entry.StatusCode)
	}
}

// ── 场景测试：isHijackRequest 扩展 ───────────────────────────────────────────

// 场景：exec start 是 hijack 请求
func TestIsHijackRequest_ExecStart(t *testing.T) {
	req := httptest.NewRequest("POST", "/exec/abc123/start", nil)
	if !isHijackRequest(req) {
		t.Error("POST /exec/{id}/start should be a hijack request")
	}
}

// 场景：普通 GET 请求不是 hijack
func TestIsHijackRequest_NormalGet(t *testing.T) {
	req := httptest.NewRequest("GET", "/containers/json", nil)
	if isHijackRequest(req) {
		t.Error("GET /containers/json should NOT be a hijack request")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────
// newTestProxy, injectIdentity, makeTestIdentityProxy, mustLoadPolicyYAML
// 已在 proxy_integration_test.go 中定义（同包），此处无需重复声明

// 确保 authz 包被引用
var _ *authz.Policy
