package forward

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"docker-authz-proxy/internal/audit"
	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
	"docker-authz-proxy/internal/isolation"

	"go.uber.org/zap"
)

// ── 测试辅助 ──────────────────────────────────────────────────────────────────

// newTestProxy 构建一个可测试的 ProxyServer，上游指向 fakeUpstream
func newTestProxy(t *testing.T, fakeUpstream *httptest.Server, policy *authz.Policy) *ProxyServer {
	t.Helper()

	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	logger := zap.NewNop()
	auditDir := t.TempDir()
	auditLog, err := audit.NewAuditLogger(auditDir)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { auditLog.Close() })

	if policy == nil {
		policy = &authz.Policy{}
	}

	// 提取 fakeUpstream 的 host:port，用 TCP transport 替代 Unix socket
	upstreamAddr := strings.TrimPrefix(fakeUpstream.URL, "http://")

	p := &ProxyServer{
		socketDir:    t.TempDir(),
		upstreamSock: upstreamAddr,
		policy:       policy,
		db:           db,
		logger:       logger,
		quota:        isolation.DefaultQuotaManager(),
		auditLog:     auditLog,
		storageBase:  t.TempDir(),
		bridge:       isolation.NewBridgeManager(""),
		storage:      isolation.NewStorageManager(t.TempDir(), ""),
		listeners:    make(map[string]net.Listener),
		transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("tcp", upstreamAddr)
			},
		},
	}
	return p
}

// injectIdentity 将 CallerIdentity 注入请求 context
func injectIdentity(r *http.Request, id *auth.CallerIdentity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identityContextKey, id))
}

func makeTestIdentityProxy(username string, uid int) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		RealGID:           uid,
		EffectiveUsername: username,
		EffectiveUID:      uid,
		UserType:          auth.UserTypeRegular,
		AuthSource:        auth.AuthSourceOS,
	}
}

// ── ServeHTTP: 认证失败 ───────────────────────────────────────────────────────

func TestServeHTTP_NoIdentity_Returns401(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	req := httptest.NewRequest("GET", "/containers/json", nil)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rw.Code)
	}
}

// ── ServeHTTP: 策略拒绝 ───────────────────────────────────────────────────────

func TestServeHTTP_PolicyDeny_Returns403(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// 策略：alice 不允许执行 run
	policy := mustLoadPolicyYAML(t, `
version: 1
default_action: allow
deny_rules:
  - users: ["alice"]
    actions: ["run"]
`)
	p := newTestProxy(t, upstream, policy)

	req := httptest.NewRequest("POST", "/containers/create", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", 1001))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rw.Code)
	}
}

// ── ServeHTTP: 允许通过并转发 ─────────────────────────────────────────────────

func TestServeHTTP_AllowedRequest_ForwardsToUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	req := httptest.NewRequest("GET", "/containers/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", 1001))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rw.Code)
	}
}

// ── ServeHTTP: root 用户不过滤 ────────────────────────────────────────────────

func TestServeHTTP_RootUser_SeesAllContainers(t *testing.T) {
	containers := []map[string]interface{}{
		{"Id": "cont-alice-1", "Labels": map[string]string{}},
		{"Id": "cont-bob-1", "Labels": map[string]string{}},
	}
	body, _ := json.Marshal(containers)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	req := httptest.NewRequest("GET", "/containers/json", nil)
	rootID := makeTestIdentityProxy("root", 0)
	rootID.UserType = auth.UserTypeRoot
	req = injectIdentity(req, rootID)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rw.Code)
	}

	var result []map[string]interface{}
	_ = json.Unmarshal(rw.Body.Bytes(), &result)
	if len(result) != 2 {
		t.Errorf("root should see all 2 containers, got %d", len(result))
	}
}

// ── ServeHTTP: 容器列表过滤 ───────────────────────────────────────────────────

func TestServeHTTP_ContainerList_FilteredByOwner(t *testing.T) {
	containers := []map[string]interface{}{
		{"Id": "cont-alice-1", "Labels": map[string]string{}},
		{"Id": "cont-bob-1", "Labels": map[string]string{}},
	}
	body, _ := json.Marshal(containers)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 注册 alice 的容器
	alice := &auth.CallerIdentity{RealUID: 1001, RealUsername: "alice"}
	_ = p.db.SetContainerOwner("cont-alice-1", alice, "")

	req := httptest.NewRequest("GET", "/containers/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", 1001))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rw.Code)
	}

	var result []map[string]interface{}
	_ = json.Unmarshal(rw.Body.Bytes(), &result)
	if len(result) != 1 {
		t.Errorf("alice should see 1 container, got %d", len(result))
	}
}

// ── ServeHTTP: 并发限制 ───────────────────────────────────────────────────────

func TestServeHTTP_ConcurrencyLimit_Returns503(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	// 信号量容量为 1，且已满
	p.semaphore = make(chan struct{}, 1)
	p.semaphore <- struct{}{} // 占满

	req := httptest.NewRequest("GET", "/containers/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", 1001))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rw.Code)
	}
}

// ── isAuxiliaryCall ───────────────────────────────────────────────────────────

func TestIsAuxiliaryCall(t *testing.T) {
	// action 常量值：pull="pull", create_container="create_container",
	// ps="ps", info="info"
	tests := []struct {
		cmd, action, method, path string
		want                      bool
	}{
		// docker run 的 targetActions = {pull, create_container, start_container, remove_container}
		// 在 targetActions 中 → false（主调用）；不在 → true（辅助调用）
		{"run", "pull", "POST", "/images/create", false},
		{"run", "create_container", "POST", "/containers/create", false},
		{"run", "ps", "GET", "/images/json", true},   // ps 不在 run 的 targetActions → 辅助
		// system_info 特殊：非 info/version 命令触发时始终是辅助
		{"run", "info", "GET", "/info", true},
		{"info", "info", "GET", "/info", false},       // info 命令的主调用
		// dockerCmd="" 时 system_info(="info") 是辅助
		{"", "info", "GET", "/info", true},
		{"", "ps", "GET", "/containers/json", false},
		// ps 命令的 targetActions = {ps}，ps 在其中 → 主调用
		{"ps", "ps", "GET", "/containers/json", false},
		// 未知命令 → false
		{"unknown_cmd", "ps", "GET", "/containers/json", false},
		// _ping 始终是辅助
		{"", "", "GET", "/_ping", true},
		{"run", "", "GET", "/_ping", true},
	}
	for _, tt := range tests {
		got := isAuxiliaryCall(tt.cmd, tt.action, tt.method, tt.path)
		if got != tt.want {
			t.Errorf("isAuxiliaryCall(%q,%q,%q,%q) = %v, want %v",
				tt.cmd, tt.action, tt.method, tt.path, got, tt.want)
		}
	}
}

// ── makeAuditEntry ────────────────────────────────────────────────────────────

func TestMakeAuditEntry(t *testing.T) {
	id := makeTestIdentityProxy("alice", 1001)
	id.ClientAddr = "127.0.0.1:54321"
	id.AuthSource = auth.AuthSourceJWT

	req := httptest.NewRequest("DELETE", "/containers/abc123", nil)

	entry := makeAuditEntry(id, req, "rm", "deny", "container_not_owned", "owner=bob", http.StatusForbidden)

	if entry.User != "alice" {
		t.Errorf("User = %q, want alice", entry.User)
	}
	if entry.UID != 1001 {
		t.Errorf("UID = %d, want 1001", entry.UID)
	}
	if entry.ClientIP != "127.0.0.1:54321" {
		t.Errorf("ClientIP = %q, want 127.0.0.1:54321", entry.ClientIP)
	}
	if entry.Method != "DELETE" {
		t.Errorf("Method = %q, want DELETE", entry.Method)
	}
	if entry.Action != "rm" {
		t.Errorf("Action = %q, want rm", entry.Action)
	}
	if entry.Result != "deny" {
		t.Errorf("Result = %q, want deny", entry.Result)
	}
	if entry.DenyReason != "container_not_owned" {
		t.Errorf("DenyReason = %q, want container_not_owned", entry.DenyReason)
	}
	if entry.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", entry.StatusCode)
	}
	if entry.AuthSource != string(auth.AuthSourceJWT) {
		t.Errorf("AuthSource = %q, want jwt", entry.AuthSource)
	}
}

// ── isHijackRequest ───────────────────────────────────────────────────────────

func TestIsHijackRequest(t *testing.T) {
	tests := []struct {
		method, path, upgrade, connection string
		want                              bool
	}{
		// attach / exec start
		{"POST", "/containers/abc/attach", "", "Upgrade", true},
		{"POST", "/exec/abc/start", "", "", true},
		{"GET", "/containers/abc/attach/ws", "websocket", "Upgrade", true},
		// 普通请求
		{"GET", "/containers/json", "", "", false},
		{"POST", "/containers/create", "", "", false},
		{"DELETE", "/containers/abc", "", "", false},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.path, nil)
		if tt.upgrade != "" {
			req.Header.Set("Upgrade", tt.upgrade)
		}
		if tt.connection != "" {
			req.Header.Set("Connection", tt.connection)
		}
		got := isHijackRequest(req)
		if got != tt.want {
			t.Errorf("isHijackRequest(%s %s) = %v, want %v", tt.method, tt.path, got, tt.want)
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func mustLoadPolicyYAML(t *testing.T, yaml string) *authz.Policy {
	t.Helper()
	f, err := os.CreateTemp("", "policy-*.yaml")
	if err != nil {
		t.Fatalf("create temp policy: %v", err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString(yaml)
	f.Close()

	p, err := authz.LoadPolicy(f.Name())
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	return p
}

type fakeBodyProxy struct{ r io.Reader }

func (f *fakeBodyProxy) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *fakeBodyProxy) Close() error               { return nil }

func fakeBodyProxyStr(s string) *fakeBodyProxy {
	return &fakeBodyProxy{r: strings.NewReader(s)}
}
