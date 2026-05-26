package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-7: sudo docker volume prune -f 无法清除任何用户的具名卷
//
// ──── 权限模型（业务规格）────────────────────────────────────────────────────
//
//   ┌─────────────────────┬───────────────────────────────────────────────────┐
//   │ 调用者类型          │ volume prune 应删除的范围                         │
//   ├─────────────────────┼───────────────────────────────────────────────────┤
//   │ root (UserTypeRoot) │ 所有用户的具名卷（GetAllVolumeNames）             │
//   │ sudo (UserTypeSudo) │ 所有用户的具名卷（GetAllVolumeNames）             │
//   │ 普通用户            │ 仅自己的具名卷（GetVolumeNamesByOwner(RealUID)）   │
//   └─────────────────────┴───────────────────────────────────────────────────┘
//
// ──── 根本原因（双层失效）─────────────────────────────────────────────────────
//
// 【第一层：代理无条件绕过特权用户】
//   handleVolumePrune (proxy.go:4907):
//     if id.IsPrivileged() { return false }
//   IsPrivileged() 对 UserTypeRoot 和 UserTypeSudo 均返回 true，
//   导致代理跳过所有自定义逻辑，将请求原封不动透传给 Docker daemon。
//
// 【第二层：Docker 原生 prune 不删具名卷】
//   `docker volume prune -f`：-f 是 --force（跳过确认），不是 --all。
//   Docker 官方文档："By default, it only removes anonymous volumes."
//   → 具名卷（user-{uid}-volume-*）全部保留，无任何 volume destroy 事件。
//
// 【期望修复】
//   handleVolumePrune 应区分：
//     IsPrivileged() == true → GetAllVolumeNames()（删全部用户的具名卷）
//     IsPrivileged() == false → GetVolumeNamesByOwner(RealUID)（只删自己的）
//   不再 return false，直接执行代理的逐个 DELETE 逻辑。
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
	"go.uber.org/zap"
)

// ──────────────────────────────────────────────────────────────────────────────
// 测试基础设施
// ──────────────────────────────────────────────────────────────────────────────

// recordingTransport 记录所有到 Docker daemon 的请求，返回可配置的响应码。
// mu 保护 calls，防止未来并发 RoundTrip 时 data race。
type recordingTransport struct {
	mu             sync.Mutex
	responseByPath map[string]int // URL.Path → status；缺省 204 NoContent
	calls          []string       // "METHOD /path" 记录
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.calls = append(rt.calls, req.Method+" "+req.URL.Path)
	code, ok := rt.responseByPath[req.URL.Path]
	rt.mu.Unlock()
	if !ok {
		code = http.StatusNoContent
	}
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
	}, nil
}

func (rt *recordingTransport) calledDelete(volName string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	want := "DELETE /volumes/" + volName
	for _, c := range rt.calls {
		if c == want {
			return true
		}
	}
	return false
}

func (rt *recordingTransport) callCount() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.calls)
}

// newVolumePruneTestProxy 构造最小化 ProxyServer（db/transport/logger），
// 足以测试 handleVolumePrune 的全部路径。
func newVolumePruneTestProxy(t *testing.T, rt http.RoundTripper) *ProxyServer {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &ProxyServer{db: db, transport: rt, logger: zap.NewNop()}
}

// ── 身份构造辅助 ──────────────────────────────────────────────────────────────

func sudoIdentity(realUsername string, realUID int) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      realUsername,
		RealUID:           realUID,
		EffectiveUsername: "root",
		EffectiveUID:      0,
		UserType:          auth.UserTypeSudo,
	}
}

func rootIdentity() *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      "root",
		RealUID:           0,
		EffectiveUsername: "root",
		EffectiveUID:      0,
		UserType:          auth.UserTypeRoot,
	}
}

func regularIdentity(username string, uid int) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		EffectiveUsername: username,
		EffectiveUID:      uid,
		UserType:          auth.UserTypeRegular,
	}
}

// ── DB 预置辅助 ───────────────────────────────────────────────────────────────

// seedVolumes 向 DB 写入 uid 用户的具名卷，返回内部卷名列表。
// 内部名格式 user-{uid}-volume-{suffix}，与 InjectVolumeNamePrefix 一致。
func seedVolumes(t *testing.T, p *ProxyServer, uid int, username string, suffixes ...string) []string {
	t.Helper()
	id := regularIdentity(username, uid)
	var names []string
	for _, s := range suffixes {
		n := fmt.Sprintf("user-%d-volume-%s", uid, s)
		if err := p.db.SetVolumeOwner(n, id); err != nil {
			t.Fatalf("seedVolumes SetVolumeOwner(%q): %v", n, err)
		}
		names = append(names, n)
	}
	return names
}

// volumesInDB 返回 uid 在 DB 中剩余的具名卷数量。
func volumesInDB(t *testing.T, p *ProxyServer, uid int) int {
	t.Helper()
	vols, err := p.db.GetVolumeNamesByOwner(uid)
	if err != nil {
		t.Fatalf("GetVolumeNamesByOwner(uid=%d): %v", uid, err)
	}
	return len(vols)
}

// allVolumesInDB 返回 DB 中所有用户的具名卷总数。
func allVolumesInDB(t *testing.T, p *ProxyServer) int {
	t.Helper()
	vols, err := p.db.GetAllVolumeNames()
	if err != nil {
		t.Fatalf("GetAllVolumeNames: %v", err)
	}
	return len(vols)
}

// ══════════════════════════════════════════════════════════════════════════════
// RED TEST: BUG-7 复现
// ══════════════════════════════════════════════════════════════════════════════

// TestBUG7_SudoVolumePrune_LeavesAllNamedVolumesIntact
//
// RED TEST: 在 Bug 修复前，此测试必须 100% 失败（三处断言均触发）。
//
// 场景：
//   - bob 拥有 2 个具名卷（已在代理 DB 中登记）
//   - alice 拥有 1 个具名卷（已在代理 DB 中登记）
//   - sudo_test 执行 sudo docker volume prune -f
//
// 当前（Bug）行为：
//   handleVolumePrune: IsPrivileged()==true → return false
//   → 代理放行，Docker 原生 prune 只删匿名卷 → 所有具名卷保持不动
//   → DB 记录不变，无任何 DELETE 请求
//
// 期望（修复后）行为：
//   sudo 与 root 权限相同，应删除所有用户的具名卷：
//   → handleVolumePrune 返回 true（拦截）
//   → 向 Docker 发出 3 个 DELETE 请求（bob×2 + alice×1）
//   → DB 全部清空（AllVolumesInDB == 0）
func TestBUG7_SudoVolumePrune_LeavesAllNamedVolumesIntact(t *testing.T) {
	rt := &recordingTransport{responseByPath: map[string]int{}}
	proxy := newVolumePruneTestProxy(t, rt)

	bobVols := seedVolumes(t, proxy, 1002, "bob", "data", "logs")
	aliceVols := seedVolumes(t, proxy, 1001, "alice", "config")
	totalVols := len(bobVols) + len(aliceVols) // 3

	sudoTest := sudoIdentity("sudo_test", 1005)
	w := httptest.NewRecorder()
	intercepted := proxy.handleVolumePrune(w, httptest.NewRequest("POST", "/volumes/prune", nil),sudoTest)

	// ── 断言 A：代理必须拦截 sudo prune（不能 return false 放行）───────────
	// Bug 行为：intercepted == false
	// 期望行为：intercepted == true，代理完成所有用户卷的删除
	if !intercepted {
		t.Errorf("[A] FAIL: handleVolumePrune(sudoUser) returned false — "+
			"proxy bypassed custom logic; Docker native prune will NOT delete "+
			"named volumes %v (both bob's and alice's)", append(bobVols, aliceVols...))
	}

	// ── 断言 B：所有用户的具名卷必须从 DB 清除 ───────────────────────────────
	// Bug 行为：allVolumesInDB == 3（代理未执行任何 DeleteVolume）
	// 期望行为：allVolumesInDB == 0
	if remaining := allVolumesInDB(t, proxy); remaining != 0 {
		t.Errorf("[B] FAIL: %d named volumes remain in DB after sudo prune — "+
			"want 0 (sudo has root-level access, must clear all users' volumes)",
			remaining)
	}

	// ── 断言 C：代理向 Docker 发出了精确数量的 DELETE 请求 ──────────────────
	// Bug 行为：callCount == 0（代理未发出任何请求）
	// 期望行为：callCount == totalVols（每个具名卷各一次 DELETE）
	if got := rt.callCount(); got != totalVols {
		t.Errorf("[C] FAIL: want %d DELETE requests to Docker (all users' volumes), got %d — "+
			"calls: %v", totalVols, got, rt.calls)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归测试矩阵（4 个）
// ══════════════════════════════════════════════════════════════════════════════

// TestVolumePrune_RootUser_DeletesAllUsersVolumes
//
// 回归-1：直接 root（UserTypeRoot，RealUID==0）执行 volume prune，
// 应删除 DB 中所有用户的具名卷，行为与 sudo 一致。
// 覆盖：root 路径 + 多用户数据清理完整性。
func TestVolumePrune_RootUser_DeletesAllUsersVolumes(t *testing.T) {
	rt := &recordingTransport{responseByPath: map[string]int{}}
	proxy := newVolumePruneTestProxy(t, rt)

	bobVols := seedVolumes(t, proxy, 1002, "bob", "data", "logs")
	aliceVols := seedVolumes(t, proxy, 1001, "alice", "config")
	charlieVols := seedVolumes(t, proxy, 1003, "charlie", "workspace")
	totalVols := len(bobVols) + len(aliceVols) + len(charlieVols) // 4

	w := httptest.NewRecorder()
	intercepted := proxy.handleVolumePrune(w, httptest.NewRequest("POST", "/volumes/prune", nil),rootIdentity())

	if !intercepted {
		t.Fatalf("root user: want intercepted=true (proxy handles all-user delete), got false")
	}

	// 所有用户的卷必须全部清除
	if remaining := allVolumesInDB(t, proxy); remaining != 0 {
		t.Errorf("root prune: want 0 volumes in DB, got %d (root must clear all users' volumes)",
			remaining)
	}

	// 每个具名卷各有一个 DELETE 请求
	for _, vol := range append(append(bobVols, aliceVols...), charlieVols...) {
		if !rt.calledDelete(vol) {
			t.Errorf("root prune: missing DELETE request for volume %q, all calls: %v",
				vol, rt.calls)
		}
	}

	// DELETE 请求总数精确等于具名卷数，无重复无遗漏
	if got := rt.callCount(); got != totalVols {
		t.Errorf("root prune: want exactly %d DELETE calls, got %d: %v",
			totalVols, got, rt.calls)
	}

	// HTTP 响应格式合规
	if w.Code != http.StatusOK {
		t.Errorf("want HTTP 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("want Content-Type application/json, got %q", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "VolumesDeleted") {
		t.Errorf("response missing VolumesDeleted field: %s", body)
	}
}

// TestVolumePrune_RegularUser_OnlyDeletesOwnVolumes
//
// 回归-2：普通用户（UserTypeRegular）执行 volume prune，
// 只能删除自己的具名卷；其他用户（alice）的卷完全不受影响。
// 覆盖：非特权用户隔离 + 最小权限原则。
func TestVolumePrune_RegularUser_OnlyDeletesOwnVolumes(t *testing.T) {
	rt := &recordingTransport{responseByPath: map[string]int{}}
	proxy := newVolumePruneTestProxy(t, rt)

	bobVols := seedVolumes(t, proxy, 1002, "bob", "data", "logs")
	seedVolumes(t, proxy, 1001, "alice", "config") // alice 的卷应保持不变

	w := httptest.NewRecorder()
	if intercepted := proxy.handleVolumePrune(w, httptest.NewRequest("POST", "/volumes/prune", nil),regularIdentity("bob", 1002)); !intercepted {
		t.Fatalf("regular user: want intercepted=true, got false")
	}

	// bob 的卷全部清除
	if remaining := volumesInDB(t, proxy, 1002); remaining != 0 {
		t.Errorf("bob's volumes: want 0 remaining, got %d", remaining)
	}
	for _, vol := range bobVols {
		if !rt.calledDelete(vol) {
			t.Errorf("bob prune: missing DELETE for own volume %q, calls: %v", vol, rt.calls)
		}
	}

	// alice 的卷完全不受影响
	if remaining := volumesInDB(t, proxy, 1001); remaining != 1 {
		t.Errorf("alice's volumes: want 1 remaining (untouched), got %d — "+
			"regular user must not delete other users' volumes", remaining)
	}
	if rt.calledDelete("user-1001-volume-config") {
		t.Errorf("bob prune: must NOT send DELETE for alice's volume, calls: %v", rt.calls)
	}

	// DELETE 请求数 == bob 的卷数，无越权请求
	if got := rt.callCount(); got != len(bobVols) {
		t.Errorf("want exactly %d DELETE calls (bob's volumes only), got %d: %v",
			len(bobVols), got, rt.calls)
	}
}

// TestVolumePrune_PrivilegedUser_SkipsVolumeInUse_409
//
// 回归-3：bob 的某个卷正在被容器使用（Docker 返回 409 Conflict），
// 代理应跳过该卷，继续删除其他（包括其他用户的）卷。
// 覆盖：特权用户 + 409 边界 + 部分成功场景。
func TestVolumePrune_PrivilegedUser_SkipsVolumeInUse_409(t *testing.T) {
	const bobUID = 1002
	inUse := fmt.Sprintf("user-%d-volume-busy", bobUID)
	free := fmt.Sprintf("user-%d-volume-free", bobUID)
	aliceVol := "user-1001-volume-data"

	rt := &recordingTransport{
		responseByPath: map[string]int{
			"/volumes/" + inUse:   http.StatusConflict,  // 409: 正在使用
			"/volumes/" + free:    http.StatusNoContent, // 204: 成功
			"/volumes/" + aliceVol: http.StatusNoContent, // 204: 成功
		},
	}
	proxy := newVolumePruneTestProxy(t, rt)

	bob := regularIdentity("bob", bobUID)
	alice := regularIdentity("alice", 1001)
	if err := proxy.db.SetVolumeOwner(inUse, bob); err != nil {
		t.Fatalf("seed inUse: %v", err)
	}
	if err := proxy.db.SetVolumeOwner(free, bob); err != nil {
		t.Fatalf("seed free: %v", err)
	}
	if err := proxy.db.SetVolumeOwner(aliceVol, alice); err != nil {
		t.Fatalf("seed alice: %v", err)
	}

	// sudo 用户执行 prune（应删除所有用户的卷，跳过 409 的）
	w := httptest.NewRecorder()
	if intercepted := proxy.handleVolumePrune(w, httptest.NewRequest("POST", "/volumes/prune", nil),sudoIdentity("sudo_test", 1005)); !intercepted {
		t.Fatalf("sudo user: want intercepted=true, got false")
	}

	remaining, err := proxy.db.GetAllVolumeNames()
	if err != nil {
		t.Fatalf("GetAllVolumeNames: %v", err)
	}

	// 409 卷：仍在 DB 中（未被删除）
	var foundInUse bool
	for _, v := range remaining {
		if v == inUse {
			foundInUse = true
		}
	}
	if !foundInUse {
		t.Errorf("in-use volume %q should remain in DB after 409 Conflict, remaining: %v",
			inUse, remaining)
	}

	// free 卷和 alice 卷：已从 DB 删除
	for _, v := range remaining {
		if v == free {
			t.Errorf("free volume %q should be deleted (204), but still in DB: %v", free, remaining)
		}
		if v == aliceVol {
			t.Errorf("alice's volume %q should be deleted by sudo prune, but still in DB: %v",
				aliceVol, remaining)
		}
	}

	// 响应体包含已删除的卷名，不含跳过的卷名
	body := w.Body.String()
	if !strings.Contains(body, free) {
		t.Errorf("VolumesDeleted should contain free vol %q, body: %s", free, body)
	}
	if !strings.Contains(body, aliceVol) {
		t.Errorf("VolumesDeleted should contain alice's vol %q (sudo deletes all), body: %s",
			aliceVol, body)
	}
	if strings.Contains(body, inUse) {
		t.Errorf("VolumesDeleted must NOT contain in-use vol %q (409 skipped), body: %s",
			inUse, body)
	}
}

// TestVolumePrune_PrivilegedUser_EmptyDB_NoRequests
//
// 回归-4：DB 中没有任何具名卷时（系统全新或已全部清理），
// sudo/root 的 prune 应正常返回 VolumesDeleted:[]，
// 不崩溃、不向 Docker 发出任何请求、HTTP 200。
// 覆盖：空集边界条件（包括 GetAllVolumeNames 返回 nil）。
func TestVolumePrune_PrivilegedUser_EmptyDB_NoRequests(t *testing.T) {
	for _, id := range []*auth.CallerIdentity{
		sudoIdentity("sudo_test", 1005),
		rootIdentity(),
	} {
		t.Run(id.UserType.String(), func(t *testing.T) {
			rt := &recordingTransport{}
			proxy := newVolumePruneTestProxy(t, rt)
			// DB 为空，不预置任何卷

			w := httptest.NewRecorder()
			intercepted := proxy.handleVolumePrune(w, httptest.NewRequest("POST", "/volumes/prune", nil),id)

			if !intercepted {
				t.Fatalf("%s: want intercepted=true even with empty DB, got false",
					id.UserType)
			}
			if w.Code != http.StatusOK {
				t.Errorf("%s: want HTTP 200, got %d", id.UserType, w.Code)
			}
			body := w.Body.String()
			if !strings.Contains(body, `"VolumesDeleted":[]`) {
				t.Errorf("%s: want VolumesDeleted:[] for empty DB, got: %s",
					id.UserType, body)
			}
			if got := rt.callCount(); got != 0 {
				t.Errorf("%s: want 0 DELETE requests for empty DB, got %d: %v",
					id.UserType, got, rt.calls)
			}
		})
	}
}
