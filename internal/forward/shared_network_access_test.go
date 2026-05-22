// shared_network_access_test.go
//
// ═══════════════════════════════════════════════════════════════════════════════
// [BUG-5] 共享基础网络 net_base 的 Inspect / Connect / List 路径 Bug
//
// 触发条件：
//   root 创建 Docker bridge 网络 net_base（Linux bridge 名称也为 net_base），
//   通过 network_access 授权给普通用户 bob。
//   bob 执行 docker network inspect net_base → 收到 404。
//   bob 执行 docker network connect net_base <container> → 404，容器未挂载 bridge。
//   bob 执行 brctl show net_base → "bridge net_base does not exist!"
//
// 根本原因（isolation/network.go RewriteNetworkURL，line 106-138）：
//   RewriteNetworkURL 对所有非豁免名称（非 hex ID、非 user-bridge、非 peer）
//   无条件添加 {username}_u{uid}_ 前缀，不区分"用户自建网络"与"管理员共享网络"。
//
//   当 net_base 由 root 创建并通过 network_access 授权给 bob 时：
//     Step 1. RewriteNetworkURL("net_base") → URL 变为 /networks/bob_u1002_net_base  ← BUG
//     Step 2. checkOwnershipPreRequest 通过 fallback（trimPrefix 后重查 DB），
//             CanUserAccessNetwork(sharedNetBaseID, bob) = true → 授权通过 ✓
//     Step 3. 实际转发给 upstream Docker 的 URL 仍是 /networks/bob_u1002_net_base
//             Docker 找不到 bob_u1002_net_base → 返回 404 ✗
//     Step 4. 容器无法 connect 到 net_base bridge
//     Step 5. 从容器内 brctl show net_base → "bridge net_base does not exist!"
//
// 修复方向：
//   RewriteNetworkURL 在添加前缀前，通过 DB 检查该名称是否为共享可直接访问的网络；
//   若 CanUserAccessNetwork(GetNetworkIDByName(name), uid) = true，则透传原始名称，不加前缀。
// ═══════════════════════════════════════════════════════════════════════════════

package forward

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/isolation"
)

// sharedNetBaseNetID 模拟 root 创建的共享网络 net_base 的 Docker 网络 ID（64 位 hex）
const sharedNetBaseNetID = "ccdd1122334455660000000000000000000000000000000000000000000000aa"

// stripAPIVersion 去掉路径中的 API 版本前缀（/v1.xx）
func stripAPIVersion(path string) string {
	for _, v := range []string{"/v1.41", "/v1.43", "/v1.46"} {
		if strings.HasPrefix(path, v) {
			return path[len(v):]
		}
	}
	return path
}

// fakeUpstreamForNetBase 返回一个 fake upstream handler：
// - /networks/net_base 或 /networks/<sharedNetBaseNetID> → 200（Docker 知道该网络）
//   修复后代理将共享网络请求改写为真实 hex ID，两种路径均需响应 200。
// - /networks/<hex_id>/connect → 200（网络 connect 操作）
// - 其他路径（带用户前缀的错误名称）→ 404
func fakeUpstreamForNetBase() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := stripAPIVersion(r.URL.Path)
		switch {
		// inspect：原始名称或真实 hex ID 均接受（修复后用 hex ID）
		case path == "/networks/net_base", path == "/networks/net_base/json",
			path == "/networks/"+sharedNetBaseNetID, path == "/networks/"+sharedNetBaseNetID+"/json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Id":"` + sharedNetBaseNetID + `","Name":"net_base","Driver":"bridge"}`))
		// connect/disconnect：原始名称或 hex ID 均接受
		case strings.HasPrefix(path, "/networks/net_base/"),
			strings.HasPrefix(path, "/networks/"+sharedNetBaseNetID+"/"):
			w.WriteHeader(http.StatusOK)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"No such network: ` + path + `"}`))
		}
	}
}

// registerSharedNetBase 在 proxy 的 DB 中注册 net_base（root 所有，bob 可访问）
func registerSharedNetBase(t *testing.T, p *ProxyServer) {
	t.Helper()
	rootID := &auth.CallerIdentity{RealUID: 0, RealUsername: "root"}
	if err := p.db.SetNetworkOwner(sharedNetBaseNetID, "net_base", rootID); err != nil {
		t.Fatalf("SetNetworkOwner(net_base): %v", err)
	}
	if err := p.db.SetNetworkShared(sharedNetBaseNetID, []int{bobUID}); err != nil {
		t.Fatalf("SetNetworkShared(net_base → bob): %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// [BUG-5] Red Tests — 修复前必定失败，修复后变绿
// ═══════════════════════════════════════════════════════════════════════════════

// [BUG-5 RED-1] bob inspect 共享网络 net_base → 应返回 200，实际因 URL 重写返回 404
//
// 根本原因：RewriteNetworkURL 将 /networks/net_base 改写为 /networks/bob_u1002_net_base，
// upstream Docker 不认识带前缀的名称，返回 404。
// 修复后：RewriteNetworkURL 识别共享网络，保留原始名称 /networks/net_base，Docker 返回 200。
func TestBug5_SharedNetwork_Inspect_WronglyReturns404(t *testing.T) {
	upstream := httptest.NewServer(fakeUpstreamForNetBase())
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	registerSharedNetBase(t, p)

	req := httptest.NewRequest("GET", "/networks/net_base", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	// 期望 200（bob 有权访问，Docker 知道 net_base）
	// BUG：实际返回 404（URL 被错误改写为 /networks/bob_u1002_net_base）
	if rw.Code != http.StatusOK {
		t.Errorf("[BUG-5 RED-1] bob inspect 共享网络 net_base → status=%d, want 200\n"+
			"根本原因：RewriteNetworkURL 将 net_base 改写为 bob_u%d_net_base，\n"+
			"upstream Docker 找不到该名称 → 404\n"+
			"连锁后果：docker network connect net_base <container> 同样失败，\n"+
			"容器未挂载 net_base bridge → brctl show net_base 报 'bridge net_base does not exist!'",
			rw.Code, bobUID)
	}
}

// [BUG-5 RED-2] bob connect 容器到共享网络 net_base → 应成功，实际因 URL 重写 404
//
// POST /networks/net_base/connect → RewriteNetworkURL 改写为
// POST /networks/bob_u1002_net_base/connect → Docker 404 → 容器不挂载 bridge。
func TestBug5_SharedNetwork_Connect_WronglyReturns404(t *testing.T) {
	upstream := httptest.NewServer(fakeUpstreamForNetBase())
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	registerSharedNetBase(t, p)

	// 注册 bob 的容器，使容器 ownership 检查通过
	bobContID := strings.Repeat("b", 64) // 64 位 hex（isHexID=true，不被 URL 重写）
	bobID := &auth.CallerIdentity{RealUID: bobUID, RealUsername: "bob"}
	_ = p.db.SetContainerOwner(bobContID, bobID, "")

	body := `{"Container":"` + bobContID + `"}`
	req := httptest.NewRequest("POST", "/networks/net_base/connect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("[BUG-5 RED-2] bob connect 容器到共享网络 net_base → status=%d, want 200\n"+
			"根本原因：RewriteNetworkURL 将 POST /networks/net_base/connect\n"+
			"改写为 POST /networks/bob_u%d_net_base/connect → Docker 404\n"+
			"直接后果：容器未连接 net_base bridge，brctl show net_base 报 bridge does not exist",
			rw.Code, bobUID)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// [BUG-5] Regression Suite — 覆盖正常路径与边界，防止修复引入新回归
// ═══════════════════════════════════════════════════════════════════════════════

// [回归-1] root 用户 inspect 任意网络应成功（特权旁路，不受 RewriteNetworkURL 影响）
func TestBug5_Regression_Root_InspectsSharedNetwork_OK(t *testing.T) {
	upstream := httptest.NewServer(fakeUpstreamForNetBase())
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	registerSharedNetBase(t, p)

	root := makeTestIdentityProxy("root", 0)
	root.UserType = auth.UserTypeRoot

	req := httptest.NewRequest("GET", "/networks/net_base", nil)
	req = injectIdentity(req, root)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("[回归-1] root inspect net_base → status=%d, want 200\n"+
			"root 应完全绕过 ownership 检查与 RewriteNetworkURL，不应受此 bug 影响",
			rw.Code)
	}
}

// [回归-2] bob inspect 自建网络 mynet（正常前缀路径）应成功
//
// 验证：修复共享网络 bug 后，用户自建网络的前缀逻辑不能被破坏。
// bob 创建的 mynet 在 Docker 中以 bob_u1002_mynet 存储，代理应添加前缀后转发。
func TestBug5_Regression_Bob_InspectsOwnNetwork_OK(t *testing.T) {
	const bobOwnNetID = "bbbb000000000000000000000000000000000000000000000000000000000001"
	const bobOwnNetDockerName = "bob_u1002_mynet"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := stripAPIVersion(r.URL.Path)
		// 修复后代理将用户自建网络的 URL 改写为真实 Docker hex ID，需同时接受两种路径
		if path == "/networks/"+bobOwnNetDockerName || path == "/networks/"+bobOwnNetDockerName+"/json" ||
			path == "/networks/"+bobOwnNetID || path == "/networks/"+bobOwnNetID+"/json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Id":"` + bobOwnNetID + `","Name":"` + bobOwnNetDockerName + `","Driver":"bridge"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"No such network"}`))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	bobCaller := &auth.CallerIdentity{RealUID: bobUID, RealUsername: "bob"}
	if err := p.db.SetNetworkOwner(bobOwnNetID, bobOwnNetDockerName, bobCaller); err != nil {
		t.Fatalf("SetNetworkOwner: %v", err)
	}

	// bob 用不带前缀的名称 inspect（用户视角），代理应添加前缀后转发
	req := httptest.NewRequest("GET", "/networks/mynet", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("[回归-2] bob inspect 自建网络 mynet → status=%d, want 200\n"+
			"修复共享网络 bug 时不应破坏用户自建网络的前缀逻辑\n"+
			"（mynet 应被代理改写为 bob_u%d_mynet 再转发）",
			rw.Code, bobUID)
	}
}

// [回归-3] bob 无权访问 alice 私有网络 → 应返回 403/404
//
// 修复共享网络 bug 时，不能导致权限检查被绕过：
// alice 的私有网络仅 alice 可访问，bob 不在 network_access 表中，应被拒绝。
func TestBug5_Regression_Bob_CannotInspectAlicePrivateNetwork_Denied(t *testing.T) {
	const alicePrivNetID = "aaaa000000000000000000000000000000000000000000000000000000000001"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// upstream 始终返回 200，验证拒绝是代理层执行而非 upstream
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Id":"` + alicePrivNetID + `","Name":"alice_u1001_secret","Driver":"bridge"}`))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	aliceCaller := &auth.CallerIdentity{RealUID: aliceUID, RealUsername: "alice"}
	if err := p.db.SetNetworkOwner(alicePrivNetID, "alice_u1001_secret", aliceCaller); err != nil {
		t.Fatalf("SetNetworkOwner: %v", err)
	}
	// 注意：不调用 SetNetworkShared，bob 不在 network_access 表中

	req := httptest.NewRequest("GET", "/networks/alice_u1001_secret", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code == http.StatusOK {
		t.Errorf("[回归-3] bob inspect alice 私有网络 → status=200（应被拒绝）\n"+
			"修复共享网络 bug 时不能破坏权限隔离：bob 不在 network_access 表中")
	}
	if rw.Code != http.StatusForbidden && rw.Code != http.StatusNotFound {
		t.Errorf("[回归-3] bob inspect alice 私有网络 → status=%d, want 403 or 404", rw.Code)
	}
}

// [回归-4] docker network ls：共享网络 net_base 应出现在 bob 的列表，alice 私有网络不应出现
//
// FilterNetworkListResponse 通过 DB network_access 匹配 ID，
// 共享网络 net_base 应对 bob 可见，且名称不被加前缀（原本无前缀）。
// 此部分逻辑已正确，回归测试确保修复不破坏它。
func TestBug5_Regression_SharedNetwork_AppearsInBobNetworkList(t *testing.T) {
	alicePrivNetID := strings.Repeat("a", 64)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[
			{"Id":"` + sharedNetBaseNetID + `","Name":"net_base","Driver":"bridge"},
			{"Id":"` + alicePrivNetID + `","Name":"alice_u1001_private","Driver":"bridge"}
		]`))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	registerSharedNetBase(t, p)
	// alice 的私有网络只有 alice 可见（未授权给 bob）
	aliceCaller := &auth.CallerIdentity{RealUID: aliceUID, RealUsername: "alice"}
	_ = p.db.SetNetworkOwner(alicePrivNetID, "alice_u1001_private", aliceCaller)

	req := httptest.NewRequest("GET", "/networks", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("[回归-4] docker network ls → status=%d, want 200", rw.Code)
	}
	body := rw.Body.String()
	if !strings.Contains(body, "net_base") {
		t.Errorf("[回归-4] bob 的网络列表应包含共享网络 net_base\n实际响应：%s", body)
	}
	if strings.Contains(body, "alice_u1001_private") {
		t.Errorf("[回归-4] bob 不应看到 alice 私有网络\n实际响应：%s", body)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// [BUG-5] 单元级验证：RewriteNetworkURL 对共享网络名称的当前（错误）行为
// ═══════════════════════════════════════════════════════════════════════════════

// [BUG-5 设计说明] RewriteNetworkURL 对 net_base 仍会添加用户前缀（设计决策）
//
// 最终选定的修复位置是 checkOwnershipPreRequest（proxy.go），而非 RewriteNetworkURL。
// 原因见 Code Review：在 RewriteNetworkURL 中查 DB 会导致双重查询、接口污染、TOCTOU。
//
// 当前设计：
//   - RewriteNetworkURL("net_base") → "/networks/bob_u1002_net_base"（仍加前缀，属预期行为）
//   - checkOwnershipPreRequest 通过 fallback 找到真实 Docker ID，并在授权通过后修正 URL
//   - upstream Docker 收到真实 hex ID 请求 → 200 ✓
//
// 此测试验证 RewriteNetworkURL 的当前行为，防止意外修改破坏回归。
func TestBug5_Unit_RewriteNetworkURL_SharedNetworkName_CurrentlyAddsPrefix(t *testing.T) {
	bob := makeTestIdentityProxy("bob", bobUID)

	req := httptest.NewRequest("GET", "/networks/net_base", nil)
	rewritten := isolation.RewriteNetworkURL(req, bob)
	gotPath := rewritten.URL.Path

	// RewriteNetworkURL 本身仍添加前缀（设计决策，由 checkOwnershipPreRequest 在下游修正）
	const expectedPath = "/networks/bob_u1002_net_base"
	if gotPath != expectedPath {
		t.Errorf("[BUG-5 单元] RewriteNetworkURL(net_base) = %q, want %q\n"+
			"此函数应保持现有前缀行为，由 checkOwnershipPreRequest 在下游修正共享网络 URL",
			gotPath, expectedPath)
	}
}

// [回归-5] RewriteNetworkURL 原有豁免逻辑不受修复影响
//
// 修复共享网络问题后，以下已有豁免规则必须继续生效：
// hex ID / user-bridge / peer-{uid}-{uid} 透传；用户自建网络添加前缀；已有前缀不重复添加。
func TestBug5_Regression_RewriteNetworkURL_ExemptNames_Unchanged(t *testing.T) {
	bob := makeTestIdentityProxy("bob", bobUID)
	cases := []struct {
		name      string
		inputPath string
		wantPath  string
	}{
		{
			"12位hex直接透传",
			"/networks/aabbccddeeff",
			"/networks/aabbccddeeff",
		},
		{
			"64位hex直接透传",
			"/networks/" + strings.Repeat("a", 64),
			"/networks/" + strings.Repeat("a", 64),
		},
		{
			"user-bridge直接透传",
			"/networks/" + isolation.UserBridgeName(bobUID),
			"/networks/" + isolation.UserBridgeName(bobUID),
		},
		{
			"peer-uidA-uidB含bob透传（bob在后）",
			"/networks/peer-1001-1002",
			"/networks/peer-1001-1002",
		},
		{
			"peer-uidA-uidB含bob透传（bob在前）",
			"/networks/peer-1002-1003",
			"/networks/peer-1002-1003",
		},
		{
			"已有用户前缀不重复添加",
			"/networks/bob_u1002_mynet",
			"/networks/bob_u1002_mynet",
		},
		{
			"普通用户自建网络添加前缀",
			"/networks/mynet",
			"/networks/bob_u1002_mynet",
		},
		{
			"create端点不处理",
			"/networks/create",
			"/networks/create",
		},
		{
			"prune端点不处理",
			"/networks/prune",
			"/networks/prune",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.inputPath, nil)
			rewritten := isolation.RewriteNetworkURL(req, bob)
			if rewritten.URL.Path != tc.wantPath {
				t.Errorf("[回归-5] RewriteNetworkURL(%q) = %q, want %q\n"+
					"修复共享网络 bug 时不应改变此豁免行为",
					tc.inputPath, rewritten.URL.Path, tc.wantPath)
			}
		})
	}
}
