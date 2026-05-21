package forward

// ── network_prune_test.go ─────────────────────────────────────────────────────
//
// Bug 描述
// ─────────
//   bob 执行 `docker network prune -f` 时，将 alice（其他用户）的网络一并清理。
//
// 预期行为
// ─────────
//   非特权用户的 POST /networks/prune 应被代理完全拦截：
//   仅删除 owner_uid == caller_uid 的网络，其余用户的网络不受影响。
//
// 根本原因
// ─────────
//   当 handleNetworkPrune 未正确返回 true（即未完成拦截），请求将继续透传给
//   Docker daemon。Docker daemon 原生执行全局 prune，无用户隔离，导致所有未被
//   任何容器连接的网络（包括其他用户的）均被删除。
//
// 测试矩阵
// ─────────
//   1. [RED]      BobPruneDoesNotDeleteAliceNetwork — Bug 复现
//   2. [NORMAL]   BobPruneOnlyDeletesOwnNetworks — 正常路径隔离验证
//   3. [EDGE]     UserWithNoNetworks — 无自有网络时返回空列表
//   4. [EDGE]     NetworkWithActiveContainersSkipped — 有活跃容器的网络被跳过
//   5. [EDGE]     DBError_ReturnsEmptyAndDoesNotForward — DB 故障时安全降级

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// ── 固定测试用常量 ─────────────────────────────────────────────────────────────
// 使用 64 字节十六进制字符串模拟真实 Docker 网络 ID。
const (
	pruneAliceNetID = "aa00000000000000000000000000000000000000000000000000000000000001"
	pruneBobNetID   = "bb00000000000000000000000000000000000000000000000000000000000001"
	pruneBobNetID2  = "bb00000000000000000000000000000000000000000000000000000000000002"
)

// networkPruneResponse 对应 Docker /networks/prune 的 JSON 格式
type networkPruneResponse struct {
	NetworksDeleted []string `json:"NetworksDeleted"`
}

// ── 辅助：构建用于 prune 测试的身份 ──────────────────────────────────────────

func aliceIdentityPrune() *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUID: aliceUID, RealUsername: "alice",
		UserType: auth.UserTypeRegular, AuthSource: auth.AuthSourceOS,
	}
}

func bobIdentityPrune() *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUID: bobUID, RealUsername: "bob",
		UserType: auth.UserTypeRegular, AuthSource: auth.AuthSourceOS,
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. [RED TEST] Bug 复现 — bob 的 prune 不得删除 alice 的网络
// ══════════════════════════════════════════════════════════════════════════════
//
// 在 Bug 未修复前（代理未拦截 /networks/prune），上游收到原始 POST /networks/prune，
// Docker daemon 将 alice 的网络一并删除，导致下面三个断言全部失败：
//   - 上游不应收到 POST /networks/prune
//   - 上游不应收到 DELETE /networks/<alice-net-id>
//   - alice 的网络记录不应从 DB 消失
func TestNetworkPrune_BobPruneDoesNotDeleteAliceNetwork(t *testing.T) {
	var mu sync.Mutex
	type upstreamCall struct{ method, path string }
	var upstreamCalls []upstreamCall

	// 模拟 Docker daemon：
	//   • 若收到 POST /networks/prune → 模拟 Docker 全局 prune（删除所有注册网络）
	//   • 若收到 DELETE /networks/{id} → 返回 204
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stripped := authz.StripAPIVersion(r.URL.Path)
		mu.Lock()
		upstreamCalls = append(upstreamCalls, upstreamCall{r.Method, stripped})
		mu.Unlock()

		switch {
		case r.Method == "DELETE" && strings.HasPrefix(stripped, "/networks/"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "POST" && stripped == "/networks/prune":
			// Docker daemon 全局 prune：alice 和 bob 的网络都会出现在结果里
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"NetworksDeleted":["` + pruneAliceNetID + `","` + pruneBobNetID + `"]}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 预置 alice 的网络归属
	if err := p.db.SetNetworkOwner(pruneAliceNetID, "alice_u1001_net", aliceIdentityPrune()); err != nil {
		t.Fatalf("SetNetworkOwner(alice): %v", err)
	}
	// 预置 bob 的网络归属
	if err := p.db.SetNetworkOwner(pruneBobNetID, "bob_u1002_net", bobIdentityPrune()); err != nil {
		t.Fatalf("SetNetworkOwner(bob): %v", err)
	}

	// bob 发起 network prune
	req := httptest.NewRequest("POST", "/networks/prune", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("HTTP status = %d, want 200", rw.Code)
	}

	mu.Lock()
	calls := make([]upstreamCall, len(upstreamCalls))
	copy(calls, upstreamCalls)
	mu.Unlock()

	// ── 断言 1：上游不得收到原始 POST /networks/prune ─────────────────────────
	// 若收到，说明代理未拦截，Docker daemon 执行了全局 prune。
	for _, c := range calls {
		if c.method == "POST" && c.path == "/networks/prune" {
			t.Errorf(
				"[BUG REPRODUCED] 代理未拦截 POST /networks/prune，请求透传至 Docker daemon，"+
					"Docker 将对所有用户的网络执行全局 prune。"+
					"\n上游实际收到的请求: %v", calls,
			)
		}
	}

	// ── 断言 2：上游不得收到删除 alice 网络的请求 ─────────────────────────────
	aliceDeletePath := "/networks/" + pruneAliceNetID
	for _, c := range calls {
		if c.method == "DELETE" && c.path == aliceDeletePath {
			t.Errorf(
				"[BUG REPRODUCED] 上游收到了删除 alice 网络（%s）的请求，"+
					"bob 的 prune 跨越了用户边界。\n上游实际收到的请求: %v",
				pruneAliceNetID, calls,
			)
		}
	}

	// ── 断言 3：alice 的网络记录应仍在 DB 中 ──────────────────────────────────
	aliceNets, err := p.db.GetNetworkIDsByOwner(aliceUID)
	if err != nil {
		t.Fatalf("GetNetworkIDsByOwner(alice): %v", err)
	}
	found := false
	for _, id := range aliceNets {
		if id == pruneAliceNetID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf(
			"[BUG REPRODUCED] alice 的网络（%s）从 DB 中消失，说明 bob 的 prune 删除了跨用户资源",
			pruneAliceNetID,
		)
	}

	// ── 断言 4：响应体中不得包含 alice 的网络 ID ──────────────────────────────
	var resp networkPruneResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应 JSON 失败: %v — body: %q", err, rw.Body.String())
	}
	for _, id := range resp.NetworksDeleted {
		if id == pruneAliceNetID {
			t.Errorf(
				"[BUG REPRODUCED] 响应 NetworksDeleted 中包含 alice 的网络（%s），"+
					"用户隔离被破坏", pruneAliceNetID,
			)
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. [NORMAL] 正常路径：bob 的 prune 只删自己的网络
// ══════════════════════════════════════════════════════════════════════════════
func TestNetworkPrune_BobPruneOnlyDeletesOwnNetworks(t *testing.T) {
	var mu sync.Mutex
	var deletedIDs []string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stripped := authz.StripAPIVersion(r.URL.Path)
		if r.Method == "DELETE" && strings.HasPrefix(stripped, "/networks/") {
			netID := strings.TrimPrefix(stripped, "/networks/")
			mu.Lock()
			deletedIDs = append(deletedIDs, netID)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 预置：alice 拥有 pruneAliceNetID
	_ = p.db.SetNetworkOwner(pruneAliceNetID, "alice_u1001_net", aliceIdentityPrune())
	// 预置：bob 拥有 pruneBobNetID 和 pruneBobNetID2
	_ = p.db.SetNetworkOwner(pruneBobNetID, "bob_u1002_net1", bobIdentityPrune())
	_ = p.db.SetNetworkOwner(pruneBobNetID2, "bob_u1002_net2", bobIdentityPrune())

	req := httptest.NewRequest("POST", "/networks/prune", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rw.Code)
	}

	mu.Lock()
	gotDeleted := make([]string, len(deletedIDs))
	copy(gotDeleted, deletedIDs)
	mu.Unlock()

	// alice 的网络不应出现在删除列表
	for _, id := range gotDeleted {
		if id == pruneAliceNetID {
			t.Errorf("alice 的网络（%s）被删除，跨用户隔离失败", pruneAliceNetID)
		}
	}

	// bob 的两个网络应均被删除
	bobNetsDeleted := 0
	for _, id := range gotDeleted {
		if id == pruneBobNetID || id == pruneBobNetID2 {
			bobNetsDeleted++
		}
	}
	if bobNetsDeleted != 2 {
		t.Errorf("bob 应有 2 个网络被删除，实际删除 %d 个（%v）", bobNetsDeleted, gotDeleted)
	}

	// 响应体验证
	var resp networkPruneResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if len(resp.NetworksDeleted) != 2 {
		t.Errorf("NetworksDeleted 长度 = %d，want 2，got %v", len(resp.NetworksDeleted), resp.NetworksDeleted)
	}

	// alice 的网络记录仍应在 DB 中
	aliceNets, _ := p.db.GetNetworkIDsByOwner(aliceUID)
	found := false
	for _, id := range aliceNets {
		if id == pruneAliceNetID {
			found = true
			break
		}
	}
	if !found {
		t.Error("alice 的网络从 DB 消失，存在跨用户资源泄漏")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. [EDGE] 用户没有任何网络时，返回 NetworksDeleted:[] 而非 null
// ══════════════════════════════════════════════════════════════════════════════
func TestNetworkPrune_UserWithNoNetworks_ReturnsEmptyList(t *testing.T) {
	var gotPruneRequest bool

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stripped := authz.StripAPIVersion(r.URL.Path)
		if r.Method == "POST" && stripped == "/networks/prune" {
			// 若代理未拦截，此请求会到达这里（Bug）
			gotPruneRequest = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"NetworksDeleted":[]}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	// bob 在 DB 中没有任何网络记录

	req := httptest.NewRequest("POST", "/networks/prune", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rw.Code)
	}

	// 代理应拦截而非透传（即使结果为空）
	if gotPruneRequest {
		t.Error("上游收到了原始 POST /networks/prune，代理未拦截空用户的 prune 请求，存在全局泄漏风险")
	}

	var resp networkPruneResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v — body: %q", err, rw.Body.String())
	}
	// 应为空切片而非 null（docker CLI 期望 [] 而非 null）
	if resp.NetworksDeleted == nil {
		t.Error("NetworksDeleted 为 null，应为空数组 []，docker CLI 可能解析异常")
	}
	if len(resp.NetworksDeleted) != 0 {
		t.Errorf("NetworksDeleted 不为空: %v，bob 没有任何网络", resp.NetworksDeleted)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. [EDGE] bob 的网络有活跃容器（Docker 返回 409）时，该网络被跳过
// ══════════════════════════════════════════════════════════════════════════════
func TestNetworkPrune_NetworkWithActiveContainers_IsSkipped(t *testing.T) {
	// pruneBobNetID  → 无活跃容器 → 可删除（204）
	// pruneBobNetID2 → 有活跃容器 → Docker 返回 409，代理应跳过
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stripped := authz.StripAPIVersion(r.URL.Path)
		if r.Method == "DELETE" {
			switch strings.TrimPrefix(stripped, "/networks/") {
			case pruneBobNetID:
				w.WriteHeader(http.StatusNoContent) // 成功删除
			case pruneBobNetID2:
				// 有活跃端点，Docker 返回 409
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"message":"network ` + pruneBobNetID2 + ` id is in use by a container"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	_ = p.db.SetNetworkOwner(pruneBobNetID, "bob_u1002_free", bobIdentityPrune())
	_ = p.db.SetNetworkOwner(pruneBobNetID2, "bob_u1002_busy", bobIdentityPrune())

	req := httptest.NewRequest("POST", "/networks/prune", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rw.Code)
	}

	var resp networkPruneResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}

	// 只有无活跃容器的网络应被计入删除
	if len(resp.NetworksDeleted) != 1 {
		t.Errorf("NetworksDeleted 长度 = %d，want 1（只应删除空闲网络）: %v",
			len(resp.NetworksDeleted), resp.NetworksDeleted)
	}
	if len(resp.NetworksDeleted) > 0 && resp.NetworksDeleted[0] != pruneBobNetID {
		t.Errorf("deleted[0] = %q，want %q（有活跃容器的网络不应出现在已删除列表）",
			resp.NetworksDeleted[0], pruneBobNetID)
	}

	// pruneBobNetID2 的 DB 记录应保留（容器仍在使用）
	bobNets, _ := p.db.GetNetworkIDsByOwner(bobUID)
	foundBusy := false
	for _, id := range bobNets {
		if id == pruneBobNetID2 {
			foundBusy = true
			break
		}
	}
	if !foundBusy {
		t.Errorf("pruneBobNetID2（有活跃容器）的 DB 记录被错误删除，应保留直到容器停止")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. [EDGE] DB 查询故障时安全降级：返回空列表，不透传请求给 Docker
// ══════════════════════════════════════════════════════════════════════════════
func TestNetworkPrune_DBError_ReturnsEmptyAndDoesNotForwardToDocker(t *testing.T) {
	var gotPruneRequest bool

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stripped := authz.StripAPIVersion(r.URL.Path)
		if r.Method == "POST" && stripped == "/networks/prune" {
			gotPruneRequest = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"NetworksDeleted":["` + pruneAliceNetID + `"]}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 关闭 DB 以模拟故障
	p.db.Close()

	req := httptest.NewRequest("POST", "/networks/prune", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	// 即便 DB 故障，代理仍应拦截（返回空列表）而非透传
	if gotPruneRequest {
		t.Error("DB 故障时代理将请求透传给 Docker daemon，导致全局 prune —— 应安全降级返回空列表")
	}

	if rw.Code != http.StatusOK {
		t.Errorf("status = %d, want 200（DB 故障应安全降级，而非 5xx）", rw.Code)
	}

	var resp networkPruneResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v — body: %q", err, rw.Body.String())
	}
	if len(resp.NetworksDeleted) != 0 {
		t.Errorf("DB 故障时 NetworksDeleted 不应包含任何 ID，got: %v", resp.NetworksDeleted)
	}
}
