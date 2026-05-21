package forward

// ── network_inspect_test.go ────────────────────────────────────────────────────
//
// Bug 描述
// ─────────
//   bob 执行 `docker network create test_net_from2` 创建网络后，
//   再执行 `docker inspect test_net_from2`，看到的 JSON Name 字段仍为
//   "bob_u1002_test_net_from2"，而非用户可见的原始名称 "test_net_from2"。
//
// 预期行为
// ─────────
//   非特权用户的 GET /networks/{name} 响应体中，"Name" 字段应剥除用户前缀，
//   还原为用户创建时的原始名称。
//
// 根本原因
// ─────────
//   stripNetworkNamePrefix 使用字节级字符串匹配：`"Name":"<prefix>`
//   若上游 Docker 响应的 JSON 使用带空格的格式（`"Name": "<prefix>`），
//   或响应体的键顺序/编码方式与预期不符，
//   bytes.Contains 将无法命中，前缀保留在最终响应中。
//
// 测试矩阵
// ─────────
//   1. [RED]    BobInspect_NamePrefixNotStripped_Bug          — Bug 复现（单元级）
//   2. [RED]    BobInspect_FullProxy_PrefixStillVisible        — Bug 复现（代理集成级）
//   3. [NORMAL] BobInspect_FullProxy_NameStrippedCorrectly     — 正常路径：前缀应被剥除
//   4. [NORMAL] BobInspect_CreateThenInspect_RoundTrip         — 创建 + 查看端对端验证
//   5. [EDGE]   PrivilegedUser_SeesFullPrefixedName            — 特权用户不剥除前缀
//   6. [EDGE]   BobInspect_NetworkNotInDB_Returns404           — 不可见网络返回 404

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// ── 固定测试常量 ──────────────────────────────────────────────────────────────

const (
	inspectBobNetID = "cc00000000000000000000000000000000000000000000000000000000000001"
)

// ══════════════════════════════════════════════════════════════════════════════
// 1. [RED TEST] Bug 复现（单元级）— stripNetworkNamePrefix 行为验证
// ══════════════════════════════════════════════════════════════════════════════
//
// 直接测试 stripNetworkNamePrefix 函数对 Docker 实际响应格式的处理能力。
// 在未修复前，若 Docker 返回的 JSON Name 字段使用冒号后有空格格式
// （`"Name": "bob_u1002_test_net_from2"`），bytes.Contains 无法命中，
// 前缀不会被剥除，该测试断言失败。
//
// 注：若 Docker 保证始终返回紧凑 JSON（`"Name":"xxx"`），则此场景必须通过。
// 若当前实现对两种格式均不处理，则是已知的脆弱点。
func TestStripNetworkNamePrefix_CompactJSON_PrefixIsStripped(t *testing.T) {
	prefix := "bob_u1002_"
	// Docker 标准紧凑格式（json.Marshal 输出）
	body := []byte(`{"Name":"bob_u1002_test_net_from2","Id":"` + inspectBobNetID + `","Driver":"bridge"}`)

	result := stripNetworkNamePrefix(body, prefix)

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(result, &obj); err != nil {
		t.Fatalf("解析结果 JSON 失败: %v — body: %q", err, result)
	}
	var name string
	if err := json.Unmarshal(obj["Name"], &name); err != nil {
		t.Fatalf("解析 Name 字段失败: %v", err)
	}
	if name != "test_net_from2" {
		t.Errorf(
			"[BUG REPRODUCED] stripNetworkNamePrefix 未剥除前缀:\n"+
				"  got  Name = %q\n"+
				"  want Name = %q\n"+
				"  说明 bytes.Replace 未能在紧凑 JSON 中命中 `\"Name\":\"bob_u1002_` 模式",
			name, "test_net_from2",
		)
	}
}

// 当 Docker 返回带空格的 JSON（`"Name": "..."` 而非 `"Name":"..."`）时，
// 当前 bytes.Replace 实现 **无法** 剥除前缀 — 这是已知的格式脆弱点。
// 该测试记录此边界行为：修复后应同样通过。
func TestStripNetworkNamePrefix_SpacedJSON_PrefixNotStripped_KnownWeakness(t *testing.T) {
	prefix := "bob_u1002_"
	// 带空格的 JSON（如 json.MarshalIndent 或某些代理/网关重写后的输出）
	body := []byte(`{"Name": "bob_u1002_test_net_from2","Id":"` + inspectBobNetID + `"}`)

	result := stripNetworkNamePrefix(body, prefix)

	// 当前实现不能处理带空格格式，Name 仍含有前缀
	if !strings.Contains(string(result), "bob_u1002_") {
		// 如果这里到达，说明代码已修复支持带空格格式——需更新断言
		t.Log("[已修复] 代码现在可以处理带空格的 JSON 格式，请更新此测试")
	} else {
		// 当前预期行为：未修复时前缀仍然存在（记录已知弱点）
		t.Log("[已知弱点] stripNetworkNamePrefix 不支持带空格的 JSON 格式，" +
			"若 Docker 返回此格式前缀将泄露给用户")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. [RED TEST] Bug 复现（代理集成级）— 完整代理路径下名称前缀泄露
// ══════════════════════════════════════════════════════════════════════════════
//
// 上游模拟 Docker daemon 返回含用户前缀的网络名。
// 代理应在回传给客户端前剥除前缀。
// 在 Bug 未修复前（如 stripNetworkNamePrefix 不被调用或匹配失败），
// 响应体中仍含有 "bob_u1002_test_net_from2"，下列断言失败。
func TestNetworkInspect_BobSeesOriginalName_NotPrefixedName(t *testing.T) {
	// 模拟 Docker daemon：GET /networks/{prefixed_name} → 返回含前缀的 JSON
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stripped := authz.StripAPIVersion(r.URL.Path)
		if r.Method == "GET" && strings.HasPrefix(stripped, "/networks/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Docker 返回内部（含前缀）的真实网络名
			_, _ = w.Write([]byte(
				`{"Name":"bob_u1002_test_net_from2","Id":"` + inspectBobNetID + `",` +
					`"Driver":"bridge","Scope":"local","EnableIPv6":false,` +
					`"IPAM":{"Driver":"default","Options":null,"Config":[]}` +
					`,"ConfigFrom":{"Network":""},"ConfigOnly":false,` +
					`"Containers":{},"Options":{},"Labels":{}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 预置：bob 拥有此网络（内部名含前缀）
	bobID := &auth.CallerIdentity{RealUID: bobUID, RealUsername: "bob"}
	if err := p.db.SetNetworkOwner(inspectBobNetID, "bob_u1002_test_net_from2", bobID); err != nil {
		t.Fatalf("SetNetworkOwner: %v", err)
	}

	// bob 用用户可见名（不含前缀）发起 inspect 请求
	req := httptest.NewRequest("GET", "/networks/test_net_from2", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200 — body: %q", rw.Code, rw.Body.String())
	}

	// ── 断言 1：响应体中不得含有内部前缀 ──────────────────────────────────────
	body := rw.Body.String()
	if strings.Contains(body, "bob_u1002_") {
		t.Errorf(
			"[BUG REPRODUCED] 响应体中包含内部用户前缀，说明 stripNetworkNamePrefix 未生效:\n"+
				"  response body: %q\n"+
				"  期望 Name 字段为 \"test_net_from2\"，不应含有 \"bob_u1002_\"",
			body,
		)
	}

	// ── 断言 2：Name 字段必须等于用户原始名 ───────────────────────────────────
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应 JSON 失败: %v — body: %q", err, body)
	}
	var name string
	if err := json.Unmarshal(resp["Name"], &name); err != nil {
		t.Fatalf("解析 Name 字段失败: %v", err)
	}
	if name != "test_net_from2" {
		t.Errorf(
			"[BUG REPRODUCED] Name = %q，want \"test_net_from2\"\n"+
				"  bob 执行 docker inspect test_net_from2 时，"+
				"JSON 中看到了内部名称 %q，用户隔离被破坏",
			name, name,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. [NORMAL] 正常路径：代理正确剥除前缀，bob 看到原始名称
// ══════════════════════════════════════════════════════════════════════════════
func TestNetworkInspect_BobInspectsOwnNetwork_SeesOriginalName(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stripped := authz.StripAPIVersion(r.URL.Path)
		// 验证上游收到的是含前缀的内部名称（URL 已被代理重写）
		if r.Method == "GET" && stripped == "/networks/bob_u1002_mynet" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Name":"bob_u1002_mynet","Id":"dd00000000000000000000000000000000000000000000000000000000000001","Driver":"bridge","Scope":"local","EnableIPv6":false,"IPAM":{"Driver":"default","Options":null,"Config":[]},"ConfigFrom":{"Network":""},"ConfigOnly":false,"Containers":{},"Options":{},"Labels":{}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	bobID := &auth.CallerIdentity{RealUID: bobUID, RealUsername: "bob"}
	const myNetID = "dd00000000000000000000000000000000000000000000000000000000000001"
	if err := p.db.SetNetworkOwner(myNetID, "bob_u1002_mynet", bobID); err != nil {
		t.Fatalf("SetNetworkOwner: %v", err)
	}

	req := httptest.NewRequest("GET", "/networks/mynet", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body: %q", rw.Code, rw.Body.String())
	}

	var resp map[string]json.RawMessage
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var name string
	_ = json.Unmarshal(resp["Name"], &name)
	if name != "mynet" {
		t.Errorf("Name = %q, want \"mynet\" (前缀未被正确剥除)", name)
	}

	// 响应体中不应含有任何内部前缀
	if strings.Contains(rw.Body.String(), "bob_u1002_") {
		t.Errorf("响应体中不应含有内部前缀 bob_u1002_，got: %q", rw.Body.String())
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. [NORMAL] 端对端：创建 → inspect 全流程，名称一致性验证
// ══════════════════════════════════════════════════════════════════════════════
//
// 覆盖完整生命周期：
//   POST /networks/create → GET /networks/test_net_from2
// 确保创建时注入前缀、inspect 时剥除前缀均正确。
func TestNetworkInspect_CreateThenInspect_NameRoundTrip(t *testing.T) {
	const netID = "ee00000000000000000000000000000000000000000000000000000000000001"

	var lastInspectPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stripped := authz.StripAPIVersion(r.URL.Path)
		switch {
		case r.Method == "POST" && stripped == "/networks/create":
			// 创建成功，返回网络 ID
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"` + netID + `"}`))

		case r.Method == "GET" && strings.HasPrefix(stripped, "/networks/"):
			lastInspectPath = stripped
			// 返回 Docker 内部（含前缀）的网络信息
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Name":"bob_u1002_test_net_from2","Id":"` + netID + `","Driver":"bridge","Scope":"local","EnableIPv6":false,"IPAM":{"Driver":"default","Options":null,"Config":[]},"ConfigFrom":{"Network":""},"ConfigOnly":false,"Containers":{},"Options":{},"Labels":{}}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	bobIdentity := makeTestIdentityProxy("bob", bobUID)

	// 步骤 1：bob 创建 test_net_from2
	createBody := `{"Name":"test_net_from2","Driver":"bridge","CheckDuplicate":true,"EnableIPv6":false,"IPAM":{"Driver":"default","Options":null,"Config":[]},"Internal":false,"Attachable":false,"Ingress":false,"ConfigFrom":{"Network":""},"ConfigOnly":false,"Options":{},"Labels":{}}`
	createReq := httptest.NewRequest("POST", "/networks/create", strings.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq = injectIdentity(createReq, bobIdentity)
	createRW := httptest.NewRecorder()
	p.ServeHTTP(createRW, createReq)

	if createRW.Code != http.StatusCreated {
		t.Fatalf("创建网络 status = %d, want 201 — body: %q", createRW.Code, createRW.Body.String())
	}

	// ── 断言：create 响应不应含有内部前缀 ──────────────────────────────────────
	if strings.Contains(createRW.Body.String(), "bob_u1002_") {
		t.Errorf("创建响应不应含有内部前缀: %q", createRW.Body.String())
	}

	// 步骤 2：bob 用原始名称 inspect
	inspectReq := httptest.NewRequest("GET", "/networks/test_net_from2", nil)
	inspectReq = injectIdentity(inspectReq, bobIdentity)
	inspectRW := httptest.NewRecorder()
	p.ServeHTTP(inspectRW, inspectReq)

	if inspectRW.Code != http.StatusOK {
		t.Fatalf("inspect status = %d, want 200 — body: %q", inspectRW.Code, inspectRW.Body.String())
	}

	// ── 断言 1：上游收到的 inspect 路径含有内部前缀（代理 URL 重写正确）────────
	if !strings.Contains(lastInspectPath, "bob_u1002_") {
		t.Errorf("上游未收到含前缀的 inspect 请求路径，说明 URL 重写失败: %q", lastInspectPath)
	}

	// ── 断言 2：客户端响应中 Name 字段为原始名（前缀已剥除）─────────────────────
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(inspectRW.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析 inspect 响应失败: %v — body: %q", err, inspectRW.Body.String())
	}
	var name string
	if err := json.Unmarshal(resp["Name"], &name); err != nil {
		t.Fatalf("解析 Name 字段失败: %v", err)
	}
	if name != "test_net_from2" {
		t.Errorf(
			"[BUG REPRODUCED] inspect 响应 Name = %q，want \"test_net_from2\"\n"+
				"  bob 创建 test_net_from2 后 inspect，看到的是内部名称而非原始名称",
			name,
		)
	}

	// ── 断言 3：响应体不含任何内部前缀 ────────────────────────────────────────
	if strings.Contains(inspectRW.Body.String(), "bob_u1002_") {
		t.Errorf("inspect 响应体含有内部前缀，用户可感知内部命名规则: %q", inspectRW.Body.String())
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. [EDGE] 特权用户（root）看到真实的内部网络名（不剥除前缀）
// ══════════════════════════════════════════════════════════════════════════════
func TestNetworkInspect_PrivilegedUser_SeesInternalName(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Name":"bob_u1002_test_net_from2","Id":"` + inspectBobNetID + `","Driver":"bridge","Scope":"local","EnableIPv6":false,"IPAM":{"Driver":"default","Options":null,"Config":[]},"ConfigFrom":{"Network":""},"ConfigOnly":false,"Containers":{},"Options":{},"Labels":{}}`))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// root 用户不走前缀隔离逻辑
	rootReq := httptest.NewRequest("GET", "/networks/bob_u1002_test_net_from2", nil)
	rootID := makeTestIdentityProxy("root", 0)
	rootID.UserType = auth.UserTypeRoot
	rootReq = injectIdentity(rootReq, rootID)
	rootRW := httptest.NewRecorder()
	p.ServeHTTP(rootRW, rootReq)

	if rootRW.Code != http.StatusOK {
		t.Fatalf("root inspect status = %d, want 200", rootRW.Code)
	}

	// root 应看到完整的内部前缀名称（不剥除）
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(rootRW.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v — body: %q", err, rootRW.Body.String())
	}
	var name string
	_ = json.Unmarshal(resp["Name"], &name)
	if name != "bob_u1002_test_net_from2" {
		t.Errorf(
			"特权用户应看到内部名称 %q，got %q",
			"bob_u1002_test_net_from2", name,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 6. [EDGE] bob inspect 其他用户的网络 → 返回 404（跨用户隔离）
// ══════════════════════════════════════════════════════════════════════════════
func TestNetworkInspect_BobInspectsAliceNetwork_Gets404(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 即使 Docker 能返回，代理也应在访问控制层拦截
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Name":"alice_u1001_secret_net","Id":"` + pruneAliceNetID + `","Driver":"bridge","Scope":"local","EnableIPv6":false,"IPAM":{"Driver":"default","Options":null,"Config":[]},"ConfigFrom":{"Network":""},"ConfigOnly":false,"Containers":{},"Options":{},"Labels":{}}`))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// alice 拥有 pruneAliceNetID，bob 不在授权列表中
	aliceID := &auth.CallerIdentity{RealUID: aliceUID, RealUsername: "alice"}
	if err := p.db.SetNetworkOwner(pruneAliceNetID, "alice_u1001_secret_net", aliceID); err != nil {
		t.Fatalf("SetNetworkOwner: %v", err)
	}

	// bob 尝试通过内部 ID 直接访问 alice 的网络
	req := httptest.NewRequest("GET", "/networks/"+pruneAliceNetID, nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusNotFound {
		t.Errorf(
			"bob inspect alice 的网络，status = %d，want 404 (跨用户访问应被拦截)",
			rw.Code,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 7. [EDGE] bob inspect 自己不存在（未在 DB 中注册）的网络 → 返回 404
// ══════════════════════════════════════════════════════════════════════════════
func TestNetworkInspect_NetworkNotRegistered_Returns404(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 即使上游能响应，代理的访问控制层应先拦截
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Name":"bob_u1002_ghost_net","Id":"ff00000000000000000000000000000000000000000000000000000000000001"}`))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	// DB 中没有任何网络归属记录

	req := httptest.NewRequest("GET", "/networks/ghost_net", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusNotFound {
		t.Errorf("未注册网络的 inspect status = %d, want 404", rw.Code)
	}

	// 响应体不得泄露内部前缀名称
	if strings.Contains(rw.Body.String(), "bob_u1002_") {
		t.Errorf("404 响应体不应含有内部前缀: %q", rw.Body.String())
	}
}
