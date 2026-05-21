package forward

// ── container_inspect_network_test.go ─────────────────────────────────────────
//
// Bug 描述
// ─────────
//   bob 执行 `docker inspect <container>` 后，响应体中
//   NetworkSettings.Networks 的键名（网络名）及每个网络条目内的 DNSNames
//   仍包含内部用户前缀 "bob_u1002_"，而非用户创建时使用的原始名称。
//
// 预期行为
// ─────────
//   非特权用户的容器 inspect 响应中：
//     1. "Name" 字段已剥除容器名前缀（现有逻辑，已正常）
//     2. NetworkSettings.Networks 的键名应还原为用户原始网络名
//     3. NetworkSettings.Networks 每条目内的 DNSNames 中，含前缀的条目应被还原
//
// 根本原因
// ─────────
//   proxy.go ActionInspect 处理分支仅执行：
//     bytes.Replace(body, `"Name":"/user-uid-xxx"`, `"Name":"/xxx"`, 1)
//   完全未处理 NetworkSettings.Networks 对象（key 为内部网络名）
//   以及各网络条目内的 DNSNames 数组（含有内部网络名）。
//
// 测试矩阵
// ─────────
//   1. [RED]    NetworkKey_PrefixNotStripped_Bug      — Bug 复现：Networks 键名含前缀
//   2. [RED]    DNSNames_PrefixNotStripped_Bug        — Bug 复现：DNSNames 含前缀
//   3. [NORMAL] ContainerName_IsCorrectlyStripped     — 已有行为回归：Name 字段正常
//   4. [NORMAL] MultipleNetworks_AllKeysStripped      — 多网络场景：所有键均被剥除
//   5. [EDGE]   PrivilegedUser_SeesFullPrefixedNames  — root 用户看到完整内部名称
//   6. [EDGE]   EmptyNetworks_NoError                 — Networks 为空时无崩溃
//   7. [EDGE]   ImageInspect_NetworkFieldAbsent_Passthrough — 镜像 inspect 无 NetworkSettings，透传不变

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"docker-authz-proxy/internal/auth"
)

// ── 测试常量 ─────────────────────────────────────────────────────────────────

const (
	// 容器 Docker ID（64 字节十六进制，模拟真实 Docker 容器 ID）
	cInspectBobContID = "c1000000000000000000000000000000000000000000000000000000000000001"
)

// ── 辅助：构造含 NetworkSettings 的容器 inspect 响应体 ─────────────────────
//
// networks: map[网络内部名][]string{DNSNames...}
func buildContainerInspectBody(containerInternalName string, networks map[string][]string) []byte {
	networksJSON := "{"
	first := true
	for netName, dnsNames := range networks {
		if !first {
			networksJSON += ","
		}
		first = false
		dnsRaw, _ := json.Marshal(dnsNames)
		networksJSON += `"` + netName + `":{"IPAMConfig":null,"Links":null,"Aliases":null,"DNSNames":` +
			string(dnsRaw) +
			`,"NetworkID":"netid0001","EndpointID":"epid0001","Gateway":"172.18.0.1",` +
			`"IPAddress":"172.18.0.2","IPPrefixLen":16,"IPv6Gateway":"","GlobalIPv6Address":"",` +
			`"GlobalIPv6PrefixLen":0,"MacAddress":"02:42:ac:12:00:02","DriverOpts":null}`
	}
	networksJSON += "}"

	body := `{"Id":"` + cInspectBobContID + `",` +
		`"Name":"/` + containerInternalName + `",` +
		`"State":{"Status":"running","Running":true},` +
		`"NetworkSettings":{"Bridge":"","SandboxID":"","HairpinMode":false,` +
		`"LinkLocalIPv6Address":"","LinkLocalIPv6PrefixLen":0,"Ports":{},` +
		`"SandboxKey":"","SecondaryIPAddresses":null,"SecondaryIPv6Addresses":null,` +
		`"EndpointID":"","Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,` +
		`"IPAddress":"","IPPrefixLen":0,"IPv6Gateway":"","MacAddress":"",` +
		`"Networks":` + networksJSON + `}}`
	return []byte(body)
}

// ── 辅助：构建带容器归属的测试代理 + 上游 ───────────────────────────────────
func buildInspectTestProxy(t *testing.T, inspectBody []byte) *ProxyServer {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(inspectBody)
	}))
	t.Cleanup(upstream.Close)

	p := newTestProxy(t, upstream, nil)

	// 预置：bob 拥有该容器
	bobIdentity := &auth.CallerIdentity{
		RealUID: bobUID, RealUsername: "bob",
		UserType: auth.UserTypeRegular, AuthSource: auth.AuthSourceOS,
	}
	if err := p.db.SetContainerOwner(cInspectBobContID, bobIdentity, ""); err != nil {
		t.Fatalf("SetContainerOwner: %v", err)
	}
	return p
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. [RED TEST] Bug 复现 — NetworkSettings.Networks 键名含有用户前缀
// ══════════════════════════════════════════════════════════════════════════════
//
// bob 执行 docker inspect mycontainer，上游返回 Networks 键为内部名称
// "bob_u1002_mynet"。
// 修复前，代理直接透传该键名，bob 在响应中看到内部前缀，用户隔离被破坏。
// 该测试在未修复时必须断言失败（t.Errorf 被触发）。
func TestContainerInspect_NetworkKey_PrefixNotStripped_Bug(t *testing.T) {
	body := buildContainerInspectBody(
		"user-1002-mycontainer",
		map[string][]string{
			"bob_u1002_mynet": {"bob_u1002_mynet", "mycontainer"},
		},
	)

	p := buildInspectTestProxy(t, body)

	req := httptest.NewRequest("GET", "/containers/"+cInspectBobContID+"/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200 — body: %q", rw.Code, rw.Body.String())
	}

	// ── 解析响应 ──────────────────────────────────────────────────────────────
	var resp struct {
		NetworkSettings struct {
			Networks map[string]json.RawMessage `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应 JSON 失败: %v — body: %q", err, rw.Body.String())
	}

	// ── 断言 1：Networks 中不应有含前缀的键 ───────────────────────────────────
	for key := range resp.NetworkSettings.Networks {
		if strings.Contains(key, "bob_u1002_") {
			t.Errorf(
				"[BUG REPRODUCED] NetworkSettings.Networks 键名含有内部用户前缀:\n"+
					"  got key  = %q\n"+
					"  want key = %q\n"+
					"  说明 ActionInspect 未剥除 NetworkSettings.Networks 键名前缀",
				key, "mynet",
			)
		}
	}

	// ── 断言 2：Networks 中应存在已还原的键名 "mynet" ─────────────────────────
	if _, ok := resp.NetworkSettings.Networks["mynet"]; !ok {
		t.Errorf(
			"[BUG REPRODUCED] NetworkSettings.Networks 中缺少用户原始键名 \"mynet\":\n"+
				"  实际键集合: %v\n"+
				"  说明前缀未被剥除，用户无法看到自己创建时使用的网络名",
			networkKeys(resp.NetworkSettings.Networks),
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. [RED TEST] Bug 复现 — DNSNames 数组中的网络名含有用户前缀
// ══════════════════════════════════════════════════════════════════════════════
//
// Docker 25+ 会在 NetworkSettings.Networks[netName].DNSNames 中注入网络名。
// 由于网络名使用了内部前缀形式，DNSNames 里同样包含 "bob_u1002_mynet"。
// 修复前，代理不处理 DNSNames，该数组中的前缀泄露给用户。
func TestContainerInspect_DNSNames_PrefixNotStripped_Bug(t *testing.T) {
	// Docker 真实输出：DNSNames 含网络前缀和容器名前缀两类内部名称
	body := buildContainerInspectBody(
		"user-1002-mycontainer",
		map[string][]string{
			"bob_u1002_mynet": {"bob_u1002_mynet", "user-1002-mycontainer"},
		},
	)

	p := buildInspectTestProxy(t, body)

	req := httptest.NewRequest("GET", "/containers/"+cInspectBobContID+"/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200 — body: %q", rw.Code, rw.Body.String())
	}

	// 查找任意 network entry 中的 DNSNames
	var resp struct {
		NetworkSettings struct {
			Networks map[string]struct {
				DNSNames []string `json:"DNSNames"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应 JSON 失败: %v — body: %q", err, rw.Body.String())
	}

	// 检查所有网络条目（不管键名是否已被剥除）中的 DNSNames
	allBodyStr := rw.Body.String()
	if strings.Contains(allBodyStr, "bob_u1002_") {
		t.Errorf(
			"[BUG REPRODUCED] 响应体中包含内部用户前缀 \"bob_u1002_\"，可能出现在:\n"+
				"  • NetworkSettings.Networks 键名\n"+
				"  • DNSNames 数组\n"+
				"  响应体片段: %q\n"+
				"  说明 ActionInspect 未对 NetworkSettings 执行前缀剥除",
			truncateStr(allBodyStr, 512),
		)
	}

	// 进一步检查 DNSNames 具体内容
	for netKey, entry := range resp.NetworkSettings.Networks {
		for _, dns := range entry.DNSNames {
			if strings.Contains(dns, "bob_u1002_") {
				t.Errorf(
					"[BUG REPRODUCED] Networks[%q].DNSNames 含有内部前缀:\n"+
						"  got DNSName = %q\n"+
						"  want        = %q\n"+
						"  用户可通过 docker inspect 感知内部网络命名规则",
					netKey, dns, strings.TrimPrefix(dns, "bob_u1002_"),
				)
			}
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. [NORMAL] 回归：容器 Name 字段前缀剥除（现有正常行为）
// ══════════════════════════════════════════════════════════════════════════════
//
// 确保修复 NetworkSettings 的同时，原有的 Name 字段剥除逻辑不被破坏。
func TestContainerInspect_ContainerName_IsCorrectlyStripped(t *testing.T) {
	body := buildContainerInspectBody(
		"user-1002-mycontainer",
		map[string][]string{
			"bob_u1002_mynet": {"bob_u1002_mynet", "mycontainer"},
		},
	)

	p := buildInspectTestProxy(t, body)

	req := httptest.NewRequest("GET", "/containers/"+cInspectBobContID+"/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", rw.Code)
	}

	var resp struct {
		Name string `json:"Name"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应 JSON 失败: %v", err)
	}

	// 容器 Name 应为原始名（无 "user-1002-" 前缀）
	if resp.Name != "/mycontainer" {
		t.Errorf(
			"容器 Name 前缀剥除失败（回归）:\n  got  = %q\n  want = %q",
			resp.Name, "/mycontainer",
		)
	}
	if strings.Contains(resp.Name, "user-1002-") {
		t.Errorf("Name 字段不应含有内部容器名前缀: %q", resp.Name)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. [NORMAL] 多网络场景 — 所有 Networks 键名均应被剥除
// ══════════════════════════════════════════════════════════════════════════════
//
// 容器同时连接到多个用户自定义网络时，每个键名和对应的 DNSNames 均需剥除前缀。
func TestContainerInspect_MultipleNetworks_AllKeysStripped(t *testing.T) {
	body := buildContainerInspectBody(
		"user-1002-mycontainer",
		map[string][]string{
			"bob_u1002_frontend": {"bob_u1002_frontend", "mycontainer"},
			"bob_u1002_backend":  {"bob_u1002_backend", "mycontainer"},
		},
	)

	p := buildInspectTestProxy(t, body)

	req := httptest.NewRequest("GET", "/containers/"+cInspectBobContID+"/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", rw.Code)
	}

	var resp struct {
		NetworkSettings struct {
			Networks map[string]json.RawMessage `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应 JSON 失败: %v — body: %q", err, rw.Body.String())
	}

	// 断言所有键均已剥除前缀
	for key := range resp.NetworkSettings.Networks {
		if strings.Contains(key, "bob_u1002_") {
			t.Errorf("多网络场景：Networks 键 %q 含有内部前缀，未被正确剥除", key)
		}
	}

	// 断言预期键存在
	for _, expectedKey := range []string{"frontend", "backend"} {
		if _, ok := resp.NetworkSettings.Networks[expectedKey]; !ok {
			t.Errorf("多网络场景：期望 Networks 中存在键 %q，实际键集合: %v",
				expectedKey, networkKeys(resp.NetworkSettings.Networks))
		}
	}

	// 断言整个响应体中无前缀泄露
	if strings.Contains(rw.Body.String(), "bob_u1002_") {
		t.Errorf("多网络场景：响应体中仍含内部前缀: %q",
			truncateStr(rw.Body.String(), 512))
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. [EDGE] 特权用户（root）看到完整内部名称，不剥除前缀
// ══════════════════════════════════════════════════════════════════════════════
//
// root 用户拥有所有资源的访问权，inspect 时应原样透传内部名称。
// 修复后，非特权分支才执行剥除，特权分支直接透传。
func TestContainerInspect_PrivilegedUser_SeesFullPrefixedNames(t *testing.T) {
	body := buildContainerInspectBody(
		"user-1002-mycontainer",
		map[string][]string{
			"bob_u1002_mynet": {"bob_u1002_mynet", "mycontainer"},
		},
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	// root 不需要 DB 中的归属记录（IsPrivileged() 跳过 ownership 检查）

	req := httptest.NewRequest("GET", "/containers/"+cInspectBobContID+"/json", nil)
	rootID := makeTestIdentityProxy("root", 0)
	rootID.UserType = auth.UserTypeRoot
	req = injectIdentity(req, rootID)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("root inspect status = %d, want 200 — body: %q", rw.Code, rw.Body.String())
	}

	// root 应看到完整的内部前缀（容器名和网络名均不剥除）
	respBody := rw.Body.String()
	if !strings.Contains(respBody, "user-1002-mycontainer") {
		t.Errorf("root 用户应在 Name 中看到内部容器名，got: %q", truncateStr(respBody, 256))
	}
	if !strings.Contains(respBody, "bob_u1002_mynet") {
		t.Errorf("root 用户应在 NetworkSettings 中看到内部网络名，got: %q", truncateStr(respBody, 256))
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 6. [EDGE] Networks 为空对象 — 无 panic，正常透传
// ══════════════════════════════════════════════════════════════════════════════
//
// 容器未连接任何网络（Networks: {}）时，剥除逻辑不应 panic 或破坏响应。
func TestContainerInspect_EmptyNetworks_NoError(t *testing.T) {
	body := buildContainerInspectBody("user-1002-isolated", map[string][]string{})

	p := buildInspectTestProxy(t, body)

	req := httptest.NewRequest("GET", "/containers/"+cInspectBobContID+"/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("空 Networks 时 HTTP status = %d, want 200 — body: %q", rw.Code, rw.Body.String())
	}

	var resp struct {
		Name            string `json:"Name"`
		NetworkSettings struct {
			Networks map[string]json.RawMessage `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v — body: %q", err, rw.Body.String())
	}

	if resp.Name != "/isolated" {
		t.Errorf("Name = %q, want \"/isolated\"（空网络场景下容器名仍应被剥除）", resp.Name)
	}
	if len(resp.NetworkSettings.Networks) != 0 {
		t.Errorf("期望 Networks 为空，got %d 个条目", len(resp.NetworkSettings.Networks))
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 7. [EDGE] 镜像 inspect — 无 NetworkSettings，完整透传，不崩溃
// ══════════════════════════════════════════════════════════════════════════════
//
// docker inspect <image> 与 docker inspect <container> 共用 ActionInspect。
// 镜像响应体中不含 NetworkSettings 或 "Name":"/user-uid-" 格式，
// 修复后的代码对镜像响应应直接透传，不引入 panic 或数据损坏。
func TestContainerInspect_ImageInspect_NotAffected(t *testing.T) {
	imageBody := []byte(`{"Id":"sha256:abc123","RepoTags":["nginx:latest"],"Size":50000000}`)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(imageBody)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 镜像 inspect：GET /images/{id}/json
	req := httptest.NewRequest("GET", "/images/sha256:abc123/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	// 镜像 inspect 不在 ownership 检查范围，可能返回 200 或 404（取决于 db.CanUseImage）
	// 这里只验证在 200 时响应体完整，不含乱码
	if rw.Code == http.StatusOK {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(rw.Body.Bytes(), &obj); err != nil {
			t.Errorf("镜像 inspect 响应被破坏（无法解析 JSON）: %v — body: %q",
				err, rw.Body.String())
		}
		// 确保无前缀误植入
		if strings.Contains(rw.Body.String(), "user-1002-") || strings.Contains(rw.Body.String(), "bob_u1002_") {
			t.Errorf("镜像 inspect 响应被误注入用户前缀: %q", rw.Body.String())
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 8. [NORMAL] DNSNames 中的容器名前缀（user-{uid}-）同样被剥除
// ══════════════════════════════════════════════════════════════════════════════
//
// Docker 将容器名（内部含 user-{uid}- 前缀）注入 DNSNames。
// 修复后网络前缀和容器前缀均应被剥除；短容器 ID（无前缀）原样保留。
func TestContainerInspect_DNSNames_ContainerNamePrefix_Stripped(t *testing.T) {
	body := buildContainerInspectBody(
		"user-1002-mycontainer",
		map[string][]string{
			"bob_u1002_mynet": {"bob_u1002_mynet", "user-1002-mycontainer", "273d88afe39b"},
		},
	)
	p := buildInspectTestProxy(t, body)

	req := httptest.NewRequest("GET", "/containers/"+cInspectBobContID+"/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rw.Code)
	}

	var resp struct {
		NetworkSettings struct {
			Networks map[string]struct {
				DNSNames []string `json:"DNSNames"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	entry, ok := resp.NetworkSettings.Networks["mynet"]
	if !ok {
		t.Fatalf("期望 Networks 存在键 \"mynet\"，实际键集合: %v",
			networkKeys2(resp.NetworkSettings.Networks))
	}

	// 断言 1：DNSNames 中无任何内部前缀
	for _, dns := range entry.DNSNames {
		if strings.Contains(dns, "user-1002-") || strings.Contains(dns, "bob_u1002_") {
			t.Errorf("DNSNames 仍含内部前缀: %q（期望已剥除）", dns)
		}
	}

	// 断言 2：短容器 ID（无前缀）应原样保留
	found := false
	for _, dns := range entry.DNSNames {
		if dns == "273d88afe39b" {
			found = true
		}
	}
	if !found {
		t.Errorf("短容器 ID 应在 DNSNames 中原样保留，got: %v", entry.DNSNames)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 9. [EDGE] 容器仅连接系统网络（无用户前缀）— body 完全透传，字段不乱序
// ══════════════════════════════════════════════════════════════════════════════
//
// 验证 changed=false 路径：无用户自定义网络时直接返回原始 body，
// 避免不必要的 JSON 重建（性能保护）且不破坏字段顺序。
func TestContainerInspect_NoUserNetwork_BodyTransparent(t *testing.T) {
	// 仅有系统桥接网络，键名无 bob_u1002_ 前缀
	rawBody := buildContainerInspectBody(
		"user-1002-isolated",
		map[string][]string{
			"user-1002-bridge": {"user-1002-isolated"},
		},
	)
	p := buildInspectTestProxy(t, rawBody)

	req := httptest.NewRequest("GET", "/containers/"+cInspectBobContID+"/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rw.Code)
	}

	var resp struct {
		NetworkSettings struct {
			Networks map[string]json.RawMessage `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 系统桥接网络键名无用户前缀，应保持不变
	if _, ok := resp.NetworkSettings.Networks["user-1002-bridge"]; !ok {
		t.Errorf("系统桥接网络键名被意外修改，实际键集合: %v",
			networkKeys(resp.NetworkSettings.Networks))
	}
	// 响应体不应含用户网络前缀
	if strings.Contains(rw.Body.String(), "bob_u1002_") {
		t.Errorf("响应体不应含有用户网络前缀: %q", truncateStr(rw.Body.String(), 256))
	}
}

// ── 内部辅助函数 ──────────────────────────────────────────────────────────────

func networkKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// networkKeys2 同 networkKeys，用于含 DNSNames 字段的 struct map。
func networkKeys2(m map[string]struct{ DNSNames []string `json:"DNSNames"` }) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncated)"
}
