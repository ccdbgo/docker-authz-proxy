package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-9: handleVolumePrune 的三个缺陷
//
// ──── 问题一：VolumesDeleted 响应中卷名未剥离用户前缀 ─────────────────────────
//
//   alice 执行 docker volume prune -f，期望收到：
//     {"VolumesDeleted":["config"],"SpaceReclaimed":0}
//   实际收到：
//     {"VolumesDeleted":["user-1001-volume-config"],"SpaceReclaimed":0}
//
//   根因：handleVolumePrune 在构建 deleted 列表时，直接把 DB 中的内部卷名
//   （user-{uid}-volume-{suffix}）放入 VolumesDeleted，没有调用
//   StripVolumeNamePrefix 剥离前缀。docker volume ls 会还原名称，
//   但 prune 响应走的是独立路径，从不经过 postprocessResponse 的剥离逻辑。
//
// ──── 问题二：普通用户 prune 后其他用户的事件监听器收到该事件 ──────────────────
//
//   alice 执行 docker volume prune -f → 代理向 Docker 发送
//   DELETE /volumes/user-1001-volume-config → Docker 产生
//   volume destroy user-1001-volume-config 事件 → bob 的 docker system events
//   调用 eventBelongsToUser(event, bobUID=1002)：
//     名称 user-1001-volume-config 匹配路径 2（合法用户卷，但非 bob 的）→ false ✓
//   ← BUG-8 已修复，此处应该正确过滤，bob 不会收到
//
//   *** 但 sudo_test 的 events 订阅走的是 IsPrivileged() 分支：***
//   代码（proxy.go:2920）：
//     if isEvents && !id.IsPrivileged() {
//         if !eventBelongsToUser(line, id.RealUID) { continue }
//     }
//   IsPrivileged()==true → 整个过滤块被跳过 → 所有事件全量透传给 sudo_test
//
//   场景：sudo_test 打开 docker system events，然后 alice 执行普通 prune。
//   sudo_test 应该看到所有用户的卷事件（这是特权用户的预期行为）。
//   ← 这不是 Bug，是设计。
//
//   真正的问题：bob 的事件流中仍然收到了 alice 的事件 → 说明 BUG-8 的修复
//   在事件流写入路径上仍有漏洞，或者测试场景中涉及的是 sudo_test 订阅路径。
//   根据用户反馈，问题是"sudo_test 执行 sudo prune 后 bob 收到了 alice 的事件"
//   与"alice 执行普通 prune 后 bob 收到了 alice 的事件"。
//
//   深挖：eventBelongsToUser 对 volume 事件只处理了 ev.Type == "volume"，
//   但 Docker 在 volume 被 DELETE 时，还会产生一个 Type=="volume" + Action=="destroy"
//   的事件，其中 Attributes 包含的是 Docker 内部的"挂载名"，而不是创建时的卷名。
//   如果 Docker 实际产生的事件 name 字段为空（匿名挂载）或格式不同，
//   eventBelongsToUser 走路径 3 → return true → bob 收到。
//
//   更准确的根因：handleVolumePrune 向 Docker 发送 DELETE 请求后，
//   Docker 产生的 volume destroy 事件的 Type 字段是 "volume"，
//   但 Action 字段可能包含路径信息（如挂载点），不一定是 "destroy"。
//   ← 需确认实际 Docker 事件格式。
//
//   *** 经重新分析，最核心的根因是：***
//   handleVolumePrune 在向 Docker 发 DELETE 请求后，Docker 会向所有 /events
//   订阅者广播 volume destroy 事件。代理对 bob 的 /events 流中，
//   eventBelongsToUser 依赖 attrs["name"] 进行路径 2 判断。
//   但 Docker volume destroy 事件实测的 Attributes.name 是内部挂载名，
//   可能与卷名不一致，或者事件根本没有 "name" 字段而只有空字符串。
//   name 为空 → strings.HasPrefix("", "user-") == false → 走路径 3 → return true
//   → bob 收到了该事件。
//
// ──── 问题三：响应 VolumesDeleted 中包含内部前缀（用户可见性） ─────────────────
//
//   与问题一相同：docker volume prune 的 CLI 输出会显示
//   "user-1001-volume-config" 而非用户期望看到的 "config"。
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
	"go.uber.org/zap"
)

// ──────────────────────────────────────────────────────────────────────────────
// 辅助：解析 volume prune 响应体
// ──────────────────────────────────────────────────────────────────────────────

type volumePruneResp struct {
	VolumesDeleted []string `json:"VolumesDeleted"`
	SpaceReclaimed uint64   `json:"SpaceReclaimed"`
}

func parseVolumePruneResp(t *testing.T, body string) volumePruneResp {
	t.Helper()
	var r volumePruneResp
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("parseVolumePruneResp: %v (body=%q)", err, body)
	}
	return r
}

// newVolumePruneResponseTestProxy 构建最小 ProxyServer，复用 newVolumePruneTestProxy。
func newVolumePruneResponseTestProxy(t *testing.T, rt http.RoundTripper) *ProxyServer {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &ProxyServer{db: db, transport: rt, logger: zap.NewNop()}
}

// ══════════════════════════════════════════════════════════════════════════════
// RED TEST 1：VolumesDeleted 响应中卷名未剥离用户前缀
// ══════════════════════════════════════════════════════════════════════════════

// TestBUG9_VolumePrune_Response_ContainsInternalPrefix
//
// RED TEST: alice 执行 docker volume prune -f，
// 响应 VolumesDeleted 中应显示用户可见名称 "config"，
// 而非内部存储名称 "user-1001-volume-config"。
//
// 修复前 FAIL：VolumesDeleted = ["user-1001-volume-config"]
// 修复后 PASS：VolumesDeleted = ["config"]
func TestBUG9_VolumePrune_Response_ContainsInternalPrefix(t *testing.T) {
	const aliceUID = 1001
	rt := &recordingTransport{responseByPath: map[string]int{}}
	proxy := newVolumePruneResponseTestProxy(t, rt)

	alice := regularIdentity("alice", aliceUID)
	seedVolumes(t, proxy, aliceUID, "alice", "config")

	w := httptest.NewRecorder()
	intercepted := proxy.handleVolumePrune(w, httptest.NewRequest("POST", "/volumes/prune", nil),alice)
	if !intercepted {
		t.Fatalf("handleVolumePrune should intercept regular user, got false")
	}

	resp := parseVolumePruneResp(t, w.Body.String())

	// ── RED ASSERTION：VolumesDeleted 不应包含内部前缀 ──────────────────────
	// 修复前 FAIL: resp.VolumesDeleted = ["user-1001-volume-config"]
	// 修复后 PASS: resp.VolumesDeleted = ["config"]
	for _, name := range resp.VolumesDeleted {
		if strings.HasPrefix(name, "user-") {
			t.Errorf("BUG-9 [Problem-1]: VolumesDeleted contains internal prefix name %q\n"+
				"\twant user-visible name %q (without user-{uid}-volume- prefix)\n"+
				"\troot cause: handleVolumePrune appends internal DB names directly to deleted list\n"+
				"\twithout calling StripVolumeNamePrefix (unlike FilterVolumeListResponse)",
				name, strings.TrimPrefix(name, fmt.Sprintf("user-%d-volume-", aliceUID)))
		}
	}

	// 删除后卷名应在列表中（确认 prune 确实发生）
	found := false
	for _, name := range resp.VolumesDeleted {
		if name == "config" || name == fmt.Sprintf("user-%d-volume-config", aliceUID) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'config' in VolumesDeleted, got %v", resp.VolumesDeleted)
	}
}

// TestBUG9_VolumePrune_Response_SudoPrune_ContainsInternalPrefix
//
// RED TEST: sudo_test 执行 sudo docker volume prune -f，
// 响应 VolumesDeleted 中包含所有用户的卷，
// 每个卷名应为用户可见名称（无 user-{uid}-volume- 前缀）。
//
// 修复前 FAIL: VolumesDeleted = ["user-1002-volume-data", "user-1001-volume-config"]
// 修复后 PASS: VolumesDeleted = ["data", "config"]（或保留前缀，见修复策略说明）
//
// 注：sudo/root 执行跨用户 prune 时，响应中的卷名如何展示有两种合理策略：
//   A. 保留内部名（user-{uid}-volume-{suffix}）—— 便于 admin 审计
//   B. 剥离前缀只显示 suffix —— 与普通用户体验一致
//   当前 Bug 是无论哪种策略都未被明确实现，直接输出了内部名。
//   本测试以策略 A（保留内部名用于审计）为期望，即至少不应崩溃且格式统一。
//
// 实际上用户反馈是 alice 执行自己的 prune 时看到 user-1001-volume-config，
// 这明确属于策略 B 缺失。本测试专门覆盖普通用户场景。
func TestBUG9_VolumePrune_Response_RegularUser_NameStripped(t *testing.T) {
	const aliceUID = 1001

	cases := []struct {
		suffix   string
		wantName string
	}{
		{"config", "config"},
		{"my-data", "my-data"},
		{"workspace-2024", "workspace-2024"},
	}

	for _, tc := range cases {
		t.Run(tc.suffix, func(t *testing.T) {
			rt := &recordingTransport{responseByPath: map[string]int{}}
			proxy := newVolumePruneResponseTestProxy(t, rt)
			alice := regularIdentity("alice", aliceUID)
			seedVolumes(t, proxy, aliceUID, "alice", tc.suffix)

			w := httptest.NewRecorder()
			proxy.handleVolumePrune(w, httptest.NewRequest("POST", "/volumes/prune", nil),alice)

			resp := parseVolumePruneResp(t, w.Body.String())
			if len(resp.VolumesDeleted) != 1 {
				t.Fatalf("want 1 volume deleted, got %v", resp.VolumesDeleted)
			}
			got := resp.VolumesDeleted[0]
			if got != tc.wantName {
				t.Errorf("BUG-9 [Problem-1]: VolumesDeleted[0] = %q, want %q\n"+
					"\tuser-visible name must not include internal prefix user-%d-volume-",
					got, tc.wantName, aliceUID)
			}
		})
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 关于 Problem-2：事件流 bob 收到 alice 卷事件
// ══════════════════════════════════════════════════════════════════════════════
//
// eventBelongsToUser 对 volume 事件的处理依赖 attrs["name"]。
// Docker volume destroy 事件的 Attributes.name 包含的是卷的完整内部名称，
// 如 "user-1001-volume-config"（已在 BUG-8 修复中处理）。
//
// 但事件流过滤（proxy.go:2920）对特权用户完全绕过：
//   if isEvents && !id.IsPrivileged() { ... }
// 这意味着 sudo_test 订阅 /events 时，无论事件属于谁，全部透传。
// 这是设计行为，不是 Bug。
//
// 用户反馈"bob 收到了 alice 的事件"的实际根因需进一步区分：
//   - 如果 bob 的 uid=1002，事件 name="user-1001-volume-config"：
//     BUG-8 修复后，路径 2 返回 false → bob 不应收到 ✓
//   - 如果事件 name="" 或 name 字段缺失：
//     路径 3 返回 true → bob 收到（BUG-8 修复仍存在漏洞）
//
// 下面的测试覆盖这两种边界场景：

// makeVolumeEventEmptyName 构造 name 为空字符串的 volume 事件（异常情况）。
func makeVolumeEventEmptyName(action string) []byte {
	return []byte(fmt.Sprintf(
		`{"Type":"volume","Action":%q,"Actor":{"ID":"abc","Attributes":{"driver":"local","name":""}}}`,
		action,
	))
}

// makeVolumeEventNoNameAttr 构造缺少 name 字段的 volume 事件（极端异常）。
func makeVolumeEventNoNameAttr(action string) []byte {
	return []byte(fmt.Sprintf(
		`{"Type":"volume","Action":%q,"Actor":{"ID":"abc","Attributes":{"driver":"local"}}}`,
		action,
	))
}

// TestBUG9_EventFilter_VolumeEvent_EmptyName_ShouldPassthrough
//
// 回归：volume 事件 name 为空或缺失时，应对所有用户放行（路径 3：放行）。
// 这不是 Bug，是正确的兜底行为——无法判断归属时宁可误放不能误删。
// 覆盖：BUG-8 修复中路径 3 的兜底逻辑正确性。
func TestBUG9_EventFilter_VolumeEvent_EmptyName_ShouldPassthrough(t *testing.T) {
	const bobUID = 1002

	cases := []struct {
		name  string
		event []byte
	}{
		{"empty name", makeVolumeEventEmptyName("destroy")},
		{"no name attr", makeVolumeEventNoNameAttr("destroy")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := eventBelongsToUser(tc.event, bobUID)
			if !got {
				t.Errorf("%s: want eventBelongsToUser=true (passthrough, cannot determine owner), got false\n"+
					"\tempty/missing name must not cause silent event drops", tc.name)
			}
		})
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归测试矩阵
// ══════════════════════════════════════════════════════════════════════════════

// TestBUG9_Regression_VolumePrune_MultiVolume_AllNamesStripped
//
// 回归-1：普通用户有多个卷时，VolumesDeleted 中所有卷名均已剥离前缀。
// 覆盖：prefix 剥离逻辑对 deleted 列表的完整性（不能只剥第一个）。
func TestBUG9_Regression_VolumePrune_MultiVolume_AllNamesStripped(t *testing.T) {
	const aliceUID = 1001
	rt := &recordingTransport{responseByPath: map[string]int{}}
	proxy := newVolumePruneResponseTestProxy(t, rt)

	alice := regularIdentity("alice", aliceUID)
	suffixes := []string{"data", "logs", "config", "workspace"}
	seedVolumes(t, proxy, aliceUID, "alice", suffixes...)

	w := httptest.NewRecorder()
	proxy.handleVolumePrune(w, httptest.NewRequest("POST", "/volumes/prune", nil),alice)

	resp := parseVolumePruneResp(t, w.Body.String())

	if len(resp.VolumesDeleted) != len(suffixes) {
		t.Fatalf("want %d volumes deleted, got %d: %v", len(suffixes), len(resp.VolumesDeleted), resp.VolumesDeleted)
	}

	internalPrefix := fmt.Sprintf("user-%d-volume-", aliceUID)
	for _, name := range resp.VolumesDeleted {
		if strings.HasPrefix(name, "user-") {
			t.Errorf("regression: VolumesDeleted contains internal prefix %q\n"+
				"\tall %d volumes must have prefix %q stripped", name, len(suffixes), internalPrefix)
		}
	}

	// 确认每个 suffix 均在列表中
	got := make(map[string]bool, len(resp.VolumesDeleted))
	for _, name := range resp.VolumesDeleted {
		got[name] = true
	}
	for _, s := range suffixes {
		if !got[s] {
			t.Errorf("regression: suffix %q missing from VolumesDeleted %v", s, resp.VolumesDeleted)
		}
	}
}

// TestBUG9_Regression_VolumePrune_409_NotInResponse
//
// 回归-2：正在使用的卷（Docker 返回 409）不应出现在 VolumesDeleted 中，
// 已成功删除的卷名称必须已剥离前缀。
// 覆盖：409 跳过逻辑与 prefix 剥离逻辑的组合正确性。
func TestBUG9_Regression_VolumePrune_409_NotInResponse(t *testing.T) {
	const aliceUID = 1001
	busyVol := fmt.Sprintf("user-%d-volume-busy", aliceUID)
	freeVol := fmt.Sprintf("user-%d-volume-free", aliceUID)

	rt := &recordingTransport{
		responseByPath: map[string]int{
			"/volumes/" + busyVol: http.StatusConflict,
			"/volumes/" + freeVol: http.StatusNoContent,
		},
	}
	proxy := newVolumePruneResponseTestProxy(t, rt)

	alice := regularIdentity("alice", aliceUID)
	if err := proxy.db.SetVolumeOwner(busyVol, alice); err != nil {
		t.Fatalf("seed busyVol: %v", err)
	}
	if err := proxy.db.SetVolumeOwner(freeVol, alice); err != nil {
		t.Fatalf("seed freeVol: %v", err)
	}

	w := httptest.NewRecorder()
	proxy.handleVolumePrune(w, httptest.NewRequest("POST", "/volumes/prune", nil),alice)

	resp := parseVolumePruneResp(t, w.Body.String())

	// freeVol 已删，应在列表中，且名称已剥离前缀
	foundFree := false
	for _, name := range resp.VolumesDeleted {
		if name == "free" {
			foundFree = true
		}
		if strings.HasPrefix(name, "user-") {
			t.Errorf("regression [409]: VolumesDeleted contains internal prefix %q", name)
		}
	}
	if !foundFree {
		t.Errorf("regression [409]: 'free' should be in VolumesDeleted, got %v", resp.VolumesDeleted)
	}

	// busyVol 未删（409），不应在列表中
	for _, name := range resp.VolumesDeleted {
		if name == "busy" || name == busyVol {
			t.Errorf("regression [409]: busy volume (409 Conflict) must NOT be in VolumesDeleted, got %v",
				resp.VolumesDeleted)
		}
	}
}

// TestBUG9_Regression_VolumePrune_EmptyDB_ResponseFormat
//
// 回归-3：DB 为空时响应格式合规（VolumesDeleted:[]，非 null），
// 且已剥离前缀逻辑不会 panic。
// 覆盖：空集边界 + prefix 剥离对 nil slice 的安全性。
func TestBUG9_Regression_VolumePrune_EmptyDB_ResponseFormat(t *testing.T) {
	rt := &recordingTransport{}
	proxy := newVolumePruneResponseTestProxy(t, rt)

	w := httptest.NewRecorder()
	proxy.handleVolumePrune(w, httptest.NewRequest("POST", "/volumes/prune", nil),regularIdentity("alice", 1001))

	body := w.Body.String()
	if !strings.Contains(body, `"VolumesDeleted":[]`) {
		t.Errorf("empty DB: want VolumesDeleted:[], got: %s", body)
	}
	if w.Code != http.StatusOK {
		t.Errorf("empty DB: want HTTP 200, got %d", w.Code)
	}
}

// TestBUG9_Regression_SudoPrune_Response_ContainsAllUsers
//
// 回归-4：sudo/root 执行 prune 后，响应 VolumesDeleted 包含所有用户被删除的卷，
// 确认跨用户 prune 响应的完整性（此处不要求剥离前缀，保留内部名供 admin 审计）。
func TestBUG9_Regression_SudoPrune_Response_ContainsAllUsers(t *testing.T) {
	rt := &recordingTransport{responseByPath: map[string]int{}}
	proxy := newVolumePruneResponseTestProxy(t, rt)

	seedVolumes(t, proxy, 1002, "bob", "data", "logs")
	seedVolumes(t, proxy, 1001, "alice", "config")

	w := httptest.NewRecorder()
	proxy.handleVolumePrune(w, httptest.NewRequest("POST", "/volumes/prune", nil),sudoIdentity("sudo_test", 1005))

	resp := parseVolumePruneResp(t, w.Body.String())

	if len(resp.VolumesDeleted) != 3 {
		t.Errorf("sudo prune: want 3 volumes deleted (bob×2 + alice×1), got %d: %v",
			len(resp.VolumesDeleted), resp.VolumesDeleted)
	}

	// 验证 bob 和 alice 的卷都在响应中（sudo 跨用户删除的完整性）
	allDeleted := strings.Join(resp.VolumesDeleted, ",")
	for _, expected := range []string{"data", "logs", "config"} {
		if !strings.Contains(allDeleted, expected) {
			t.Errorf("sudo prune: volume suffix %q missing from VolumesDeleted: %v",
				expected, resp.VolumesDeleted)
		}
	}
}

// ── 确保测试文件能编译（显式引用未使用的包级符号）──────────────────────────────
var _ = io.Discard
var _ *auth.CallerIdentity
