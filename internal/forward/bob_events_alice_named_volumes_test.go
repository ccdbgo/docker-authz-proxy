package forward

// ══════════════════════════════════════════════════════════════════════════════
// 场景复现与回归测试：alice volume prune 后 bob 的事件流隔离
//
// ──── Bug 报告场景 ──────────────────────────────────────────────────────────
//
//   · alice(uid=1001) 拥有卷：data1-alice, data2-alice
//   · bob(uid=1002)   拥有卷：data1-bob
//   · bob  先执行 docker system events
//   · alice 后执行 docker volume prune -f
//   · 期望：bob 的事件流中 不含 alice 的任何卷删除事件
//   · 实际：bob 收到了 alice 两个卷的 volume destroy 事件（隔离失效）
//
// ──── 根本原因 ──────────────────────────────────────────────────────────────
//
//   alice 执行 docker volume prune -f 时：
//     handleVolumePrune → 从 DB 查询 alice 的具名卷
//     → 逐个调用 DELETE /volumes/user-1001-volume-data1-alice
//     → DELETE /volumes/user-1001-volume-data2-alice
//     → Docker 对每次删除产生 volume destroy 事件（Attributes 仅含 driver/name）
//
//   bob 执行 docker system events 时，proxy 逐行读上游事件流并调用：
//     eventBelongsToUser(line, bobUID=1002)
//
//   [修复前] eventBelongsToUser 缺少 volume 分支：
//     Docker volume API 无法在 Attributes 中携带自定义 owner 标签。
//     故 volume destroy 事件既无 system.authz.owner.uid，也无 user_id。
//     → 走到末尾兜底逻辑 return true（视为系统事件，所有用户可见）
//     → alice 的卷删除事件全部写入 bob 的响应体
//
//   [修复后] proxy.go:1906-1924 增加 volume 分支：
//     卷名 user-1001-volume-data1-alice 的 uid 段 1001 ≠ bob uid 1002
//     → return false（路径2：格式合法，属于其他用户）→ 事件被过滤
//
// ──── 测试文件职责 ──────────────────────────────────────────────────────────
//
//   现有测试（event_filter_volume_isolation_test.go / event_stream_integration_test.go /
//   alice_prune_bob_events_test.go）使用泛型卷名（config/data/workspace）验证过滤逻辑。
//
//   本文件使用 Bug 报告中的原始卷名（data1-alice / data2-alice / data1-bob），
//   验证实际报告场景下的完整隔离链路，并覆盖以下额外边界：
//     1. alice 两个卷的独立隔离（data1-alice 和 data2-alice 分别被过滤）
//     2. bob 自己的 data1-bob 在 alice prune 后仍然可见（不被误过滤）
//     3. 对称隔离：alice 的事件流中不含 bob 的卷删除事件
//     4. 与 alice prune 端到端因果链的完整集成验证
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ──────────────────────────────────────────────────────────────────────────────
// 场景常量（与 Bug 报告一一对应）
// ──────────────────────────────────────────────────────────────────────────────

const (
	aliceUID2 = 1001 // alice 的 Real UID（避免与其他测试文件中的 aliceUID 重定义冲突）
	bobUID2   = 1002 // bob 的 Real UID
)

// 内部卷名：user-{uid}-volume-{user-facing-suffix}
// 与 InjectVolumeNamePrefix / handleVolumePrune 使用的命名方案完全一致。
var (
	aliceVol1 = fmt.Sprintf("user-%d-volume-data1-alice", aliceUID2) // "user-1001-volume-data1-alice"
	aliceVol2 = fmt.Sprintf("user-%d-volume-data2-alice", aliceUID2) // "user-1001-volume-data2-alice"
	bobVol1   = fmt.Sprintf("user-%d-volume-data1-bob", bobUID2)     // "user-1002-volume-data1-bob"
)

// ══════════════════════════════════════════════════════════════════════════════
// RED TEST：Bug 复现
// ══════════════════════════════════════════════════════════════════════════════

// TestBug_BobEvents_SeeAliceNamedVolumePrune
//
// RED TEST：修复前必须 100% 失败。
//
// 精确复现 Bug 报告场景：
//
//	alice(uid=1001) 拥有 data1-alice, data2-alice
//	bob(uid=1002)   拥有 data1-bob
//	alice 执行 docker volume prune -f → Docker 产生 destroy 事件
//	bob 的 docker system events 不应收到任何 alice 的卷删除事件
//
// 失败路径（修复前）：
//
//	eventBelongsToUser(aliceEvent, bobUID) == true
//	  ↑ volume 分支缺失 → 无 owner 标签 → return true（系统事件透传）
//	→ alice 的 data1-alice / data2-alice destroy 事件写入 bob 的响应体
//
// 通过路径（修复后 proxy.go:1906-1924）：
//
//	ev.Type == "volume"
//	  名称 user-1001-volume-data1-alice 不以 user-1002-volume- 开头 → 路径1 false
//	  但以 user- 开头且 uid 段合法（1001）→ 路径2 return false（隔离）
func TestBug_BobEvents_SeeAliceNamedVolumePrune(t *testing.T) {
	// ── RED ASSERTION A：bob 不应收到 alice 的 data1-alice 卷删除事件 ─────
	// 修复前 FAIL: eventBelongsToUser(aliceVol1Event, bobUID) == true
	// 修复后 PASS: uid 段 1001 ≠ 1002 → return false
	aliceVol1Event := makeVolumeEventWithAction("destroy", aliceVol1)
	if eventBelongsToUser(aliceVol1Event, bobUID2) {
		t.Errorf(
			"BUG [bob events → alice prune]:\n"+
				"\tbob(uid=%d) 收到了 alice(uid=%d) 的卷删除事件\n"+
				"\t泄漏卷名: %q（用户呈现名: data1-alice）\n"+
				"\t根因: eventBelongsToUser volume 分支缺失 → return true（系统事件透传）\n"+
				"\tDocker volume Attributes 仅含 {driver, name}，无 system.authz.owner.uid 标签\n"+
				"\t修复: proxy.go 增加 volume 分支，按卷名前缀 user-{uid}-volume-* 判断归属",
			bobUID2, aliceUID2, aliceVol1,
		)
	}

	// ── RED ASSERTION B：bob 不应收到 alice 的 data2-alice 卷删除事件 ─────
	// 修复前 FAIL: 同上根因，两个卷均泄漏
	// 修复后 PASS: user-1001-volume-data2-alice → uid 段 1001 ≠ 1002 → false
	aliceVol2Event := makeVolumeEventWithAction("destroy", aliceVol2)
	if eventBelongsToUser(aliceVol2Event, bobUID2) {
		t.Errorf(
			"BUG [bob events → alice prune]:\n"+
				"\tbob(uid=%d) 收到了 alice(uid=%d) 的卷删除事件\n"+
				"\t泄漏卷名: %q（用户呈现名: data2-alice）\n"+
				"\t根因: 与 data1-alice 相同，volume 分支缺失导致所有 alice 的卷事件均泄漏",
			bobUID2, aliceUID2, aliceVol2,
		)
	}

	// ── 正向断言（不被修复破坏）：bob 本人的 data1-bob 必须对 bob 可见 ────
	bobVol1Event := makeVolumeEventWithAction("destroy", bobVol1)
	if !eventBelongsToUser(bobVol1Event, bobUID2) {
		t.Errorf(
			"回归断言失败: bob(uid=%d) 应收到自己的卷删除事件\n"+
				"\t卷名: %q（用户呈现名: data1-bob）\n"+
				"\t修复后不能误过滤 owner 本人的卷事件",
			bobUID2, bobVol1,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归测试矩阵（4 个）
// ══════════════════════════════════════════════════════════════════════════════

// TestReg1_BobOwnVolume_data1bob_AlwaysVisible
//
// 回归-1：bob 的 data1-bob 卷在 alice volume prune 后仍然能在 bob 的事件流中看到。
//
// 覆盖：修复 alice→bob 隔离的同时，不能误过滤 bob 自己的卷删除事件。
// 场景：bob 自己也执行了 volume prune，data1-bob 被删除产生 destroy 事件，
// 该事件必须在 bob 的事件订阅中可见。
func TestReg1_BobOwnVolume_data1bob_AlwaysVisible(t *testing.T) {
	// alice 的事件（用来验证 bob 的事件流中没有干扰）
	aliceEvents := []string{
		makeRawVolumeDestroyEvent(aliceVol1),
		makeRawVolumeDestroyEvent(aliceVol2),
	}
	// bob 自己的事件
	bobEvent := makeRawVolumeDestroyEvent(bobVol1)
	allEvents := append(aliceEvents, bobEvent)

	upstream := fakeDockerEventsServer(allEvents)
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest("GET", "/events?type=volume", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID2))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)
	body := rw.Body.String()

	// bob 的 data1-bob 事件必须到达（不被误过滤）
	if !strings.Contains(body, bobVol1) {
		t.Errorf(
			"回归-1: bob(uid=%d) 应收到自己的卷删除事件\n"+
				"\t内部卷名: %q（用户名: data1-bob）\n"+
				"\t但响应体中缺失 → 修复误过滤了 bob 自己的 volume 事件\n"+
				"\t响应体: %s",
			bobUID2, bobVol1, body,
		)
	}

	// alice 的事件不应到达 bob（确认隔离有效，不误开放）
	for _, aliceVol := range []string{aliceVol1, aliceVol2} {
		if strings.Contains(body, aliceVol) {
			t.Errorf(
				"回归-1: bob(uid=%d) 不应收到 alice(uid=%d) 的卷事件\n"+
					"\t内部卷名: %q\n"+
					"\t响应体: %s",
				bobUID2, aliceUID2, aliceVol, body,
			)
		}
	}
}

// TestReg2_BothAliceVolumes_IndependentlyHiddenFromBob
//
// 回归-2：alice 的 data1-alice 和 data2-alice 两个卷的事件均独立被过滤，
// 不依赖于同一事件流中是否存在其他卷。
//
// 覆盖：修复时不能只对第一个 alice 卷生效，每个卷的事件必须独立地被过滤。
// 若过滤逻辑依赖全局状态（如"只要有 alice 卷就全不过滤"），则本测试会捕获该回归。
func TestReg2_BothAliceVolumes_IndependentlyHiddenFromBob(t *testing.T) {
	cases := []struct {
		desc    string
		volName string
	}{
		{"data1-alice 单独发送时应被过滤", aliceVol1},
		{"data2-alice 单独发送时应被过滤", aliceVol2},
	}

	for _, tc := range cases {
		tc := tc // 捕获循环变量
		t.Run(tc.desc, func(t *testing.T) {
			// 每次只发送一个 alice 的卷事件（排除批量过滤的假阳性）
			upstream := fakeDockerEventsServer([]string{
				makeRawVolumeDestroyEvent(tc.volName),
			})
			defer upstream.Close()

			p := newTestProxy(t, upstream, nil)
			req := httptest.NewRequest("GET", "/events?type=volume", nil)
			req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID2))
			rw := httptest.NewRecorder()
			p.ServeHTTP(rw, req)
			body := rw.Body.String()

			if strings.Contains(body, tc.volName) {
				t.Errorf(
					"回归-2 [独立过滤]: bob(uid=%d) 收到了 alice(uid=%d) 的卷事件\n"+
						"\t卷名: %q\n"+
						"\t该卷单独在事件流中时应独立被过滤，\n"+
						"\t修复不能依赖批量状态或其他卷的存在\n"+
						"\t响应体: %s",
					bobUID2, aliceUID2, tc.volName, body,
				)
			}
		})
	}
}

// TestReg3_SymmetricIsolation_AliceEventStream_HidesBobVolume
//
// 回归-3：对称性验证 —— alice 的事件流中不包含 bob 的 data1-bob 卷删除事件。
//
// 覆盖：修复只对"alice prune → bob events"方向生效是不够的；
// 反向（bob prune → alice events）也必须成立。
// 若 eventBelongsToUser 的 volume 分支只对 uid=1002（bob）构造判断，
// 而对 uid=1001（alice）遗漏，则本测试会捕获该不对称回归。
func TestReg3_SymmetricIsolation_AliceEventStream_HidesBobVolume(t *testing.T) {
	// 事件流：bob 的卷被删除 + alice 自己的卷被删除
	aliceOwnEvent := makeRawVolumeDestroyEvent(aliceVol1)
	bobEvent := makeRawVolumeDestroyEvent(bobVol1)

	upstream := fakeDockerEventsServer([]string{bobEvent, aliceOwnEvent})
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest("GET", "/events?type=volume", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", aliceUID2))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)
	body := rw.Body.String()

	// ── 对称隔离断言：alice 不应收到 bob 的 data1-bob 事件 ───────────────
	if strings.Contains(body, bobVol1) {
		t.Errorf(
			"回归-3 [对称隔离]: alice(uid=%d) 收到了 bob(uid=%d) 的卷删除事件\n"+
				"\t内部卷名: %q（用户名: data1-bob）\n"+
				"\t隔离必须双向对称，bob→alice 方向也必须被过滤\n"+
				"\t响应体: %s",
			aliceUID2, bobUID2, bobVol1, body,
		)
	}

	// alice 自己的 data1-alice 事件必须在 alice 的事件流中可见
	if !strings.Contains(body, aliceVol1) {
		t.Errorf(
			"回归-3: alice(uid=%d) 应收到自己的卷删除事件\n"+
				"\t内部卷名: %q（用户名: data1-alice）\n"+
				"\t修复不能误过滤 alice 自己的 volume 事件\n"+
				"\t响应体: %s",
			aliceUID2, aliceVol1, body,
		)
	}
}

// TestReg4_AliceNamedVolumePrune_BobEvents_EndToEnd
//
// 回归-4：端到端集成测试（有状态 fake Docker），验证因果链完整性：
//
//	alice POST /volumes/prune → proxy handleVolumePrune → DELETE 各卷（fake Docker 记录）
//	→ bob GET /events → fake Docker 返回已被 DELETE 的卷的 destroy 事件
//	→ proxy eventBelongsToUser 过滤 → bob 响应体不含任何 alice 的卷名
//
// 与单元测试的区别：此测试验证 handleVolumePrune 的卷名格式（user-1001-volume-data1-alice）
// 与 eventBelongsToUser 的过滤模式在真实 HTTP 路径下严格一致。
// 若 handleVolumePrune 改变卷名格式但过滤规则未同步，本测试会捕获该静默失效。
func TestReg4_AliceNamedVolumePrune_BobEvents_EndToEnd(t *testing.T) {
	// 有状态 fake Docker：记录 DELETE → GET /events 返回对应的 destroy 事件（因果链）
	fakeDocker, _ := newStatefulFakeDocker(t)

	p := newTestProxy(t, fakeDocker, nil)
	aliceID := regularIdentity("alice", aliceUID2)

	// 预置 alice 的两个具名卷到 DB
	for _, v := range []string{aliceVol1, aliceVol2} {
		if err := p.db.SetVolumeOwner(v, aliceID); err != nil {
			t.Fatalf("SetVolumeOwner(%q): %v", v, err)
		}
	}

	// ── Step 1：alice 执行 docker volume prune -f ────────────────────────
	pruneReq := httptest.NewRequest("POST", "/volumes/prune", nil)
	pruneReq = injectIdentity(pruneReq, aliceID)
	pruneRW := httptest.NewRecorder()
	p.ServeHTTP(pruneRW, pruneReq)

	if pruneRW.Code != http.StatusOK {
		t.Fatalf("alice POST /volumes/prune: status = %d, want 200\nbody: %s",
			pruneRW.Code, pruneRW.Body.String())
	}

	// 验证 prune 响应中用户呈现名已剥离内部前缀（user-1001-volume-）
	var pruneResp struct {
		VolumesDeleted []string `json:"VolumesDeleted"`
	}
	if err := json.Unmarshal(pruneRW.Body.Bytes(), &pruneResp); err != nil {
		t.Fatalf("decode prune response: %v\nbody: %s", err, pruneRW.Body.String())
	}
	if len(pruneResp.VolumesDeleted) != 2 {
		t.Fatalf("alice prune: want 2 volumes deleted, got %d: %v",
			len(pruneResp.VolumesDeleted), pruneResp.VolumesDeleted)
	}
	wantUserFacing := map[string]bool{"data1-alice": true, "data2-alice": true}
	for _, name := range pruneResp.VolumesDeleted {
		if strings.HasPrefix(name, "user-") {
			t.Errorf("prune 响应含内部前缀卷名 %q：普通用户响应应已剥离 user-%%d-volume- 前缀", name)
		}
		if !wantUserFacing[name] {
			t.Errorf("prune 响应含意外卷名 %q，期望 {data1-alice, data2-alice}", name)
		}
	}

	// ── Step 2：bob 执行 docker system events ────────────────────────────
	// 此时 statefulFakeDocker 已记录 alice 删除的 2 个卷，GET /events 返回对应事件。
	// proxy 的 eventBelongsToUser 应将这 2 个事件过滤掉，bob 响应体为空。
	eventsReq := httptest.NewRequest("GET", "/events?type=volume", nil)
	eventsReq = injectIdentity(eventsReq, makeTestIdentityProxy("bob", bobUID2))
	eventsRW := httptest.NewRecorder()
	p.ServeHTTP(eventsRW, eventsReq)

	body := eventsRW.Body.String()

	// ── 端到端隔离断言（核心）────────────────────────────────────────────
	// 修复前 FAIL: eventBelongsToUser volume 分支缺失 → return true → 两个 alice 卷均泄漏
	// 修复后 PASS: volume 分支 uid 段匹配 → user-1001-* ≠ user-1002-* → return false
	for _, v := range []string{aliceVol1, aliceVol2} {
		if strings.Contains(body, v) {
			t.Errorf(
				"回归-4 [端到端]: bob(uid=%d) 收到了 alice(uid=%d) 的卷删除事件\n"+
					"\t内部卷名: %q\n"+
					"\t因果链: alice prune DELETE /volumes/%s → fake Docker 记录 → \n"+
					"\t         bob GET /events → proxy 应过滤此事件\n"+
					"\t根因: eventBelongsToUser 无 volume 分支 → return true（修复前）\n"+
					"\tbob 响应体: %s",
				bobUID2, aliceUID2, v, v, body,
			)
		}
	}
}
