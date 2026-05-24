package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG 复现 + 回归测试矩阵
// 场景：alice 执行 docker volume prune -f，bob 执行 docker system events
//
// ──── 根本原因 ─────────────────────────────────────────────────────────────────
//
//   alice: POST /volumes/prune
//     → proxy.handleVolumePrune() 从 DB 取出 alice 的具名卷
//     → 逐个调用 DELETE /volumes/user-1001-volume-{suffix}（通过 p.transport）
//     → Docker 对每次删除产生 volume destroy 事件：
//         {"Type":"volume","Actor":{"Attributes":{"driver":"local","name":"user-1001-volume-config"}}}
//
//   bob: GET /events
//     → proxy 的 flusher 分支逐行读取 Docker 上游事件流
//     → eventBelongsToUser(line, bobUID=1002)
//         [旧代码] ev.Type=="volume" 无专门分支 → return true（系统事件透传）
//         → bob 收到 alice 的卷删除事件 ← 隔离失效
//
//   [新代码] proxy.go:1906-1924 增加 volume 事件的名称前缀分支：
//       user-1001-volume-config 的 uid 段 1001 ≠ bob uid 1002 → return false
//       → 事件被正确过滤，bob 的事件流中不含 alice 的卷名
//
// ──── 测试盲区（本文件填补）──────────────────────────────────────────────────
//
//   现有测试（event_stream_integration_test.go）用预制事件流验证 eventBelongsToUser
//   过滤，但未覆盖：
//     1. alice 的 POST /volumes/prune 触发路径（handleVolumePrune 生成的卷名格式）
//        与 eventBelongsToUser 的匹配模式是否严格一致
//     2. 同一 ProxyServer 实例同时处理"prune 请求 + 事件订阅"的端到端协调
//   若两侧的名称格式发生分离（如 UserVolumePrefix 变更但过滤规则未更新），
//   隔离将静默失效，而现有测试不会感知到该变化。
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"docker-authz-proxy/internal/isolation"
)

// ──────────────────────────────────────────────────────────────────────────────
// 辅助：有状态 fake Docker，建立 prune → events 的真实因果链
// ──────────────────────────────────────────────────────────────────────────────

// statefulFakeDocker 记录被 DELETE 的卷名，GET /events 只返回对应被删卷的 destroy 事件。
// 这建立了"alice prune DELETE /volumes/X → GET /events 返回 X 的 destroy 事件"的因果链，
// 而非旧设计中静态预置、与 prune 请求完全无关的事件流。
//
// default 路由返回 500（而非 200），使 handleVolumePrune 意外转发 POST /volumes/prune
// 时测试立即失败，而非静默通过。
type statefulFakeDocker struct {
	mu      sync.Mutex
	deleted []string // 被 DELETE 请求删除的卷名（按顺序记录）
}

func (s *statefulFakeDocker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/volumes/"):
		volName := strings.TrimPrefix(r.URL.Path, "/volumes/")
		s.mu.Lock()
		s.deleted = append(s.deleted, volName)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)

	case strings.Contains(r.URL.Path, "/events"):
		// 只返回已被 DELETE 的卷的 destroy 事件（快照），与 prune 强耦合
		s.mu.Lock()
		snap := append([]string(nil), s.deleted...)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		// 不设 Content-Length → isStreaming=true，proxy 走 flusher 逐行分支
		flusher, ok := w.(http.Flusher)
		for _, v := range snap {
			fmt.Fprintln(w, makeRawVolumeDestroyEvent(v)) // 复用同包已有辅助函数
			if ok {
				flusher.Flush()
			}
		}

	default:
		// 故意返回 500：若 handleVolumePrune 意外将 POST /volumes/prune 转发到此，
		// 测试会立即失败，而非静默通过（原设计返回 200 会掩盖此类回归）。
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// newStatefulFakeDocker 构造 statefulFakeDocker 并将 Close 注册到 t.Cleanup，
// 确保 httptest.Server 在测试结束后及时释放，避免 fd 积累。
func newStatefulFakeDocker(t *testing.T) (*httptest.Server, *statefulFakeDocker) {
	t.Helper()
	s := &statefulFakeDocker{}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return srv, s
}

// ══════════════════════════════════════════════════════════════════════════════
// RED TEST: BUG 复现 — alice volume prune 事件泄漏给 bob
// ══════════════════════════════════════════════════════════════════════════════

// TestAliceVolumePrune_EventsHiddenFromBob_EndToEnd
//
// RED TEST：在修复前，此测试 100% 失败。
//
// 因果链（有状态 fake Docker）：
//  1. 预置：alice(uid=1001) 拥有 3 个具名卷（DB 中已记录）
//  2. alice 执行 POST /volumes/prune → handleVolumePrune 逐个 DELETE 各卷
//     → statefulFakeDocker 记录被删卷名（3 次 DELETE 各记录一条）
//  3. bob(uid=1002) 执行 GET /events → statefulFakeDocker 仅返回已被 DELETE 的卷的 destroy 事件
//     → proxy 逐行过滤 → bob 响应体不含 alice 的卷名
//
// 与旧设计的区别：events 不再是静态预置，而是 DELETE 请求的直接产物，
// 真正验证 handleVolumePrune 卷名格式 → 事件格式 → eventBelongsToUser 过滤的完整链路。
//
// 修复前失败路径：
//   eventBelongsToUser 无 volume 分支 → return true
//   → alice 的 user-1001-volume-* 事件写入 bob 的响应体
//
// 修复后通过路径（proxy.go:1906-1924）：
//   volume 分支：名称前缀 user-1001-volume- ≠ user-1002-volume- → return false → 跳过
func TestAliceVolumePrune_EventsHiddenFromBob_EndToEnd(t *testing.T) {
	const aliceUID = 1001
	const bobUID = 1002

	// alice 的卷（内部格式：user-{uid}-volume-{suffix}，与 handleVolumePrune 一致）
	aliceVols := []string{
		fmt.Sprintf("user-%d-volume-config", aliceUID),
		fmt.Sprintf("user-%d-volume-data", aliceUID),
		fmt.Sprintf("user-%d-volume-cache", aliceUID),
	}

	// 有状态 fake Docker：记录 DELETE，GET /events 返回对应事件（Cleanup 已注册）
	fakeDocker, _ := newStatefulFakeDocker(t)

	// 构建代理，预置 alice 的卷到 DB
	p := newTestProxy(t, fakeDocker, nil)
	aliceID := regularIdentity("alice", aliceUID)
	for _, v := range aliceVols {
		if err := p.db.SetVolumeOwner(v, aliceID); err != nil {
			t.Fatalf("SetVolumeOwner(%q): %v", v, err)
		}
	}

	// ── Step 1: alice 执行 docker volume prune -f ──────────────────────────
	pruneReq := httptest.NewRequest("POST", "/volumes/prune", nil)
	pruneReq = injectIdentity(pruneReq, aliceID)
	pruneRW := httptest.NewRecorder()
	p.ServeHTTP(pruneRW, pruneReq)

	if pruneRW.Code != http.StatusOK {
		t.Fatalf("alice POST /volumes/prune: status = %d, want 200", pruneRW.Code)
	}

	// 验证 prune 成功（alice 的 3 个卷在响应中），并校验前缀已剥离
	var pruneResp struct {
		VolumesDeleted []string `json:"VolumesDeleted"`
	}
	if err := json.Unmarshal(pruneRW.Body.Bytes(), &pruneResp); err != nil {
		t.Fatalf("decode prune response: %v", err)
	}
	if len(pruneResp.VolumesDeleted) != 3 {
		t.Fatalf("alice prune: want 3 volumes deleted, got %d: %v",
			len(pruneResp.VolumesDeleted), pruneResp.VolumesDeleted)
	}
	// 普通用户响应中卷名必须已剥离 user-{uid}-volume- 内部前缀
	wantSuffixes := map[string]bool{"config": true, "data": true, "cache": true}
	for _, deleted := range pruneResp.VolumesDeleted {
		if strings.HasPrefix(deleted, "user-") {
			t.Errorf("prune response 含内部前缀卷名 %q：普通用户响应应已剥离 user-%%d-volume- 前缀", deleted)
		}
		if !wantSuffixes[deleted] {
			t.Errorf("prune response 含意外卷名 %q，期望 {config,data,cache}", deleted)
		}
	}

	// ── Step 2: bob 执行 docker system events ─────────────────────────────
	// 此时 statefulFakeDocker 已记录了 3 次 DELETE，GET /events 返回对应的 3 条 destroy 事件
	eventsReq := httptest.NewRequest("GET", "/events?type=volume", nil)
	eventsReq = injectIdentity(eventsReq, makeTestIdentityProxy("bob", bobUID))
	eventsRW := httptest.NewRecorder()
	p.ServeHTTP(eventsRW, eventsReq)

	body := eventsRW.Body.String()

	// ── RED ASSERTION: bob 不应收到 alice 任何一个卷的删除事件 ────────────
	// 修复前 FAIL: eventBelongsToUser 无 volume 分支 → return true → bob 可见
	// 修复后 PASS: 名称前缀 user-1001-volume-* ≠ user-1002-volume-* → false
	for _, v := range aliceVols {
		if strings.Contains(body, v) {
			t.Errorf("BUG [alice prune → bob events]: bob(uid=%d) 收到了 alice(uid=%d) 的卷删除事件\n"+
				"\t泄漏卷名: %q\n"+
				"\tbob 响应体: %s\n"+
				"\t根因: eventBelongsToUser 无 volume 分支 → 走 return true（系统事件透传）\n"+
				"\t修复: proxy.go 增加 volume 名称前缀分支 user-{uid}-volume-*",
				bobUID, aliceUID, v, body)
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归测试矩阵（4 个）
// ══════════════════════════════════════════════════════════════════════════════

// TestAlicePrune_VolumeName_FormatConsistency_WithEventFilter
//
// 回归-1：handleVolumePrune 使用的卷名格式必须与 eventBelongsToUser 过滤模式严格一致。
//
// 验证：isolation.UserVolumePrefix(uid) 生成的前缀格式
//
//	user-{uid}-volume-
//
// 与 eventBelongsToUser volume 分支的匹配逻辑
//
//	strings.HasPrefix(name, "user-"+uidStr+"-volume-")
//
// 在所有 uid 值下完全等价。
//
// 覆盖：防止 UserVolumePrefix 格式变更但 eventBelongsToUser 模式未同步更新，
// 导致 alice 删卷事件静默泄漏给所有用户。
//
// 注：uid=0 (root) 不通过用户卷命名方案管理卷，不在测试矩阵内，避免产生误导性绿灯。
func TestAlicePrune_VolumeName_FormatConsistency_WithEventFilter(t *testing.T) {
	testUIDs := []int{1001, 1002, 1003, 999, 65534}

	for _, uid := range testUIDs {
		prefix := isolation.UserVolumePrefix(uid)
		volName := prefix + "workspace"

		// 格式检查：必须以 user-{uid}-volume- 开头
		expectedPrefix := fmt.Sprintf("user-%d-volume-", uid)
		if prefix != expectedPrefix {
			t.Errorf("uid=%d: isolation.UserVolumePrefix()=%q, want %q\n"+
				"\tUserVolumePrefix 格式变更会导致 eventBelongsToUser 无法识别，隔离静默失效",
				uid, prefix, expectedPrefix)
		}

		// 卷名必须被 eventBelongsToUser 认定为属于 uid 本人
		event := []byte(fmt.Sprintf(
			`{"Type":"volume","Action":"destroy","Actor":{"ID":%q,"Attributes":{"driver":"local","name":%q}}}`,
			volName, volName,
		))
		if !eventBelongsToUser(event, uid) {
			t.Errorf("uid=%d: volume %q 由 UserVolumePrefix 生成，但 eventBelongsToUser 返回 false\n"+
				"\t说明两侧格式已分离，卷删除事件会被 owner 本人的事件流过滤掉（DoS 副作用）",
				uid, volName)
		}

		// 卷名不能被任何其他 uid 认领（抽查相邻 uid）
		for _, otherUID := range []int{uid + 1, uid - 1, uid + 1000} {
			if otherUID == uid || otherUID < 0 {
				continue
			}
			if eventBelongsToUser(event, otherUID) {
				t.Errorf("uid=%d 的卷 %q 被 otherUID=%d 认领（eventBelongsToUser=true）\n"+
					"\t隔离失效：其他用户可以看到此卷的事件",
					uid, volName, otherUID)
			}
		}
	}
}

// TestBobPrune_AliceEventsHidden_SymmetricIsolation
//
// 回归-2：互换 alice/bob 角色（bob 执行 prune，alice 监听 events），
// 验证隔离对称性：任意方向的跨用户卷事件均不泄漏。
//
// 覆盖：修复不能只对"alice → bob"方向生效，反向也必须成立。
//
// 注：本测试关注过滤结果，不需要 prune → events 的因果链，使用
// fakeDockerEventsServer（预制事件流）即可，无需 statefulFakeDocker。
func TestBobPrune_AliceEventsHidden_SymmetricIsolation(t *testing.T) {
	const aliceUID = 1001
	const bobUID = 1002

	bobVols := []string{
		fmt.Sprintf("user-%d-volume-model", bobUID),
		fmt.Sprintf("user-%d-volume-tmp", bobUID),
	}

	// 预制事件流：bob 的两个卷 + alice 自己的一个卷
	var events []string
	for _, v := range bobVols {
		events = append(events, makeRawVolumeDestroyEvent(v))
	}
	aliceOwnVol := fmt.Sprintf("user-%d-volume-scratch", aliceUID)
	events = append(events, makeRawVolumeDestroyEvent(aliceOwnVol))

	// fakeDockerEventsServer 已在 event_stream_integration_test.go 中定义（同包可直接复用）
	fakeDocker := fakeDockerEventsServer(events)
	defer fakeDocker.Close() // 非循环内的 defer，无资源积累问题

	p := newTestProxy(t, fakeDocker, nil)
	bobID := regularIdentity("bob", bobUID)
	for _, v := range bobVols {
		if err := p.db.SetVolumeOwner(v, bobID); err != nil {
			t.Fatalf("SetVolumeOwner(%q): %v", v, err)
		}
	}

	// bob 执行 prune
	pruneReq := httptest.NewRequest("POST", "/volumes/prune", nil)
	pruneReq = injectIdentity(pruneReq, bobID)
	pruneRW := httptest.NewRecorder()
	p.ServeHTTP(pruneRW, pruneReq)
	if pruneRW.Code != http.StatusOK {
		t.Fatalf("bob POST /volumes/prune: status = %d, want 200", pruneRW.Code)
	}

	// alice 监听 events
	eventsReq := httptest.NewRequest("GET", "/events?type=volume", nil)
	eventsReq = injectIdentity(eventsReq, makeTestIdentityProxy("alice", aliceUID))
	eventsRW := httptest.NewRecorder()
	p.ServeHTTP(eventsRW, eventsReq)

	body := eventsRW.Body.String()

	// ── 对称性断言 ─────────────────────────────────────────────────────────
	for _, v := range bobVols {
		if strings.Contains(body, v) {
			t.Errorf("回归-2 对称性: alice(uid=%d) 收到了 bob(uid=%d) 的卷删除事件 %q\n"+
				"\t修复必须对 bob→alice 方向同样生效",
				aliceUID, bobUID, v)
		}
	}

	// alice 本人的事件必须到达 alice
	if !strings.Contains(body, aliceOwnVol) {
		t.Errorf("回归-2: alice(uid=%d) 应收到自己的卷事件 %q，但响应体中缺失\n"+
			"\t修复后不能误过滤 owner 本人的 volume 事件\n\t响应体: %s",
			aliceUID, aliceOwnVol, body)
	}
}

// TestVolumePrune_ThreeUser_MutualIsolation
//
// 回归-3：三用户（alice/bob/charlie）互不可见对方的 prune 触发事件。
//
// 每个用户的事件流中：
//   - 自己的卷事件：必须出现
//   - 其他两人的卷事件：必须不出现
//
// 覆盖：不只测一对用户，确保任意 N 用户组合的隔离正确性。
func TestVolumePrune_ThreeUser_MutualIsolation(t *testing.T) {
	users := []struct {
		uid  int
		name string
	}{
		{1001, "alice"},
		{1002, "bob"},
		{1003, "charlie"},
	}

	// 为每个用户构造一个卷的 destroy 事件
	var events []string
	for _, u := range users {
		events = append(events, makeRawVolumeDestroyEvent(
			fmt.Sprintf("user-%d-volume-workspace", u.uid),
		))
	}

	for _, viewer := range users {
		viewer := viewer // 捕获循环变量，防止 Go 1.21 及以下版本的闭包陷阱
		// IIFE 将每次迭代的 httptest.Server + SQLite DB 限定在迭代作用域内，
		// 保证 defer Close() 在本次迭代结束时立即执行，不会在循环内积累 fd。
		func() {
			fakeDocker := fakeDockerEventsServer(events)
			defer fakeDocker.Close()

			p := newTestProxy(t, fakeDocker, nil)
			req := httptest.NewRequest("GET", "/events?type=volume", nil)
			req = injectIdentity(req, makeTestIdentityProxy(viewer.name, viewer.uid))
			rw := httptest.NewRecorder()
			p.ServeHTTP(rw, req)
			body := rw.Body.String()

			for _, owner := range users {
				volName := fmt.Sprintf("user-%d-volume-workspace", owner.uid)
				contains := strings.Contains(body, volName)
				shouldContain := owner.uid == viewer.uid

				if contains && !shouldContain {
					t.Errorf("回归-3 三用户: %s(uid=%d) 收到了 %s(uid=%d) 的卷事件 %q\n"+
						"\t任意用户对之间均不应存在事件泄漏",
						viewer.name, viewer.uid, owner.name, owner.uid, volName)
				}
				if !contains && shouldContain {
					t.Errorf("回归-3 三用户: %s(uid=%d) 未收到自己的卷事件 %q\n"+
						"\t修复不能误过滤 owner 本人的事件\n\t响应体: %s",
						viewer.name, viewer.uid, volName, body)
				}
			}
		}()
	}
}

// TestVolumePrune_NullAndEdgeCases_NoPanic
//
// 回归-4：边界条件与异常输入下 eventBelongsToUser 不崩溃、不误判。
//
// 覆盖：
//   - 空卷名（name=""）：非用户格式，透传（return true）
//   - user- 前缀但 uid 段非纯数字：非法格式，透传
//   - 大 uid 值（65534 等）：名称前缀仍能正确匹配
//   - 卷名与另一用户 uid 完全匹配（边界）：不泄漏
//   - 事件 JSON 格式异常：兜底 return true，不崩溃
func TestVolumePrune_NullAndEdgeCases_NoPanic(t *testing.T) {
	const bobUID = 1002

	t.Run("empty_volume_name_passthrough", func(t *testing.T) {
		event := []byte(`{"Type":"volume","Action":"destroy","Actor":{"ID":"","Attributes":{"driver":"local","name":""}}}`)
		// 空名不匹配任何用户前缀 → 路径3 透传，所有用户可见
		if !eventBelongsToUser(event, bobUID) {
			t.Error("空卷名（name=''）应透传，eventBelongsToUser 不应返回 false")
		}
	})

	t.Run("user_prefix_non_numeric_uid_passthrough", func(t *testing.T) {
		// "user-abc-volume-data"：user- 前缀但 uid 非纯数字 → 路径3 透传
		event := []byte(`{"Type":"volume","Action":"destroy","Actor":{"ID":"x","Attributes":{"driver":"local","name":"user-abc-volume-data"}}}`)
		if !eventBelongsToUser(event, bobUID) {
			t.Error("非法格式卷名（uid 段非数字）应透传，eventBelongsToUser 不应返回 false")
		}
	})

	t.Run("large_uid_isolation", func(t *testing.T) {
		const largeUID = 65534
		ownVol := fmt.Sprintf("user-%d-volume-data", largeUID)
		otherVol := fmt.Sprintf("user-%d-volume-data", bobUID) // uid=1002

		ownEvent := []byte(fmt.Sprintf(
			`{"Type":"volume","Action":"destroy","Actor":{"ID":%q,"Attributes":{"driver":"local","name":%q}}}`,
			ownVol, ownVol,
		))
		otherEvent := []byte(fmt.Sprintf(
			`{"Type":"volume","Action":"destroy","Actor":{"ID":%q,"Attributes":{"driver":"local","name":%q}}}`,
			otherVol, otherVol,
		))

		if !eventBelongsToUser(ownEvent, largeUID) {
			t.Errorf("uid=%d 应收到自己的卷 %q 的事件", largeUID, ownVol)
		}
		if eventBelongsToUser(otherEvent, largeUID) {
			t.Errorf("uid=%d 不应收到 bob(uid=%d) 的卷 %q 的事件", largeUID, bobUID, otherVol)
		}
	})

	t.Run("malformed_json_no_panic", func(t *testing.T) {
		malformed := [][]byte{
			nil,
			{},
			[]byte("not json at all"),
			[]byte(`{"Type":"volume"`), // truncated
			[]byte(`null`),
		}
		for _, ev := range malformed {
			ev := ev // 捕获循环变量（IIFE 内 defer 闭包安全）
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("eventBelongsToUser panicked on malformed input %q: %v", ev, r)
					}
				}()
				// 异常输入应兜底返回 true（不丢弃事件），且不崩溃
				got := eventBelongsToUser(ev, bobUID)
				if !got {
					t.Errorf("malformed input %q: 应兜底返回 true（宁滥勿缺），实际返回 false", ev)
				}
			}()
		}
	})
}
