package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-8 / BUG-9 集成测试：HTTP 事件流过滤路径
//
// ──── 测试目标 ────────────────────────────────────────────────────────────────
//
//   上层单元测试（event_filter_volume_isolation_test.go）只验证了
//   eventBelongsToUser 函数本身。
//
//   本文件从 HTTP handler 层面（ServeHTTP → GET /events）验证：
//
//     1. isStreaming 检测是否正确触发 flusher 分支（而非 io.Copy 旁路）
//     2. flusher 分支内的 eventBelongsToUser 过滤是否真正生效
//     3. 整条链路：fake Docker 上游 → proxy ServeHTTP → client 侧收到的事件
//
// ──── RED TEST 的失败路径（修复前）────────────────────────────────────────────
//
//   修复前：eventBelongsToUser 对 volume 类型无专门分支，走到
//     return true（系统事件透传）→ alice 的卷事件写入 bob 的响应体。
//
//   或：若未来 isStreaming 检测逻辑变化导致走 else 分支（io.Copy），
//     则 ALL events 无过滤透传，也会触发同样失败。
//
// ──── 触发场景（对应线上报告）────────────────────────────────────────────────
//
//   alice 执行 docker volume prune -f
//     → proxy 逐个 DELETE user-1001-volume-config
//     → Docker 发出 volume destroy 事件（name=user-1001-volume-config）
//     → bob 的 GET /events 流接收到该事件（隔离失效）
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"docker-authz-proxy/internal/auth"
)

// ──────────────────────────────────────────────────────────────────────────────
// 辅助：构造完整的 volume destroy 事件行（真实格式，无 owner 标签）
// ──────────────────────────────────────────────────────────────────────────────

func makeRawVolumeDestroyEvent(volumeName string) string {
	return fmt.Sprintf(
		`{"Type":"volume","Action":"destroy","Actor":{"ID":%q,"Attributes":{"driver":"local"}}}`,
		volumeName,
	)
}

// ──────────────────────────────────────────────────────────────────────────────
// 辅助：构造 fake Docker /events 端点，一次性发送指定事件流后关闭
// ──────────────────────────────────────────────────────────────────────────────

func fakeDockerEventsServer(events []string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/events") {
			w.WriteHeader(http.StatusOK)
			return
		}
		// 不设 Content-Length → isStreaming=true（proxy 走 flusher 分支）
		w.Header().Set("Content-Type", "application/json")
		flusher, ok := w.(http.Flusher)
		for _, ev := range events {
			fmt.Fprintln(w, ev)
			if ok {
				flusher.Flush()
			}
		}
		// 函数返回 → upstream 关闭连接 → proxy 读到 EOF → 事件循环结束
	}))
}

// ══════════════════════════════════════════════════════════════════════════════
// RED TEST: BUG-8 集成复现
// ══════════════════════════════════════════════════════════════════════════════

// TestBUG8_EventStream_VolumeDestroyLeak_Integration
//
// RED TEST（修复前必须 100% 失败）：
//
//	alice 的卷删除事件（user-1001-volume-config destroy）
//	通过 proxy 的 GET /events 流传给 bob（uid=1002）时，
//	应被过滤掉，bob 不应收到任何包含 alice 卷名的行。
//
// 失败路径（修复前）：
//
//	eventBelongsToUser 没有 volume 分支 → return true
//	→ alice 的卷事件写入 bob 的响应体
//	→ strings.Contains(body, aliceVolName) == true → t.Errorf
//
// 通过路径（修复后）：
//
//	volume 分支：user-1001-volume-config 的 uid=1001 ≠ bob uid=1002
//	→ return false → continue（跳过）→ bob 响应体不含 alice 的卷名
func TestBUG8_EventStream_VolumeDestroyLeak_Integration(t *testing.T) {
	const aliceUID = 1001
	const bobUID = 1002

	aliceVolName := fmt.Sprintf("user-%d-volume-config", aliceUID)
	bobVolName := fmt.Sprintf("user-%d-volume-data", bobUID)

	upstream := fakeDockerEventsServer([]string{
		makeRawVolumeDestroyEvent(aliceVolName), // alice 的卷 — bob 不应收到
		makeRawVolumeDestroyEvent(bobVolName),   // bob 自己的卷 — bob 应收到
	})
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	req := httptest.NewRequest("GET", "/events?type=volume", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()

	// ── RED ASSERTION: alice 的卷名不应出现在 bob 的事件流 ────────────────
	// 修复前 FAIL: eventBelongsToUser(aliceEvent, bobUID) == true
	//   → 事件写入响应，strings.Contains(body, aliceVolName) == true
	// 修复后 PASS: volume 分支路径 2 返回 false → 事件跳过，body 不含 aliceVolName
	if strings.Contains(body, aliceVolName) {
		t.Errorf("BUG-8 [集成]: bob(uid=%d) 的事件流收到了 alice 的卷删除事件\n"+
			"\t事件名: %q\n"+
			"\t响应体: %s\n"+
			"\t根因: eventBelongsToUser volume 分支缺失，走 return true (系统事件透传)\n"+
			"\t修复: 增加 volume 类型分支，按卷名前缀 user-{uid}-volume-* 判断归属",
			bobUID, aliceVolName, body)
	}

	// ── 正向断言: bob 自己的卷事件必须到达 ────────────────────────────────
	if !strings.Contains(body, bobVolName) {
		t.Errorf("bob(uid=%d) 应收到自己的卷删除事件 %q，但响应体不含该名称\n\t响应体: %s",
			bobUID, bobVolName, body)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归测试矩阵（4 个）
// ══════════════════════════════════════════════════════════════════════════════

// TestEventStream_SystemVolumes_PassthroughToAllUsers
//
// 回归-1：非 user-{uid}-volume-* 格式的系统卷（buildkit、tmpfs 等）
// 应对所有普通用户透传——路径 3（return true）。
// 覆盖：修复后系统级事件不被误过滤。
func TestEventStream_SystemVolumes_PassthroughToAllUsers(t *testing.T) {
	systemVols := []string{
		"buildkit-cache-xyz",
		"tmpfs-overlay-abc",
		"docker-compose_db_data",
	}

	var events []string
	for _, v := range systemVols {
		events = append(events, makeRawVolumeDestroyEvent(v))
	}

	upstream := fakeDockerEventsServer(events)
	defer upstream.Close()

	for _, uid := range []int{1001, 1002} {
		p := newTestProxy(t, upstream, nil)
		req := httptest.NewRequest("GET", "/events?type=volume", nil)
		req = injectIdentity(req, makeTestIdentityProxy(fmt.Sprintf("user-%d", uid), uid))
		rw := httptest.NewRecorder()
		p.ServeHTTP(rw, req)

		body := rw.Body.String()
		for _, v := range systemVols {
			if !strings.Contains(body, v) {
				t.Errorf("uid=%d: 系统卷 %q 的事件应透传，但在响应体中缺失\n"+
					"\t修复后不能误过滤非用户格式的卷事件",
					uid, v)
			}
		}
	}
}

// TestEventStream_MultiUser_MutualIsolation
//
// 回归-2：alice / bob / charlie 三用户各自只收到自己的卷事件，
// 不收到其他任何用户的卷事件（完整隔离矩阵）。
// 覆盖：确保修复不只对一对用户生效，对任意用户组合均成立。
func TestEventStream_MultiUser_MutualIsolation(t *testing.T) {
	users := []struct {
		uid  int
		name string
	}{
		{1001, "alice"},
		{1002, "bob"},
		{1003, "charlie"},
	}

	// 构造每个用户的卷事件
	var events []string
	for _, u := range users {
		events = append(events, makeRawVolumeDestroyEvent(
			fmt.Sprintf("user-%d-volume-workspace", u.uid),
		))
	}

	for _, viewer := range users {
		upstream := fakeDockerEventsServer(events)
		defer upstream.Close()

		p := newTestProxy(t, upstream, nil)
		req := httptest.NewRequest("GET", "/events?type=volume", nil)
		req = injectIdentity(req, makeTestIdentityProxy(viewer.name, viewer.uid))
		rw := httptest.NewRecorder()
		p.ServeHTTP(rw, req)
		body := rw.Body.String()

		for _, owner := range users {
			volName := fmt.Sprintf("user-%d-volume-workspace", owner.uid)
			contains := strings.Contains(body, volName)
			want := owner.uid == viewer.uid

			if contains != want {
				if want {
					t.Errorf("[%s uid=%d] 应收到自己的卷事件 %q，但响应体中缺失",
						viewer.name, viewer.uid, volName)
				} else {
					t.Errorf("[%s uid=%d] 不应收到 %s(uid=%d) 的卷事件 %q\n"+
						"\t响应体包含该卷名 → 事件隔离失效",
						viewer.name, viewer.uid, owner.name, owner.uid, volName)
				}
			}
		}
	}
}

// TestEventStream_PrivilegedUser_SeesAllVolumeEvents
//
// 回归-3：sudo / root 等特权用户（IsPrivileged()==true）的事件流
// 不经过任何 eventBelongsToUser 过滤——可看到全部用户的卷事件。
// 覆盖：修复后特权用户的事件订阅路径不应被误过滤。
func TestEventStream_PrivilegedUser_SeesAllVolumeEvents(t *testing.T) {
	aliceVolName := "user-1001-volume-config"
	bobVolName := "user-1002-volume-data"

	upstream := fakeDockerEventsServer([]string{
		makeRawVolumeDestroyEvent(aliceVolName),
		makeRawVolumeDestroyEvent(bobVolName),
	})
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	req := httptest.NewRequest("GET", "/events?type=volume", nil)
	sudoID := &auth.CallerIdentity{
		RealUsername:      "sudo_test",
		RealUID:           1005,
		RealGID:           1005,
		EffectiveUsername: "root",
		EffectiveUID:      0,
		UserType:          auth.UserTypeSudo, // IsPrivileged() == true
		AuthSource:        auth.AuthSourceOS,
	}
	req = injectIdentity(req, sudoID)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()

	// 特权用户应收到所有用户的卷事件（无过滤）
	for _, volName := range []string{aliceVolName, bobVolName} {
		if !strings.Contains(body, volName) {
			t.Errorf("sudo_test(privileged) 应收到卷事件 %q，但响应体不含该名称\n"+
				"\t特权用户的事件流不应被 eventBelongsToUser 过滤",
				volName)
		}
	}
}

// TestEventStream_AllVolumeActions_SameFilterRule
//
// 回归-4：volume 的所有 action（create/destroy/mount/unmount）
// 均应使用相同的名称前缀过滤规则，action 不影响隔离逻辑。
// 覆盖：修复时不能只处理 destroy 而遗漏其他 action。
func TestEventStream_AllVolumeActions_SameFilterRule(t *testing.T) {
	const aliceUID = 1001
	const bobUID = 1002

	aliceVolName := fmt.Sprintf("user-%d-volume-config", aliceUID)

	actions := []string{"create", "destroy", "mount", "unmount"}

	for _, action := range actions {
		event := fmt.Sprintf(
			`{"Type":"volume","Action":%q,"Actor":{"ID":%q,"Attributes":{"driver":"local","name":%q}}}`,
			action, aliceVolName, aliceVolName,
		)

		upstream := fakeDockerEventsServer([]string{event})
		p := newTestProxy(t, upstream, nil)

		req := httptest.NewRequest("GET", "/events?type=volume", nil)
		req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
		rw := httptest.NewRecorder()
		p.ServeHTTP(rw, req)
		upstream.Close()

		body := rw.Body.String()
		if strings.Contains(body, aliceVolName) {
			t.Errorf("action=%q: bob(uid=%d) 不应收到 alice 的卷事件 %q\n"+
				"\t所有 volume action 必须遵循相同的名称前缀过滤规则\n"+
				"\t响应体: %s",
				action, bobUID, aliceVolName, body)
		}
	}
}
