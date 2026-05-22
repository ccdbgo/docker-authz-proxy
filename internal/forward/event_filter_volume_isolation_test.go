package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-8: volume 事件流未按用户隔离 — 所有用户收到全部 volume 事件
//
// ──── 触发场景 ────────────────────────────────────────────────────────────────
//
//   [场景 A] sudo_test 执行 sudo docker volume prune -f
//     → 代理依次 DELETE user-1002-volume-data、user-1001-volume-config ...
//     → Docker 对每个被删除的卷产生 volume destroy 事件
//     → bob 的 docker system events 同时收到 alice 的卷删除事件（隔离失效）
//
//   [场景 B] alice 执行 docker volume prune -f（普通用户）
//     → 代理 DELETE user-1001-volume-config
//     → Docker 产生 volume destroy 事件
//     → bob 的 docker system events 收到 alice 的卷删除事件（隔离失效）
//
// ──── 根本原因 ────────────────────────────────────────────────────────────────
//
//   eventBelongsToUser (proxy.go:1866) 的 volume 事件分支缺失：
//
//   1. network 事件：通过名称前缀 user-<uid>- / peer-<uid>- 判断 → 隔离正确
//   2. container 事件：通过 system.authz.owner.uid / user_id 标签判断 → 隔离正确
//   3. volume 事件：代理创卷时未向 Docker 注入标签（Docker volume API 不支持
//      在 Attributes 中携带自定义标签并透传到 events 流中），故 volume destroy
//      事件的 Attributes 只含 driver 和 name，无 system.authz.owner.uid。
//      → eventBelongsToUser 走到最后的兜底逻辑 return true（系统事件放行）
//      → 所有用户均收到所有其他用户的卷事件
//
//   【可用的归属信息】volume 名称本身携带所有者信息：
//     格式：user-{uid}-volume-{suffix}
//     与 InjectVolumeNamePrefix、isUserVolumePrefix 使用的格式完全一致。
//
// ──── 修复方向 ────────────────────────────────────────────────────────────────
//
//   在 eventBelongsToUser 中，在 network 分支之后、标签分支之前，
//   增加 volume 事件的名称前缀匹配分支：
//
//     if ev.Type == "volume" {
//         name := attrs["name"]
//         prefix := "user-" + uidStr + "-volume-"
//         if strings.HasPrefix(name, "user-") {
//             return strings.HasPrefix(name, prefix)
//         }
//         return true // 非用户格式的卷（系统卷）放行
//     }
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"fmt"
	"testing"
)

// ──────────────────────────────────────────────────────────────────────────────
// 辅助函数：构造各种 volume 事件格式
// ──────────────────────────────────────────────────────────────────────────────

// makeVolumeEventWithAction 构造指定 action 的 volume 事件（当前代理真实格式）。
// Attributes 仅含 driver 和 name，无任何 owner 标签。
func makeVolumeEventWithAction(action, volumeName string) []byte {
	return []byte(fmt.Sprintf(
		`{"Type":"volume","Action":%q,"Actor":{"ID":%q,"Attributes":{"driver":"local","name":%q}}}`,
		action, volumeName, volumeName,
	))
}

// makeVolumeEventDockerSystem 构造 docker system 级别的 volume 事件
// （非 user-{uid}-volume-* 格式，如 tmpfs、buildkit-cache 等）。
func makeVolumeEventDockerSystem(action, volumeName string) []byte {
	return []byte(fmt.Sprintf(
		`{"Type":"volume","Action":%q,"Actor":{"ID":%q,"Attributes":{"driver":"local","name":%q}}}`,
		action, volumeName, volumeName,
	))
}

// ══════════════════════════════════════════════════════════════════════════════
// RED TEST: BUG-8 复现
// ══════════════════════════════════════════════════════════════════════════════

// TestBUG8_VolumeDestroyEvent_LeaksToOtherUsers
//
// RED TEST: 在修复前，此测试必须 100% 失败。
//
// 复现场景 A（sudo prune）+ 场景 B（普通用户 prune）的共同根因：
//
//	docker volume destroy 事件只含 driver 和 name，无归属标签。
//	eventBelongsToUser 对 volume 类型无专门处理 → return true（放行给所有人）。
//
// 期望行为（修复后）：
//
//	volume 事件通过卷名前缀 user-{uid}-volume-* 判断归属：
//	  - user-1002-volume-data: bob(uid=1002) 收到，alice(uid=1001) 不收到
//	  - user-1001-volume-config: alice 收到，bob 不收到
func TestBUG8_VolumeDestroyEvent_LeaksToOtherUsers(t *testing.T) {
	const bobUID = 1002
	const aliceUID = 1001

	// ── 场景：bob 的卷被删除（由 sudo prune 或 bob 自己的 prune 触发）────────
	bobVolName := fmt.Sprintf("user-%d-volume-data", bobUID)
	bobDestroyEvent := makeVolumeEventWithAction("destroy", bobVolName)

	// bob 本人必须收到自己的卷删除事件
	if !eventBelongsToUser(bobDestroyEvent, bobUID) {
		t.Errorf("bob(uid=%d) should receive destroy event for his own volume %q, got false",
			bobUID, bobVolName)
	}

	// ── RED ASSERTION A：alice 不应收到 bob 的卷删除事件 ─────────────────────
	// 修复前 FAIL: eventBelongsToUser(bobEvent, alice) == true
	//   → volume 事件无归属标签，走 return true（系统事件放行），alice 也能看到
	// 修复后 PASS: 名称前缀 user-1002-volume-* ≠ user-1001-volume-* → false
	if eventBelongsToUser(bobDestroyEvent, aliceUID) {
		t.Errorf("BUG-8 [场景A/B]: alice(uid=%d) should NOT receive bob's volume destroy event %q\n"+
			"\troot cause: eventBelongsToUser has no volume branch — falls through to return true\n"+
			"\tDocker volume events carry only {driver, name} in Attributes (no owner label)\n"+
			"\tfix: use name prefix user-{uid}-volume-* to route volume events",
			aliceUID, bobVolName)
	}

	// ── 场景：alice 的卷被删除（由 alice prune 触发）──────────────────────────
	aliceVolName := fmt.Sprintf("user-%d-volume-config", aliceUID)
	aliceDestroyEvent := makeVolumeEventWithAction("destroy", aliceVolName)

	// alice 本人必须收到
	if !eventBelongsToUser(aliceDestroyEvent, aliceUID) {
		t.Errorf("alice(uid=%d) should receive destroy event for her own volume %q, got false",
			aliceUID, aliceVolName)
	}

	// ── RED ASSERTION B：bob 不应收到 alice 的卷删除事件 ─────────────────────
	// 修复前 FAIL: eventBelongsToUser(aliceEvent, bob) == true（同上根因）
	// 修复后 PASS: 名称前缀 user-1001-volume-* ≠ user-1002-volume-* → false
	if eventBelongsToUser(aliceDestroyEvent, bobUID) {
		t.Errorf("BUG-8 [场景B]: bob(uid=%d) should NOT receive alice's volume destroy event %q\n"+
			"\troot cause: same as above — eventBelongsToUser returns true for all volume events\n"+
			"\tfix: use name prefix routing for volume events",
			bobUID, aliceVolName)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归测试矩阵（4 个）
// ══════════════════════════════════════════════════════════════════════════════

// TestEventBelongsToUser_VolumeEvent_NamePrefix_MultiUser
//
// 回归-1：volume 事件经名称前缀精确路由到对应用户。
// 覆盖：多用户场景下 bob/alice/charlie 各自的卷不会互相泄漏。
func TestEventBelongsToUser_VolumeEvent_NamePrefix_MultiUser(t *testing.T) {
	users := []struct {
		uid  int
		name string
	}{
		{1001, "alice"},
		{1002, "bob"},
		{1003, "charlie"},
	}

	for _, owner := range users {
		volName := fmt.Sprintf("user-%d-volume-workspace", owner.uid)
		event := makeVolumeEventWithAction("destroy", volName)

		for _, viewer := range users {
			got := eventBelongsToUser(event, viewer.uid)
			want := owner.uid == viewer.uid

			if got != want {
				t.Errorf("volume %q: eventBelongsToUser(uid=%d/%s) = %v, want %v\n"+
					"\t(owner=%s uid=%d, viewer=%s uid=%d)",
					volName, viewer.uid, viewer.name, got, want,
					owner.name, owner.uid, viewer.name, viewer.uid)
			}
		}
	}
}

// TestEventBelongsToUser_VolumeEvent_AllActions_SameRouting
//
// 回归-2：volume 事件的所有 action（create / destroy / mount / unmount）
// 均应使用相同的名称前缀路由规则，action 类型不影响归属判断。
// 覆盖：修复时不能只处理 destroy 而遗漏其他 action。
func TestEventBelongsToUser_VolumeEvent_AllActions_SameRouting(t *testing.T) {
	const bobUID = 1002
	const aliceUID = 1001
	volName := fmt.Sprintf("user-%d-volume-data", bobUID)

	actions := []string{"create", "destroy", "mount", "unmount"}

	for _, action := range actions {
		event := makeVolumeEventWithAction(action, volName)

		// bob 应收到自己所有 action 的事件
		if !eventBelongsToUser(event, bobUID) {
			t.Errorf("action=%q: bob(uid=%d) should receive own volume event, got false", action, bobUID)
		}

		// alice 不应收到 bob 任何 action 的事件
		if eventBelongsToUser(event, aliceUID) {
			t.Errorf("action=%q: alice(uid=%d) should NOT receive bob's volume event %q\n"+
				"\tall volume actions must follow the same name-prefix routing rule",
				action, aliceUID, volName)
		}
	}
}

// TestEventBelongsToUser_VolumeEvent_SystemVolumes_Passthrough
//
// 回归-3：非用户格式的卷（系统卷、buildkit 缓存、tmpfs 等）
// 不匹配 user-{uid}-volume-* 前缀，应对所有用户透传（return true）。
// 覆盖：修复后不能误伤系统级 volume 事件的正常透传。
func TestEventBelongsToUser_VolumeEvent_SystemVolumes_Passthrough(t *testing.T) {
	const bobUID = 1002

	systemVolumes := []struct {
		name string
		desc string
	}{
		{"buildkit-cache-xyz", "buildkit 内部缓存卷"},
		{"tmpfs-overlay-abc", "tmpfs 叠加卷"},
		{"docker-compose_db_data", "compose 项目卷"},
		{"sha256abcdef123456", "内容寻址卷"},
		{"", "空名称（兜底）"},
		{"user-abc-volume-data", "user- 前缀但 uid 非数字（非法格式）"},
		{"user--volume-data", "user- 后紧跟 -（无数字）"},
	}

	for _, sv := range systemVolumes {
		event := makeVolumeEventDockerSystem("destroy", sv.name)
		got := eventBelongsToUser(event, bobUID)
		if !got {
			t.Errorf("system volume %q (%s): want eventBelongsToUser(uid=%d)=true (passthrough), got false\n"+
				"\tsystem volumes must not be silently dropped from event stream",
				sv.name, sv.desc, bobUID)
		}
	}
}

// TestEventBelongsToUser_VolumeEvent_RootAndPrivilegedSudoRouting
//
// 回归-4：root(uid=0) 和 sudo_test(uid=1005) 调用 docker system events 时的过滤行为。
//
//   - root 通过代理以 uid=0 订阅：user-{uid}-volume-* 格式中不存在 uid=0 的卷，
//     故 root 订阅的事件流中不应收到普通用户的卷 destroy 事件。
//     【注】这是 eventBelongsToUser 的语义：判断"是否属于 uid"，
//     root 用 uid=0 查询时，user-1002-volume-data 不属于 uid=0 → false。
//     实际业务中 root 通常不经代理订阅（或有独立逻辑），此测试记录当前语义。
//
//   - sudo_test(uid=1005) 通过代理订阅：
//     sudo_test 没有 user-1005-volume-* 卷，故不应收到 bob 或 alice 的卷事件。
//
// 覆盖：修复后特权用户的事件订阅路径不应引入隔离漏洞。
func TestEventBelongsToUser_VolumeEvent_RootAndPrivilegedSudoRouting(t *testing.T) {
	const bobUID = 1002
	const aliceUID = 1001
	const rootUID = 0
	const sudoTestUID = 1005

	cases := []struct {
		viewerUID int
		viewerTag string
		volUID    int
		volName   string
		want      bool
		desc      string
	}{
		// root(uid=0) 不应收到 bob 的卷事件（user-1002-* 不属于 uid=0）
		{rootUID, "root", bobUID,
			fmt.Sprintf("user-%d-volume-data", bobUID),
			false, "root(uid=0) should NOT receive bob's volume events via uid-based filter"},

		// root(uid=0) 不应收到 alice 的卷事件
		{rootUID, "root", aliceUID,
			fmt.Sprintf("user-%d-volume-config", aliceUID),
			false, "root(uid=0) should NOT receive alice's volume events via uid-based filter"},

		// sudo_test(uid=1005) 不应收到 bob 的卷事件
		{sudoTestUID, "sudo_test", bobUID,
			fmt.Sprintf("user-%d-volume-data", bobUID),
			false, "sudo_test(uid=1005) should NOT receive bob's volume events"},

		// sudo_test(uid=1005) 自己的具名卷（虽然业务上不常用）应能收到
		{sudoTestUID, "sudo_test", sudoTestUID,
			fmt.Sprintf("user-%d-volume-workspace", sudoTestUID),
			true, "sudo_test should receive events for his own named volumes"},

		// bob 不应收到 alice 的卷事件（基础隔离保证）
		{bobUID, "bob", aliceUID,
			fmt.Sprintf("user-%d-volume-config", aliceUID),
			false, "bob should NOT receive alice's volume events"},
	}

	for _, tc := range cases {
		event := makeVolumeEventWithAction("destroy", tc.volName)
		got := eventBelongsToUser(event, tc.viewerUID)
		if got != tc.want {
			t.Errorf("[%s uid=%d] volume=%q: want eventBelongsToUser=%v, got %v\n\t%s",
				tc.viewerTag, tc.viewerUID, tc.volName, tc.want, got, tc.desc)
		}
	}
}
