package forward

// ══════════════════════════════════════════════════════════════════════════════
// eventBelongsToUser 单元测试套件
//
// 关联 Bug：BUG-7 sudo volume prune 后 bob 收不到自己的卷删除事件。
//
// 事件缺失的根因链：
//   代理绕过 → Docker 原生 prune（无 -a）→ 只删匿名卷 → 具名卷不被删除
//   → Docker 不产生任何 volume destroy 事件 → bob 的 event listener 空转
//
// 次要问题（独立 Bug，本套件覆盖）：
//   即使未来修复 sudo prune 使具名卷被删除，volume 事件仍缺少
//   system.authz.owner.uid 标签（InjectVolumeNamePrefix 只注入名称前缀，
//   不注入归属标签）。导致 eventBelongsToUser 对 volume 事件无法精确过滤：
//     - 无 uid 标签 → return true（系统事件透传）
//     - alice 和 bob 都能收到对方的 volume 删除事件（隔离失效）
// ══════════════════════════════════════════════════════════════════════════════

import (
	"fmt"
	"testing"
)

// eventBelongsToUser 是测试用的包级包装函数，使用无 DB 的 ProxyServer 实例。
// image 事件在无 DB 时走路径3（DB无记录→放行），与旧行为兼容。
// 需要测试 image 事件隔离时请直接使用 ProxyServer.eventBelongsToUser 并传入真实 DB。
func eventBelongsToUser(line []byte, uid int) bool {
	p := &ProxyServer{}
	return p.eventBelongsToUser(line, uid)
}

// ──────────────────────────────────────────────────────────────────────────────
// 事件 JSON 构造辅助函数
// ──────────────────────────────────────────────────────────────────────────────

// makeVolumeEvent 构造 volume 事件（与真实 Docker daemon 格式一致）。
// 真实 Docker 事件：卷名在 Actor.ID，Attributes 仅含 driver（无 name 字段）。
func makeVolumeEvent(action, volumeName string) []byte {
	return []byte(fmt.Sprintf(
		`{"Type":"volume","Action":%q,"Actor":{"ID":%q,"Attributes":{"driver":"local"}}}`,
		action, volumeName,
	))
}

// makeVolumeEventWithOwnerLabel 构造携带 system.authz.owner.uid 标签的 volume 事件（修复后状态）。
func makeVolumeEventWithOwnerLabel(action, volumeName string, ownerUID int) []byte {
	return []byte(fmt.Sprintf(
		`{"Type":"volume","Action":%q,"Actor":{"ID":%q,"Attributes":{"driver":"local","name":%q,"system.authz.owner.uid":%q}}}`,
		action, volumeName, volumeName, fmt.Sprintf("%d", ownerUID),
	))
}

// makeContainerEvent 构造携带 system.authz.owner.uid 标签的 container 事件。
func makeContainerEvent(action, containerID string, ownerUID int) []byte {
	return []byte(fmt.Sprintf(
		`{"Type":"container","Action":%q,"Actor":{"ID":%q,"Attributes":{"system.authz.owner.uid":%q,"image":"nginx"}}}`,
		action, containerID, fmt.Sprintf("%d", ownerUID),
	))
}

// makeContainerEventUserIDFallback 构造仅有 user_id 标签（无 system.authz.owner.uid）的 container 事件。
func makeContainerEventUserIDFallback(action, containerID string, ownerUID int) []byte {
	return []byte(fmt.Sprintf(
		`{"Type":"container","Action":%q,"Actor":{"ID":%q,"Attributes":{"user_id":%q,"image":"nginx"}}}`,
		action, containerID, fmt.Sprintf("%d", ownerUID),
	))
}

// makeNetworkEvent 构造指定网络名的 network 事件。
func makeNetworkEvent(action, networkName string) []byte {
	return []byte(fmt.Sprintf(
		`{"Type":"network","Action":%q,"Actor":{"ID":"abc123def456","Attributes":{"name":%q,"type":"bridge"}}}`,
		action, networkName,
	))
}

// ──────────────────────────────────────────────────────────────────────────────
// RED TEST: BUG-7 次要问题 — volume 事件缺少归属标签导致隔离失效
// ──────────────────────────────────────────────────────────────────────────────

// TestBUG7_VolumeDestroyEvent_NoOwnerLabel_BreaksIsolation
//
// RED TEST: 在修复前，此测试必须失败（t.Errorf 被触发）。
//
// 复现场景：
//   bob 的具名卷被删除（假设 sudo prune 已修复，卷能被正常删除）。
//   Docker 生成的 volume destroy 事件：
//     {"Type":"volume","Actor":{"Attributes":{"driver":"local","name":"user-1002-volume-data"}}}
//   Attributes 中没有 system.authz.owner.uid 标签（代理创卷时未注入归属标签）。
//   eventBelongsToUser(event, alice.UID=1001):
//     - Type != "network"
//     - attrs["system.authz.owner.uid"] → not found
//     - attrs["user_id"] → not found
//     - return true（视为系统事件，所有用户可见）
//   → alice 收到 bob 的卷删除事件（事件隔离失效）
//
// 修复方向：在 volume 创建时向 Labels 注入 system.authz.owner.uid，
//
//	使 volume destroy 事件携带归属信息，供 eventBelongsToUser 精确过滤。
func TestBUG7_VolumeDestroyEvent_NoOwnerLabel_BreaksIsolation(t *testing.T) {
	const bobUID = 1002
	const aliceUID = 1001
	volName := fmt.Sprintf("user-%d-volume-data", bobUID)

	// 无归属标签的事件（当前代理行为下产生的真实格式）
	event := makeVolumeEvent("destroy", volName)

	// bob 本人应收到自己的卷删除事件（这一点在修复前后均应成立）
	if !eventBelongsToUser(event, bobUID) {
		t.Errorf("bob (uid=%d) should receive destroy event for his own volume %q, got false",
			bobUID, volName)
	}

	// ── RED ASSERTION: alice 不应收到 bob 的卷删除事件 ─────────────────────
	// 修复前 FAIL: eventBelongsToUser(event, alice) == true（无标签 → 透传 → alice 可见）
	// 修复后 PASS: volume 携带 owner 标签 → eventBelongsToUser(event, alice) == false
	if eventBelongsToUser(event, aliceUID) {
		t.Errorf("BUG: alice (uid=%d) should NOT receive bob's volume destroy event for %q — "+
			"volume events lack system.authz.owner.uid label (not injected at creation), "+
			"eventBelongsToUser treats them as system events (return true) for all users",
			aliceUID, volName)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// 回归测试矩阵
// ──────────────────────────────────────────────────────────────────────────────

// TestEventBelongsToUser_VolumeEvent_WithOwnerLabel_CorrectRouting
//
// 回归-1：volume 事件携带 system.authz.owner.uid 标签时，
// 应精确路由到对应用户，不泄漏到其他用户。
// 覆盖：修复后 volume 事件的正确过滤行为。
func TestEventBelongsToUser_VolumeEvent_WithOwnerLabel_CorrectRouting(t *testing.T) {
	const bobUID = 1002
	event := makeVolumeEventWithOwnerLabel("destroy", fmt.Sprintf("user-%d-volume-data", bobUID), bobUID)

	cases := []struct {
		uid  int
		want bool
		desc string
	}{
		{bobUID, true, "volume owner should receive his own event"},
		{1001, false, "other user (alice) should NOT receive bob's volume event"},
		{0, false, "root should not receive user-owned volume event via regular filter"},
	}
	for _, tc := range cases {
		got := eventBelongsToUser(event, tc.uid)
		if got != tc.want {
			t.Errorf("uid=%d: %s — want eventBelongsToUser=%v, got %v",
				tc.uid, tc.desc, tc.want, got)
		}
	}
}

// TestEventBelongsToUser_ContainerEvent_PriorityLabel
//
// 回归-2：container 事件的标签优先级与回退机制：
//   ① system.authz.owner.uid（最高优先级，代理注入，防篡改）
//   ② user_id（回退，用户可见标签）
//   ③ 两者均无 → 透传（系统事件）
// 覆盖：标签优先级顺序不应倒置，回退逻辑不应引入误判。
func TestEventBelongsToUser_ContainerEvent_PriorityLabel(t *testing.T) {
	const bobUID = 1002

	t.Run("system.authz.owner.uid match", func(t *testing.T) {
		event := makeContainerEvent("stop", "c-abc123", bobUID)
		if !eventBelongsToUser(event, bobUID) {
			t.Errorf("container event with system.authz.owner.uid=%d: want true", bobUID)
		}
		if eventBelongsToUser(event, 1001) {
			t.Errorf("container event uid=%d: eventBelongsToUser(alice=1001) want false", bobUID)
		}
	})

	t.Run("user_id fallback match", func(t *testing.T) {
		event := makeContainerEventUserIDFallback("start", "c-xyz789", bobUID)
		if !eventBelongsToUser(event, bobUID) {
			t.Errorf("container event with user_id=%d fallback: want true", bobUID)
		}
		if eventBelongsToUser(event, 1001) {
			t.Errorf("container event user_id=%d: eventBelongsToUser(alice=1001) want false, got true", bobUID)
		}
	})
}

// TestEventBelongsToUser_NetworkEvent_PrefixMatching
//
// 回归-3：network 事件按网络名模式三路过滤：
//
//	路径 1a：user-{uid}-bridge（用户专属桥接，connect/disconnect 事件用此名）
//	路径 1b：peer-{digits}-{digits} 互通对等网络
//	路径 2 ：{username}_u{uid}_{name} 用户自建网络（含 _u{digits}_ 段）
//	路径 3 ：无以上模式 → 系统内置网络（bridge/host/docker_gwbridge），
//	         对所有用户放行（return true）
//
// 覆盖：各路径正向匹配、他人网络拒绝、系统网络对所有用户透传。
func TestEventBelongsToUser_NetworkEvent_PrefixMatching(t *testing.T) {
	const bobUID = 1002

	cases := []struct {
		netName string
		uid     int
		want    bool
		desc    string
	}{
		// 路径 2：真实用户网络格式 {username}_u{uid}_{name}
		{"bob_u1002_mynet", bobUID, true, "bob's user network → visible to bob"},
		{"bob_u1002_mynet", 1001, false, "bob's network → alice should not see"},
		{"alice_u1001_mynet", bobUID, false, "alice's network → bob should not see"},
		// 路径 1a：user-{uid}-bridge（connect/disconnect 事件用桥接网络名）
		{fmt.Sprintf("user-%d-bridge", bobUID), bobUID, true, "bob's bridge network"},
		{"user-1001-bridge", bobUID, false, "alice's bridge → bob should not see"},
		// 路径 1b：peer-{digits}-{digits} 互通网络
		{"peer-1002-1001", bobUID, true, "peer network containing bob's uid"},
		{"peer-1001-1003", bobUID, false, "peer between others → bob should not see"},
		// 路径 3：系统内置网络，对所有用户放行（return true）
		{"bridge", bobUID, true, "system bridge → passthrough to all users"},
		{"host", bobUID, true, "system host → passthrough to all users"},
		{"docker_gwbridge", bobUID, true, "docker gateway bridge → passthrough to all users"},
	}
	for _, tc := range cases {
		event := makeNetworkEvent("connect", tc.netName)
		got := eventBelongsToUser(event, tc.uid)
		if got != tc.want {
			t.Errorf("network %q uid=%d: %s — want %v, got %v",
				tc.netName, tc.uid, tc.desc, tc.want, got)
		}
	}
}

// TestEventBelongsToUser_MalformedInput_SafeDefault
//
// 回归-4：异常输入（空、截断、非 JSON）必须安全兜底返回 true，
// 确保事件流不因解析错误而中断。
// 覆盖：空值 / null / 极端格式 等边界条件。
func TestEventBelongsToUser_MalformedInput_SafeDefault(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
	}{
		{"empty slice", []byte{}},
		{"nil-like empty", []byte(nil)},
		{"plain text", []byte("not json")},
		{"truncated json", []byte(`{"Type":"volume","Action":"destroy"`)},
		{"null literal", []byte("null")},
		{"zero byte", []byte{0x00}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !eventBelongsToUser(tc.input, 1002) {
				t.Errorf("malformed input %q: want true (safe default), got false — "+
					"invalid events must not be silently dropped", tc.name)
			}
		})
	}
}
