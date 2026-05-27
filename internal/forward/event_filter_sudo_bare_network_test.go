package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-26：sudo docker network create <裸名> 事件泄漏给所有用户
//
// 根因：ActionNetworkCreate 对特权用户跳过前缀注入，且 rewrittenNameCtxKey 未写入
// context，导致 DB name 字段 fallback 为 hex ID。eventBelongsToUser 路径3对无
// _u{digits}_ 段的网络名无条件放行（return true），create 和 destroy 事件均泄漏。
//
// 修复点 1（Change 1，DB name 正确存储）：
//   modifyRequest ActionNetworkCreate 的特权用户 else 分支从 body 解析 Name 字段
//   并写入 rewrittenNameCtxKey，确保 DB 存的是 "sudovol123" 而非 hex ID。
//
// 修复点 2（Change 2，create 事件窗口）：
//   路径3 前加 DB fallback—— GetNetworkPrivCtxByName(name) found && privCtx==1 && !sudoCtx → false。
//
// 修复点 3（Change 3，destroy 事件竞态窗口）：
//   ActionNetworkRemove 在 DeleteNetwork 前将 pruneOwnerInfo 存入 completedPruneOwner；
//   路径3 同时检查 completedPruneOwner 补偿。
// ══════════════════════════════════════════════════════════════════════════════

import (
	"net/http/httptest"
	"testing"
)

// ──────────────────────────────────────────────────────────────────────────────
// BUG-26 create 事件：DB fallback 路径
// ──────────────────────────────────────────────────────────────────────────────

// TestBug26_SudoBareNetwork_CreateEvent_HiddenFromBob_regression
//
// sudo_test 以 sudo 命令创建裸名网络 "sudovol123"（无 _u{uid}_ 前缀），
// DB 经 Change 1 正确存 name="sudovol123", privileged_context=1。
// bob(uid=1002) 监听普通 docker events，不应收到该网络的 create 事件。
//
// 修复前 FAIL：裸名命中路径3 → return true → bob 收到事件。
// 修复后 PASS：Change 2 DB fallback 查到 privCtx=1 && !sudoCtx → return false。
func TestBug26_SudoBareNetwork_CreateEvent_HiddenFromBob_regression(t *testing.T) {
	db := newBug23DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	sudoID := bug23SudoIdentity("sudo_test", bug23SudoUID)
	netName := "sudovol123"
	fakeHexID := "aabbccddeeff1122"

	if err := db.SetNetworkOwner(fakeHexID, netName, sudoID); err != nil {
		t.Fatalf("SetNetworkOwner: %v", err)
	}

	event := makeNetworkEvent("create", netName)

	if p.eventBelongsToUser(event, bug23BobUID, false) {
		t.Errorf(
			"BUG-26 [裸名网络 create 事件泄漏 → bob]:\n"+
				"\tbob(uid=%d) 不应收到 sudo_test 的 sudo 裸名网络 create 事件\n"+
				"\t网络名: %q（DB owner_uid=%d, privileged_context=1）\n"+
				"\t预期: eventBelongsToUser=false\n"+
				"\t实际: eventBelongsToUser=true（路径3对无前缀网络无条件放行）",
			bug23BobUID, netName, bug23SudoUID,
		)
	}
}

// TestBug26_SudoBareNetwork_CreateEvent_HiddenFromOwnerNonSudo_regression
//
// sudo_test 以非 sudo 模式监听，不应收到自己 sudo 创建的裸名网络事件。
//
// 修复前 FAIL：路径3 → return true。
// 修复后 PASS：DB fallback privCtx==1 && !sudoCtx → return false。
func TestBug26_SudoBareNetwork_CreateEvent_HiddenFromOwnerNonSudo_regression(t *testing.T) {
	db := newBug23DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	sudoID := bug23SudoIdentity("sudo_test", bug23SudoUID)
	netName := "sudovol123"
	fakeHexID := "aabbccddeeff1122"

	if err := db.SetNetworkOwner(fakeHexID, netName, sudoID); err != nil {
		t.Fatalf("SetNetworkOwner: %v", err)
	}

	event := makeNetworkEvent("create", netName)

	if p.eventBelongsToUser(event, bug23SudoUID, false) {
		t.Errorf(
			"BUG-26 [裸名网络 create 事件泄漏 → owner 非 sudo 视图]:\n"+
				"\tsudo_test(uid=%d) 非 sudo 模式不应收到自己 sudo 创建的裸名网络 create 事件\n"+
				"\t网络名: %q（privileged_context=1）\n"+
				"\t预期: eventBelongsToUser=false\n"+
				"\t实际: eventBelongsToUser=true",
			bug23SudoUID, netName,
		)
	}
}

// TestBug26_SudoBareNetwork_CreateEvent_VisibleInSudoView_regression
//
// sudo_test 以 sudo 模式监听（sudoCtx=true），应能看到自己的 sudo 裸名网络 create 事件。
// 这是 sudo docker events 的预期行为。
func TestBug26_SudoBareNetwork_CreateEvent_VisibleInSudoView_regression(t *testing.T) {
	db := newBug23DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	sudoID := bug23SudoIdentity("sudo_test", bug23SudoUID)
	netName := "sudovol123"
	fakeHexID := "aabbccddeeff1122"

	if err := db.SetNetworkOwner(fakeHexID, netName, sudoID); err != nil {
		t.Fatalf("SetNetworkOwner: %v", err)
	}

	event := makeNetworkEvent("create", netName)

	if !p.eventBelongsToUser(event, bug23SudoUID, true) {
		t.Errorf(
			"回归 [sudo 视图应可见自己的裸名网络 create 事件]:\n"+
				"\tsudo_test(uid=%d) sudo 模式应收到裸名网络 create 事件\n"+
				"\t网络名: %q，sudoCtx=true\n"+
				"\t预期: eventBelongsToUser=true\n"+
				"\t实际: eventBelongsToUser=false",
			bug23SudoUID, netName,
		)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// BUG-26 destroy 事件：completedPruneOwner 竞态补偿路径
// ──────────────────────────────────────────────────────────────────────────────

// TestBug26_SudoBareNetwork_DestroyEvent_HiddenFromBob_regression
//
// ActionNetworkRemove 已将 pruneOwnerInfo{ownerUID=1005, privCtx=1} 存入
// completedPruneOwner（Change 3）。bob(uid=1002) 不应收到 "sudovol123" 的 destroy 事件。
//
// 修复前 FAIL：DB 记录已删，路径3 直接 return true → bob 收到事件。
// 修复后 PASS：completedPruneOwner 路径 privCtx==1 && !sudoCtx → return false。
func TestBug26_SudoBareNetwork_DestroyEvent_HiddenFromBob_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	netName := "sudovol123"
	pruneKey := "network:" + netName
	p.completedPruneOwner.Store(pruneKey, pruneOwnerInfo{ownerUID: bug23SudoUID, privCtx: 1})

	event := makeNetworkEvent("destroy", netName)

	if p.eventBelongsToUser(event, bug23BobUID, false) {
		t.Errorf(
			"BUG-26 [裸名网络 destroy 事件泄漏 → bob]:\n"+
				"\tbob(uid=%d) 不应收到 sudo_test 的裸名网络 destroy 事件\n"+
				"\t网络名: %q（completedPruneOwner ownerUID=%d, privCtx=1）\n"+
				"\t预期: eventBelongsToUser=false\n"+
				"\t实际: eventBelongsToUser=true（路径3未查 completedPruneOwner）",
			bug23BobUID, netName, bug23SudoUID,
		)
	}
}

// TestBug26_SudoBareNetwork_DestroyEvent_HiddenFromOwnerNonSudo_regression
//
// ActionNetworkRemove 已存 pruneOwnerInfo{ownerUID=1005, privCtx=1}。
// sudo_test 以非 sudo 模式监听，不应收到 "sudovol123" 的 destroy 事件。
//
// 修复前 FAIL：路径3 return true → 泄漏。
// 修复后 PASS：completedPruneOwner privCtx==1 && !sudoCtx → return false。
func TestBug26_SudoBareNetwork_DestroyEvent_HiddenFromOwnerNonSudo_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	netName := "sudovol123"
	pruneKey := "network:" + netName
	p.completedPruneOwner.Store(pruneKey, pruneOwnerInfo{ownerUID: bug23SudoUID, privCtx: 1})

	event := makeNetworkEvent("destroy", netName)

	if p.eventBelongsToUser(event, bug23SudoUID, false) {
		t.Errorf(
			"BUG-26 [裸名网络 destroy 事件泄漏 → owner 非 sudo 视图]:\n"+
				"\tsudo_test(uid=%d) 非 sudo 模式不应收到 privCtx=1 的裸名网络 destroy 事件\n"+
				"\t网络名: %q（completedPruneOwner privCtx=1）\n"+
				"\t预期: eventBelongsToUser=false\n"+
				"\t实际: eventBelongsToUser=true",
			bug23SudoUID, netName,
		)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// 回归：系统内置网络和前缀网络不受影响
// ──────────────────────────────────────────────────────────────────────────────

// TestBug26_SystemNetwork_AlwaysVisible_regression
//
// 系统内置网络（bridge/host/none）不在 DB 中，路径3 应对所有用户放行。
func TestBug26_SystemNetwork_AlwaysVisible_regression(t *testing.T) {
	db := newBug23DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	for _, sysNet := range []string{"bridge", "host", "none"} {
		event := makeNetworkEvent("connect", sysNet)
		if !p.eventBelongsToUser(event, bug23BobUID, false) {
			t.Errorf(
				"回归 [系统内置网络 %q 应对所有用户可见]:\n"+
					"\tbob(uid=%d) 应收到系统网络事件\n"+
					"\t预期: eventBelongsToUser=true\n"+
					"\t实际: eventBelongsToUser=false",
				sysNet, bug23BobUID,
			)
		}
	}
}

// TestBug26_PrefixedNetwork_IsolationUnchanged_regression
//
// 前缀格式网络（_u{uid}_ 路径2）隔离逻辑不受 Change 2 影响。
func TestBug26_PrefixedNetwork_IsolationUnchanged_regression(t *testing.T) {
	db := newBug23DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	bobNetName := "bob_u1002_mynet"
	event := makeNetworkEvent("create", bobNetName)

	// bob 本人可见
	if !p.eventBelongsToUser(event, bug23BobUID, false) {
		t.Errorf("回归: bob(uid=%d) 应能看到自己的前缀网络 %q 事件", bug23BobUID, bobNetName)
	}
	// sudo_test(uid=1005) 不可见（路径2 foundUID=1002 ≠ 1005）
	if p.eventBelongsToUser(event, bug23SudoUID, false) {
		t.Errorf("回归: sudo_test(uid=%d) 不应看到 bob 的前缀网络 %q 事件", bug23SudoUID, bobNetName)
	}
}
