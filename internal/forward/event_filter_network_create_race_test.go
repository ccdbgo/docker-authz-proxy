package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-29b：sudo 裸名网络 create 事件在竞态窗口内泄漏给所有订阅者
//
// 根因：sudo docker network create sudovol123（裸名，无 _u{uid}_ 前缀）
// 导致 Docker 在 SetNetworkOwner 写入 DB 之前就发出 network create 事件。
// eventBelongsToUser 路径：
//   1. path 2 miss：名称无 _u{digits}_ 段
//   2. 路径 3 DB miss：SetNetworkOwner 尚未调用
//   3. completedPruneOwner miss：无预注册条目
//   4. return true → 泄漏给所有订阅者 ✗
//
// 修复：ServeHTTP 在 forward 前预注册 completedPruneOwner（ActionNetworkCreate 分支），
// 覆盖从请求发出到 DB 写入之间的竞态窗口。与 BUG-29 卷的修复对称。
// ══════════════════════════════════════════════════════════════════════════════

import (
	"net/http/httptest"
	"testing"

	"docker-authz-proxy/internal/authz"
)

const (
	bug29bSudoUID  = 1003 // sudo_test
	bug29bBobUID   = 1001
	bug29bAliceUID = 1002
)

// newBug29bDB 创建内存 DB 并注册 t.Cleanup 关闭（不预写任何网络记录，模拟竞态窗口）
func newBug29bDB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// makeNetworkEventWithAction 构造 Docker network 事件 JSON（name 在 Attributes["name"]）
func makeNetworkEventWithAction(action, netName string) []byte {
	return []byte(`{"Type":"network","Action":"` + action + `","Actor":{"ID":"deadbeef1234","Attributes":{"name":"` + netName + `","type":"bridge"}},"time":1700000000}`)
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG-29b 核心复现：竞态窗口内 completedPruneOwner 预注册阻止泄漏
// ══════════════════════════════════════════════════════════════════════════════

// TestBug29b_SudoBareNetCreate_RaceWindow_HiddenFromOthers
//
// 模拟竞态窗口：DB 尚未写入（SetNetworkOwner 未调用），
// 但 completedPruneOwner 已由修复代码预注册（模拟 forward 前的 Store）。
// 验证 bob、alice、sudo_test 非 sudo 视图均不应收到该事件。
func TestBug29b_SudoBareNetCreate_RaceWindow_HiddenFromOthers(t *testing.T) {
	db := newBug29bDB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	const netName = "sudovol123"

	// 模拟修复：forward 前预注册（DB 此时为空，等同于竞态窗口）
	entry := pruneOwnerInfo{ownerUID: bug29bSudoUID, privCtx: 1}
	p.completedPruneOwner.Store("network:"+netName, entry)
	defer p.completedPruneOwner.CompareAndDelete("network:"+netName, entry)

	createEvent := makeNetworkEventWithAction("create", netName)

	// Bug 核心断言：竞态窗口内 bob 不应收到 sudo 裸名网络 create 事件
	if p.eventBelongsToUser(createEvent, bug29bBobUID, false) {
		t.Errorf(
			"BUG-29b [竞态窗口泄漏]:\n"+
				"\t bob(uid=%d) 在竞态窗口内收到了 sudo 裸名网络 create 事件\n"+
				"\t 网络名: %s（DB 未写入，仅 completedPruneOwner 预注册）\n"+
				"\t 预期: eventBelongsToUser=false\n"+
				"\t 实际: eventBelongsToUser=true",
			bug29bBobUID, netName,
		)
	}

	// alice 也不应收到
	if p.eventBelongsToUser(createEvent, bug29bAliceUID, false) {
		t.Errorf("BUG-29b: alice(uid=%d) 不应收到 sudo_test 的 sudo 裸名网络 create 事件", bug29bAliceUID)
	}

	// sudo_test 以非 sudo 模式监听：privCtx==1 → 不应收到
	if p.eventBelongsToUser(createEvent, bug29bSudoUID, false) {
		t.Errorf("BUG-29b: sudo_test(uid=%d) 以非 sudo 模式监听，不应收到 privCtx=1 的裸名网络 create 事件", bug29bSudoUID)
	}
}

// TestBug29b_SudoBareNetCreate_SudoViewSees
//
// sudo 视图（sudoCtx=true）下，竞态窗口内仍能看到 create 事件。
func TestBug29b_SudoBareNetCreate_SudoViewSees(t *testing.T) {
	db := newBug29bDB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	const netName = "sudovol123"

	entry := pruneOwnerInfo{ownerUID: bug29bSudoUID, privCtx: 1}
	p.completedPruneOwner.Store("network:"+netName, entry)
	defer p.completedPruneOwner.CompareAndDelete("network:"+netName, entry)

	createEvent := makeNetworkEventWithAction("create", netName)

	// sudoCtx=true：completedPruneOwner 中 privCtx==1 的条件 (!sudoCtx && ...) 不触发
	if !p.eventBelongsToUser(createEvent, bug29bSudoUID, true) {
		t.Errorf("回归：sudo_test 以 sudo 模式监听时，应能在竞态窗口内看到自己的裸名网络 create 事件")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归：竞态窗口关闭后（DB 已写入），DB fallback 仍能正确隔离
// ══════════════════════════════════════════════════════════════════════════════

// TestBug29b_AfterRaceWindow_DBFallbackFiltersCorrectly
//
// 模拟竞态窗口关闭（SetNetworkOwner 已写入 DB，completedPruneOwner 条目已 defer 清理）。
// 验证 DB fallback 路径对 privCtx=1 的裸名网络仍能正确隔离。
func TestBug29b_AfterRaceWindow_DBFallbackFiltersCorrectly(t *testing.T) {
	db := newBug29bDB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	const netName = "sudovol123"
	const hexID = "deadbeef1234567890ab"
	sudoID := bug23SudoIdentity("sudo_test", bug29bSudoUID)

	// 模拟 postprocessResponse 调用 SetNetworkOwner（竞态窗口已关闭）
	if err := db.SetNetworkOwner(hexID, netName, sudoID); err != nil {
		t.Fatalf("SetNetworkOwner: %v", err)
	}
	// completedPruneOwner 无条目（defer 已清理）

	createEvent := makeNetworkEventWithAction("create", netName)

	// DB fallback：privCtx=1 → bob 不可见
	if p.eventBelongsToUser(createEvent, bug29bBobUID, false) {
		t.Errorf("回归：竞态窗口关闭后，bob 不应通过 DB fallback 看到 sudo 裸名网络 create 事件")
	}

	// sudo_test 非 sudo 视图：privCtx=1 → 不可见
	if p.eventBelongsToUser(createEvent, bug29bSudoUID, false) {
		t.Errorf("回归：竞态窗口关闭后，sudo_test 非 sudo 视图不应看到 privCtx=1 的裸名网络事件")
	}

	// sudo_test sudo 视图：可见
	if !p.eventBelongsToUser(createEvent, bug29bSudoUID, true) {
		t.Errorf("回归：sudo_test sudo 视图在竞态窗口关闭后应能看到自己的裸名网络事件")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归：前缀命名网络（非特权用户）path 2 不受影响
// ══════════════════════════════════════════════════════════════════════════════

// TestBug29b_RegularUserPrefixedNet_Unaffected
//
// 普通用户 docker network create → 名称有 _u{uid}_ 段。
// 事件通过 path 2 直接处理，不依赖 completedPruneOwner 或路径3。
// 修复不应影响此路径。
func TestBug29b_RegularUserPrefixedNet_Unaffected(t *testing.T) {
	db := newBug29bDB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	bobNetName := "mynet_u1001_mynet"

	createEvent := makeNetworkEventWithAction("create", bobNetName)

	// bob 对自己前缀命名的网络 create 事件：path 2 命中
	if !p.eventBelongsToUser(createEvent, bug29bBobUID, false) {
		t.Errorf("回归：bob 对自己前缀命名的网络 create 事件应能看到（path 2）")
	}

	// alice 对 bob 网络的 create 事件：path 2 命中 → 不可见
	if p.eventBelongsToUser(createEvent, bug29bAliceUID, false) {
		t.Errorf("回归：alice 不应看到 bob 的前缀命名网络 create 事件（path 2）")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归：handleNetworkPrune 移除死写后，prune 事件过滤行为不变
// ══════════════════════════════════════════════════════════════════════════════

// TestBug29b_NetworkPrune_DeadStoreRemoved_NoRegressionInEventFilter
//
// 验证 handleNetworkPrune 移除 completedPruneOwner hex-ID 死写后，
// 路径3对裸名网络（名称匹配）的查询行为不受影响。
// 死写 key 为 "network:hexID"，路径3 Load key 为 "network:name"，从未命中，移除无副作用。
func TestBug29b_NetworkPrune_DeadStoreRemoved_NoRegressionInEventFilter(t *testing.T) {
	db := newBug29bDB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	const netName = "mynet"
	const hexID = "aabbcc112233445566"

	// 模拟移除死写之前的行为：手动向 map 存入 hex-ID key（旧代码会存这个）
	deadEntry := pruneOwnerInfo{ownerUID: bug29bBobUID, privCtx: 0}
	p.completedPruneOwner.Store("network:"+hexID, deadEntry)
	defer p.completedPruneOwner.Delete("network:" + hexID)

	destroyEvent := makeNetworkEventWithAction("destroy", netName)

	// 路径3 Load("network:name") ≠ Load("network:hexID")，hex key 不命中
	// DB 也无记录 → return true（系统网络放行）
	if !p.eventBelongsToUser(destroyEvent, bug29bBobUID, false) {
		t.Errorf("回归：hex-ID 死写 key 不影响路径3对名称 key 的查询，系统网络应放行")
	}
}
