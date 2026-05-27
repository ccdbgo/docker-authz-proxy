package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-29：sudo 裸名卷 create 事件在竞态窗口内泄漏给所有订阅者
//
// 根因：sudo docker volume create sudovol123（裸名，无 user-{uid}-volume- 前缀）
// 导致 Docker 在 SetVolumeOwner 写入 DB 之前就发出 volume create 事件。
// eventBelongsToUser 路径：
//   1. path 1 miss：名称无 user-{uid}-volume- 前缀
//   2. path 2 miss：名称无 user- 前缀
//   3. completedPruneOwner miss：无 prune/rm 条目
//   4. DB fallback miss：SetVolumeOwner 尚未调用
//   5. 路径3：return true → 泄漏给所有订阅者 ✗
//
// 修复：preprocessRequest ActionVolumeCreate 特权分支解析 Name 存入 context；
// ServeHTTP 在 forward 前预注册 completedPruneOwner，覆盖竞态窗口。
// ══════════════════════════════════════════════════════════════════════════════

import (
	"net/http/httptest"
	"testing"

	"docker-authz-proxy/internal/authz"
)

const (
	bug29SudoUID  = 1003 // sudo_test
	bug29BobUID   = 1001
	bug29AliceUID = 1002
)

// newBug29DB 创建内存 DB 并注册 t.Cleanup 关闭（不预写任何卷记录，模拟竞态窗口）
func newBug29DB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG-29 核心复现：竞态窗口内 completedPruneOwner 预注册阻止泄漏
// ══════════════════════════════════════════════════════════════════════════════

// TestBug29_SudoBareVolCreate_RaceWindow_HiddenFromOthers
//
// 模拟竞态窗口：DB 尚未写入（SetVolumeOwner 未调用），
// 但 completedPruneOwner 已由修复代码预注册（模拟 forward 前的 Store）。
// 验证 bob、alice、sudo_test 非 sudo 视图均不应收到该事件。
func TestBug29_SudoBareVolCreate_RaceWindow_HiddenFromOthers(t *testing.T) {
	db := newBug29DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	const volName = "sudovol123"

	// 模拟修复：forward 前预注册（DB 此时为空，等同于竞态窗口）
	entry := pruneOwnerInfo{ownerUID: bug29SudoUID, privCtx: 1}
	p.completedPruneOwner.Store("volume:"+volName, entry)
	defer p.completedPruneOwner.CompareAndDelete("volume:"+volName, entry)

	createEvent := makeVolumeEventWithAction("create", volName)

	// Bug 核心断言：竞态窗口内 bob 不应收到 sudo 裸名卷 create 事件
	if p.eventBelongsToUser(createEvent, bug29BobUID, false) {
		t.Errorf(
			"BUG-29 [竞态窗口泄漏]:\n"+
				"\t bob(uid=%d) 在竞态窗口内收到了 sudo 裸名卷 create 事件\n"+
				"\t 卷名: %s（DB 未写入，仅 completedPruneOwner 预注册）\n"+
				"\t 预期: eventBelongsToUser=false\n"+
				"\t 实际: eventBelongsToUser=true",
			bug29BobUID, volName,
		)
	}

	// alice 也不应收到
	if p.eventBelongsToUser(createEvent, bug29AliceUID, false) {
		t.Errorf("BUG-29: alice(uid=%d) 不应收到 sudo_test 的 sudo 裸名卷 create 事件", bug29AliceUID)
	}

	// sudo_test 以非 sudo 模式监听：privCtx==1 → 不应收到
	if p.eventBelongsToUser(createEvent, bug29SudoUID, false) {
		t.Errorf("BUG-29: sudo_test(uid=%d) 以非 sudo 模式监听，不应收到 privCtx=1 的裸名卷 create 事件", bug29SudoUID)
	}
}

// TestBug29_SudoBareVolCreate_SudoViewSees
//
// sudo 视图（sudoCtx=true 或 IsPrivileged=true）不进入 eventBelongsToUser，
// 此处仅验证：sudo_test 以 sudo 模式监听时，竞态窗口内也能看到 create 事件。
func TestBug29_SudoBareVolCreate_SudoViewSees(t *testing.T) {
	db := newBug29DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	const volName = "sudovol123"

	entry := pruneOwnerInfo{ownerUID: bug29SudoUID, privCtx: 1}
	p.completedPruneOwner.Store("volume:"+volName, entry)
	defer p.completedPruneOwner.CompareAndDelete("volume:"+volName, entry)

	createEvent := makeVolumeEventWithAction("create", volName)

	// sudoCtx=true：completedPruneOwner 中 privCtx==1 的条件 (!sudoCtx && ...) 不触发
	if !p.eventBelongsToUser(createEvent, bug29SudoUID, true) {
		t.Errorf("回归：sudo_test 以 sudo 模式监听时，应能在竞态窗口内看到自己的裸名卷 create 事件")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归：竞态窗口关闭后（DB 已写入），DB fallback 仍能正确隔离
// ══════════════════════════════════════════════════════════════════════════════

// TestBug29_AfterRaceWindow_DBFallbackFiltersCorrectly
//
// 模拟竞态窗口关闭（SetVolumeOwner 已写入 DB，completedPruneOwner 条目已 defer 清理）。
// 验证 DB fallback 路径对 privCtx=1 的裸名卷仍能正确隔离。
func TestBug29_AfterRaceWindow_DBFallbackFiltersCorrectly(t *testing.T) {
	db := newBug29DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	const volName = "sudovol123"
	sudoID := bug23SudoIdentity("sudo_test", bug29SudoUID)

	// 模拟 postprocessResponse 调用 SetVolumeOwner（竞态窗口已关闭）
	if err := db.SetVolumeOwner(volName, sudoID); err != nil {
		t.Fatalf("SetVolumeOwner: %v", err)
	}
	// completedPruneOwner 无条目（defer 已清理）

	createEvent := makeVolumeEventWithAction("create", volName)

	// DB fallback：owner=sudo_test_uid，privCtx=1 → bob 不可见
	if p.eventBelongsToUser(createEvent, bug29BobUID, false) {
		t.Errorf("回归：竞态窗口关闭后，bob 不应通过 DB fallback 看到 sudo 裸名卷 create 事件")
	}

	// sudo_test 非 sudo 视图：privCtx=1 → 不可见
	if p.eventBelongsToUser(createEvent, bug29SudoUID, false) {
		t.Errorf("回归：竞态窗口关闭后，sudo_test 非 sudo 视图不应看到 privCtx=1 的裸名卷事件")
	}

	// sudo_test sudo 视图：可见
	if !p.eventBelongsToUser(createEvent, bug29SudoUID, true) {
		t.Errorf("回归：sudo_test sudo 视图在竞态窗口关闭后应能看到自己的裸名卷事件")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归：前缀命名卷（非特权用户）路径 1/2 不受影响
// ══════════════════════════════════════════════════════════════════════════════

// TestBug29_RegularUserPrefixedVol_Unaffected
//
// 普通用户 docker volume create → 卷名有 user-{uid}-volume- 前缀。
// 事件通过 path 1/2 直接处理，不依赖 completedPruneOwner 或 DB。
// 修复不应影响此路径。
func TestBug29_RegularUserPrefixedVol_Unaffected(t *testing.T) {
	db := newBug29DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	bobVolName := "user-1001-volume-mydata"

	createEvent := makeVolumeEventWithAction("create", bobVolName)

	// bob 对自己前缀命名的卷 create 事件：path 1 命中，DB 无记录也应返回 true
	if !p.eventBelongsToUser(createEvent, bug29BobUID, false) {
		t.Errorf("回归：bob 对自己前缀命名的卷 create 事件应能看到（path 1）")
	}

	// alice 对 bob 卷的 create 事件：path 2 命中 → 不可见
	if p.eventBelongsToUser(createEvent, bug29AliceUID, false) {
		t.Errorf("回归：alice 不应看到 bob 的前缀命名卷 create 事件（path 2）")
	}
}
