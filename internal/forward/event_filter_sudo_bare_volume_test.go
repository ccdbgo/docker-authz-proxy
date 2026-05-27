package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-26：sudo docker volume create <裸名> 事件泄漏给所有用户
//
// 根因：ActionVolumeCreate 对特权用户跳过 InjectVolumeNamePrefix
// （"if !id.IsPrivileged()"），sudo 创建的卷名无 user-{uid}-volume- 前缀。
// eventBelongsToUser 路径 1/2 均依赖前缀格式；裸名卷绕过所有前缀检查，
// 直接命中路径 3（return true），致使 create/destroy 事件广播给所有用户。
//
// 修复点 A（create 事件，BUG-26a）：
//   路径 3 前加 DB fallback——对 DB 中存在的裸名卷做属主 + privCtx 检查。
//
// 修复点 B（destroy 事件，BUG-26b）：
//   ActionVolumeRemove 在 DeleteVolume 前将 pruneOwnerInfo{ownerUID, privCtx}
//   存入 completedPruneOwner；同时在该路径增加 !sudoCtx && privCtx==1 守卫。
// ══════════════════════════════════════════════════════════════════════════════

import (
	"net/http/httptest"
	"testing"
)

// ──────────────────────────────────────────────────────────────────────────────
// BUG-26a：裸名卷 create 事件泄漏（DB fallback 缺失）
// ──────────────────────────────────────────────────────────────────────────────

// TestBug26a_SudoBareVolume_CreateEvent_HiddenFromBob_regression
//
// sudo_test 以 sudo 命令创建裸名卷 "sudovol123"（无 user- 前缀），DB 存有 privCtx=1。
// bob(uid=1002) 监听 docker events，不应收到该卷的 create 事件。
//
// 修复前 FAIL：裸名命中路径 3 → return true → bob 收到事件。
// 修复后 PASS：DB fallback 查到 owner.UID=1005 ≠ bob.UID=1002 → return false。
func TestBug26a_SudoBareVolume_CreateEvent_HiddenFromBob_regression(t *testing.T) {
	db := newBug23DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	sudoID := bug23SudoIdentity("sudo_test", bug23SudoUID)
	volName := "sudovol123" // 裸名，无 user-{uid}-volume- 前缀

	if err := db.SetVolumeOwner(volName, sudoID); err != nil {
		t.Fatalf("SetVolumeOwner: %v", err)
	}

	createEvent := makeVolumeEventWithAction("create", volName)

	if p.eventBelongsToUser(createEvent, bug23BobUID, false) {
		t.Errorf(
			"BUG-26a [裸名卷 create 事件泄漏 → bob]:\n"+
				"\tbob(uid=%d) 不应收到 sudo_test 的 sudo 裸名卷 create 事件\n"+
				"\t卷名: %q（DB owner_uid=%d, privileged_context=1）\n"+
				"\t预期: eventBelongsToUser=false\n"+
				"\t实际: eventBelongsToUser=true（路径 3 对无前缀卷放行）",
			bug23BobUID, volName, bug23SudoUID,
		)
	}
}

// TestBug26a_SudoBareVolume_CreateEvent_HiddenFromOwnerNonSudo_regression
//
// sudo_test 以非 sudo 模式监听，不应收到自己 sudo 创建的裸名卷事件。
//
// 修复前 FAIL：路径 3 → return true。
// 修复后 PASS：DB fallback owner.UID 匹配，但 privCtx==1 && !sudoCtx → return false。
func TestBug26a_SudoBareVolume_CreateEvent_HiddenFromOwnerNonSudo_regression(t *testing.T) {
	db := newBug23DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	sudoID := bug23SudoIdentity("sudo_test", bug23SudoUID)
	volName := "sudovol123"

	if err := db.SetVolumeOwner(volName, sudoID); err != nil {
		t.Fatalf("SetVolumeOwner: %v", err)
	}

	createEvent := makeVolumeEventWithAction("create", volName)

	if p.eventBelongsToUser(createEvent, bug23SudoUID, false) {
		t.Errorf(
			"BUG-26a [裸名卷 create 事件泄漏 → owner 非 sudo 视图]:\n"+
				"\tsudo_test(uid=%d) 非 sudo 模式不应收到自己 sudo 创建的裸名卷 create 事件\n"+
				"\t卷名: %q（privileged_context=1）\n"+
				"\t预期: eventBelongsToUser=false\n"+
				"\t实际: eventBelongsToUser=true（privCtx 检查缺失）",
			bug23SudoUID, volName,
		)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// BUG-26b：裸名卷 destroy 事件泄漏（completedPruneOwner privCtx 守卫缺失）
// ──────────────────────────────────────────────────────────────────────────────

// TestBug26b_SudoBareVolume_DestroyEvent_HiddenFromBob_regression
//
// ActionVolumeRemove 已将 pruneOwnerInfo{ownerUID=1005, privCtx=1} 存入 completedPruneOwner。
// bob(uid=1002) 不应收到 "sudovol123" 的 destroy 事件。
//
// 修复前 FAIL：completedPruneOwner 路径 entry.ownerUID(1005) != bob(1002) → return false（实际已正确）。
// 此用例验证 bob 路径在修改 completedPruneOwner 逻辑后仍保持正确。
func TestBug26b_SudoBareVolume_DestroyEvent_HiddenFromBob_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	volName := "sudovol123"
	pruneKey := "volume:" + volName
	p.completedPruneOwner.Store(pruneKey, pruneOwnerInfo{ownerUID: bug23SudoUID, privCtx: 1})

	destroyEvent := makeVolumeEventWithAction("destroy", volName)

	if p.eventBelongsToUser(destroyEvent, bug23BobUID, false) {
		t.Errorf(
			"BUG-26b [completedPruneOwner 路径：bob 不应看到他人 sudo 卷 destroy]:\n"+
				"\tbob(uid=%d) 不应收到 sudo_test 的裸名卷 destroy 事件\n"+
				"\t卷名: %q（completedPruneOwner ownerUID=%d, privCtx=1）\n"+
				"\t预期: eventBelongsToUser=false\n"+
				"\t实际: eventBelongsToUser=true",
			bug23BobUID, volName, bug23SudoUID,
		)
	}
}

// TestBug26b_SudoBareVolume_DestroyEvent_HiddenFromOwnerNonSudo_regression
//
// ActionVolumeRemove 已将 pruneOwnerInfo{ownerUID=1005, privCtx=1} 存入 completedPruneOwner。
// sudo_test 以非 sudo 模式监听，不应收到 "sudovol123" 的 destroy 事件。
//
// 修复前 FAIL：completedPruneOwner 路径仅检查 ownerUID==uid → return true（泄漏）。
// 修复后 PASS：增加 !sudoCtx && privCtx==1 → return false。
func TestBug26b_SudoBareVolume_DestroyEvent_HiddenFromOwnerNonSudo_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	volName := "sudovol123"
	pruneKey := "volume:" + volName
	p.completedPruneOwner.Store(pruneKey, pruneOwnerInfo{ownerUID: bug23SudoUID, privCtx: 1})

	destroyEvent := makeVolumeEventWithAction("destroy", volName)

	if p.eventBelongsToUser(destroyEvent, bug23SudoUID, false) {
		t.Errorf(
			"BUG-26b [completedPruneOwner privCtx 守卫缺失]:\n"+
				"\tsudo_test(uid=%d) 非 sudo 模式不应收到 privCtx=1 的裸名卷 destroy 事件\n"+
				"\t卷名: %q（completedPruneOwner privCtx=1）\n"+
				"\t预期: eventBelongsToUser=false\n"+
				"\t实际: eventBelongsToUser=true（completedPruneOwner 路径未检查 privCtx）",
			bug23SudoUID, volName,
		)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// 回归：正确行为不受影响
// ──────────────────────────────────────────────────────────────────────────────

// TestBug26_SudoBareVolume_VisibleInSudoView_regression
//
// sudo_test 以 sudo 模式监听（sudoCtx=true），应能看到自己的 sudo 裸名卷事件。
func TestBug26_SudoBareVolume_VisibleInSudoView_regression(t *testing.T) {
	db := newBug23DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	sudoID := bug23SudoIdentity("sudo_test", bug23SudoUID)
	volName := "sudovol123"

	if err := db.SetVolumeOwner(volName, sudoID); err != nil {
		t.Fatalf("SetVolumeOwner: %v", err)
	}

	createEvent := makeVolumeEventWithAction("create", volName)

	if !p.eventBelongsToUser(createEvent, bug23SudoUID, true) {
		t.Errorf(
			"回归：sudo_test(uid=%d) 以 sudo 模式监听时应能看到自己的 sudo 裸名卷 create 事件，但被过滤",
			bug23SudoUID,
		)
	}
}

// TestBug26_RegularBareVolumeRm_DestroyStillVisibleToOwner_regression
//
// 普通命令创建的裸名卷（privCtx=0）被 rm 后，destroy 事件仍应对属主可见。
// 此测试使用裸名（无前缀），强制走 completedPruneOwner 路径，
// 验证 privCtx=0 的守卫条件 (!sudoCtx && privCtx==1) 为 false，不引入过度过滤。
func TestBug26_RegularBareVolumeRm_DestroyStillVisibleToOwner_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// 裸名，无前缀 → 强制走 completedPruneOwner 路径（路径 1/2 不命中）
	volName := "regularbarevol"
	pruneKey := "volume:" + volName
	p.completedPruneOwner.Store(pruneKey, pruneOwnerInfo{ownerUID: bug23SudoUID, privCtx: 0})

	destroyEvent := makeVolumeEventWithAction("destroy", volName)

	if !p.eventBelongsToUser(destroyEvent, bug23SudoUID, false) {
		t.Errorf(
			"回归：普通裸名卷（privCtx=0）destroy 事件应对属主(uid=%d)可见（completedPruneOwner 路径），但被过滤",
			bug23SudoUID,
		)
	}
}

// TestBug26_SystemVolume_UnknownName_Passthrough_regression
//
// 名称既无标准前缀、又不在 DB 中的卷（系统卷/匿名卷），事件应放行（路径 3）。
// 验证 DB fallback 的 found=false 分支不引入过度过滤。
func TestBug26_SystemVolume_UnknownName_Passthrough_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	// DB 中无任何记录，模拟系统卷或 buildkit 匿名卷事件

	sysVolEvent := makeVolumeEventWithAction("mount", "tmpfs-buildkit-cache-001")

	if !p.eventBelongsToUser(sysVolEvent, bug23BobUID, false) {
		t.Errorf(
			"回归：系统卷（非用户卷，DB 无记录）事件应放行（路径 3），但被过滤",
		)
	}
}
