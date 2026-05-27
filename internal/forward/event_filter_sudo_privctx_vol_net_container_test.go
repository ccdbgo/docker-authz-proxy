package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-23：volume / network / container 事件流缺少 privileged_context 隔离
//
// BUG-22 修复了 image 事件流的 privileged_context 隔离（path 2 加了 privCtx 检查）；
// 但 volume / network 的路径 1/2 和 container 的 system.authz.owner.uid 路径
// 均未检查 privileged_context，导致：
//   - sudo docker volume create V → 普通 docker system events 仍能收到该 volume 事件
//   - sudo docker network create N → 普通 docker system events 仍能收到该 network 事件
//   - sudo docker run ...         → 普通 docker system events 仍能收到该 container 事件
//
// 修复：
//   - volume 路径 1：HasPrefix(ownPrefix) 后查 DB GetVolumePrivCtx；found && privCtx==1 → false
//   - network 路径 2：foundUID==uidStr 后查 DB GetNetworkPrivCtxByName；found && privCtx==1 → false
//   - container 路径：v==uidStr 后读 Attributes[LabelCallerType]；GetLastLabelValue=="sudo" → false
//   - 遗留容器（无 LabelCallerType 标签）：GetLastLabelValue("")=="" → 正常放行
//   - DB 无记录时（prune 已删）：found=false → 不隐藏，属主仍可收到自己的 prune 事件
//   - completedPruneOwner 值类型 int → pruneOwnerInfo{uid,privCtx}，保持 prune 竞态补偿正确
// ══════════════════════════════════════════════════════════════════════════════

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// makeContainerEventWithCallerType 构造携带 system.authz.owner.uid 和 system.authz.caller.type 的 container 事件。
// callerType 为 "" 时不注入该字段（模拟遗留容器）。
func makeContainerEventWithCallerType(action, containerID string, ownerUID int, callerType string) []byte {
	uidStr := fmt.Sprintf("%d", ownerUID)
	if callerType == "" {
		return []byte(fmt.Sprintf(
			`{"Type":"container","Action":%q,"Actor":{"ID":%q,"Attributes":{"system.authz.owner.uid":%q,"image":"alpine"}}}`,
			action, containerID, uidStr,
		))
	}
	return []byte(fmt.Sprintf(
		`{"Type":"container","Action":%q,"Actor":{"ID":%q,"Attributes":{"system.authz.owner.uid":%q,"system.authz.caller.type":%q,"image":"alpine"}}}`,
		action, containerID, uidStr, callerType,
	))
}

const (
	bug23SudoUID = 1005 // sudo_test
	bug23BobUID  = 1002
)

// ── 辅助：构造 sudo / regular 身份 ──────────────────────────────────────────

func bug23SudoIdentity(username string, uid int) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		EffectiveUsername: "root",
		EffectiveUID:      0,
		UserType:          auth.UserTypeSudo,
	}
}

func bug23RegularIdentity(username string, uid int) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		EffectiveUsername: username,
		EffectiveUID:      uid,
		UserType:          auth.UserTypeRegular,
	}
}

// newBug23DB 创建内存 DB 并注册 t.Cleanup 关闭
func newBug23DB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG-23a：sudo volume 事件在非 sudo 视图中应不可见
// ══════════════════════════════════════════════════════════════════════════════

// TestPrivCtx_SudoVolumeEvent_HiddenInNonSudoView_regression
//
// sudo_test 以 sudo 命令创建卷（privileged_context=1），
// 之后以非 sudo 模式监听事件（sudoCtx=false）。
// 修复前 FAIL：volume 路径 1 直接 return true，不检查 privileged_context。
// 修复后 PASS：路径 1 查 DB，found && privCtx==1 → return false。
func TestPrivCtx_SudoVolumeEvent_HiddenInNonSudoView_regression(t *testing.T) {
	db := newBug23DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	sudoID := bug23SudoIdentity("sudo_test", bug23SudoUID)
	volName := fmt.Sprintf("user-%d-volume-secret", bug23SudoUID)

	// sudo docker volume create → privileged_context=1
	if err := db.SetVolumeOwner(volName, sudoID); err != nil {
		t.Fatalf("SetVolumeOwner: %v", err)
	}

	destroyEvent := makeVolumeEventWithAction("destroy", volName)

	// Bug 核心断言：非 sudo 视图不应收到 sudo volume 事件
	if p.eventBelongsToUser(destroyEvent, bug23SudoUID, false) {
		t.Errorf(
			"BUG-23a [volume privileged_context 隔离失效]:\n"+
				"\tsudo_test(uid=%d) 以非 sudo 模式监听，但收到了 sudo volume destroy 事件\n"+
				"\t卷名: %s（privileged_context=1）\n"+
				"\t预期: eventBelongsToUser=false\n"+
				"\t实际: eventBelongsToUser=true（事件泄漏到非特权视图）",
			bug23SudoUID, volName,
		)
	}

	// 回归：bob 不应看到 sudo_test 的 sudo volume 事件
	if p.eventBelongsToUser(destroyEvent, bug23BobUID, false) {
		t.Errorf("回归：bob(uid=%d) 不应看到 sudo_test 的 sudo volume 事件", bug23BobUID)
	}

	// 回归：sudo_test 以 sudo 模式监听（sudoCtx=true）时应能看到
	if !p.eventBelongsToUser(destroyEvent, bug23SudoUID, true) {
		t.Errorf("回归：sudo_test 以 sudo 模式监听时应能看到自己的 sudo volume 事件")
	}
}

// TestPrivCtx_RegularVolumeEvent_VisibleInNonSudoView_regression
//
// sudo_test 以普通命令创建卷（privileged_context=0），
// 以非 sudo 模式监听时应能看到该事件（回归：修复不应过度过滤）。
func TestPrivCtx_RegularVolumeEvent_VisibleInNonSudoView_regression(t *testing.T) {
	db := newBug23DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	regularID := bug23RegularIdentity("sudo_test", bug23SudoUID)
	volName := fmt.Sprintf("user-%d-volume-data", bug23SudoUID)

	// 普通命令创建卷 → privileged_context=0
	if err := db.SetVolumeOwner(volName, regularID); err != nil {
		t.Fatalf("SetVolumeOwner: %v", err)
	}

	createEvent := makeVolumeEventWithAction("create", volName)

	// 普通卷（privileged_context=0）在非 sudo 视图中应可见
	if !p.eventBelongsToUser(createEvent, bug23SudoUID, false) {
		t.Errorf(
			"回归失效：sudo_test 以非 sudo 模式创建的卷（privileged_context=0），"+
				"以非 sudo 模式监听时不应被过滤，但 eventBelongsToUser 返回 false",
		)
	}
}

// TestPrivCtx_VolumeEvent_DBNotFound_Passthrough_regression
//
// 卷已被 prune 删除（DB 无记录），eventBelongsToUser 不应因 DB miss 而误隐藏属主的事件。
// 此场景由 completedPruneOwner 竞态补偿覆盖，但若窗口已过期（无记录），
// volume 路径应退化到路径 3（放行）而非 return false。
func TestPrivCtx_VolumeEvent_DBNotFound_Passthrough_regression(t *testing.T) {
	// DB 为空（无任何卷记录）
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	volName := fmt.Sprintf("user-%d-volume-gone", bug23SudoUID)
	destroyEvent := makeVolumeEventWithAction("destroy", volName)

	// DB 无记录时，属主的事件应放行（路径 prune 竞态补偿窗口过期后的行为）
	if !p.eventBelongsToUser(destroyEvent, bug23SudoUID, false) {
		t.Errorf(
			"回归：DB 无记录的卷 destroy 事件应放行（路径 3），但 eventBelongsToUser 返回 false",
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG-23b：sudo network 事件在非 sudo 视图中应不可见
// ══════════════════════════════════════════════════════════════════════════════

// TestPrivCtx_SudoNetworkEvent_HiddenInNonSudoView_regression
//
// sudo_test 以 sudo 命令创建普通用户网络（privileged_context=1），
// 以非 sudo 模式监听时不应看到该网络事件。
// 修复前 FAIL：网络路径 2 直接 return foundUID==uidStr，不检查 privileged_context。
// 修复后 PASS：路径 2 查 DB，found && privCtx==1 → return false。
func TestPrivCtx_SudoNetworkEvent_HiddenInNonSudoView_regression(t *testing.T) {
	db := newBug23DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	sudoID := bug23SudoIdentity("sudo_test", bug23SudoUID)
	// 用户普通网络格式：{username}_u{uid}_{user-defined-name}
	netName := fmt.Sprintf("sudo_test_u%d_mynet", bug23SudoUID)
	netID := "deadbeef001122334455667788990000aabbccdd"

	// sudo docker network create → privileged_context=1
	if err := db.SetNetworkOwner(netID, netName, sudoID); err != nil {
		t.Fatalf("SetNetworkOwner: %v", err)
	}

	// Docker 网络事件：Attributes["name"] 为网络名
	netEvent := makeNetworkEvent("create", netName)

	// Bug 核心断言：非 sudo 视图不应收到 sudo network 事件
	if p.eventBelongsToUser(netEvent, bug23SudoUID, false) {
		t.Errorf(
			"BUG-23b [network privileged_context 隔离失效]:\n"+
				"\tsudo_test(uid=%d) 以非 sudo 模式监听，但收到了 sudo network create 事件\n"+
				"\t网络名: %s（privileged_context=1）\n"+
				"\t预期: eventBelongsToUser=false\n"+
				"\t实际: eventBelongsToUser=true",
			bug23SudoUID, netName,
		)
	}

	// 回归：bob 不应看到 sudo_test 的 sudo 网络事件
	if p.eventBelongsToUser(netEvent, bug23BobUID, false) {
		t.Errorf("回归：bob(uid=%d) 不应看到 sudo_test 的 sudo network 事件", bug23BobUID)
	}

	// 回归：sudo_test 以 sudo 模式监听时应能看到
	if !p.eventBelongsToUser(netEvent, bug23SudoUID, true) {
		t.Errorf("回归：sudo_test 以 sudo 模式监听时应能看到自己的 sudo network 事件")
	}
}

// TestPrivCtx_RegularNetworkEvent_VisibleInNonSudoView_regression
//
// sudo_test 以普通命令创建网络（privileged_context=0），
// 以非 sudo 模式监听时应能看到该事件。
func TestPrivCtx_RegularNetworkEvent_VisibleInNonSudoView_regression(t *testing.T) {
	db := newBug23DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	regularID := bug23RegularIdentity("sudo_test", bug23SudoUID)
	netName := fmt.Sprintf("sudo_test_u%d_pubnet", bug23SudoUID)
	netID := "aabb0011ccdd2233445566778899eeff00112233"

	// 普通命令创建网络 → privileged_context=0
	if err := db.SetNetworkOwner(netID, netName, regularID); err != nil {
		t.Fatalf("SetNetworkOwner: %v", err)
	}

	netEvent := makeNetworkEvent("connect", netName)

	if !p.eventBelongsToUser(netEvent, bug23SudoUID, false) {
		t.Errorf(
			"回归失效：普通网络（privileged_context=0）在非 sudo 视图中应可见，但 eventBelongsToUser 返回 false",
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG-23c：sudo container 事件在非 sudo 视图中应不可见
// ══════════════════════════════════════════════════════════════════════════════

// TestPrivCtx_SudoContainerEvent_HiddenInNonSudoView_regression
//
// sudo docker run 创建的容器（LabelCallerType="sudo"），
// 以非 sudo 模式监听时不应看到 start/stop 等容器事件。
// 修复前 FAIL：container 路径仅检查 system.authz.owner.uid == uidStr，不检查 caller type。
// 修复后 PASS：v==uidStr 后检查 isolation.LabelCallerType=="sudo" → return false。
func TestPrivCtx_SudoContainerEvent_HiddenInNonSudoView_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// sudo docker run 的容器事件：owner.uid=1005，caller.type=sudo
	ctrEvent := makeContainerEventWithCallerType("start", "user-1005-ctr-abc123", bug23SudoUID, "sudo")

	// Bug 核心断言：非 sudo 视图不应收到 sudo container 事件
	if p.eventBelongsToUser(ctrEvent, bug23SudoUID, false) {
		t.Errorf(
			"BUG-23c [container privileged_context 隔离失效]:\n"+
				"\tsudo_test(uid=%d) 以非 sudo 模式监听，但收到了 sudo container start 事件\n"+
				"\tLabelCallerType=sudo\n"+
				"\t预期: eventBelongsToUser=false\n"+
				"\t实际: eventBelongsToUser=true",
			bug23SudoUID,
		)
	}

	// 回归：bob 不应看到 sudo_test 的容器事件
	if p.eventBelongsToUser(ctrEvent, bug23BobUID, false) {
		t.Errorf("回归：bob(uid=%d) 不应看到 sudo_test 的 sudo container 事件", bug23BobUID)
	}

	// 回归：sudo_test 以 sudo 模式监听（sudoCtx=true）时应能看到
	if !p.eventBelongsToUser(ctrEvent, bug23SudoUID, true) {
		t.Errorf("回归：sudo_test 以 sudo 模式监听时应能看到自己的 sudo container 事件")
	}
}

// TestPrivCtx_RegularContainerEvent_VisibleInNonSudoView_regression
//
// 普通命令创建的容器（LabelCallerType="regular"），
// 以非 sudo 模式监听时应能看到该事件。
func TestPrivCtx_RegularContainerEvent_VisibleInNonSudoView_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	ctrEvent := makeContainerEventWithCallerType("stop", "user-1005-ctr-xyz789", bug23SudoUID, "regular")

	if !p.eventBelongsToUser(ctrEvent, bug23SudoUID, false) {
		t.Errorf(
			"回归失效：普通容器（LabelCallerType=regular）在非 sudo 视图中应可见，但 eventBelongsToUser 返回 false",
		)
	}
}

// TestPrivCtx_LegacyContainer_NoCallerType_Passthrough_regression
//
// 遗留容器（代理上线前创建，无 LabelCallerType 标签）：
// GetLastLabelValue("") == "" != "sudo"，不应被过滤，正常放行。
func TestPrivCtx_LegacyContainer_NoCallerType_Passthrough_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// 无 LabelCallerType 标签的遗留容器事件
	ctrEvent := makeContainerEventWithCallerType("die", "user-1005-ctr-legacy0", bug23SudoUID, "")

	if !p.eventBelongsToUser(ctrEvent, bug23SudoUID, false) {
		t.Errorf(
			"回归失效：遗留容器（无 LabelCallerType）应通过 owner.uid 匹配放行，但 eventBelongsToUser 返回 false",
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG-23d：pruneOwnerInfo 类型升级后竞态补偿行为正确
// ══════════════════════════════════════════════════════════════════════════════

// TestPrivCtx_PruneRace_VolumeWithPruneOwnerInfo_regression
//
// completedPruneOwner 值类型从 int 升级为 pruneOwnerInfo 后，
// 属主仍能看到自己的 prune 事件，其他用户仍不可见。
func TestPrivCtx_PruneRace_VolumeWithPruneOwnerInfo_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	volName := fmt.Sprintf("user-%d-volume-pruned", bug23SudoUID)
	pruneKey := "volume:" + volName
	p.completedPruneOwner.Store(pruneKey, pruneOwnerInfo{ownerUID: bug23SudoUID, privCtx: 0})

	destroyEvent := makeVolumeEventWithAction("destroy", volName)

	// 属主可见
	if !p.eventBelongsToUser(destroyEvent, bug23SudoUID, false) {
		t.Errorf("pruneOwnerInfo 升级后：属主(uid=%d) 应能看到自己的 prune volume 事件", bug23SudoUID)
	}

	// 他人不可见
	if p.eventBelongsToUser(destroyEvent, bug23BobUID, false) {
		t.Errorf("pruneOwnerInfo 升级后：bob(uid=%d) 不应看到 sudo_test 的 prune volume 事件", bug23BobUID)
	}
}
