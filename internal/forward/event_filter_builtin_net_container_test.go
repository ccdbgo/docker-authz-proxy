package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-31：sudo docker run 的 network connect/disconnect 事件通过内置 bridge 网络
// 泄漏给其他用户及属主非 sudo 视图。
//
// 根因：eventBelongsToUser path 3（无 _u{digits}_ 段）完全忽略
// attrs["container"] 字段，内置网络事件无条件 return true。
//
// 修复：path 3 末尾若 attrs["container"] 非空，查 DB GetContainerOwnerAndPrivCtx：
//   - found=false → 放行（竞态窗口/系统容器）
//   - ownerUID != uid → false（他人容器）
//   - !sudoCtx && privCtx==1 → false（sudo 容器在非 sudo 视图中不可见）
//
// 关于 completedPruneOwner 补偿路径的 privCtx 值：
//   handleContainerPrune 调用 GetContainerIDsByOwner（SQL: privileged_context=0），
//   因此 completedPruneOwner["container:ctnID"] 中 privCtx 在生产中始终为 0。
//   else if 内的 privCtx==1 分支为防御性代码，生产中不可达。
// ══════════════════════════════════════════════════════════════════════════════

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// makeNetworkConnectEvent 构造 network connect/disconnect 事件 JSON。
// Docker 真实格式：Actor.ID 为网络 hex ID，Attributes 含 container/name/type。
func makeNetworkConnectEvent(action, netName, containerID string) []byte {
	return []byte(fmt.Sprintf(
		`{"Type":"network","Action":%q,"Actor":{"ID":"70840325c2dee182a55b","Attributes":{"container":%q,"name":%q,"type":"bridge"}},"time":1700000000}`,
		action, containerID, netName,
	))
}

const (
	bug31SudoUID  = 1005 // sudo_test
	bug31BobUID   = 1002
	bug31AliceUID = 1003
)

func bug31SudoIdentity() *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      "sudo_test",
		RealUID:           bug31SudoUID,
		EffectiveUsername: "root",
		EffectiveUID:      0,
		UserType:          auth.UserTypeSudo,
	}
}

func bug31RegularIdentity(username string, uid int) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		EffectiveUsername: username,
		EffectiveUID:      uid,
		UserType:          auth.UserTypeRegular,
	}
}

func newBug31DB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ── BUG-31 核心复现 ───────────────────────────────────────────────────────────

// TestBug31_SudoRun_BridgeConnectEvent_HiddenFromOthers_regression
//
// 修复前 FAIL：sudo docker run 的 network connect 事件（name=bridge）
// 通过 path 3 return true 泄漏给 bob、alice、sudo_test 非 sudo 视图。
// 修复后 PASS：path 3 末尾检查 attrs["container"]，按容器归属过滤。
func TestBug31_SudoRun_BridgeConnectEvent_HiddenFromOthers_regression(t *testing.T) {
	db := newBug31DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	const containerID = "3c0cbcc6bc7f5021587e837026853ee0e3927f7e64b5ac43ed75f6b809d9c3a5"

	// sudo docker run → SetContainerOwner with sudo identity → privileged_context=1
	if err := db.SetContainerOwner(containerID, bug31SudoIdentity(), "sha256:abc123"); err != nil {
		t.Fatalf("SetContainerOwner: %v", err)
	}

	connectEvent := makeNetworkConnectEvent("connect", "bridge", containerID)

	// ── Bug 核心断言 ──────────────────────────────────────────────────────────

	if p.eventBelongsToUser(connectEvent, bug31BobUID, false) {
		t.Errorf(
			"BUG-31 [泄漏给 bob]:\n"+
				"\tbob(uid=%d) 收到了 sudo_test 的 sudo 容器 bridge connect 事件\n"+
				"\tcontainerID=%s, privileged_context=1\n"+
				"\t预期: false（他人容器）\n"+
				"\t实际: true（泄漏）",
			bug31BobUID, containerID,
		)
	}

	if p.eventBelongsToUser(connectEvent, bug31AliceUID, false) {
		t.Errorf(
			"BUG-31 [泄漏给 alice]:\n"+
				"\talice(uid=%d) 收到了 sudo_test 的 sudo 容器 bridge connect 事件\n"+
				"\t预期: false，实际: true（泄漏）",
			bug31AliceUID,
		)
	}

	// sudo_test 以非 sudo 视图监听（sudoCtx=false）→ privCtx==1 → 不可见
	if p.eventBelongsToUser(connectEvent, bug31SudoUID, false) {
		t.Errorf(
			"BUG-31 [泄漏给属主非 sudo 视图]:\n"+
				"\tsudo_test(uid=%d) 以非 sudo 模式监听，仍收到 sudo 容器 bridge connect 事件\n"+
				"\t预期: false（privCtx=1 非 sudo 视图隐藏）\n"+
				"\t实际: true（泄漏）",
			bug31SudoUID,
		)
	}

	// ── 回归：sudo 视图（函数层面 sudoCtx=true）应可见 ──────────────────────
	// 注意：生产路径中 sudo docker events 会由 IsPrivileged() 在 line 3598 直接跳过过滤；
	// 此处直接调用函数，验证函数本身在 sudoCtx=true 时不误过滤属主。
	if !p.eventBelongsToUser(connectEvent, bug31SudoUID, true) {
		t.Errorf(
			"回归 [sudo 视图丢失]:\n"+
				"\tsudo_test(uid=%d) 以 sudo 模式监听，不应被过滤\n"+
				"\t预期: true，实际: false",
			bug31SudoUID,
		)
	}

	// ── 对称验证：disconnect 事件相同逻辑 ───────────────────────────────────

	disconnectEvent := makeNetworkConnectEvent("disconnect", "bridge", containerID)

	if p.eventBelongsToUser(disconnectEvent, bug31BobUID, false) {
		t.Errorf("BUG-31: bob 不应收到 sudo 容器的 bridge disconnect 事件")
	}
	if !p.eventBelongsToUser(disconnectEvent, bug31SudoUID, true) {
		t.Errorf("回归: sudo 视图应看到 bridge disconnect 事件")
	}
}

// ── 回归：不影响普通用户容器 ────────────────────────────────────────────────

// TestBug31_RegularRun_BridgeConnectEvent_VisibleToOwner_regression
//
// 普通 docker run（privileged_context=0）的容器连接 bridge，
// 属主在非 sudo 视图下应仍可见（修复不应过度过滤）。
func TestBug31_RegularRun_BridgeConnectEvent_VisibleToOwner_regression(t *testing.T) {
	db := newBug31DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	const containerID = "aabbcc001122334455667788990000aabbccdd0011"

	bobID := bug31RegularIdentity("bob", bug31BobUID)
	if err := db.SetContainerOwner(containerID, bobID, "sha256:def456"); err != nil {
		t.Fatalf("SetContainerOwner: %v", err)
	}

	connectEvent := makeNetworkConnectEvent("connect", "bridge", containerID)

	// bob 以非 sudo 模式监听自己的普通容器 bridge 事件 → 应可见
	if !p.eventBelongsToUser(connectEvent, bug31BobUID, false) {
		t.Errorf(
			"回归 [普通容器过滤过度]:\n"+
				"\tbob(uid=%d) 的普通容器（privileged_context=0）bridge connect 事件被错误过滤\n"+
				"\t预期: true，实际: false",
			bug31BobUID,
		)
	}

	// alice 不应看到 bob 的容器事件
	if p.eventBelongsToUser(connectEvent, bug31AliceUID, false) {
		t.Errorf("回归: alice 不应看到 bob 的普通容器 bridge connect 事件")
	}
}

// ── 回归：无 container 属性的内置网络事件仍放行 ─────────────────────────────

// TestBug31_NetworkEventNoContainer_PassThrough_regression
//
// 无 attrs["container"] 的内置网络事件（如 network create bridge 管理操作）
// 不应被新增的检查拦截，维持原有放行语义。
func TestBug31_NetworkEventNoContainer_PassThrough_regression(t *testing.T) {
	db := newBug31DB(t)
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.db = db

	// 无 container 属性的 bridge 事件（管理类操作）
	noContainerEvent := []byte(
		`{"Type":"network","Action":"create","Actor":{"ID":"70840325c2d","Attributes":{"name":"bridge","type":"bridge"}},"time":1700000000}`,
	)

	if !p.eventBelongsToUser(noContainerEvent, bug31BobUID, false) {
		t.Errorf("回归: 无 container 属性的内置网络事件应放行，但被错误过滤")
	}
}

// ── 回归：容器不在 DB（竞态窗口）→ 放行 ─────────────────────────────────────

// TestBug31_ContainerNotInDB_PassThrough_regression
//
// 容器 ID 在 DB 中不存在（竞态窗口：SetContainerOwner 尚未调用）时，
// GetContainerOwnerAndPrivCtx 返回 found=false，应退化到路径 3 放行。
func TestBug31_ContainerNotInDB_PassThrough_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	// p.db 由 newTestProxy 创建，DB 为空，无任何容器记录

	const containerID = "999999container000000notindb1234567890abcd"
	connectEvent := makeNetworkConnectEvent("connect", "bridge", containerID)

	// DB 无记录时应放行（竞态窗口语义）
	if !p.eventBelongsToUser(connectEvent, bug31BobUID, false) {
		t.Errorf("回归: 容器不在 DB 时，bridge connect 事件应放行（竞态窗口），但被错误过滤")
	}
}

// ── 回归：completedPruneOwner 补偿路径（container prune 后 30s 窗口）────────

// TestBug31_ContainerPruned_CompletedPruneOwner_regression
//
// container prune 后 DB 记录已删除，但 bridge disconnect 事件在 30s 补偿窗口内迟到。
// 生产约束：GetContainerIDsByOwner（SQL: privileged_context=0）决定了 prune 只处理
// 普通容器，因此 completedPruneOwner 存储的 privCtx 在生产中始终为 0。
// 本测试严格对齐生产行为：
//   - 属主（bob）应能在补偿窗口内看到自己容器的 bridge disconnect 事件
//   - 他人（alice）通过 entry.ownerUID != uid 被过滤
func TestBug31_ContainerPruned_CompletedPruneOwner_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	const containerID = "aabbccdd11223344556677889900aabbccdd1122"

	// 严格复现 handleContainerPrune（line 6097-6098）的存储行为：privCtx 固定为 0。
	// 原因：container prune 仅处理 privileged_context=0 的容器。
	entry := pruneOwnerInfo{ownerUID: bug31BobUID, privCtx: 0}
	p.completedPruneOwner.Store("container:"+containerID, entry)
	defer p.completedPruneOwner.CompareAndDelete("container:"+containerID, entry)

	event := makeNetworkConnectEvent("disconnect", "bridge", containerID)

	// bob 是属主，补偿窗口内应可见（修复不应过度过滤属主的普通容器事件）
	if !p.eventBelongsToUser(event, bug31BobUID, false) {
		t.Errorf(
			"BUG-31 [prune 补偿路径过度过滤]:\n"+
				"\tbob(uid=%d) 的普通容器（privCtx=0）prune 后 bridge disconnect 事件被错误过滤\n"+
				"\t预期: true，实际: false",
			bug31BobUID,
		)
	}

	// alice 不应看到 bob 的容器事件（通过 entry.ownerUID != uid 过滤）
	if p.eventBelongsToUser(event, bug31AliceUID, false) {
		t.Errorf(
			"BUG-31 [prune 补偿路径泄漏]:\n"+
				"\talice(uid=%d) 不应看到 bob 容器的 bridge disconnect 事件（prune 补偿路径）\n"+
				"\t预期: false，实际: true",
			bug31AliceUID,
		)
	}
}

// TestBug31_SudoContainerDestroyed_NoCompensation_PassThrough_doc
//
// 文档性测试：sudo 上下文容器（privileged_context=1）不会进入 container prune 流程，
// 因此 completedPruneOwner 中永远不会出现 sudo 容器的 "container:ctnID" 条目。
// 验证：sudo 容器被 --rm 销毁后（DB 记录已删，无补偿条目），bridge disconnect 事件
// 退化到 return true（放行）——这是已知的 --rm 竞态窗口限制，不属于 BUG-31 修复范围。
func TestBug31_SudoContainerDestroyed_NoCompensation_PassThrough_doc(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	// DB 为空：模拟 container destroy 已触发 DeleteContainer，且无 completedPruneOwner 条目

	const containerID = "deadbeef0000111122223333444455556666777788aa"
	event := makeNetworkConnectEvent("disconnect", "bridge", containerID)

	// 无 DB 记录、无补偿条目 → 退化到 return true（--rm 竞态窗口已知限制）
	// 此行为与修复前相同，无回归
	if !p.eventBelongsToUser(event, bug31BobUID, false) {
		t.Errorf(
			"已知限制变更 [--rm 竞态窗口]:\n"+
				"\t预期：容器 destroy 后无补偿条目时 bridge disconnect 事件放行（return true）\n"+
				"\t但现在 eventBelongsToUser 返回 false，行为已改变，需检查",
		)
	}
}
