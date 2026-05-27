package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-27：sudo docker pull 事件在非 sudo docker events 视图中泄漏
//
// ──── 触发条件 ──────────────────────────────────────────────────────────────
//
//   sudo_test(uid=1005) 在终端 A 执行 docker events（非 sudo 模式）
//   sudo_test 在终端 B 执行 sudo docker pull alpine:3.17
//
//   期望：终端 A 不应收到 sudo pull 产生的事件
//   实际：终端 A 收到：
//     image pull alpine:3.17 (name=alpine)
//
// ──── 根本原因 ─────────────────────────────────────────────────────────────
//
//   pendingPullRefs / completedPullOwner 值类型为 int（仅存 ownerUID），
//   丢失 privileged_context 信息。
//
//   eventBelongsToUser 路径 0b.2（pendingPullRefs）和路径 0c.2（completedPullOwner）
//   命中后直接 return ownerUID == uid，绕过路径 2 的 !sudoCtx && privCtx==1 检查：
//
//     pendingPullRefs["alpine:3.17"] = int(1005)   ← 无 privCtx
//     路径 0b.2：ownerUID(1005) == uid(1005) → return true ← BUG（应 false）
//
// ──── 修复 ─────────────────────────────────────────────────────────────────
//
//   值类型改为 pruneOwnerInfo{ownerUID, privCtx}。
//   路径 0a/0b/0b.2/0c/0c.2 读取后加：
//     if !sudoCtx && entry.privCtx == 1 { return false }
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// ──────────────────────────────────────────────────────────────────────────────
// 场景常量
// ──────────────────────────────────────────────────────────────────────────────

const (
	bug27SudoTestUID = 1005 // sudo_test
	bug27BobUID      = 1002
	bug27AliceUID    = 1001
)

// bug27AlpineRef 是 sudo_test 以 sudo 身份 pull 的完整 ref。
const bug27AlpineRef = "alpine:3.17"

// bug27AlpineContentID 是 alpine:3.17 的 sha256 content ID（hex 无前缀）。
const bug27AlpineContentID = "sha256:deadbeef1234abcd5678ef901234abcd5678ef901234abcd5678ef901234abcd"

// ──────────────────────────────────────────────────────────────────────────────
// 辅助
// ──────────────────────────────────────────────────────────────────────────────

// bug27MakePullEvent 构造真实 Docker image pull 事件。
// Actor.ID = 完整 ref（如 "alpine:3.17"），attrs["name"] = 仓库名（"alpine"）。
func bug27MakePullEvent(ref, repoName string) []byte {
	return makeImageEvent("pull", ref, repoName)
}

// ══════════════════════════════════════════════════════════════════════════════
// 主场景：pendingPullRefs 窗口（pull 进行中）
// ══════════════════════════════════════════════════════════════════════════════

// TestBug27_SudoPull_HiddenInNonSudoEvents_PendingWindow
//
// sudo_test 执行 sudo docker pull alpine:3.17（pull 进行中，ServeHTTP 已注册
// pendingPullRefs["alpine:3.17"] = {ownerUID:1005, privCtx:1}）。
//
// 同用户的非 sudo docker events 终端处理该事件时：
//   修复前 FAIL：路径 0b.2 命中，ownerUID==uid → return true → 事件泄漏。
//   修复后 PASS：路径 0b.2 检查 !sudoCtx && privCtx==1 → return false。
func TestBug27_SudoPull_HiddenInNonSudoEvents_PendingWindow(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// 模拟 sudo docker pull 进行中：ServeHTTP 已注册 pendingPullRefs（privCtx=1）
	owner := pruneOwnerInfo{ownerUID: bug27SudoTestUID, privCtx: 1}
	p.pendingPullRefs.Store(bug27AlpineRef, owner)
	defer p.pendingPullRefs.CompareAndDelete(bug27AlpineRef, owner)

	pullEvent := bug27MakePullEvent(bug27AlpineRef, "alpine")

	// ── 核心断言：非 sudo 视图不可见 ─────────────────────────────────────────
	if p.eventBelongsToUser(pullEvent, bug27SudoTestUID, false) {
		t.Errorf(
			"BUG-27 [pendingPullRefs 窗口]:\n"+
				"\tsudo_test(uid=%d) 的非 sudo docker events 收到了 sudo pull 事件\n"+
				"\tActor.ID=%q  pendingPullRefs[%q]={ownerUID:%d, privCtx:1}\n"+
				"\t预期: eventBelongsToUser=false（!sudoCtx && privCtx==1 → 隐藏）\n"+
				"\t实际: eventBelongsToUser=true（泄漏）",
			bug27SudoTestUID, bug27AlpineRef, bug27AlpineRef, bug27SudoTestUID,
		)
	}

	// ── 回归1：sudo 视图（sudoCtx=true）应能看到 ────────────────────────────
	if !p.eventBelongsToUser(pullEvent, bug27SudoTestUID, true) {
		t.Errorf(
			"回归1: sudo_test(uid=%d) 以 sudo 模式监听时，应能看到自己的 sudo pull 事件",
			bug27SudoTestUID,
		)
	}

	// ── 回归2：其他用户（bob）始终不可见 ────────────────────────────────────
	if p.eventBelongsToUser(pullEvent, bug27BobUID, false) {
		t.Errorf(
			"回归2: bob(uid=%d) 不应看到 sudo_test 的 sudo pull 事件",
			bug27BobUID,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 主场景：completedPullOwner 窗口（pull 完成后 30s 内）
// ══════════════════════════════════════════════════════════════════════════════

// TestBug27_SudoPull_HiddenInNonSudoEvents_CompletedWindow
//
// sudo docker pull alpine:3.17 已完成（ServeHTTP defer 清除了 pendingPullRefs），
// postprocessResponse ActionPull 写入 completedPullOwner["alpine:3.17"] = {1005, privCtx:1}。
//
// Docker 事件在 30s 内迟到时，非 sudo events 终端处理该事件：
//   修复前 FAIL：路径 0c.2 命中，ownerUID==uid → return true → 事件泄漏。
//   修复后 PASS：路径 0c.2 检查 !sudoCtx && privCtx==1 → return false。
func TestBug27_SudoPull_HiddenInNonSudoEvents_CompletedWindow(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// 模拟 pull 完成：pendingPullRefs 已清除，completedPullOwner 已写入（privCtx=1）
	sudoID := privCtxSudoIdentity("sudo_test", bug27SudoTestUID)
	if err := p.db.SetImageOwner(bug27AlpineContentID, sudoID, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}
	owner := pruneOwnerInfo{ownerUID: bug27SudoTestUID, privCtx: 1}
	p.completedPullOwner.Store(bug27AlpineRef, owner)

	pullEvent := bug27MakePullEvent(bug27AlpineRef, "alpine")

	// ── 核心断言：非 sudo 视图不可见 ─────────────────────────────────────────
	if p.eventBelongsToUser(pullEvent, bug27SudoTestUID, false) {
		t.Errorf(
			"BUG-27 [completedPullOwner 窗口]:\n"+
				"\tsudo_test(uid=%d) 的非 sudo docker events 收到了 sudo pull 完成事件\n"+
				"\tActor.ID=%q  completedPullOwner[%q]={ownerUID:%d, privCtx:1}\n"+
				"\t预期: eventBelongsToUser=false\n"+
				"\t实际: eventBelongsToUser=true（泄漏）",
			bug27SudoTestUID, bug27AlpineRef, bug27AlpineRef, bug27SudoTestUID,
		)
	}

	// ── 回归1：sudo 视图应能看到 ─────────────────────────────────────────────
	if !p.eventBelongsToUser(pullEvent, bug27SudoTestUID, true) {
		t.Errorf(
			"回归1: sudo_test(uid=%d) 以 sudo 模式监听时，应能看到自己的 sudo pull 事件",
			bug27SudoTestUID,
		)
	}

	// ── 回归2：其他用户（alice）不可见 ───────────────────────────────────────
	if p.eventBelongsToUser(pullEvent, bug27AliceUID, false) {
		t.Errorf(
			"回归2: alice(uid=%d) 不应看到 sudo_test 的 sudo pull 事件",
			bug27AliceUID,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归：普通 pull（非 sudo）行为不受影响
// ══════════════════════════════════════════════════════════════════════════════

// TestBug27_Reg_RegularPull_VisibleInNonSudoEvents
//
// docker pull alpine:3.17（非 sudo，privCtx=0）进行中时，
// 同用户的非 sudo docker events 应能正常看到该事件。
func TestBug27_Reg_RegularPull_VisibleInNonSudoEvents(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// 普通 pull：privCtx=0
	owner := pruneOwnerInfo{ownerUID: bug27SudoTestUID, privCtx: 0}
	p.pendingPullRefs.Store(bug27AlpineRef, owner)
	defer p.pendingPullRefs.CompareAndDelete(bug27AlpineRef, owner)

	pullEvent := bug27MakePullEvent(bug27AlpineRef, "alpine")

	// 非 sudo 视图（sudoCtx=false）+ privCtx=0 → 可见
	if !p.eventBelongsToUser(pullEvent, bug27SudoTestUID, false) {
		t.Errorf(
			"回归 [普通 pull]: sudo_test(uid=%d) 以非 sudo 模式 pull 的镜像事件，"+
				"在非 sudo docker events 中应可见（privCtx=0）",
			bug27SudoTestUID,
		)
	}

	// bob 仍不可见（属主不同）
	if p.eventBelongsToUser(pullEvent, bug27BobUID, false) {
		t.Errorf(
			"回归 [普通 pull]: bob(uid=%d) 不应看到 sudo_test 的 pull 事件",
			bug27BobUID,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// HTTP 集成测试
// ══════════════════════════════════════════════════════════════════════════════

// TestBug27_Integration_SudoPull_NotInNonSudoEventsResponse
//
// HTTP 层集成验证：sudo_test 以非 sudo 模式监听 /events 时，
// sudo pull alpine:3.17 的事件不出现在响应体中；
// sudo_test 自己的普通镜像事件（DB 已注册，content ID 格式）正常到达。
func TestBug27_Integration_SudoPull_NotInNonSudoEventsResponse(t *testing.T) {
	// 上游：sudo pull 事件（具名 ref 格式） + sudo_test 自己的普通镜像 tag 事件
	const bug27OwnImageID = "sha256:ccddee001122334455667788990011223344556677889900112233445566778899"
	events := []string{
		// sudo pull alpine:3.17 产生的事件（privCtx=1，非 sudo 视图应过滤）
		makeRawImageEvent("pull", bug27AlpineRef, "alpine"),
		// sudo_test 自己的普通镜像 tag 事件（privCtx=0，非 sudo 视图应可见）
		makeRawImageEvent("tag", bug27OwnImageID, "myapp:stable"),
	}
	upstream := fakeDockerEventsServer(events)
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// sudo pull 已完成：DB 有 privileged_context=1 记录，completedPullOwner 已注册
	sudoID := privCtxSudoIdentity("sudo_test", bug27SudoTestUID)
	if err := p.db.SetImageOwner(bug27AlpineContentID, sudoID, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner(sudo alpine): %v", err)
	}
	p.completedPullOwner.Store(bug27AlpineRef, pruneOwnerInfo{ownerUID: bug27SudoTestUID, privCtx: 1})

	// sudo_test 的普通镜像（privCtx=0）
	regularID := regularIdentity("sudo_test", bug27SudoTestUID)
	if err := p.db.SetImageOwner(bug27OwnImageID, regularID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner(regular image): %v", err)
	}

	// sudo_test 以非 sudo 模式（makeTestIdentityProxy 创建 regular 身份）监听 /events
	req := httptest.NewRequest("GET", "/events?type=image", nil)
	req = injectIdentity(req, makeTestIdentityProxy("sudo_test", bug27SudoTestUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)
	body := rw.Body.String()

	// sudo pull 事件不应出现
	if strings.Contains(body, bug27AlpineRef) {
		t.Errorf(
			"BUG-27 [HTTP集成]: sudo_test 非 sudo events 收到了 sudo pull 事件\n"+
				"\t包含: %q\n"+
				"\t完整响应: %s",
			bug27AlpineRef, body,
		)
	}

	// 自己的普通镜像事件必须正常到达
	if !strings.Contains(body, bug27OwnImageID) {
		t.Errorf(
			"BUG-27 [HTTP集成回归]: sudo_test 的普通镜像事件（privCtx=0）应在非 sudo events 中可见\n"+
				"\t镜像 ID: %q\n"+
				"\t完整响应: %s",
			bug27OwnImageID, body,
		)
	}
}
