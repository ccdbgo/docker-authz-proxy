package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-20：image pull 事件在 pull 完成后仍泄漏给其他用户
//
// ──── 触发条件 ──────────────────────────────────────────────────────────────
//
//   alice(uid=1001) 执行 docker pull alpine:3.18
//   bob(uid=1002)   执行 docker system events
//
//   期望：bob 不应收到 alice 的 image pull 事件
//   实际：bob 收到：
//     2026-05-25T16:30:14.223686405+08:00 image pull alpine:3.18 (name=alpine)
//
// ──── 根本原因 ─────────────────────────────────────────────────────────────
//
//   alice pull 完成时，ServeHTTP defer 运行 CompareAndDelete，将
//   pendingPullRefs["alpine:3.18"] 清除。随后 bob 的事件流协程处理该事件：
//
//   Docker image pull 事件的真实格式：
//     Actor.ID  = "alpine:3.18"（具名 ref，含 tag）
//     attrs["name"] = "alpine"（仓库名，不含 tag）
//
//   eventBelongsToUser 执行路径：
//     路径 0b：pendingPullRefs.Load("alpine")    → miss（key 为 "alpine:3.18"）
//     路径 0b.2：pendingPullRefs.Load("alpine:3.18") → miss（defer 已删除）
//     DB 路径：GetImageOwner("alpine:3.18")
//              → resolveImageIDInDB("alpine:3.18")
//              → norm = "alpine:3.18"（无 sha256: 前缀，原样保留）
//              → 精确匹配失败（DB 存 hex content ID，非具名 ref）
//              → len("alpine:3.18") = 11 < 12，LIKE 匹配不触发
//              → 返回 ""，GetImageOwner 返回 found=false
//     路径 3：!found → return true → bob 收到 alice 的 pull 事件 ← BUG
//
// ──── 与 BUG-19 的区别 ─────────────────────────────────────────────────────
//
//   BUG-19：pull 期间竞态（pendingPullRefs 尚未注册时事件已到达）
//           修复：ServeHTTP forward 前注册 pendingPullRefs（路径 0b.2）
//   BUG-20：pull 完成后（pendingPullRefs 已清除），DB 无法按具名 ref 查归属
//           修复：需要持久化 ref → ownerUID 映射（如 completedPullOwner），
//                 在 eventBelongsToUser 中补充查询
//
// ──── 已有测试的问题 ────────────────────────────────────────────────────────
//
//   TestBug19_Reg2_AfterPullComplete_DBFiltersCorrectly 用
//   Actor.ID = "sha256:3fbc..." 模拟 pull 事件，与真实 Docker 格式不符
//   （真实 pull 事件 Actor.ID = "busybox"，非 sha256）。
//   该测试通过 DB content ID 查询路径，绕过了本 bug，因此通过但遮蔽了缺陷。
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// ──────────────────────────────────────────────────────────────────────────────
// 场景常量（与其他测试文件区分，避免冲突）
// ──────────────────────────────────────────────────────────────────────────────

const (
	bug20AliceUID   = 1001
	bug20BobUID     = 1002
	bug20CharlieUID = 1003
)

// bug20AlpineRef 是 alice pull 的完整 ref（含 tag，非 latest）。
// parseImageRefFromURI("?fromImage=alpine&tag=3.18") 的返回值。
const bug20AlpineRef = "alpine:3.18"

// bug20AlpineContentID 是 alpine:3.18 的 sha256 content ID（hex 无前缀）。
// SetImageOwner 使用此 ID；DB 存储以此为主键。
const bug20AlpineContentID = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

// bug20MakePullEvent 构造真实 Docker image pull 事件。
//
// 真实格式（已在服务器验证）：
//
//	Actor.ID  = 完整 ref（如 "alpine:3.18"）
//	attrs["name"] = 仓库名（如 "alpine"，不含 tag）
func bug20MakePullEvent(ref, repoName string) []byte {
	return makeImageEvent("pull", ref, repoName)
}

// ══════════════════════════════════════════════════════════════════════════════
// RED TEST：复现 BUG-20（修复前必须 100% 失败）
// ══════════════════════════════════════════════════════════════════════════════

// TestBug20_PullEvent_AfterPullComplete_LeaksToOtherUsers
//
// RED TEST：精确复现 "alice pull alpine:3.18 完成后 bob 收到其事件" 的场景。
//
// 初始状态（模拟 pull 完成后 30s 内的正常窗口）：
//   - SetImageOwner(contentID, alice) 已调用（DB 已有 alice 的镜像记录）
//   - pendingPullRefs 已清空（ServeHTTP defer 已运行）
//   - completedPullOwner 已注册（postprocessResponse ActionPull 在 SetImageOwner 后写入）
//
// 事件格式（与真实 Docker daemon 一致）：
//
//	Actor.ID  = "alpine:3.18"（具名 ref，含 tag）
//	attrs["name"] = "alpine"（仓库名，不含 tag）
//
// 失败路径（修复前）：
//
//	completedPullOwner 已注册，但 eventBelongsToUser 无路径 0c 查询 →
//	DB 路径：GetImageOwner("alpine:3.18") → found=false（DB 存 hex，非具名 ref）
//	→ 路径 3：return true → bob 和 charlie 均收到 alice 的 pull 事件
//
// 通过路径（修复后）：
//
//	路径 0c.2：completedPullOwner.Load("alpine:3.18") → ownerUID=alice ≠ bob → false
func TestBug20_PullEvent_AfterPullComplete_LeaksToOtherUsers(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// 模拟 pull 完成后 30s 内：DB 已有 alice 的镜像记录，pendingPullRefs 已清空，
	// completedPullOwner 已由 postprocessResponse ActionPull 注册。
	aliceID := regularIdentity("alice", bug20AliceUID)
	if err := p.db.SetImageOwner(bug20AlpineContentID, aliceID, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}
	// pendingPullRefs 未设置——模拟 defer CompareAndDelete 已执行
	// completedPullOwner 已设置——模拟 postprocessResponse ActionPull 写入
	p.completedPullOwner.Store(bug20AlpineRef, bug20AliceUID)

	// 真实 Docker pull 事件：Actor.ID=完整 ref，attrs["name"]=仓库名
	pullEvent := bug20MakePullEvent(bug20AlpineRef, "alpine")

	// ── RED ASSERTION A：bob 不应收到 alice 的 pull 事件 ────────────────────
	if p.eventBelongsToUser(pullEvent, bug20BobUID, false) {
		t.Errorf(
			"BUG-20 [pull 完成后泄漏]:\n"+
				"\tbob(uid=%d) 收到了 alice(uid=%d) 的 image pull 事件\n"+
				"\tpull 已完成，pendingPullRefs 已清空\n"+
				"\tActor.ID=%q  attrs[\"name\"]=%q\n"+
				"\tDB 以 content ID 存储，GetImageOwner(%q) 返回 found=false\n"+
				"\t→ 路径3 return true → 泄漏\n"+
				"\t根因：DB 不支持按具名 ref 查归属",
			bug20BobUID, bug20AliceUID, bug20AlpineRef, "alpine", bug20AlpineRef,
		)
	}

	// ── RED ASSERTION B：charlie 同样不应收到 ───────────────────────────────
	if p.eventBelongsToUser(pullEvent, bug20CharlieUID, false) {
		t.Errorf(
			"BUG-20 [pull 完成后泄漏]: charlie(uid=%d) 收到了 alice(uid=%d) 的 pull 事件\n"+
				"\t隔离失效对任意非拉取者均成立，不止 bob",
			bug20CharlieUID, bug20AliceUID,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归矩阵（修复前后均应通过）
// ══════════════════════════════════════════════════════════════════════════════

// TestBug20_Reg1_Alice_ReceivesOwnPullEvent_AfterComplete
//
// 回归-1：pull 完成后（completedPullOwner 已设置），alice 应能看到自己的 pull 事件。
//
// 修复前：路径3 → return true（completedPullOwner 有值但不被查询，偶然正确）
// 修复后：路径 0c.2：completedPullOwner["alpine:3.18"]=alice → uid 匹配 → return true（正确）
func TestBug20_Reg1_Alice_ReceivesOwnPullEvent_AfterComplete(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	aliceID := regularIdentity("alice", bug20AliceUID)
	if err := p.db.SetImageOwner(bug20AlpineContentID, aliceID, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}
	// pendingPullRefs 未设置（pull 已完成）
	// completedPullOwner 已设置（postprocessResponse ActionPull 写入）
	p.completedPullOwner.Store(bug20AlpineRef, bug20AliceUID)

	pullEvent := bug20MakePullEvent(bug20AlpineRef, "alpine")

	if !p.eventBelongsToUser(pullEvent, bug20AliceUID, false) {
		t.Errorf(
			"回归-1 [alice 自己的 pull 事件]: alice(uid=%d) 应能看到自己的 alpine:3.18 pull 事件\n"+
				"\tpull 完成后归属路径应识别 alice 为拉取者",
			bug20AliceUID,
		)
	}
}

// TestBug20_Reg2_SHA256ActorID_DBPath_Unaffected
//
// 回归-2：Actor.ID 为 sha256 content ID 格式时，DB 路径仍正确过滤。
//
// 本测试覆盖"content ID 格式 pull 事件"场景，确保修复不破坏已有 DB 路径。
// （TestBug19_Reg2 使用的格式，实际上测试了 sha256 格式的正确性）
func TestBug20_Reg2_SHA256ActorID_DBPath_Unaffected(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// DB 中注册 alice 的 busybox 镜像（content ID 格式）
	const busyboxContentID = "sha256:3fbc632167424a6d997e74f52b878d7cc478225cffac6bc977eedfe51c7f4e79"
	aliceID := regularIdentity("alice", bug20AliceUID)
	if err := p.db.SetImageOwner(busyboxContentID, aliceID, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	// 注意：这里使用 sha256 content ID 作为 Actor.ID（与 TestBug19_Reg2 一致）
	// 真实 Docker pull 事件不是这个格式，但用于验证 DB 路径不被修复破坏
	pullEvent := makeImageEvent("pull", busyboxContentID, "busybox")

	if p.eventBelongsToUser(pullEvent, bug20BobUID, false) {
		t.Errorf(
			"回归-2 [sha256 content ID 格式]: bob(uid=%d) 不应收到 DB 中 alice 的镜像事件\n"+
				"\t修复不得破坏 sha256 content ID 的 DB 过滤路径",
			bug20BobUID,
		)
	}
	if !p.eventBelongsToUser(pullEvent, bug20AliceUID, false) {
		t.Errorf(
			"回归-2: alice(uid=%d) 应能看到自己的镜像事件（sha256 content ID，DB 路径）",
			bug20AliceUID,
		)
	}
}

// TestBug20_Reg3_RaceWindow_PendingPullRefs_Unaffected
//
// 回归-3：pull 进行中（pendingPullRefs 已注册），具名 ref 事件仍由路径 0b.2 正确过滤。
//
// 这是 BUG-19/83b59ff 修复的覆盖范围，修复 BUG-20 不得破坏此路径。
func TestBug20_Reg3_RaceWindow_PendingPullRefs_Unaffected(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// 模拟 pull 进行中：pendingPullRefs 已注册
	p.pendingPullRefs.Store(bug20AlpineRef, bug20AliceUID)
	defer p.pendingPullRefs.CompareAndDelete(bug20AlpineRef, bug20AliceUID)
	// DB 尚未更新（竞态窗口）

	pullEvent := bug20MakePullEvent(bug20AlpineRef, "alpine")

	// bob 不应收到（路径 0b.2：pendingPullRefs 命中，ownerUID=alice ≠ bob）
	if p.eventBelongsToUser(pullEvent, bug20BobUID, false) {
		t.Errorf(
			"回归-3 [竞态窗口]: bob(uid=%d) 不应收到 alice(uid=%d) 的 alpine:3.18 pull 事件\n"+
				"\tpendingPullRefs 已注册，路径 0b.2 应正确过滤",
			bug20BobUID, bug20AliceUID,
		)
	}
	// alice 应收到自己的事件
	if !p.eventBelongsToUser(pullEvent, bug20AliceUID, false) {
		t.Errorf(
			"回归-3 [竞态窗口]: alice(uid=%d) 应能看到自己的 alpine:3.18 pull 事件（路径 0b.2）",
			bug20AliceUID,
		)
	}
}

// TestBug20_Reg4_IntermediateLayer_Create_StillPassthrough
//
// 回归-4：image create 事件（中间层，name 为 sha256 格式）在 DB 无记录时
// 仍对所有用户放行（路径3）。修复不得将中间层事件错误隔离。
func TestBug20_Reg4_IntermediateLayer_Create_StillPassthrough(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	// DB 为空，无任何镜像记录

	const layerID = "sha256:deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
	createEvent := makeImageEvent("create", layerID, layerID) // name 也是 sha256

	for _, uid := range []int{bug20AliceUID, bug20BobUID, bug20CharlieUID} {
		if !p.eventBelongsToUser(createEvent, uid, false) {
			t.Errorf(
				"回归-4 [中间层 create 事件]: uid=%d 不应被过滤\n"+
					"\t中间层 image create（sha256 name，DB 无记录）→ 路径3 放行\n"+
					"\t修复不得影响此行为",
				uid,
			)
		}
	}
}

// TestBug20_Reg5_Integration_PullComplete_BobDoesNotSeeEvent
//
// 回归-5：HTTP 集成测试（通过 ServeHTTP）。
//
// 验证在 HTTP 层面：alice 的 alpine:3.18 pull 完成事件不出现在 bob 的 /events 响应中；
// bob 自己的镜像事件（DB 已注册，content ID 格式）正常到达。
//
// 初始状态模拟 pull 完成后 30s 内：completedPullOwner 已注册 alice 的 imageRef。
// 注意：此集成测试使用真实 Docker pull 事件格式（Actor.ID = 具名 ref），
// 而非 TestBug19_Reg5 中 SetImageOwner 注册后的 sha256 格式。
func TestBug20_Reg5_Integration_PullComplete_BobDoesNotSeeEvent(t *testing.T) {
	// 上游事件流：alice 的 pull 完成事件（具名 ref 格式）+ bob 自己的镜像事件
	events := []string{
		// alice pull alpine:3.18 完成事件（真实 Docker 格式）
		makeRawImageEvent("pull", bug20AlpineRef, "alpine"),
		// bob 自己构建的镜像（sha256 content ID，DB 已注册）
		makeRawImageEvent("tag", bobImageID, "bob-app:v2"),
	}
	upstream := fakeDockerEventsServer(events)
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// alice 的镜像已在 DB 中（content ID 格式，pendingPullRefs 已清空）
	// completedPullOwner 已注册（模拟 alice 的 pull 在 30s 内通过 postprocessResponse）
	aliceID := regularIdentity("alice", bug20AliceUID)
	if err := p.db.SetImageOwner(bug20AlpineContentID, aliceID, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner(alice/alpine): %v", err)
	}
	p.completedPullOwner.Store(bug20AlpineRef, bug20AliceUID)

	// bob 自己的镜像已在 DB 中
	bobID := regularIdentity("bob", bug20BobUID)
	if err := p.db.SetImageOwner(bobImageID, bobID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner(bob): %v", err)
	}

	req := httptest.NewRequest("GET", "/events?type=image", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bug20BobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)
	body := rw.Body.String()

	// bob 不应收到 alice 的 alpine:3.18 pull 事件
	if strings.Contains(body, bug20AlpineRef) {
		t.Errorf(
			"回归-5 [HTTP集成]: bob(uid=%d) 收到了 alice(uid=%d) 的 pull 完成事件\n"+
				"\t包含: %q\n"+
				"\t完整响应: %s",
			bug20BobUID, bug20AliceUID, bug20AlpineRef, body,
		)
	}

	// bob 自己的镜像事件必须正常到达
	if !strings.Contains(body, bobImageID) {
		t.Errorf(
			"回归-5: bob(uid=%d) 应收到自己的镜像事件\n"+
				"\t镜像 ID: %q\n"+
				"\t完整响应: %s",
			bug20BobUID, bobImageID, body,
		)
	}
}
