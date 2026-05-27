package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-28：重建同内容镜像时旧 owner 收到新构建者的 image 事件
//
// ──── 触发条件 ──────────────────────────────────────────────────────────────
//
//   sudo_test(uid=1005) 先执行 docker build -t myapp:test（成为 DB owner）
//   bob(uid=1002) 后执行 docker build -t myapp:test /tmp/testbuild/
//     → 相同 Dockerfile + base → 产出相同 sha256 content ID
//     → trackBuildKitImages.writeOne: 发现 owner!=bob，仅调用 EnsureImageAccess，
//       images 表 owner 字段不变，仍为 sudo_test
//   sudo_test 以非 sudo 模式运行 docker events
//
//   期望：sudo_test 的非 sudo events 不应收到 bob 的 image tag 事件
//   实际（修复前）：DB owner=sudo_test → 路径2（owner==uid）→ return true → 泄漏
//
// ──── 根本原因 ─────────────────────────────────────────────────────────────
//
//   eventBelongsToUser 路径2 使用 DB images.owner 判断，但 DB owner 反映的是
//   "原始构建者"而非"最近构建者"。build 完成后 pendingBuildTags 已被 CompareAndDelete
//   清除，缺少 completedBuildOwner 覆盖 pendingBuildTags → DB owner 之间的投递窗口。
//
// ──── 修复 ─────────────────────────────────────────────────────────────────
//
//   新增 completedBuildOwner sync.Map（tag → pruneOwnerInfo，TTL=30s）。
//   build 完成时写入：
//     • ActionBuild（经典 builder）：新增 defer，LIFO 先于 CompareAndDelete 执行
//     • trackBuildKitImages（BuildKit）：CompareAndDelete 前 Store
//   eventBelongsToUser 路径 0a.2：pendingBuildTags miss 后先查 completedBuildOwner，
//   命中且 ownerUID≠uid → return false，不再落入 DB owner 路径。
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	// bug28RebuildImageID 是 sha256 content ID（sudo_test 和 bob 均构建出此内容）。
	bug28RebuildImageID = "sha256:aabbcc001122334455667788990011223344556677889900112233445566778899"
	// bug28Tag 是双方均使用的镜像 tag。
	bug28Tag = "myapp:test"
	// bug28BobUID / bug28SudoTestUID / bug28AliceUID 复用已有常量（同包可见）。
	bug28BobUID      = bobUID3     // 1002
	bug28SudoTestUID = sudoTestUID // 1005
	bug28AliceUID    = 1001
)

// ══════════════════════════════════════════════════════════════════════════════
// RED TEST：修复前失败，修复后通过
// ══════════════════════════════════════════════════════════════════════════════

// TestBug28_RebuildLeak_OldOwnerSeesNewBuildEvent
//
// RED TEST：精确复现 BUG-28。
//
// 状态设置：
//   - DB: images[bug28RebuildImageID].owner = sudo_test(1005), privileged_context=0（先前构建）
//   - pendingBuildTags: 空（bob 的 build 已完成，CompareAndDelete 已执行）
//   - completedBuildOwner["myapp:test"] = {ownerUID:1002, privCtx:0}（bob 最近构建）
//
// 修复前（无路径 0a.2）：
//
//	路径 0a → MISS → DB: owner=1005==uid(1005) → return true → FAIL
//
// 修复后（路径 0a.2）：
//
//	completedBuildOwner["myapp:test"].ownerUID(1002) ≠ uid(1005) → return false → PASS
func TestBug28_RebuildLeak_OldOwnerSeesNewBuildEvent(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// 步骤1：sudo_test 先前构建了同内容镜像 → 成为 DB owner（普通 build，privCtx=0）
	sudoTestID := regularIdentity("sudo_test", bug28SudoTestUID)
	if err := p.db.SetImageOwner(bug28RebuildImageID, sudoTestID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner(sudo_test): %v", err)
	}

	// 步骤2：bob 重建同 sha256 内容，trackBuildKitImages 仅添加 image_access，
	// owner 不变（仍为 sudo_test）。
	// 步骤3：bob 的 build 完成，completedBuildOwner 写入最近构建者（bob）。
	bobOwner := pruneOwnerInfo{ownerUID: bug28BobUID, privCtx: 0}
	p.completedBuildOwner.Store(bug28Tag, bobOwner)
	// pendingBuildTags 已被 CompareAndDelete 清除（不在此注册，模拟 post-build 状态）

	// Docker 发出 image tag 事件（对应 bob 的 build 产出）
	buildEvent := makeImageEvent("tag", bug28RebuildImageID, bug28Tag)

	// ── 核心断言1：sudo_test 非 sudo 视图不应收到 bob 的构建事件 ─────────────
	if p.eventBelongsToUser(buildEvent, bug28SudoTestUID, false) {
		t.Errorf(
			"BUG-28 [旧 owner 泄漏]:\n"+
				"\tsudo_test(uid=%d) 的非 sudo docker events 收到了 bob(uid=%d) 的 image tag 事件\n"+
				"\tDB owner=sudo_test, completedBuildOwner[%q]={ownerUID:%d}\n"+
				"\t预期: eventBelongsToUser=false（路径 0a.2 按最近构建者过滤）\n"+
				"\t实际: eventBelongsToUser=true（回落到 DB owner 路径，泄漏）",
			bug28SudoTestUID, bug28BobUID, bug28Tag, bug28BobUID,
		)
	}

	// ── 核心断言2：alice 同样不应收到 ────────────────────────────────────────
	if p.eventBelongsToUser(buildEvent, bug28AliceUID, false) {
		t.Errorf(
			"BUG-28 [alice 泄漏]: alice(uid=%d) 不应收到 bob(uid=%d) 的 image tag 事件",
			bug28AliceUID, bug28BobUID,
		)
	}

	// ── 正向断言：bob 自己应收到 ──────────────────────────────────────────────
	if !p.eventBelongsToUser(buildEvent, bug28BobUID, false) {
		t.Errorf(
			"BUG-28 [bob 自身]: bob(uid=%d) 应收到自己的 image tag 事件\n"+
				"\tcompletedBuildOwner[%q].ownerUID=%d 应与 uid 匹配",
			bug28BobUID, bug28Tag, bug28BobUID,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归矩阵
// ══════════════════════════════════════════════════════════════════════════════

// TestBug28_Reg1_PendingBuildTags_StillWorks
//
// 回归-1：pendingBuildTags（路径 0a）在 build 进行中时仍正确工作，
// completedBuildOwner（路径 0a.2）的加入不干扰 BUG-18/18b 的保护机制。
func TestBug28_Reg1_PendingBuildTags_StillWorks(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// 模拟 build 进行中：pendingBuildTags 有 bob 的 entry，completedBuildOwner 为空
	bobOwner := pruneOwnerInfo{ownerUID: bug28BobUID, privCtx: 0}
	p.pendingBuildTags.Store(bug28Tag, bobOwner)
	defer p.pendingBuildTags.CompareAndDelete(bug28Tag, bobOwner)

	buildEvent := makeImageEvent("tag", bug28RebuildImageID, bug28Tag)

	if p.eventBelongsToUser(buildEvent, bug28SudoTestUID, false) {
		t.Errorf(
			"回归-1 [BUG-18 对齐]: sudo_test(uid=%d) 不应在 build 进行中收到 bob 的事件\n"+
				"\t路径 0a（pendingBuildTags）应拦截",
			bug28SudoTestUID,
		)
	}
	if !p.eventBelongsToUser(buildEvent, bug28BobUID, false) {
		t.Errorf(
			"回归-1: bob(uid=%d) 应在 build 进行中收到自己的事件（路径 0a）",
			bug28BobUID,
		)
	}
}

// TestBug28_Reg2_SudoBuild_CompletedBuildOwner_HiddenInNonSudoView
//
// 回归-2：sudo docker build 完成后 completedBuildOwner privCtx=1，
// 同用户的非 sudo events 不应看到该 build 事件（与 BUG-27 对齐）。
func TestBug28_Reg2_SudoBuild_CompletedBuildOwner_HiddenInNonSudoView(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// sudo docker build 完成：completedBuildOwner 记录 privCtx=1
	sudoOwner := pruneOwnerInfo{ownerUID: bug28SudoTestUID, privCtx: 1}
	p.completedBuildOwner.Store(bug28Tag, sudoOwner)

	buildEvent := makeImageEvent("tag", bug28RebuildImageID, bug28Tag)

	// 非 sudo 视图不可见（!sudoCtx && privCtx==1）
	if p.eventBelongsToUser(buildEvent, bug28SudoTestUID, false) {
		t.Errorf(
			"回归-2 [BUG-27 对齐]: sudo_test(uid=%d) 的非 sudo events 收到了 sudo build 事件\n"+
				"\tcompletedBuildOwner[%q]={ownerUID:%d, privCtx:1}，应被过滤",
			bug28SudoTestUID, bug28Tag, bug28SudoTestUID,
		)
	}

	// sudo 视图可见（sudoCtx=true 不触发 privCtx 检查）
	if !p.eventBelongsToUser(buildEvent, bug28SudoTestUID, true) {
		t.Errorf(
			"回归-2: sudo_test(uid=%d) 以 sudo 视图应收到自己的 sudo build 事件",
			bug28SudoTestUID,
		)
	}
}

// TestBug28_Reg3_DBOwner_AfterGraceExpiry
//
// 回归-3：completedBuildOwner TTL 到期后（用空 map 模拟），
// DB owner 路径仍正确过滤（BUG-16 基础功能不受影响）。
func TestBug28_Reg3_DBOwner_AfterGraceExpiry(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// DB: bob 是 owner（TTL 到期后 DB 路径接管）
	bobID := regularIdentity("bob", bug28BobUID)
	if err := p.db.SetImageOwner(bug28RebuildImageID, bobID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}
	// completedBuildOwner 已过期（为空），pendingBuildTags 也已清除

	buildEvent := makeImageEvent("tag", bug28RebuildImageID, bug28Tag)

	if p.eventBelongsToUser(buildEvent, bug28SudoTestUID, false) {
		t.Errorf(
			"回归-3 [DB 路径]: sudo_test(uid=%d) 不应收到 bob 的 image 事件（DB owner=bob）",
			bug28SudoTestUID,
		)
	}
	if !p.eventBelongsToUser(buildEvent, bug28BobUID, false) {
		t.Errorf(
			"回归-3 [DB 路径]: bob(uid=%d) 应收到自己的 image 事件（DB owner 匹配）",
			bug28BobUID,
		)
	}
}

// TestBug28_Reg4_CompletedBuildOwner_BlocksBothPendingAndDB
//
// 回归-4：completedBuildOwner 优先于 DB owner，即使 DB owner == uid 也应拦截。
// 场景：sudo_test 是 DB owner，但最近是 bob 构建的；sudo_test 不应看到此事件。
func TestBug28_Reg4_CompletedBuildOwner_BlocksBothPendingAndDB(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// DB: sudo_test 是 owner
	sudoTestID := regularIdentity("sudo_test", bug28SudoTestUID)
	if err := p.db.SetImageOwner(bug28RebuildImageID, sudoTestID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}
	// completedBuildOwner: bob 是最近构建者
	p.completedBuildOwner.Store(bug28Tag, pruneOwnerInfo{ownerUID: bug28BobUID, privCtx: 0})

	buildEvent := makeImageEvent("tag", bug28RebuildImageID, bug28Tag)

	// completedBuildOwner 命中，ownerUID=bob≠sudo_test → 拦截，不因 DB owner==uid 放行
	if p.eventBelongsToUser(buildEvent, bug28SudoTestUID, false) {
		t.Errorf(
			"回归-4: sudo_test(uid=%d) 不应收到 bob 的事件，即使 DB owner=sudo_test\n"+
				"\tcompletedBuildOwner 应优先于 DB owner 路径",
			bug28SudoTestUID,
		)
	}
}

// TestBug28_Reg5_NoTag_Sha256NameEventUnaffected
//
// 回归-5：sha256 name 的 image create 事件（中间层）不进入 completedBuildOwner 检查，
// 行为与修复前完全一致（路径3放行，设计行为）。
func TestBug28_Reg5_NoTag_Sha256NameEventUnaffected(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// completedBuildOwner 有某 tag 的记录（不影响 sha256 name 事件）
	p.completedBuildOwner.Store(bug28Tag, pruneOwnerInfo{ownerUID: bug28BobUID})

	// sha256 name 的 create 事件（中间层，name 以 sha256: 开头）
	sha256Name := "sha256:deadbeef001122334455667788990011223344556677889900112233445566"
	createEvent := makeImageEvent("create", sha256Name, sha256Name)

	// 所有用户均可见（路径3，设计行为：sha256 中间层不携带有意义的 owner 信息）
	for _, uid := range []int{bug28BobUID, bug28SudoTestUID, bug28AliceUID} {
		if !p.eventBelongsToUser(createEvent, uid, false) {
			t.Errorf(
				"回归-5: uid=%d 不应被过滤 sha256 name 的 image create 事件（路径3设计行为）",
				uid,
			)
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// HTTP 集成验证
// ══════════════════════════════════════════════════════════════════════════════

// TestBug28_Integration_RebuildLeak_NotInOldOwnerEvents
//
// HTTP 层集成验证：sudo_test 以非 sudo 模式监听 /events 时，
// bob 重建同 sha256 镜像产生的 image tag 事件不出现在响应中；
// sudo_test 自己的另一个镜像事件（不同 sha256，DB owner=sudo_test）正常到达。
func TestBug28_Integration_RebuildLeak_NotInOldOwnerEvents(t *testing.T) {
	// sudo_test 自己另一个镜像（与重建无关）
	const bug28OwnImageID = "sha256:ff001122334455667788990011223344556677889900112233445566778899ff"

	events := []string{
		// bob 重建的 image tag 事件（completedBuildOwner 将过滤）
		makeRawImageEvent("tag", bug28RebuildImageID, bug28Tag),
		// sudo_test 自己的普通镜像 tag 事件（DB owner=sudo_test，应可见）
		makeRawImageEvent("tag", bug28OwnImageID, "myapp:stable"),
	}
	upstream := fakeDockerEventsServer(events)
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// DB: bug28RebuildImageID owner = sudo_test（先前构建）
	sudoTestID := regularIdentity("sudo_test", bug28SudoTestUID)
	if err := p.db.SetImageOwner(bug28RebuildImageID, sudoTestID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner(rebuild): %v", err)
	}
	// completedBuildOwner: bob 是 bug28Tag 的最近构建者
	p.completedBuildOwner.Store(bug28Tag, pruneOwnerInfo{ownerUID: bug28BobUID, privCtx: 0})

	// sudo_test 自己的另一个镜像（privCtx=0，正常可见）
	if err := p.db.SetImageOwner(bug28OwnImageID, sudoTestID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner(own): %v", err)
	}

	// sudo_test 以非 sudo 模式（regularIdentity）监听 /events
	req := httptest.NewRequest("GET", "/events?type=image", nil)
	req = injectIdentity(req, makeTestIdentityProxy("sudo_test", bug28SudoTestUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)
	body := rw.Body.String()

	// bob 重建的事件不应出现
	if strings.Contains(body, bug28Tag) {
		t.Errorf(
			"BUG-28 [HTTP集成]: sudo_test 非 sudo events 收到了 bob 重建的事件\n"+
				"\t包含: %q\n\t完整响应: %s",
			bug28Tag, body,
		)
	}

	// sudo_test 自己的镜像事件必须正常到达
	if !strings.Contains(body, bug28OwnImageID) {
		t.Errorf(
			"BUG-28 [HTTP集成回归]: sudo_test 自己的镜像事件应在非 sudo events 中可见\n"+
				"\t镜像 ID: %q\n\t完整响应: %s",
			bug28OwnImageID, body,
		)
	}
}
