package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-18：docker build 竞态 —— image tag 事件在 SetImageOwner 完成前泄漏
//
// ──── 根因 ─────────────────────────────────────────────────────────────────
//
//   sudo_test(uid=1005) 执行 sudo docker build -t image_sudo:test_sudo .
//
//   Docker daemon 在构建完成瞬间同时做两件事：
//     (a) 向所有订阅者推送 image create / image tag 事件
//     (b) 向代理返回构建响应流（流末尾含 "Successfully built sha256:9da033..."）
//
//   代理处理顺序（ActionBuild case）：
//     streamAndCaptureImageID() 读完整个响应流 → 提取 sha256 → SetImageOwner()
//
//   竞态窗口：
//     事件 (a) 在构建完成时发出，而 SetImageOwner（DB 写入）在响应流全部读完后才执行。
//     bob 的事件监听器在此窗口内收到事件：
//       GetImageOwner("sha256:9da033...") → found=false
//       → 路径3 return true → bob 收到 sudo_test 的 image tag 事件 ✗
//
//   BUG-16 的测试未覆盖此场景：TestBug16 预先调用了 SetImageOwner（DB 已有记录），
//   与真实竞态场景不一致，测试通过但生产仍失败。
//
// ──── 修复 ─────────────────────────────────────────────────────────────────
//
//   ProxyServer 增加 pendingBuildTags sync.Map（tag → ownerUID）：
//     ActionBuild case 开始时（响应头到达，早于构建完成和事件发出）：
//       for _, tag := range u.Query()["t"] { Store(tag, uid); defer CompareAndDelete }
//     eventBelongsToUser image 分支路径 0（优先于 DB 查询）：
//       若 attrs["name"] 非 sha256 前缀 → 查 pendingBuildTags → 按 uid 过滤
//
//   覆盖范围：仅限经典 builder（POST /build）。
//   BuildKit（POST /grpc → trackBuildKitImages goroutine）需独立修复（BUG-18b）。
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// bug18Tag 是 sudo_test 构建的镜像 tag，与 event_filter_image_isolation_test.go
// 中的 sudoTestImageID / bobImageID / sudoTestUID / bobUID3 共用。
const bug18Tag = "image_sudo:test_sudo"

// ══════════════════════════════════════════════════════════════════════════════
// RED TEST：竞态复现（DB 为空时 image tag 事件泄漏）
// ══════════════════════════════════════════════════════════════════════════════

// TestBug18_ImageTagRace_NamedTagLeaksWhenDBEmpty
//
// RED TEST：修复前必须 100% 失败。
//
// 精确复现竞态窗口：
//   DB 为空（SetImageOwner 尚未被调用），
//   Docker 已发出 "image tag sha256:9da033... name=image_sudo:test_sudo"，
//   bob 不应收到该事件。
//
// 失败路径（修复前）：
//   ev.Type=="image" → GetImageOwner("sha256:9da033...") → found=false
//   → 路径3 return true → bob 收到 sudo_test 的构建镜像 tag 事件
//
// 通过路径（修复后）：
//   路径0：pendingBuildTags["image_sudo:test_sudo"] = 1005
//          ownerUID(1005) ≠ bob(1002) → return false
func TestBug18_ImageTagRace_NamedTagLeaksWhenDBEmpty(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	// pendingBuildTags 模拟 ActionBuild case 开始时已注册（响应头到达时）
	p.pendingBuildTags.Store(bug18Tag, sudoTestUID)
	defer p.pendingBuildTags.CompareAndDelete(bug18Tag, sudoTestUID)
	// DB 完全为空 —— 模拟竞态窗口：SetImageOwner 尚未执行

	tagEvent := makeImageEvent("tag", sudoTestImageID, bug18Tag)

	// ── RED ASSERTION A：image tag 事件不应泄漏给 bob ──────────────────────
	if p.eventBelongsToUser(tagEvent, bobUID3, false) {
		t.Errorf(
			"BUG-18 [image tag 竞态泄漏]:\n"+
				"\tbob(uid=%d) 收到了 sudo_test(uid=%d) 的 image tag 事件\n"+
				"\tDB 为空（竞态窗口），pendingBuildTags 已注册但未生效\n"+
				"\tAction=%q  imageID=%q  name=%q\n"+
				"\t根因：路径0（pendingBuildTags）未实现，命名 tag 事件走路径3放行",
			bobUID3, sudoTestUID, "tag", sudoTestImageID, bug18Tag,
		)
	}

	// ── RED ASSERTION B：alice 同样不应收到 ────────────────────────────────
	if p.eventBelongsToUser(tagEvent, 1001, false) {
		t.Errorf(
			"BUG-18 [竞态泄漏]: alice(uid=1001) 收到了 sudo_test 的 image tag 事件\n"+
				"\t隔离失效对任意非构建者均成立",
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归矩阵
// ══════════════════════════════════════════════════════════════════════════════

// TestBug18_Reg1_PendingBuild_BuilderAllowed
//
// 回归-1：pendingBuildTags 已注册时，构建者（sudo_test）应能看到自己的 image tag 事件。
func TestBug18_Reg1_PendingBuild_BuilderAllowed(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.pendingBuildTags.Store(bug18Tag, sudoTestUID)
	defer p.pendingBuildTags.CompareAndDelete(bug18Tag, sudoTestUID)

	tagEvent := makeImageEvent("tag", sudoTestImageID, bug18Tag)

	if !p.eventBelongsToUser(tagEvent, sudoTestUID, false) {
		t.Errorf(
			"回归-1: sudo_test(uid=%d) 应能看到自己的 image tag 事件\n"+
				"\tpendingBuildTags[%q]=%d → uid 匹配 → return true",
			sudoTestUID, bug18Tag, sudoTestUID,
		)
	}
}

// TestBug18_Reg2_ImageCreateSHA256_StillPassthrough
//
// 回归-2：image create 事件（name 为 sha256 格式，构建中间层）在 DB 为空时
// 仍应对所有用户放行（路径 3）。修复不得将中间层 create 事件错误隔离。
func TestBug18_Reg2_ImageCreateSHA256_StillPassthrough(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	// DB 为空，pendingBuildTags 也为空

	// image create：name 为 sha256（中间层格式，非命名 tag）
	createEvent := makeImageEvent("create", sudoTestImageID, sudoTestImageID)

	for _, uid := range []int{bobUID3, sudoTestUID, 1001} {
		if !p.eventBelongsToUser(createEvent, uid, false) {
			t.Errorf(
				"回归-2: uid=%d 不应被过滤 image create sha256 事件（DB 无记录 → 中间层放行）\n"+
					"\timageID=%q  name=%q（sha256 前缀，非命名 tag，路径0 不生效）\n"+
					"\t修复不得破坏构建中间层事件的透传行为",
				uid, sudoTestImageID, sudoTestImageID,
			)
		}
	}
}

// TestBug18_Reg3_AfterBuildComplete_DBFiltersCorrectly
//
// 回归-3：build 完成后 SetImageOwner 已调用（DB 有记录，pending map 已清理），
// 后续同一 image tag 事件仍通过 DB 路径正确过滤（BUG-16 路径不受影响）。
func TestBug18_Reg3_AfterBuildComplete_DBFiltersCorrectly(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	// 模拟 build 完成后：pending map 已清理，DB 已更新
	sudoID := regularIdentity("sudo_test", sudoTestUID)
	if err := p.db.SetImageOwner(sudoTestImageID, sudoID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	tagEvent := makeImageEvent("tag", sudoTestImageID, bug18Tag)

	if p.eventBelongsToUser(tagEvent, bobUID3, false) {
		t.Errorf(
			"回归-3: bob(uid=%d) 不应收到 DB 已注册的 sudo_test(uid=%d) image tag 事件\n"+
				"\tBUG-16 的 DB 过滤路径应继续正确工作",
			bobUID3, sudoTestUID,
		)
	}
	if !p.eventBelongsToUser(tagEvent, sudoTestUID, false) {
		t.Errorf(
			"回归-3: sudo_test(uid=%d) 应收到自己的 image tag 事件（DB 路径）",
			sudoTestUID,
		)
	}
}

// TestBug18_Reg4_MultiTag_AllProtected
//
// 回归-4：docker build -t foo:v1 -t foo:latest（多 tag）时，
// 所有 tag 的 image tag 事件均受保护，不只第一个。
func TestBug18_Reg4_MultiTag_AllProtected(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	tag1 := "image_sudo:test_sudo"
	tag2 := "image_sudo:latest"
	// 模拟 ActionBuild case 为两个 tag 均注册 pending
	p.pendingBuildTags.Store(tag1, sudoTestUID)
	defer p.pendingBuildTags.CompareAndDelete(tag1, sudoTestUID)
	p.pendingBuildTags.Store(tag2, sudoTestUID)
	defer p.pendingBuildTags.CompareAndDelete(tag2, sudoTestUID)

	for _, tag := range []string{tag1, tag2} {
		event := makeImageEvent("tag", sudoTestImageID, tag)
		if p.eventBelongsToUser(event, bobUID3, false) {
			t.Errorf(
				"回归-4 [多 tag]: bob(uid=%d) 收到了 sudo_test 的 image tag 事件\n"+
					"\ttag=%q 应受 pendingBuildTags 保护",
				bobUID3, tag,
			)
		}
		if !p.eventBelongsToUser(event, sudoTestUID, false) {
			t.Errorf(
				"回归-4 [多 tag]: sudo_test(uid=%d) 应能看到自己的 image tag 事件\n"+
					"\ttag=%q",
				sudoTestUID, tag,
			)
		}
	}
}

// TestBug18_Reg5_Integration_PendingBlocksOtherUsers
//
// 回归-5：HTTP 集成测试（通过 ServeHTTP）。
// pendingBuildTags 已注册 sudo_test 的 tag → bob 响应体不含该 tag；
// bob 自己的 image 事件（DB 已注册）必须到达。
func TestBug18_Reg5_Integration_PendingBlocksOtherUsers(t *testing.T) {
	events := []string{
		makeRawImageEvent("tag", sudoTestImageID, bug18Tag),
		makeRawImageEvent("tag", bobImageID, "bob-app:latest"),
	}
	upstream := fakeDockerEventsServer(events)
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	p.pendingBuildTags.Store(bug18Tag, sudoTestUID)
	defer p.pendingBuildTags.CompareAndDelete(bug18Tag, sudoTestUID)

	bobID := regularIdentity("bob", bobUID3)
	if err := p.db.SetImageOwner(bobImageID, bobID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner(bob): %v", err)
	}

	req := httptest.NewRequest("GET", "/events?type=image", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID3))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)
	body := rw.Body.String()

	if strings.Contains(body, bug18Tag) {
		t.Errorf(
			"回归-5 [HTTP集成]: bob(uid=%d) 收到了 sudo_test(uid=%d) 的 image tag 事件\n"+
				"\t包含: %q\n"+
				"\t响应体: %s",
			bobUID3, sudoTestUID, bug18Tag, body,
		)
	}
	if !strings.Contains(body, bobImageID) {
		t.Errorf(
			"回归-5: bob(uid=%d) 应收到自己的 image 事件\n"+
				"\t镜像 ID: %q\n"+
				"\t响应体: %s",
			bobUID3, bobImageID, body,
		)
	}
}
