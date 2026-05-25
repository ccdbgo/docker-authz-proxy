package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-16：image 事件流用户隔离失效
//
// ──── Bug 场景 ─────────────────────────────────────────────────────────────
//
//   sudo_test(uid=1005) 执行 sudo docker image build -t image_sudo:test_sudo .
//   bob(uid=1002) 执行 docker system events --filter type=image
//
//   期望：bob 不应收到 sudo_test 的镜像构建事件
//   实际：bob 收到了：
//     image tag sha256:9da033... (name=image_sudo:test_sudo)
//     image create sha256:9da033... (name=sha256:9da033...)
//
// ──── 根本原因 ─────────────────────────────────────────────────────────────
//
//   image 事件的 Attributes 中只有 name（tag 或 sha256 ID），
//   无 system.authz.owner.uid 字段。
//   eventBelongsToUser 对 image 事件无专门处理，走到兜底 return true，
//   所有用户均可收到所有 image 事件。
//
// ──── 修复方案 ─────────────────────────────────────────────────────────────
//
//   在 eventBelongsToUser（已改为 ProxyServer 方法）中增加 image 分支：
//     Actor.ID = sha256:...（镜像 content ID）
//     查询 p.db.GetImageOwner(imageID)：
//       路径 1：found && isPublic            → true（公共镜像所有人可见）
//       路径 2：found && ownerUID == uid     → true（本人镜像）
//       路径 3：found && ownerUID != uid     → false（他人私有镜像，隔离）
//       路径 4：!found（DB 无记录）          → true（基础镜像/中间层，放行）
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// ──────────────────────────────────────────────────────────────────────────────
// 场景常量
// ──────────────────────────────────────────────────────────────────────────────

const (
	sudoTestUID = 1005 // sudo_test 的 Real UID
	bobUID3     = 1002 // bob 的 Real UID（与其他文件中 bobUID 等区分）
)

// 镜像 content ID（sha256: 前缀，与真实 Docker 事件格式一致）
var (
	sudoTestImageID = "sha256:9da033d6be322ed2efdba84a9c973bb046793fadbc71108e48914091546d5c93"
	bobImageID      = "sha256:aabbcc1122334455667788990011223344556677889900112233445566778899aa"
	publicImageID   = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00"
)

// ──────────────────────────────────────────────────────────────────────────────
// 辅助：构造 image 事件（与真实 Docker daemon 格式一致）
// ──────────────────────────────────────────────────────────────────────────────

// makeImageEvent 构造 image 事件。
// 真实 Docker 事件：Actor.ID = sha256:...，Attributes["name"] = tag 或 sha256:...。
func makeImageEvent(action, imageID, name string) []byte {
	return []byte(fmt.Sprintf(
		`{"Type":"image","Action":%q,"Actor":{"ID":%q,"Attributes":{"name":%q}}}`,
		action, imageID, name,
	))
}

// makeRawImageEvent 构造 image 事件字符串（用于 fakeDockerEventsServer）。
func makeRawImageEvent(action, imageID, name string) string {
	return fmt.Sprintf(
		`{"Type":"image","Action":%q,"Actor":{"ID":%q,"Attributes":{"name":%q}}}`,
		action, imageID, name,
	)
}

// ══════════════════════════════════════════════════════════════════════════════
// RED TEST：Bug 复现
// ══════════════════════════════════════════════════════════════════════════════

// TestBug16_ImageEvent_LeaksToOtherUsers
//
// RED TEST：修复前必须 100% 失败。
//
// 精确复现 Bug 报告场景：
//
//	sudo_test(uid=1005) build 镜像 → Docker 产生 image tag / image create 事件
//	bob(uid=1002) 的 docker system events 不应收到 sudo_test 的镜像事件
//
// 失败路径（修复前）：
//
//	eventBelongsToUser 无 image 分支 → 走兜底 return true → 所有 image 事件透传
//
// 通过路径（修复后）：
//
//	ev.Type == "image" → 查 DB → sudoTestImageID owner=1005 ≠ bob 1002 → false
func TestBug16_ImageEvent_LeaksToOtherUsers(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// 预置：sudo_test 的私有镜像写入 DB
	sudoID := regularIdentity("sudo_test", sudoTestUID)
	if err := p.db.SetImageOwner(sudoTestImageID, sudoID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	// ── RED ASSERTION A：image tag 事件不应泄漏给 bob ────────────────────
	tagEvent := makeImageEvent("tag", sudoTestImageID, "image_sudo:test_sudo")
	if p.eventBelongsToUser(tagEvent, bobUID3) {
		t.Errorf(
			"BUG-16 [image tag 事件泄漏]:\n"+
				"\tbob(uid=%d) 收到了 sudo_test(uid=%d) 的 image tag 事件\n"+
				"\t镜像 ID: %q\n"+
				"\t根因: eventBelongsToUser 无 image 分支 → return true（系统事件透传）\n"+
				"\tDocker image Attributes 仅含 name，无 system.authz.owner.uid 标签\n"+
				"\t修复: 增加 image 分支，通过 DB 查询归属",
			bobUID3, sudoTestUID, sudoTestImageID,
		)
	}

	// ── RED ASSERTION B：image create 事件不应泄漏给 bob ─────────────────
	createEvent := makeImageEvent("create", sudoTestImageID, sudoTestImageID)
	if p.eventBelongsToUser(createEvent, bobUID3) {
		t.Errorf(
			"BUG-16 [image create 事件泄漏]:\n"+
				"\tbob(uid=%d) 收到了 sudo_test(uid=%d) 的 image create 事件\n"+
				"\t镜像 ID: %q\n"+
				"\t根因: 与 tag 事件相同，image create 同样无 owner 标签",
			bobUID3, sudoTestUID, sudoTestImageID,
		)
	}

	// ── 正向断言：sudo_test 自己的镜像事件对 sudo_test 可见 ──────────────
	if !p.eventBelongsToUser(tagEvent, sudoTestUID) {
		t.Errorf(
			"回归: sudo_test(uid=%d) 不应被过滤掉自己的 image tag 事件\n"+
				"\t镜像 ID: %q",
			sudoTestUID, sudoTestImageID,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归测试矩阵
// ══════════════════════════════════════════════════════════════════════════════

// TestBug16_Reg1_PublicImage_VisibleToAll
//
// 回归-1：公共镜像（is_public=true）的事件对所有用户可见。
// 修复不能过度隔离——公共镜像（如 ubuntu、nginx）被所有人使用，
// 其 pull/tag 事件应对全部用户开放。
func TestBug16_Reg1_PublicImage_VisibleToAll(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// 预置：公共镜像（root pull，is_public=true）
	rootID := regularIdentity("root", 0)
	if err := p.db.SetImageOwner(publicImageID, rootID, true, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	pullEvent := makeImageEvent("pull", publicImageID, "ubuntu:22.04")

	for _, uid := range []int{bobUID3, sudoTestUID, 1001} {
		if !p.eventBelongsToUser(pullEvent, uid) {
			t.Errorf(
				"回归-1: 公共镜像事件应对 uid=%d 可见\n"+
					"\t镜像 ID: %q\n"+
					"\t修复不得将公共镜像事件误过滤",
				uid, publicImageID,
			)
		}
	}
}

// TestBug16_Reg2_DBNotFound_Passthrough
//
// 回归-2：DB 中无记录的镜像（基础镜像、中间层、系统镜像）事件应放行。
// 场景：Docker build 过程产生大量中间层镜像事件，这些镜像不在 DB 中，
// 不能因此屏蔽所有用户的中间层事件（否则构建日志流丢失）。
func TestBug16_Reg2_DBNotFound_Passthrough(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	// DB 为空，无任何镜像记录

	unknownID := "sha256:deadbeef11223344556677889900aabbccddeeff112233445566778899001122"
	event := makeImageEvent("create", unknownID, unknownID)

	for _, uid := range []int{bobUID3, sudoTestUID, 1001} {
		if !p.eventBelongsToUser(event, uid) {
			t.Errorf(
				"回归-2: DB 无记录的镜像事件应对 uid=%d 放行（不能误过滤）\n"+
					"\t镜像 ID: %q\n"+
					"\t基础镜像/中间层不在 DB 中，应走路径4：放行",
				uid, unknownID,
			)
		}
	}
}

// TestBug16_Reg3_SymmetricIsolation
//
// 回归-3：对称隔离 —— bob 的镜像事件对 sudo_test 也不可见（反向验证）。
// 修复必须双向对称，不能只隔离 sudo_test → bob 方向。
func TestBug16_Reg3_SymmetricIsolation(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// 预置：bob 的私有镜像
	bobID := regularIdentity("bob", bobUID3)
	if err := p.db.SetImageOwner(bobImageID, bobID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	bobEvent := makeImageEvent("tag", bobImageID, "bob-app:latest")

	// sudo_test 不应收到 bob 的镜像事件
	if p.eventBelongsToUser(bobEvent, sudoTestUID) {
		t.Errorf(
			"回归-3 [对称隔离]: sudo_test(uid=%d) 收到了 bob(uid=%d) 的 image 事件\n"+
				"\t镜像 ID: %q\n"+
				"\t隔离必须双向对称，bob→sudo_test 方向也必须被过滤",
			sudoTestUID, bobUID3, bobImageID,
		)
	}

	// bob 自己的镜像事件对 bob 可见
	if !p.eventBelongsToUser(bobEvent, bobUID3) {
		t.Errorf(
			"回归-3: bob(uid=%d) 不应被过滤掉自己的 image 事件\n"+
				"\t镜像 ID: %q",
			bobUID3, bobImageID,
		)
	}
}

// TestBug16_Reg4_ImageEventStream_Integration
//
// 回归-4：HTTP 集成测试（通过 proxy ServeHTTP），验证因果链完整性：
//
//	DB 预置 sudo_test 的私有镜像 → bob GET /events?type=image
//	→ fake Docker 返回 sudo_test 的 image tag/create 事件 + bob 自己的镜像事件
//	→ proxy 过滤 → bob 响应体只含自己的镜像事件
func TestBug16_Reg4_ImageEventStream_Integration(t *testing.T) {
	// fake Docker 返回混合事件流：sudo_test 的事件 + bob 自己的事件
	events := []string{
		makeRawImageEvent("tag", sudoTestImageID, "image_sudo:test_sudo"),
		makeRawImageEvent("create", sudoTestImageID, sudoTestImageID),
		makeRawImageEvent("tag", bobImageID, "bob-app:latest"),
	}
	upstream := fakeDockerEventsServer(events)
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 预置 DB：sudo_test 私有镜像 + bob 自己的镜像
	sudoID := regularIdentity("sudo_test", sudoTestUID)
	if err := p.db.SetImageOwner(sudoTestImageID, sudoID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner(sudoTest): %v", err)
	}
	bobID := regularIdentity("bob", bobUID3)
	if err := p.db.SetImageOwner(bobImageID, bobID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner(bob): %v", err)
	}

	// bob 订阅 image 事件
	req := httptest.NewRequest("GET", "/events?type=image", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID3))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)
	body := rw.Body.String()

	// sudo_test 的事件不应到达 bob
	for _, forbidden := range []string{"image_sudo:test_sudo", sudoTestImageID} {
		if strings.Contains(body, forbidden) {
			t.Errorf(
				"回归-4 [HTTP集成]: bob(uid=%d) 收到了 sudo_test(uid=%d) 的 image 事件\n"+
					"\t包含: %q\n"+
					"\t响应体: %s",
				bobUID3, sudoTestUID, forbidden, body,
			)
		}
	}

	// bob 自己的镜像事件必须到达
	if !strings.Contains(body, bobImageID) {
		t.Errorf(
			"回归-4: bob(uid=%d) 应收到自己的 image 事件\n"+
				"\t镜像 ID: %q\n"+
				"\t响应体: %s",
			bobUID3, bobImageID, body,
		)
	}
}
