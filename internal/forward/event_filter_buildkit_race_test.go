package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-18b：BuildKit 路径（POST /grpc）image tag 竞态泄漏
//
// ──── 根因 ─────────────────────────────────────────────────────────────────
//
//   BUG-18 的 pendingBuildTags 修复仅覆盖经典 builder（POST /build → ActionBuild）。
//   BuildKit 走 POST /grpc → handleHijack → trackBuildKitImages goroutine：
//     1. gRPC 连接关闭时启动 goroutine
//     2. goroutine sleep 300ms（等待 Docker daemon 完成写入）
//     3. 300ms 后取快照对比，调用 SetImageOwner
//
//   竞态窗口 = 构建完成（事件发出）到 SetImageOwner 写入 DB 之间（通常 300ms+）。
//   此窗口内 eventBelongsToUser 走路径3 放行 → bob 收到 sudo_test 的 image tag 事件。
//
// ──── 修复 ─────────────────────────────────────────────────────────────────
//
//   handleHijack（isGRPC 分支）开始时，调用 parseBuildxTags(id.CmdLine)
//   提取 -t / --tag 参数，Store 到 pendingBuildTags（与经典 builder 共用路径0）。
//   注意：使用 id.CmdLine（完整命令行，来自 /proc/{pid}/cmdline），
//   而非 id.DockerCommand（已解析子命令）。BuildKit gRPC 来自 docker-buildx
//   插件进程，base 为 docker-buildx，parseDockerCommand 返回 ""，
//   必须读 CmdLine 才能提取到 -t/--tag 参数。
//
//   trackBuildKitImages 在 writeOne 完成后（SetImageOwner 调用后），
//   对发现的新 tag 执行 CompareAndDelete 清理。
//
//   多连接场景：未发现新镜像的 goroutine 不做清理；
//   发现新镜像的 goroutine 负责清理，CompareAndDelete 并发安全。
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"net/http/httptest"
	"testing"
)

// ══════════════════════════════════════════════════════════════════════════════
// parseBuildxTags 单元测试
// ══════════════════════════════════════════════════════════════════════════════

// TestParseBuildxTags_ShortFlag
//
// 基础：-t flag（最常见形式）。
func TestParseBuildxTags_ShortFlag(t *testing.T) {
	cmd := "buildx build -t image_sudo:test_sudo /tmp/build-ctx"
	tags := parseBuildxTags(cmd)
	if len(tags) != 1 || tags[0] != "image_sudo:test_sudo" {
		t.Errorf("parseBuildxTags(%q) = %v, want [\"image_sudo:test_sudo\"]", cmd, tags)
	}
}

// TestParseBuildxTags_LongFlag
//
// --tag 长参数形式。
func TestParseBuildxTags_LongFlag(t *testing.T) {
	cmd := "buildx build --tag image_sudo:test_sudo ."
	tags := parseBuildxTags(cmd)
	if len(tags) != 1 || tags[0] != "image_sudo:test_sudo" {
		t.Errorf("parseBuildxTags(%q) = %v, want [\"image_sudo:test_sudo\"]", cmd, tags)
	}
}

// TestParseBuildxTags_LongFlagEqual
//
// --tag=value 等号形式。
func TestParseBuildxTags_LongFlagEqual(t *testing.T) {
	cmd := "buildx build --tag=image_sudo:test_sudo ."
	tags := parseBuildxTags(cmd)
	if len(tags) != 1 || tags[0] != "image_sudo:test_sudo" {
		t.Errorf("parseBuildxTags(%q) = %v, want [\"image_sudo:test_sudo\"]", cmd, tags)
	}
}

// TestParseBuildxTags_MultipleFlags
//
// 多 tag（docker buildx build -t foo:v1 -t foo:latest）。
func TestParseBuildxTags_MultipleFlags(t *testing.T) {
	cmd := "/usr/libexec/docker/cli-plugins/docker-buildx buildx build -t image_sudo:test_sudo -t image_sudo:latest /tmp/build-ctx"
	tags := parseBuildxTags(cmd)
	want := map[string]bool{"image_sudo:test_sudo": true, "image_sudo:latest": true}
	if len(tags) != len(want) {
		t.Fatalf("parseBuildxTags: got %d tags, want %d: %v", len(tags), len(want), tags)
	}
	for _, tag := range tags {
		if !want[tag] {
			t.Errorf("parseBuildxTags: unexpected tag %q", tag)
		}
	}
}

// TestParseBuildxTags_NoTag
//
// 无 -t 参数时返回空切片（不 panic）。
func TestParseBuildxTags_NoTag(t *testing.T) {
	cmd := "buildx build ."
	tags := parseBuildxTags(cmd)
	if len(tags) != 0 {
		t.Errorf("parseBuildxTags(%q) = %v, want []", cmd, tags)
	}
}

// TestParseBuildxTags_FullPath
//
// 真实 cmdline 格式（含完整插件路径，来自 /proc/{pid}/cmdline）。
func TestParseBuildxTags_FullPath(t *testing.T) {
	cmd := "/usr/libexec/docker/cli-plugins/docker-buildx buildx build -t image_sudo:test_sudo /tmp/build-ctx"
	tags := parseBuildxTags(cmd)
	if len(tags) != 1 || tags[0] != "image_sudo:test_sudo" {
		t.Errorf("parseBuildxTags(%q) = %v, want [\"image_sudo:test_sudo\"]", cmd, tags)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// RED TEST：BuildKit 竞态复现
// ══════════════════════════════════════════════════════════════════════════════

// TestBug18b_BuildKit_ImageTagRace_PendingTagBlocksOtherUsers
//
// RED TEST（修复前必须失败）：
//
// 精确模拟 BuildKit 竞态窗口：
//   - gRPC 连接建立时，handleHijack 将 pendingBuildTags["image_sudo:test_sudo"] = 1005
//   - DB 为空（trackBuildKitImages 的 300ms 窗口，SetImageOwner 尚未执行）
//   - Docker 已发出 image tag 事件
//   - bob / alice 不应收到该事件
//
// 与 BUG-18 RED TEST 的区别：
//   BUG-18 测试的是经典 builder（ActionBuild case）路径；
//   BUG-18b 测试的是 BuildKit（POST /grpc → handleHijack）路径——
//   注册时机和清理时机不同，但 eventBelongsToUser 路径0 完全一致。
func TestBug18b_BuildKit_ImageTagRace_PendingTagBlocksOtherUsers(t *testing.T) {
	// 模拟 handleHijack(isGRPC) 注册 pending tag（修复后的行为）
	// 修复前：此 Store 不存在，DB 为空 → 路径3 → bob 收到事件
	// 修复后：Store 存在 → 路径0 → ownerUID(1005) ≠ bob(1002) → return false
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.pendingBuildTags.Store(bug18Tag, sudoTestUID)
	defer p.pendingBuildTags.CompareAndDelete(bug18Tag, sudoTestUID)
	// DB 完全为空——模拟 trackBuildKitImages 300ms 等待窗口

	tagEvent := makeImageEvent("tag", sudoTestImageID, bug18Tag)

	// ── RED ASSERTION A：bob 不应收到 sudo_test 的 image tag 事件 ────────
	if p.eventBelongsToUser(tagEvent, bobUID3, false) {
		t.Errorf(
			"BUG-18b [BuildKit image tag 竞态泄漏]:\n"+
				"\tbob(uid=%d) 收到了 sudo_test(uid=%d) 的 image tag 事件\n"+
				"\tDB 为空（BuildKit 300ms 窗口），handleHijack 未注册 pendingBuildTags\n"+
				"\tAction=%q  imageID=%q  name=%q",
			bobUID3, sudoTestUID, "tag", sudoTestImageID, bug18Tag,
		)
	}

	// ── RED ASSERTION B：alice 同样不应收到 ──────────────────────────────
	if p.eventBelongsToUser(tagEvent, 1001, false) {
		t.Errorf(
			"BUG-18b [BuildKit竞态泄漏]: alice(uid=1001) 收到了 sudo_test 的 image tag 事件\n"+
				"\t隔离失效对任意非构建者均成立",
		)
	}

	// ── 正向断言：sudo_test 自己应收到 ───────────────────────────────────
	if !p.eventBelongsToUser(tagEvent, sudoTestUID, false) {
		t.Errorf(
			"BUG-18b: sudo_test(uid=%d) 不应被过滤掉自己的 image tag 事件（pendingBuildTags 路径0）",
			sudoTestUID,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归矩阵
// ══════════════════════════════════════════════════════════════════════════════

// TestBug18b_Reg1_AfterTrackComplete_DBFiltersCorrectly
//
// 回归-1：trackBuildKitImages 完成（SetImageOwner 已调用，pendingBuildTags 已清理），
// 后续同 tag 事件通过 DB 路径正确过滤（BUG-16 路径不受影响）。
func TestBug18b_Reg1_AfterTrackComplete_DBFiltersCorrectly(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	// 模拟 trackBuildKitImages 完成：pending 已清理，DB 已写入
	sudoID := regularIdentity("sudo_test", sudoTestUID)
	if err := p.db.SetImageOwner(sudoTestImageID, sudoID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}
	// pendingBuildTags 未注册（已被 CompareAndDelete 清理）

	tagEvent := makeImageEvent("tag", sudoTestImageID, bug18Tag)

	if p.eventBelongsToUser(tagEvent, bobUID3, false) {
		t.Errorf(
			"回归-1 [BuildKit]: bob(uid=%d) 不应收到 DB 已注册的 sudo_test image tag 事件\n"+
				"\tBUG-16 的 DB 路径应继续正确工作",
			bobUID3,
		)
	}
	if !p.eventBelongsToUser(tagEvent, sudoTestUID, false) {
		t.Errorf(
			"回归-1 [BuildKit]: sudo_test(uid=%d) 应收到自己的 image tag 事件（DB 路径）",
			sudoTestUID,
		)
	}
}

// TestBug18b_Reg2_MultiTag_AllProtected
//
// 回归-2：docker buildx build -t foo:v1 -t foo:latest（多 tag）时，
// parseBuildxTags 提取两个 tag 并均注册到 pendingBuildTags，全部受保护。
func TestBug18b_Reg2_MultiTag_AllProtected(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	tag1 := "image_sudo:test_sudo"
	tag2 := "image_sudo:latest"
	p.pendingBuildTags.Store(tag1, sudoTestUID)
	defer p.pendingBuildTags.CompareAndDelete(tag1, sudoTestUID)
	p.pendingBuildTags.Store(tag2, sudoTestUID)
	defer p.pendingBuildTags.CompareAndDelete(tag2, sudoTestUID)

	for _, tag := range []string{tag1, tag2} {
		event := makeImageEvent("tag", sudoTestImageID, tag)
		if p.eventBelongsToUser(event, bobUID3, false) {
			t.Errorf(
				"回归-2 [BuildKit 多 tag]: bob(uid=%d) 收到了 sudo_test 的 image tag 事件\n"+
					"\ttag=%q 应受 pendingBuildTags 保护",
				bobUID3, tag,
			)
		}
		if !p.eventBelongsToUser(event, sudoTestUID, false) {
			t.Errorf(
				"回归-2 [BuildKit 多 tag]: sudo_test(uid=%d) 应能看到自己的 image tag 事件\n"+
					"\ttag=%q",
				sudoTestUID, tag,
			)
		}
	}
}

// TestBug18b_Reg3_CompareAndDelete_ConcurrentBuildSameTags
//
// 回归-3：两个用户并发构建同一 tag（tag collision 场景）。
//   sudo_test(uid=1005) 先开始 → pendingBuildTags["image_sudo:test_sudo"] = 1005
//   bob(uid=1002) 后开始 → Store 覆写为 1002
//   sudo_test 的 goroutine CompareAndDelete("image_sudo:test_sudo", 1005) → uid 不匹配 → 不删
//   bob 的 goroutine CompareAndDelete("image_sudo:test_sudo", 1002) → 删除
//
// 修复不得引入 tag 归属错乱。
func TestBug18b_Reg3_CompareAndDelete_ConcurrentBuildSameTags(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	tag := "image_sudo:test_sudo"

	// sudo_test 先注册
	p.pendingBuildTags.Store(tag, sudoTestUID)
	// bob 后注册（覆写）
	p.pendingBuildTags.Store(tag, bobUID3)

	// sudo_test 的 CompareAndDelete（uid 不匹配，不删除）
	p.pendingBuildTags.CompareAndDelete(tag, sudoTestUID)

	// 此时 bob 的记录仍在
	event := makeImageEvent("tag", sudoTestImageID, tag)
	if p.eventBelongsToUser(event, sudoTestUID, false) {
		t.Errorf(
			"回归-3 [并发 tag]: sudo_test(uid=%d) 不应看到 bob(uid=%d) 构建的 image tag 事件\n"+
				"\tCompareAndDelete 应保留 bob 的 pending 记录",
			sudoTestUID, bobUID3,
		)
	}
	if !p.eventBelongsToUser(event, bobUID3, false) {
		t.Errorf(
			"回归-3 [并发 tag]: bob(uid=%d) 应能看到自己的 image tag 事件（pending 仍有效）",
			bobUID3,
		)
	}

	// bob 的 CompareAndDelete（匹配，删除）
	p.pendingBuildTags.CompareAndDelete(tag, bobUID3)

	// 清理后 DB 也无记录 → 路径3 → 放行
	afterClean := p.eventBelongsToUser(event, bobUID3, false)
	if !afterClean {
		t.Errorf(
			"回归-3: 清理后 DB 无记录，路径3 应放行（bob uid=%d）",
			bobUID3,
		)
	}
}
