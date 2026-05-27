package forward

// ══════════════════════════════════════════════════════════════════════════════
// Bug A（privileged_context 隔离）+ Bug B（prune 竞态）回归测试
//
// ──── Bug A 场景 ───────────────────────────────────────────────────────────
//
//   sudo_test(uid=1005) 先执行 sudo docker pull alpine:3.18（privileged_context=1）
//   sudo_test 之后以非 sudo 模式执行 docker system events
//
//   期望：sudo_test 的非特权视图不应看到该 sudo 操作产生的镜像事件
//   修复前：eventBelongsToUser 路径 2（owner.UID == uid）不检查 privileged_context，
//           sudo_test 以非 sudo 监听时收到了自己的 sudo 镜像事件
//
//   修复：GetImageOwner 返回 privCtx；路径 2 当 !sudoCtx && privCtx==1 时 return false
//
// ──── Bug B 场景 ───────────────────────────────────────────────────────────
//
//   alice(uid=1001) 执行 docker volume prune / docker image prune
//   bob(uid=1002) 同时执行 docker system events
//
//   期望：bob 不应看到 alice 的 volume destroy / image delete 事件
//   修复前：handle*Prune 同步删 DB → Docker 异步发事件 → 事件到达时 DB 已空
//           eventBelongsToUser 路径 3（found=false → return true）放行 → bob 可见
//
//   修复：completedPruneOwner sync.Map 在删 DB 前 Store，路径 3 前先查此 map
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

const (
	privCtxSudoTestUID = 1005 // sudo_test
	privCtxBobUID      = 1002
	privCtxAliceUID    = 1001
)

var (
	privCtxSudoImageID = "sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aa"
	privCtxVolumeName  = "user-1001-volume-mydata"
)

// ──────────────────────────────────────────────────────────────────────────────
// 辅助：构造 sudo 用户 CallerIdentity（IsSudoCommand() = true）
// ──────────────────────────────────────────────────────────────────────────────

func privCtxSudoIdentity(username string, uid int) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		EffectiveUsername: "root",
		EffectiveUID:      0,
		UserType:          auth.UserTypeSudo,
	}
}

func privCtxRegularIdentity(username string, uid int) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		EffectiveUsername: username,
		EffectiveUID:      uid,
		UserType:          auth.UserTypeRegular,
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Bug A：privileged_context 隔离 — 回归测试
// ══════════════════════════════════════════════════════════════════════════════

// TestPrivCtx_SudoImageEvent_HiddenInNonSudoView_regression
//
// sudo_test 以 sudo 命令 pull 了镜像（privileged_context=1），
// 之后以非 sudo 模式监听事件（sudoCtx=false）。
// 修复前 FAIL：路径 2 直接 return true，不检查 privileged_context。
// 修复后 PASS：路径 2 检查 !sudoCtx && privCtx==1 → return false。
func TestPrivCtx_SudoImageEvent_HiddenInNonSudoView_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// sudo_test 以 sudo 命令创建镜像 → privileged_context=1
	sudoID := privCtxSudoIdentity("sudo_test", privCtxSudoTestUID)
	if err := p.db.SetImageOwner(privCtxSudoImageID, sudoID, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	// 确认 DB 中 privileged_context=1（通过 CanSeeImage 与 eventBelongsToUser 的行为对比验证）
	if p.db.CanSeeImage(privCtxSudoTestUID, privCtxSudoImageID) {
		t.Fatal("前置条件失败：privileged_context=1 的镜像不应在 CanSeeImage 中可见")
	}

	imageDeleteEvent := makeImageEvent("delete", privCtxSudoImageID, privCtxSudoImageID)

	// Bug A 核心断言：sudo_test 以非 sudo 模式监听（sudoCtx=false）时，
	// 不应看到自己 sudo 操作产生的镜像事件
	if p.eventBelongsToUser(imageDeleteEvent, privCtxSudoTestUID, false) {
		t.Errorf(
			"Bug A [privileged_context 隔离失效]:\n"+
				"\tsudo_test(uid=%d) 以非 sudo 模式监听，但收到了自己 sudo pull 产生的 image delete 事件\n"+
				"\t镜像 ID: %s（privileged_context=1）\n"+
				"\t预期: eventBelongsToUser=false（与 docker image ls 行为一致，该镜像不显示）\n"+
				"\t实际: eventBelongsToUser=true（事件泄漏到非特权视图）",
			privCtxSudoTestUID, privCtxSudoImageID,
		)
	}

	// 回归：bob 不应看到 sudo_test 的 sudo 镜像事件（无论 sudoCtx）
	if p.eventBelongsToUser(imageDeleteEvent, privCtxBobUID, false) {
		t.Errorf("回归：bob(uid=%d) 不应看到 sudo_test 的镜像事件", privCtxBobUID)
	}

	// 回归：sudo_test 以 sudo 模式监听（sudoCtx=true）时，应能看到（虽实际上不进入此函数）
	if !p.eventBelongsToUser(imageDeleteEvent, privCtxSudoTestUID, true) {
		t.Errorf("回归：sudo_test 以 sudo 模式监听时，应能看到自己 sudo 操作的镜像事件")
	}
}

// TestPrivCtx_RegularImageEvent_VisibleInNonSudoView_regression
//
// sudo_test 以普通命令 pull 了镜像（privileged_context=0），
// 以非 sudo 模式监听时应能看到该事件。
func TestPrivCtx_RegularImageEvent_VisibleInNonSudoView_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// sudo_test 以普通命令创建镜像 → privileged_context=0
	regularID := privCtxRegularIdentity("sudo_test", privCtxSudoTestUID)
	if err := p.db.SetImageOwner(privCtxSudoImageID, regularID, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	imageTagEvent := makeImageEvent("tag", privCtxSudoImageID, "myapp:latest")

	// 普通镜像（privileged_context=0）在非 sudo 视图中应可见
	if !p.eventBelongsToUser(imageTagEvent, privCtxSudoTestUID, false) {
		t.Errorf(
			"回归失效：sudo_test 以非 sudo 模式创建的镜像（privileged_context=0），"+
				"以非 sudo 模式监听时不应被过滤，但 eventBelongsToUser 返回 false",
		)
	}
}

// TestPrivCtx_SudoVolumeEvent_PassthroughByName_regression
//
// volume 事件通过名称前缀判断属主（不查 DB），不受 privileged_context 影响。
// 验证 volume 事件的现有行为不被本次修改破坏。
func TestPrivCtx_SudoVolumeEvent_PassthroughByName_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// alice 的卷（名称前缀 user-1001-volume-）
	aliceVolEvent := makeVolumeEventWithAction("destroy", privCtxVolumeName)

	// alice 可见自己的卷事件
	if !p.eventBelongsToUser(aliceVolEvent, privCtxAliceUID, false) {
		t.Errorf("回归：alice(uid=%d) 应能看到自己的 volume destroy 事件", privCtxAliceUID)
	}

	// bob 不可见 alice 的卷事件
	if p.eventBelongsToUser(aliceVolEvent, privCtxBobUID, false) {
		t.Errorf("回归：bob(uid=%d) 不应看到 alice(uid=%d) 的 volume destroy 事件",
			privCtxBobUID, privCtxAliceUID)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Bug B：prune 竞态 — 回归测试
// ══════════════════════════════════════════════════════════════════════════════

// TestPruneRace_VolumeDestroyEvent_HiddenAfterDBDelete_regression
//
// 模拟竞态窗口：handle*Prune 已删除 DB 记录，但 Docker 事件尚未投递。
// 修复前 FAIL：DB 无记录 → 路径 3 → return true → bob 收到 alice 的 volume 事件。
// 修复后 PASS：completedPruneOwner 中有记录 → 返回 ownerUID==uid 判断 → bob 不可见。
func TestPruneRace_VolumeDestroyEvent_HiddenAfterDBDelete_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// 模拟竞态：alice 的卷已从 DB 删除，但 completedPruneOwner 中还有记录
	volumeName := fmt.Sprintf("user-%d-volume-mydata", privCtxAliceUID)
	pruneKey := "volume:" + volumeName
	p.completedPruneOwner.Store(pruneKey, privCtxAliceUID)

	destroyEvent := makeVolumeEventWithAction("destroy", volumeName)

	// Bug B 核心断言：bob 不应看到 alice 已被 prune 删除的卷的 destroy 事件
	if p.eventBelongsToUser(destroyEvent, privCtxBobUID, false) {
		t.Errorf(
			"Bug B [prune 竞态泄漏]:\n"+
				"\talice(uid=%d) 的卷 %q 已被 prune 删除（DB 无记录），\n"+
				"\t但 bob(uid=%d) 仍收到了该卷的 destroy 事件\n"+
				"\t预期: eventBelongsToUser=false（completedPruneOwner 应提供所有权信息）\n"+
				"\t实际: eventBelongsToUser=true（事件泄漏）",
			privCtxAliceUID, volumeName, privCtxBobUID,
		)
	}

	// 回归：alice 本人应能看到自己的 prune 删除事件
	if !p.eventBelongsToUser(destroyEvent, privCtxAliceUID, false) {
		t.Errorf(
			"回归：alice(uid=%d) 应能看到自己的 volume destroy 事件（来自 prune）",
			privCtxAliceUID,
		)
	}
}

// TestPruneRace_ImageDeleteEvent_HiddenAfterDBDelete_regression
//
// 模拟竞态窗口：handleImagePrune 已删除镜像 DB 记录，Docker 事件尚未投递。
// 修复前 FAIL：DB 无记录 → 路径 3 → return true → bob 收到 alice 的 image delete 事件。
// 修复后 PASS：completedPruneOwner 中有记录 → ownerUID 判断 → bob 不可见。
func TestPruneRace_ImageDeleteEvent_HiddenAfterDBDelete_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	imageID := "sha256:deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb"

	// 模拟竞态：alice 的镜像已从 DB 删除，completedPruneOwner 中有 30s 的残留记录
	pruneKey := "image:" + imageID
	p.completedPruneOwner.Store(pruneKey, privCtxAliceUID)

	deleteEvent := makeImageEvent("delete", imageID, imageID)

	// Bug B 核心断言：bob 不应看到 alice 已被 prune 删除的镜像的 delete 事件
	if p.eventBelongsToUser(deleteEvent, privCtxBobUID, false) {
		t.Errorf(
			"Bug B [prune 竞态泄漏 - image]:\n"+
				"\talice(uid=%d) 的镜像 %s 已被 image prune 删除（DB 无记录），\n"+
				"\t但 bob(uid=%d) 仍收到了该镜像的 delete 事件\n"+
				"\t预期: eventBelongsToUser=false\n"+
				"\t实际: eventBelongsToUser=true（路径 3 放行）",
			privCtxAliceUID, imageID[:16], privCtxBobUID,
		)
	}

	// 回归：alice 本人应能看到自己的 prune 删除事件
	if !p.eventBelongsToUser(deleteEvent, privCtxAliceUID, false) {
		t.Errorf(
			"回归：alice(uid=%d) 应能看到自己的 image delete 事件（来自 image prune）",
			privCtxAliceUID,
		)
	}

	// 回归：竞态窗口过期后（手动清除 map），事件回到路径 3（放行）
	p.completedPruneOwner.CompareAndDelete(pruneKey, privCtxAliceUID)
	if !p.eventBelongsToUser(deleteEvent, privCtxBobUID, false) {
		t.Errorf(
			"回归：completedPruneOwner 过期后，无法判断属主的 sha256 镜像事件应透传（路径 3）",
		)
	}
}

// TestPruneRace_OtherUserCannotClaimViaCompletedPruneOwner_regression
//
// completedPruneOwner 存的是 ownerUID，不应让其他用户冒认属主。
func TestPruneRace_OtherUserCannotClaimViaCompletedPruneOwner_regression(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	volumeName := fmt.Sprintf("user-%d-volume-secret", privCtxAliceUID)
	pruneKey := "volume:" + volumeName
	p.completedPruneOwner.Store(pruneKey, privCtxAliceUID) // alice 是属主

	destroyEvent := makeVolumeEventWithAction("destroy", volumeName)

	// 第三方用户 charlie（uid=1003）不应能看到 alice 的事件
	charlieUID := 1003
	if p.eventBelongsToUser(destroyEvent, charlieUID, false) {
		t.Errorf(
			"安全回归：charlie(uid=%d) 不应通过 completedPruneOwner 看到 alice(uid=%d) 的卷事件",
			charlieUID, privCtxAliceUID,
		)
	}
}

// TestPrivCtx_GetImageOwner_ReturnsPrivilegedContext_regression
//
// 直接验证 GetImageOwner 返回正确的 privileged_context 值。
func TestPrivCtx_GetImageOwner_ReturnsPrivilegedContext_regression(t *testing.T) {
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	defer db.Close()

	sudoID := privCtxSudoIdentity("sudo_test", privCtxSudoTestUID)
	regularID := privCtxRegularIdentity("alice", privCtxAliceUID)

	sudoImageID := "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff00"
	regularImageID := "sha256:aaaa0000bbbb1111cccc2222dddd3333eeee4444ffff5555666677778888999900"

	if err := db.SetImageOwner(sudoImageID, sudoID, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner(sudo): %v", err)
	}
	if err := db.SetImageOwner(regularImageID, regularID, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner(regular): %v", err)
	}

	_, _, privCtxSudo, found := db.GetImageOwner(sudoImageID)
	if !found {
		t.Fatal("GetImageOwner: sudo 镜像未找到")
	}
	if privCtxSudo != 1 {
		t.Errorf("sudo 命令创建的镜像 privileged_context 应为 1，实际为 %d", privCtxSudo)
	}

	_, _, privCtxRegular, found := db.GetImageOwner(regularImageID)
	if !found {
		t.Fatal("GetImageOwner: regular 镜像未找到")
	}
	if privCtxRegular != 0 {
		t.Errorf("普通命令创建的镜像 privileged_context 应为 0，实际为 %d", privCtxRegular)
	}
}
