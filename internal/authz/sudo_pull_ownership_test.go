//go:build linux

// sudo_pull_ownership_test.go
//
// [BUG] sudo_test 用户执行 `sudo docker pull busybox` 后，
//       `docker-authz-proxy-ctl image list` 显示 owner=root（UID 0），
//       而期望 owner=sudo_test（UID 1005）。
//
// ══════════════════════════════════════════════════════════════════════════════
// 所有权语义（业务规则）：
//   首次 pull 该镜像的用户永久成为 owner；后续任何用户 pull 不改变 ownership。
//
// 根本原因（ownership.go SetImageOwner）：
//   当 sudo_test 以 `sudo docker pull` 方式执行拉取时，代理从连接中读取：
//     EffectiveUID = 0  （sudo 提权后的 root eUID）
//     RealUID      = 1005（/proc/PID/loginuid，即真实登录用户）
//
//   Bug 在 identity.go ResolveCallerIdentity（中间件层），非 DB 层：
//     若 loginUID 读取正确 → UserTypeSudo, RealUID=1005 → SetImageOwner 存 uid=1005 ✓
//     若 loginUID 读取失败 → UserTypeRoot,  RealUID=0   → SetImageOwner 存 uid=0   ✗
//
// 注意：本文件的两个"Red Test"在 DB 层始终 PASS（SetImageOwner 已正确使用
//   RealUID），它们是 DB 层正确性验证，而非能复现上层 bug 的真正 Red Test。
//   真正的 Red Test 需在 internal/auth 包对 ResolveCallerIdentity 编写
//   或通过端到端集成测试覆盖。
//
// ══════════════════════════════════════════════════════════════════════════════
// 修复方向：
//   确保 identity.go ResolveCallerIdentity 在 sudo 场景下正确读取 loginUID，
//   使 RealUID=loginUID=1005（而非退化为 0）。
//   SetImageOwner 的 SQL 逻辑（pull-over-pull 不更新）符合首次 pull 永久 owner 语义，
//   无需修改。
// ══════════════════════════════════════════════════════════════════════════════

package authz

import (
	"testing"

	"docker-authz-proxy/internal/auth"
)

// makeSudoIdentity 构造一个 UserTypeSudo 身份：
//   - 模拟 sudo_test (uid=1005) 执行 `sudo docker pull`
//   - EffectiveUID=0（sudo 提权后为 root），RealUID=loginUID=1005
//   - 对应 identity.go 中 eUID=0 且 loginUID!=0 的身份解析路径
func makeSudoIdentity(loginUsername string, loginUID int) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      loginUsername,
		RealUID:           loginUID,
		RealGID:           loginUID,
		EffectiveUsername: "root",
		EffectiveUID:      0,
		EffectiveGID:      0,
		LoginUID:          loginUID,
		LoginUsername:     loginUsername,
		UserType:          auth.UserTypeSudo,
		SwitchedIdentity:  true,
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// [DB 层正确性验证] SetImageOwner 对 UserTypeSudo 身份的存储行为
// 这些测试在 DB 层始终 PASS；真正的 Red Test 需在 identity.go 层编写。
// ══════════════════════════════════════════════════════════════════════════════

// TestSudoPull_FirstPull_OwnerIsSudoTestNotRoot 验证 DB 层正确性：
//   sudo_test 是 busybox 的首次拉取者，owner 应记录为 sudo_test(uid=1005)，
//   而非 root(uid=0)。
//
// DB 层验证：当传入正确的 UserTypeSudo 身份（RealUID=1005）时，
//   SetImageOwner 必须存储 uid=1005。
// （此测试在修复前后均通过；端到端 bug 复现见集成测试）
func TestSudoPull_FirstPull_OwnerIsSudoTestNotRoot(t *testing.T) {
	db := newTestDB(t)

	const imageID = "busyboximageid000000000000000000000000000000000000000000000000"
	const sudoTestUID = 1005

	sudoTestID := makeSudoIdentity("sudo_test", sudoTestUID)

	// sudo_test 首次 pull busybox（DB 中无此镜像记录）
	if err := db.SetImageOwner(imageID, sudoTestID, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	owner, _, _, found := db.GetImageOwner(imageID)
	if !found {
		t.Fatal("image should exist after sudo_test first pull")
	}

	if owner.UID != sudoTestUID {
		t.Errorf(
			"sudo first pull: owner.UID=%d (username=%q)\n"+
				"  want owner.UID=%d (username=%q)\n"+
				"  SetImageOwner must use identity.RealUID, not identity.EffectiveUID",
			owner.UID, owner.Username,
			sudoTestUID, "sudo_test",
		)
	}
	if owner.Username != "sudo_test" {
		t.Errorf("owner.Username=%q, want %q", owner.Username, "sudo_test")
	}
}

// TestSudoPull_SetImageOwner_UsesRealUID_NotEffectiveUID 验证：
//   SetImageOwner 在存储时使用 identity.RealUID（1005），
//   而非 identity.EffectiveUID（0，sudo 后的 root eUID）。
//
//   EffectiveUID=0 和 RealUID=0 在 root 身份下无法区分；
//   本测试构造 EffectiveUID=0、RealUID=1005 的身份来暴露差异。
func TestSudoPull_SetImageOwner_UsesRealUID_NotEffectiveUID(t *testing.T) {
	db := newTestDB(t)

	const imageID = "sudotestfirstpull0000000000000000000000000000000000000000000000"
	const sudoTestUID = 1005

	// 构造 EffectiveUID=0（root）但 RealUID=1005（sudo_test）的身份
	sudoTestID := makeSudoIdentity("sudo_test", sudoTestUID)
	if sudoTestID.EffectiveUID != 0 || sudoTestID.RealUID != sudoTestUID {
		t.Fatalf("test setup: identity should have EffectiveUID=0 and RealUID=%d", sudoTestUID)
	}

	if err := db.SetImageOwner(imageID, sudoTestID, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	owner, _, _, found := db.GetImageOwner(imageID)
	if !found {
		t.Fatal("image should be found after sudo pull")
	}

	// 断言 owner.UID 是 RealUID=1005，而非 EffectiveUID=0
	if owner.UID == 0 {
		t.Errorf(
			"SetImageOwner stored EffectiveUID=0 instead of RealUID=%d\n"+
				"  identity.RealUID=%d, identity.EffectiveUID=%d\n"+
				"  SetImageOwner must read identity.RealUID, not identity.EffectiveUID",
			sudoTestUID, sudoTestID.RealUID, sudoTestID.EffectiveUID,
		)
	}
	if owner.UID != sudoTestUID {
		t.Errorf("owner.UID=%d, want %d (sudo_test RealUID)", owner.UID, sudoTestUID)
	}
	if owner.Username != "sudo_test" {
		t.Errorf("owner.Username=%q, want \"sudo_test\"", owner.Username)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression Suite — 修复后必须保持通过，防止"按下葫芦起了瓢"
// ══════════════════════════════════════════════════════════════════════════════

// [Reg-1] 首次 pull 的 owner 不被后续 pull 覆盖（pull-over-pull 不更新）。
//   语义：首次 pull 永久锁定 owner；sudo_test 先 pull 后，root 再 pull，
//   owner 仍为 sudo_test。
func TestSudoPull_Reg1_FirstPullerStaysOwner_RootPullAfter(t *testing.T) {
	db := newTestDB(t)

	const imageID = "reg1firstpullersudo000000000000000000000000000000000000000000"
	const sudoTestUID = 1005

	sudoTestID := makeSudoIdentity("sudo_test", sudoTestUID)
	rootID := makeTestIdentity("root", 0, 0)

	// sudo_test 首次 pull
	if err := db.SetImageOwner(imageID, sudoTestID, false, "pull"); err != nil {
		t.Fatalf("sudo_test SetImageOwner: %v", err)
	}

	// root 后续 pull 同一镜像
	if err := db.SetImageOwner(imageID, rootID, false, "pull"); err != nil {
		t.Fatalf("root SetImageOwner: %v", err)
	}

	owner, _, _, found := db.GetImageOwner(imageID)
	if !found {
		t.Fatal("[Reg-1] image not found")
	}
	// 首次 puller（sudo_test）应保持 owner，root 的后续 pull 不应覆盖
	if owner.UID != sudoTestUID {
		t.Errorf(
			"[Reg-1] owner changed after root pulled over sudo_test:\n"+
				"  got  owner.UID=%d (username=%q)\n"+
				"  want owner.UID=%d (username=%q)\n"+
				"  first puller must remain permanent owner",
			owner.UID, owner.Username,
			sudoTestUID, "sudo_test",
		)
	}
}

// [Reg-2] image_access 使用 sudo_test 的 RealUID（1005）而非 EffectiveUID（0）。
//   SetImageOwner 在 INSERT INTO image_access 时必须用 identity.RealUID，
//   否则 sudo_test 在过滤层看不到自己拉取的镜像。
func TestSudoPull_Reg2_ImageAccessRecordedWithRealUID(t *testing.T) {
	db := newTestDB(t)

	const imageID = "reg2imageaccessuid00000000000000000000000000000000000000000000"
	const sudoTestUID = 1005

	sudoTestID := makeSudoIdentity("sudo_test", sudoTestUID)

	if err := db.SetImageOwner(imageID, sudoTestID, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	// sudo_test 的 RealUID 应在 image_access 中有记录
	// 注意：CanSeeImage 对 privileged_context=1 的镜像在非特权视图中返回 false（正确行为）；
	// 此处改用 HasUserImageAccess 直接验证 image_access 表存储的是 RealUID 而非 EffectiveUID(0)。
	hasAccess, err := db.HasUserImageAccess(imageID, sudoTestUID)
	if err != nil {
		t.Fatalf("[Reg-2] HasUserImageAccess: %v", err)
	}
	if !hasAccess {
		t.Errorf(
			"[Reg-2] image_access has no record for uid=%d after sudo pull\n"+
				"  image_access must store RealUID (%d), not EffectiveUID (0)",
			sudoTestUID, sudoTestUID,
		)
	}

	// EffectiveUID=0 (root) 不应因为 sudo_test 拉取而自动获得 image_access
	hasRootAccess, _ := db.HasUserImageAccess(imageID, 0)
	if hasRootAccess {
		t.Errorf(
			"[Reg-2] image_access should NOT have uid=0 (EffectiveUID) entry\n"+
				"  only sudo_test's RealUID=%d should be in image_access",
			sudoTestUID,
		)
	}
}

// [Reg-3] 多个 sudo 用户先后 pull 同一镜像：首个 puller 永久持有 owner。
//   sudo_test1 先 pull → sudo_test2 后 pull → owner 仍为 sudo_test1。
func TestSudoPull_Reg3_MultipleSudoPullers_FirstPullerStaysOwner(t *testing.T) {
	db := newTestDB(t)

	const imageID = "reg3multisudo00000000000000000000000000000000000000000000000000"

	sudoTest1 := makeSudoIdentity("sudo_test1", 1005)
	sudoTest2 := makeSudoIdentity("sudo_test2", 1006)

	// sudo_test1 首次 pull
	if err := db.SetImageOwner(imageID, sudoTest1, false, "pull"); err != nil {
		t.Fatalf("sudoTest1 SetImageOwner: %v", err)
	}

	// sudo_test2 后续 pull（不应改变 ownership）
	if err := db.SetImageOwner(imageID, sudoTest2, false, "pull"); err != nil {
		t.Fatalf("sudoTest2 SetImageOwner: %v", err)
	}

	owner, _, _, found := db.GetImageOwner(imageID)
	if !found {
		t.Fatal("[Reg-3] image not found")
	}
	// 首次 puller（sudo_test1, uid=1005）应保持 owner
	if owner.UID != 1005 {
		t.Errorf(
			"[Reg-3] owner changed after second sudo pull:\n"+
				"  got  owner.UID=%d (username=%q)\n"+
				"  want owner.UID=1005 (sudo_test1)\n"+
				"  first puller must remain permanent owner, subsequent pull must not overwrite",
			owner.UID, owner.Username,
		)
	}
}

// [Reg-4] is_public 标志在后续 pull 后不应被重置。
//   sudo_test 将镜像设为 public 后，其他用户再 pull 不应将 is_public 置回 false。
func TestSudoPull_Reg4_PublicFlagPreservedAfterSubsequentPull(t *testing.T) {
	db := newTestDB(t)

	const imageID = "reg4publicflag00000000000000000000000000000000000000000000000000"
	const sudoTestUID = 1005

	sudoTestID := makeSudoIdentity("sudo_test", sudoTestUID)
	rootID := makeTestIdentity("root", 0, 0)

	// sudo_test 首次 pull 并设为 public（前置条件，错误须 Fatal 而非静默忽略）
	if err := db.SetImageOwner(imageID, sudoTestID, false, "pull"); err != nil {
		t.Fatalf("[Reg-4] setup SetImageOwner(sudo_test): %v", err)
	}
	if err := db.SetImagePublic(imageID, true); err != nil {
		t.Fatalf("[Reg-4] setup SetImagePublic: %v", err)
	}

	_, prePublic, _, _ := db.GetImageOwner(imageID)
	if !prePublic {
		t.Fatal("[Reg-4] pre-condition: image should be public after SetImagePublic")
	}

	// root 后续 pull（isPublic 参数为 false，后续 pull 不应覆盖公共标志）
	if err := db.SetImageOwner(imageID, rootID, false, "pull"); err != nil {
		t.Fatalf("[Reg-4] root subsequent pull SetImageOwner: %v", err)
	}

	_, postPublic, _, found := db.GetImageOwner(imageID)
	if !found {
		t.Fatal("[Reg-4] image should still exist after subsequent pull")
	}
	if !postPublic {
		t.Errorf(
			"[Reg-4] is_public was reset to false after subsequent pull\n"+
				"  public images must remain public regardless of subsequent pulls",
		)
	}
}

// [Reg-5] 普通用户 bob 在 sudo_test 首次 pull 之后再 pull 同一镜像：
//   owner 仍为首次 puller（sudo_test），bob 的后续 pull 不改变 ownership。
func TestSudoPull_Reg5_RegularUserPullAfterSudoPull_FirstPullerStaysOwner(t *testing.T) {
	db := newTestDB(t)

	const imageID = "reg5regularaftersudo0000000000000000000000000000000000000000000"
	const sudoTestUID = 1005

	sudoTestID := makeSudoIdentity("sudo_test", sudoTestUID)
	bob := makeTestIdentity("bob", 1002, 1002)

	// sudo_test 首次 pull（source=pull, owner=sudo_test, uid=1005）
	if err := db.SetImageOwner(imageID, sudoTestID, false, "pull"); err != nil {
		t.Fatalf("sudo_test SetImageOwner: %v", err)
	}

	// bob 后续 pull（不应改变 ownership）
	if err := db.SetImageOwner(imageID, bob, false, "pull"); err != nil {
		t.Fatalf("bob SetImageOwner: %v", err)
	}

	owner, _, _, found := db.GetImageOwner(imageID)
	if !found {
		t.Fatal("[Reg-5] image not found")
	}
	// 首次 puller（sudo_test, uid=1005）应保持 owner，bob 的后续 pull 不应覆盖
	if owner.UID != sudoTestUID {
		t.Errorf(
			"[Reg-5] owner changed after regular user pulled over sudo_test:\n"+
				"  got  owner.UID=%d (username=%q)\n"+
				"  want owner.UID=%d (username=%q)\n"+
				"  first puller must remain permanent owner",
			owner.UID, owner.Username,
			sudoTestUID, "sudo_test",
		)
	}
}
