// image_pull_ownership_bug_test.go
//
// [BUG-8] SetImageOwner: 第一个拉取某镜像的用户应成为 owner，
//         但若该镜像之前曾被其他用户（包括 root）以 source='pull' 拉过，
//         后来的用户再 pull 时 ownership 不会更新，仍显示为原始 puller。
//
// ══════════════════════════════════════════════════════════════════════════════
// 根本原因（authz/ownership.go, SetImageOwner, ~line 353）：
//
//   INSERT INTO images(...)
//   VALUES (?, ?, ...)
//   ON CONFLICT(image_id) DO UPDATE SET
//       owner_username = excluded.owner_username,
//       ...
//   WHERE images.source = 'build' AND excluded.source = 'pull'
//         ─────────────────────────────────────────────────────
//         ↑ 这个 WHERE 子句的含义：只有当"现有记录 source='build'"
//           且"新记录 source='pull'"时才执行 UPDATE。
//
//   设计意图：允许 pull 覆盖 build（两人各自 build/pull 同名镜像时）。
//   副作用：当现有记录的 source 也是 'pull'（或其他任何非 'build' 值）时，
//           WHERE 条件不满足，UPDATE 被 SQLite 静默跳过。
//
// ══════════════════════════════════════════════════════════════════════════════
// 触发路径（已在生产服务器 DB 确认）：
//
//   1. root 先  docker pull busybox  → DB: image_id|root|0|pull
//   2. bob  后  docker pull busybox  → SetImageOwner 触发 ON CONFLICT
//      → WHERE images.source='build' 不满足（现有 source='pull'）
//      → UPDATE 静默跳过
//   3. sudo docker-authz-proxy-ctl image list → 显示 owner=root（错误）
//
//   实际查询：
//     sqlite3 /var/lib/docker-authz/owners.db
//     "SELECT image_id,owner_username,owner_uid,source FROM images
//      WHERE image_id='925ff61909ae...';"
//     → 925ff61...|root|0|pull   ← bob pull 后仍显示 root
//
// ══════════════════════════════════════════════════════════════════════════════
// 修复方向（三选一，修复后本文件所有测试应全部通过）：
//   A. 去掉 WHERE 子句：让后一次 pull 始终覆盖 ownership
//   B. 改 WHERE 为 `excluded.source = 'pull'`（pull 可覆盖任何来源）
//   C. 扩展 WHERE 使 pull-over-pull 也生效
//      （但要避免 build 被 pull 覆盖，需在此处明确区分）

package authz

import "testing"

// ══════════════════════════════════════════════════════════════════════════════
// [BUG-8] Red Test — pull-over-pull：后来的 puller 应成为新 owner
//
// 场景：root 先 pull busybox，bob 后 pull busybox。
// 期望：bob 是 owner。实际（修复前）：root 仍是 owner。
// 在修复前运行此测试必定失败（AssertionError）。
// ══════════════════════════════════════════════════════════════════════════════

func TestBug8_PullOverPull_LaterPullerShouldBecomeOwner(t *testing.T) {
	db := newTestDB(t)

	const imageID = "925ff61909aebae4bcc9bc04bb96a8bd15cd2271f13159fe95ce4338824531dd"

	root := makeTestIdentity("root", 0, 0)
	bob := makeTestIdentity("bob", 1002, 1002)

	// Step 1: root 先 pull 同一镜像（前置状态）
	if err := db.SetImageOwner(imageID, root, false, "pull"); err != nil {
		t.Fatalf("root SetImageOwner: %v", err)
	}
	// 验证前置条件正确
	pre, _, _ := db.GetImageOwner(imageID)
	if pre == nil || pre.UID != 0 {
		t.Fatalf("pre-condition failed: owner should be root(uid=0), got %v", pre)
	}

	// Step 2: bob 后 pull 同一镜像
	if err := db.SetImageOwner(imageID, bob, false, "pull"); err != nil {
		t.Fatalf("bob SetImageOwner: %v", err)
	}

	// Step 3: 验证 owner 已更新为 bob
	owner, _, found := db.GetImageOwner(imageID)
	if !found {
		t.Fatal("image should exist after bob pull")
	}

	// ──── 核心断言 ────
	// [BUG-8 RED] 修复前：owner.UID == 0 (root)，断言失败
	// 修复后：owner.UID == 1002 (bob)，断言通过
	if owner.UID != bob.RealUID {
		t.Errorf(
			"[BUG-8 RED] pull-over-pull ownership not updated:\n"+
				"  got  owner.UID=%d (username=%q)\n"+
				"  want owner.UID=%d (username=%q)\n"+
				"  root cause: ON CONFLICT WHERE images.source='build' does not match\n"+
				"  existing source='pull', so UPDATE is silently skipped",
			owner.UID, owner.Username,
			bob.RealUID, bob.RealUsername,
		)
	}
	if owner.Username != bob.RealUsername {
		t.Errorf("[BUG-8 RED] owner.Username=%q, want %q", owner.Username, bob.RealUsername)
	}
}

// TestBug8_PullOverPull_NonRootOverNonRoot 验证非 root 用户之间的 pull-over-pull。
// alice 先 pull，bob 后 pull → owner 应为 bob。
func TestBug8_PullOverPull_NonRootOverNonRoot(t *testing.T) {
	db := newTestDB(t)
	const imageID = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	alice := makeTestIdentity("alice", 1001, 1001)
	bob := makeTestIdentity("bob", 1002, 1002)

	_ = db.SetImageOwner(imageID, alice, false, "pull")
	_ = db.SetImageOwner(imageID, bob, false, "pull")

	owner, _, found := db.GetImageOwner(imageID)
	if !found {
		t.Fatal("image not found")
	}
	if owner.UID != bob.RealUID {
		t.Errorf(
			"[BUG-8 RED] non-root pull-over-pull: owner.UID=%d, want %d (bob)\n"+
				"  alice pulled first, bob pulled second — owner should be bob",
			owner.UID, bob.RealUID,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression Suite — 修复 BUG-8 后必须保持通过
// ══════════════════════════════════════════════════════════════════════════════

// [Reg-1] 首次 pull：DB 为空时，第一个 puller 正确成为 owner
func TestBug8_Reg_FirstPull_RecordsCorrectOwner(t *testing.T) {
	db := newTestDB(t)
	const imageID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	bob := makeTestIdentity("bob", 1002, 1002)

	if err := db.SetImageOwner(imageID, bob, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	owner, isPublic, found := db.GetImageOwner(imageID)
	if !found {
		t.Fatal("[Reg-1] image should be found after first pull")
	}
	if owner.UID != 1002 {
		t.Errorf("[Reg-1] first pull: owner.UID=%d, want 1002", owner.UID)
	}
	if owner.Username != "bob" {
		t.Errorf("[Reg-1] first pull: owner.Username=%q, want bob", owner.Username)
	}
	if isPublic {
		t.Error("[Reg-1] first pull: isPublic should be false by default")
	}
}

// [Reg-2] pull-over-build：pull 应能覆盖 build ownership（原 WHERE 子句的设计目标）
// 修复后此行为必须保留，不能被破坏。
func TestBug8_Reg_PullOverBuild_ShouldUpdateOwner(t *testing.T) {
	db := newTestDB(t)
	const imageID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	alice := makeTestIdentity("alice", 1001, 1001)
	bob := makeTestIdentity("bob", 1002, 1002)

	// alice build 了镜像
	if err := db.SetImageOwner(imageID, alice, false, "build"); err != nil {
		t.Fatalf("alice build SetImageOwner: %v", err)
	}

	// bob pull 同一镜像（例如从 registry pull alice 推送的同名镜像）
	if err := db.SetImageOwner(imageID, bob, false, "pull"); err != nil {
		t.Fatalf("bob pull SetImageOwner: %v", err)
	}

	owner, _, found := db.GetImageOwner(imageID)
	if !found {
		t.Fatal("[Reg-2] image not found")
	}
	// pull 覆盖 build 是原本正确的行为，修复不应破坏它
	if owner.UID != bob.RealUID {
		t.Errorf(
			"[Reg-2] pull-over-build: owner.UID=%d, want %d (bob)\n"+
				"  this was the original correct behavior — fix must preserve it",
			owner.UID, bob.RealUID,
		)
	}
}

// [Reg-3] build-over-pull：build 操作应能覆盖已有 pull 归属
// 当前行为（修复前）：build 也无法覆盖 pull，owner 仍为原始 puller。
// 这是 BUG-8 同一根因导致的对称 bug（ON CONFLICT WHERE 只允许 pull 覆盖 build，
// 反方向 build-over-pull 同样被 WHERE 条件拦截，因为现有 source='pull' 不等于 'build'）。
//
// 注意：本测试当前也会失败（与 BUG-8 Red Test 同源）。
// 修复时需要决策语义：
//   - 方案 A（后来者覆盖）：去掉 WHERE，两个方向都覆盖，本测试通过
//   - 方案 B（pull 覆盖一切）：改 WHERE 为 excluded.source='pull'，build 仍不能覆盖 pull
// 此测试记录"build 应覆盖 pull"的期望语义，供修复者决策。
func TestBug8_Reg_BuildOverPull_BuildOwnerPersists(t *testing.T) {
	db := newTestDB(t)
	const imageID = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	bob := makeTestIdentity("bob", 1002, 1002)
	alice := makeTestIdentity("alice", 1001, 1001)

	// bob 先 pull
	_ = db.SetImageOwner(imageID, bob, false, "pull")

	// alice 后 build 同一 image ID（本地重 build 同内容镜像）
	_ = db.SetImageOwner(imageID, alice, false, "build")

	owner, _, found := db.GetImageOwner(imageID)
	if !found {
		t.Fatal("[Reg-3] image not found")
	}
	// 期望：build 覆盖 pull（构建者拥有自己 build 的镜像）
	// 修复前：owner 仍为 bob（pull），因为 ON CONFLICT WHERE 同样阻止了 build-over-pull
	if owner.UID != alice.RealUID {
		t.Errorf(
			"[Reg-3] build-over-pull: owner.UID=%d (username=%q), want %d (alice/builder)\n"+
				"  same root cause as BUG-8: ON CONFLICT WHERE blocks all overwrites\n"+
				"  where existing source != 'build'",
			owner.UID, owner.Username, alice.RealUID,
		)
	}
}

// [Reg-4] is_public 标志在 pull-over-pull 后不应被重置
// 若管理员将镜像标记为 public，bob pull 时不应把 is_public 重置为 false。
func TestBug8_Reg_PullOverPull_PublicFlagNotReset(t *testing.T) {
	db := newTestDB(t)
	const imageID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

	root := makeTestIdentity("root", 0, 0)
	bob := makeTestIdentity("bob", 1002, 1002)

	// root pull 并将镜像设为 public
	_ = db.SetImageOwner(imageID, root, false, "pull")
	_ = db.SetImagePublic(imageID, true)

	preOwner, prePublic, _ := db.GetImageOwner(imageID)
	if !prePublic {
		t.Fatal("[Reg-4] pre-condition: image should be public")
	}
	_ = preOwner

	// bob pull 同一镜像（SetImageOwner 的 isPublic 参数为 false，普通 pull 不设公共）
	_ = db.SetImageOwner(imageID, bob, false, "pull")

	// is_public 不应被本次 pull 重置为 false
	_, postPublic, found := db.GetImageOwner(imageID)
	if !found {
		t.Fatal("[Reg-4] image should still exist")
	}
	if !postPublic {
		t.Errorf(
			"[Reg-4] is_public was reset to false after pull-over-pull\n"+
				"  public images should remain public regardless of subsequent pulls",
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// [BUG-8b] Red Test — alice 可见性泄漏
//
// 场景：root 先 pull busybox（image_access 记录 root），bob 后 pull busybox。
// 因 pull-over-pull 时 ownership 未更新为 bob，且 is_public=0，
// root 的 image_access 记录仍存在 → alice（uid=1001）不在 image_access 中，
// 但 alice 却能通过 CanSeeImage 看到该镜像？
//
// 实际 BUG 路径（CanSeeImage line 474-486）：
//   CanSeeImage 检查 owner_uid==realUID || image_access 中有记录。
//   alice 不是 owner，image_access 也没有 alice，所以 alice 本应看不到。
//   但 root pull 后把 busybox 登记为 is_public=0，owner=root。
//   若管理员之前操作过（或 is_public 被误设为 1），alice 就能看到。
//
// 此测试覆盖"alice 不应看到 bob pull 的私有镜像"的隔离语义。
// ══════════════════════════════════════════════════════════════════════════════

// [BUG-8b] alice 不应看到 bob pull 的非公共镜像
// 注意：此测试在修复前后都应通过（验证 CanSeeImage 的隔离逻辑本身正确）。
// 若失败，说明 CanSeeImage 本身存在问题（第二类 bug）。
func TestBug8b_AliceCannotSeeBobPrivateImage(t *testing.T) {
	db := newTestDB(t)
	const imageID = "1111111111111111111111111111111111111111111111111111111111111111"

	bob := makeTestIdentity("bob", 1002, 1002)
	aliceUID := 1001

	// bob pull busybox（非公共）
	if err := db.SetImageOwner(imageID, bob, false, "pull"); err != nil {
		t.Fatalf("bob SetImageOwner: %v", err)
	}

	// alice 不应能看到 bob 的私有镜像
	if db.CanSeeImage(aliceUID, imageID) {
		t.Errorf(
			"[BUG-8b RED] alice (uid=%d) can see bob's private image (uid=%d)\n"+
				"  bob pulled a non-public image — alice must not see it\n"+
				"  check CanSeeImage: owner_uid != aliceUID, alice not in image_access",
			aliceUID, bob.RealUID,
		)
	}
}

// [BUG-8b] root 先 pull（登记 owner=root），bob 后 pull（ownership 未更新，仍为 root）→
// alice 不应能看到该镜像（因 is_public=0，且 alice 不在 image_access）
func TestBug8b_AliceCannotSeeImage_AfterRootPullThenBobPull(t *testing.T) {
	db := newTestDB(t)
	const imageID = "2222222222222222222222222222222222222222222222222222222222222222"

	root := makeTestIdentity("root", 0, 0)
	bob := makeTestIdentity("bob", 1002, 1002)
	aliceUID := 1001

	// root 先 pull（模拟已有记录：owner=root, source=pull, is_public=0）
	if err := db.SetImageOwner(imageID, root, false, "pull"); err != nil {
		t.Fatalf("root SetImageOwner: %v", err)
	}
	// bob 后 pull（修复前：owner 不变仍为 root；修复后：owner 更新为 bob）
	if err := db.SetImageOwner(imageID, bob, false, "pull"); err != nil {
		t.Fatalf("bob SetImageOwner: %v", err)
	}

	// 无论 owner 是 root 还是 bob，is_public=0 → alice 都不应看到
	if db.CanSeeImage(aliceUID, imageID) {
		// 确认 owner 以便精确诊断
		owner, isPublic, _ := db.GetImageOwner(imageID)
		ownerUID := -1
		if owner != nil {
			ownerUID = owner.UID
		}
		t.Errorf(
			"[BUG-8b RED] alice (uid=%d) can see image after root+bob pull\n"+
				"  owner_uid=%d, is_public=%v — alice should NOT have visibility\n"+
				"  possible cause: is_public was inadvertently set to true, or\n"+
				"  CanSeeImage has a logic error",
			aliceUID, ownerUID, isPublic,
		)
	}
}

// [Reg-6] image_access 多用户共享访问，只有有记录的用户可见
// 验证 image_access 表的多租户隔离：bob 和 charlie 可见，alice 不可见。
func TestBug8_Reg_ImageAccess_MultiUserIsolation(t *testing.T) {
	db := newTestDB(t)
	const imageID = "3333333333333333333333333333333333333333333333333333333333333333"

	bob := makeTestIdentity("bob", 1002, 1002)
	charlieUID := 1003
	aliceUID := 1001

	// bob pull（自动加 image_access 记录）
	if err := db.SetImageOwner(imageID, bob, false, "pull"); err != nil {
		t.Fatalf("bob SetImageOwner: %v", err)
	}
	// 管理员手动授权 charlie 访问
	if err := db.EnsureImageAccess(imageID, charlieUID); err != nil {
		t.Fatalf("EnsureImageAccess charlie: %v", err)
	}

	// bob 可见（owner）
	if !db.CanSeeImage(bob.RealUID, imageID) {
		t.Error("[Reg-6] bob (owner) should be able to see his own image")
	}
	// charlie 可见（image_access）
	if !db.CanSeeImage(charlieUID, imageID) {
		t.Error("[Reg-6] charlie (granted access) should see the image")
	}
	// alice 不可见（无记录）
	if db.CanSeeImage(aliceUID, imageID) {
		t.Error("[Reg-6] alice (no access) must NOT see the image — isolation violated")
	}
}

// [Reg-5] sha256: 前缀规范化：SetImageOwner 带/不带前缀存储结果一致
// 防止修复引入前缀处理回归。
func TestBug8_Reg_Sha256PrefixNormalization(t *testing.T) {
	db := newTestDB(t)
	const rawID = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	const withPrefix = "sha256:" + rawID

	bob := makeTestIdentity("bob", 1002, 1002)

	// 以带 sha256: 前缀写入
	_ = db.SetImageOwner(withPrefix, bob, false, "pull")

	// 不带前缀查询
	owner1, _, found1 := db.GetImageOwner(rawID)
	if !found1 {
		t.Error("[Reg-5] stored with sha256: prefix, but not queryable without prefix")
	} else if owner1.UID != 1002 {
		t.Errorf("[Reg-5] owner.UID=%d, want 1002 (bob)", owner1.UID)
	}

	// 带前缀查询
	owner2, _, found2 := db.GetImageOwner(withPrefix)
	if !found2 {
		t.Error("[Reg-5] not queryable with sha256: prefix either")
	} else if owner2.UID != 1002 {
		t.Errorf("[Reg-5] owner.UID=%d, want 1002 (bob)", owner2.UID)
	}
}
