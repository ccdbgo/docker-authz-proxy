package authz_test

import (
	"os"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// newIsolationTestDB 创建临时测试数据库
func newIsolationTestDB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	f, err := os.CreateTemp("", "sudo-isolation-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	db, err := authz.NewOwnershipDB(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.DB.Close() })
	return db
}

// makeSudoIdentity 模拟 "sudo docker cmd"：effectiveUID=0，UserTypeSudo，RealUID=原始用户
func makeSudoIdentity(uid int, username string) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUID:      uid,
		RealUsername: username,
		RealGID:      uid,
		EffectiveUID: 0,
		UserType:     auth.UserTypeSudo,
	}
}

// makeRegularIdentity 模拟 "docker cmd"（不带sudo）：effectiveUID=uid，UserTypeRegular
func makeRegularIdentity(uid int, username string) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUID:      uid,
		RealUsername: username,
		RealGID:      uid,
		EffectiveUID: uid,
		UserType:     auth.UserTypeRegular,
	}
}

// Test_SudoCommandIsolation_regression 验证 sudo 上下文创建的资源不会泄漏给非 sudo 查询。
//
// 修复前失败的原因：
//   Set*Owner 均存 identity.RealUID（sudo 和非 sudo 相同，均为 1005），
//   查询时 WHERE owner_uid=1005 会同时返回两个上下文的资源，导致泄漏。
//
// 修复后通过的原因：
//   Set*Owner 额外存 privileged_context（IsSudoCommand()=true 时为 1），
//   非特权查询加 AND privileged_context=0，过滤掉 sudo 创建的资源。
func Test_SudoCommandIsolation_regression(t *testing.T) {
	const uid = 1005
	const username = "sudo_test"

	sudoID := makeSudoIdentity(uid, username)
	_ = makeRegularIdentity(uid, username) // 非特权查询使用 uid 直接传入

	// ── BUG-1/2：镜像（pull/build）────────────────────────────────
	t.Run("image_sudo_pull_not_visible_to_regular_ls", func(t *testing.T) {
		db := newIsolationTestDB(t)

		// sudo docker pull alpine:3.10 → SetImageOwner with sudo identity
		if err := db.SetImageOwner("aabbcc112233aabb", sudoID, false, "pull"); err != nil {
			t.Fatalf("SetImageOwner: %v", err)
		}

		// docker image ls（非 sudo）→ CanSeeImage 应返回 false
		if db.CanSeeImage(uid, "aabbcc112233aabb") {
			t.Error("FAIL: sudo-pulled image visible via non-sudo CanSeeImage (want invisible)")
		}
	})

	t.Run("image_sudo_pull_visible_to_sudo_ls", func(t *testing.T) {
		// sudo docker image ls 走 if privileged { return body, nil }，
		// 不经过 CanSeeImage；此处仅验证 IsSudoCommand() 标记写入正确。
		db := newIsolationTestDB(t)
		if err := db.SetImageOwner("aabbcc112233aabb", sudoID, false, "pull"); err != nil {
			t.Fatalf("SetImageOwner: %v", err)
		}
		// 用 GetImageOwner 验证 owner_uid 仍为原始用户（非 root），身份记录正确
		info, _, _, found := db.GetImageOwner("aabbcc112233aabb")
		if !found {
			t.Fatal("GetImageOwner: image not found")
		}
		if info.UID != uid {
			t.Errorf("owner_uid = %d, want %d", info.UID, uid)
		}
	})

	// ── BUG-3：容器（run）───────────────────────────────────────
	t.Run("container_sudo_run_not_visible_to_regular_ls", func(t *testing.T) {
		db := newIsolationTestDB(t)

		// sudo docker run → SetContainerOwner with sudo identity
		if err := db.SetContainerOwner("ctr-sudo-abc123", sudoID, "aabbcc112233aabb"); err != nil {
			t.Fatalf("SetContainerOwner: %v", err)
		}

		// docker container ls（非 sudo）→ GetContainerIDsByOwner 不应返回此容器
		ids, err := db.GetContainerIDsByOwner(uid)
		if err != nil {
			t.Fatalf("GetContainerIDsByOwner: %v", err)
		}
		for _, id := range ids {
			if id == "ctr-sudo-abc123" {
				t.Error("FAIL: sudo-created container visible via non-sudo GetContainerIDsByOwner (want invisible)")
			}
		}
	})

	// ── BUG-4：网络（network create）──────────────────────────────
	t.Run("network_sudo_create_not_visible_to_regular_ls", func(t *testing.T) {
		db := newIsolationTestDB(t)

		// sudo docker network create test_net → SetNetworkOwner with sudo identity
		if err := db.SetNetworkOwner("net-hex-deadbeef1234", "test_net", sudoID); err != nil {
			t.Fatalf("SetNetworkOwner: %v", err)
		}

		// docker network ls（非 sudo）→ GetAccessibleNetworkIDs 不应返回此网络
		ids, err := db.GetAccessibleNetworkIDs(uid)
		if err != nil {
			t.Fatalf("GetAccessibleNetworkIDs: %v", err)
		}
		for _, id := range ids {
			if id == "net-hex-deadbeef1234" {
				t.Error("FAIL: sudo-created network visible via non-sudo GetAccessibleNetworkIDs (want invisible)")
			}
		}
	})

	// ── BUG-5：卷（volume create）──────────────────────────────────
	t.Run("volume_sudo_create_not_visible_to_regular_ls", func(t *testing.T) {
		db := newIsolationTestDB(t)

		// sudo docker volume create test_vol → SetVolumeOwner with sudo identity
		if err := db.SetVolumeOwner("test_vol", sudoID); err != nil {
			t.Fatalf("SetVolumeOwner: %v", err)
		}

		// docker volume ls（非 sudo）→ GetVolumeNamesByOwner 不应返回此 volume
		names, err := db.GetVolumeNamesByOwner(uid)
		if err != nil {
			t.Fatalf("GetVolumeNamesByOwner: %v", err)
		}
		for _, name := range names {
			if name == "test_vol" {
				t.Error("FAIL: sudo-created volume visible via non-sudo GetVolumeNamesByOwner (want invisible)")
			}
		}
	})

	// ── 回归：非 sudo 创建的资源对非 sudo 查询依然可见 ──────────────
	t.Run("regular_resources_remain_visible_to_regular_ls", func(t *testing.T) {
		db := newIsolationTestDB(t)
		regularID := makeRegularIdentity(uid, username)

		// docker volume create → SetVolumeOwner with regular identity
		if err := db.SetVolumeOwner("user-1005-volume-myvol", regularID); err != nil {
			t.Fatalf("SetVolumeOwner: %v", err)
		}

		names, err := db.GetVolumeNamesByOwner(uid)
		if err != nil {
			t.Fatalf("GetVolumeNamesByOwner: %v", err)
		}
		found := false
		for _, name := range names {
			if name == "user-1005-volume-myvol" {
				found = true
			}
		}
		if !found {
			t.Error("REGRESSION: regular-created volume NOT visible via non-sudo query (want visible)")
		}
	})

	// ── FAIL-1 修复验证：sudo pull 后 regular pull 同一镜像，非sudo可见 ──────
	t.Run("image_sudo_pull_then_regular_pull_visible_to_regular_ls", func(t *testing.T) {
		db := newIsolationTestDB(t)
		regularID := makeRegularIdentity(uid, username)

		// sudo docker pull alpine:3.10
		if err := db.SetImageOwner("aabbcc112233aabb", sudoID, false, "pull"); err != nil {
			t.Fatalf("SetImageOwner(sudo): %v", err)
		}
		// docker pull alpine:3.10（非sudo，同一镜像）
		if err := db.SetImageOwner("aabbcc112233aabb", regularID, false, "pull"); err != nil {
			t.Fatalf("SetImageOwner(regular): %v", err)
		}

		// docker image ls（非sudo）→ 应可见（image_access.privileged_context 被 MIN 更新为 0）
		if !db.CanSeeImage(uid, "aabbcc112233aabb") {
			t.Error("FAIL: image not visible after regular pull following sudo pull (want visible)")
		}
	})

	// ── FAIL-2 修复验证：sudo pull 后，HasImageAccess 对非特权查询返回 false ──
	t.Run("has_image_access_filters_sudo_only_access", func(t *testing.T) {
		db := newIsolationTestDB(t)

		// sudo docker pull → image_access(privCtx=1)，无后续 regular pull
		if err := db.SetImageOwner("ccddee334455ccdd", sudoID, false, "pull"); err != nil {
			t.Fatalf("SetImageOwner(sudo): %v", err)
		}

		// eventBelongsToUser path 2.5 → HasImageAccess 应返回 false（只有 sudo 访问记录）
		if db.HasImageAccess("ccddee334455ccdd", uid) {
			t.Error("FAIL: HasImageAccess returns true for sudo-only access (event stream leak)")
		}
	})

	// ── 回归：sudo 创建的资源不影响其他用户的查询 ────────────────
	t.Run("sudo_resource_not_visible_to_other_user", func(t *testing.T) {
		db := newIsolationTestDB(t)

		const otherUID = 1006
		// sudo_test 用 sudo 创建 volume
		if err := db.SetVolumeOwner("test_vol", sudoID); err != nil {
			t.Fatalf("SetVolumeOwner: %v", err)
		}
		// 其他用户（uid=1006）的非特权查询不应看到此 volume
		names, err := db.GetVolumeNamesByOwner(otherUID)
		if err != nil {
			t.Fatalf("GetVolumeNamesByOwner: %v", err)
		}
		for _, name := range names {
			if name == "test_vol" {
				t.Error("FAIL: sudo-created volume visible to a different user's non-sudo query")
			}
		}
	})
}
