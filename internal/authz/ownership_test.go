package authz

import (
	"testing"

	"docker-authz-proxy/internal/auth"
)

func newTestDB(t *testing.T) *OwnershipDB {
	t.Helper()
	db, err := NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func makeTestIdentity(username string, uid, gid int) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		RealGID:           gid,
		EffectiveUsername: username,
		EffectiveUID:      uid,
		UserType:          auth.UserTypeRegular,
	}
}

// ── 容器归属 CRUD ─────────────────────────────────────────────────────────────

func TestOwnershipDB_ContainerSetGet(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)

	if err := db.SetContainerOwner("cont-1", alice, ""); err != nil {
		t.Fatalf("SetContainerOwner: %v", err)
	}

	owner, found := db.GetContainerOwner("cont-1")
	if !found {
		t.Fatal("container not found after insert")
	}
	if owner.UID != 1001 {
		t.Errorf("owner UID = %d, want 1001", owner.UID)
	}
	if owner.Username != "alice" {
		t.Errorf("owner username = %q, want alice", owner.Username)
	}
}

func TestOwnershipDB_ContainerNotFound(t *testing.T) {
	db := newTestDB(t)
	_, found := db.GetContainerOwner("nonexistent")
	if found {
		t.Error("should not find nonexistent container")
	}
}

func TestOwnershipDB_ContainerDelete(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)

	_ = db.SetContainerOwner("cont-del", alice, "")
	if err := db.DeleteContainer("cont-del"); err != nil {
		t.Fatalf("DeleteContainer: %v", err)
	}
	_, found := db.GetContainerOwner("cont-del")
	if found {
		t.Error("container should be gone after delete")
	}
}

func TestOwnershipDB_GetContainerIDsByOwner(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	bob := makeTestIdentity("bob", 1002, 1002)

	_ = db.SetContainerOwner("c1", alice, "")
	_ = db.SetContainerOwner("c2", alice, "")
	_ = db.SetContainerOwner("c3", bob, "")

	ids, err := db.GetContainerIDsByOwner(1001)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Errorf("alice should own 2 containers, got %d", len(ids))
	}
	for _, id := range ids {
		if id != "c1" && id != "c2" {
			t.Errorf("unexpected container %q in alice's list", id)
		}
	}
}

// ── 镜像归属 CRUD ─────────────────────────────────────────────────────────────

func TestOwnershipDB_ImageSetGet(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)

	if err := db.SetImageOwner("sha256:img1", alice, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	owner, isPublic, found := db.GetImageOwner("sha256:img1")
	if !found {
		t.Fatal("image not found")
	}
	if isPublic {
		t.Error("image should not be public")
	}
	if owner.UID != 1001 {
		t.Errorf("owner UID = %d, want 1001", owner.UID)
	}
}

func TestOwnershipDB_ImagePublic(t *testing.T) {
	db := newTestDB(t)
	root := makeTestIdentity("root", 0, 0)

	_ = db.SetImageOwner("sha256:pub", root, true, "pull")

	_, isPublic, found := db.GetImageOwner("sha256:pub")
	if !found {
		t.Fatal("image not found")
	}
	if !isPublic {
		t.Error("image should be public")
	}
}

func TestOwnershipDB_ImageDelete(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)

	_ = db.SetImageOwner("sha256:del-img", alice, false, "build")
	if err := db.DeleteImage("sha256:del-img"); err != nil {
		t.Fatalf("DeleteImage: %v", err)
	}

	_, _, found := db.GetImageOwner("sha256:del-img")
	if found {
		t.Error("image should be gone after delete")
	}
	// 删除后不在 DB，CanUseImage 对非 root 返回 false（设计决策：未入库=不可用）
	if db.CanUseImage(1001, "sha256:del-img") {
		t.Error("after delete, non-root should not be able to use image not in DB")
	}
	// root 不受限制
	if !db.CanUseImage(0, "sha256:del-img") {
		t.Error("root should always be able to use any image")
	}
}

// ── CanUseImage ───────────────────────────────────────────────────────────────

func TestCanUseImage_OwnImage(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	_ = db.SetImageOwner("sha256:alice-img", alice, false, "pull")

	if !db.CanUseImage(1001, "sha256:alice-img") {
		t.Error("alice should be able to use her own image")
	}
}

func TestCanUseImage_OtherPrivateImage(t *testing.T) {
	db := newTestDB(t)
	bob := makeTestIdentity("bob", 1002, 1002)
	_ = db.SetImageOwner("sha256:bob-img", bob, false, "pull")

	if db.CanUseImage(1001, "sha256:bob-img") {
		t.Error("alice should NOT be able to use bob's private image")
	}
}

func TestCanUseImage_PublicImage(t *testing.T) {
	db := newTestDB(t)
	root := makeTestIdentity("root", 0, 0)
	_ = db.SetImageOwner("sha256:pub-img", root, true, "pull")

	if !db.CanUseImage(1001, "sha256:pub-img") {
		t.Error("alice should be able to use public image")
	}
	if !db.CanUseImage(1002, "sha256:pub-img") {
		t.Error("bob should be able to use public image")
	}
}

func TestCanUseImage_NotInDB(t *testing.T) {
	db := newTestDB(t)
	// 未入库的镜像：非 root 不可用，root 可用（设计决策：严格模式）
	if db.CanUseImage(1001, "sha256:legacy") {
		t.Error("image not in DB should NOT be accessible to non-root")
	}
	if !db.CanUseImage(0, "sha256:legacy") {
		t.Error("image not in DB should be accessible to root")
	}
}

func TestCanUseImage_MultipleUsers(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	bob := makeTestIdentity("bob", 1002, 1002)

	_ = db.SetImageOwner("sha256:shared-img", alice, false, "pull")
	_ = db.SetImageOwner("sha256:shared-img", bob, false, "pull")

	if !db.CanUseImage(1001, "sha256:shared-img") {
		t.Error("alice should be able to use image she pulled first")
	}
	if !db.CanUseImage(1002, "sha256:shared-img") {
		t.Error("bob should be able to use image he also pulled")
	}
	if db.CanUseImage(1003, "sha256:shared-img") {
		t.Error("charlie should NOT be able to use image he never pulled")
	}

	owner, _, found := db.GetImageOwner("sha256:shared-img")
	if !found {
		t.Fatal("image not found")
	}
	if owner.UID != 1001 {
		t.Errorf("image owner UID = %d, want 1001 (alice)", owner.UID)
	}
}

// ── MarkImagePublic ───────────────────────────────────────────────────────────

func TestMarkImagePublic(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	_ = db.SetImageOwner("sha256:priv-img", alice, false, "build")

	if err := db.MarkImagePublic("sha256:priv-img", true); err != nil {
		t.Fatalf("MarkImagePublic: %v", err)
	}

	_, isPublic, _ := db.GetImageOwner("sha256:priv-img")
	if !isPublic {
		t.Error("image should be public after MarkImagePublic(true)")
	}

	_ = db.MarkImagePublic("sha256:priv-img", false)
	_, isPublic, _ = db.GetImageOwner("sha256:priv-img")
	if isPublic {
		t.Error("image should be private after MarkImagePublic(false)")
	}
}

// ── GetImageIDsByOwner ────────────────────────────────────────────────────────

func TestGetImageIDsByOwner(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	root := makeTestIdentity("root", 0, 0)

	_ = db.SetImageOwner("sha256:img-a1", alice, false, "pull")
	_ = db.SetImageOwner("sha256:img-a2", alice, false, "build")
	_ = db.SetImageOwner("sha256:pub-img", root, true, "pull")

	ids, err := db.GetImageIDsByOwner(1001)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Errorf("alice owns 2 private images, got %d", len(ids))
	}
}

// ── 镜像引用计数 ──────────────────────────────────────────────────────────────

func TestImageRefCount_SingleUser(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	_ = db.SetImageOwner("sha256:img1", alice, false, "pull")

	count, err := db.GetImageRefCount("sha256:img1")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("ref count = %d, want 1", count)
	}
}

func TestImageRefCount_MultiUser(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	_ = db.SetImageOwner("sha256:img1", alice, true, "pull") // public image

	// bob also gets access
	_ = db.EnsureImageAccess("sha256:img1", 1002)
	_ = db.EnsureImageAccess("sha256:img1", 1003)

	count, err := db.GetImageRefCount("sha256:img1")
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("ref count = %d, want 3", count)
	}
}

func TestImageRefCount_AfterRemove(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	_ = db.SetImageOwner("sha256:img1", alice, true, "pull")
	_ = db.EnsureImageAccess("sha256:img1", 1002)

	// bob removes his reference
	shouldDelete, err := db.RemoveUserImageAccess("sha256:img1", 1002)
	if err != nil {
		t.Fatal(err)
	}
	if shouldDelete {
		t.Error("shouldDelete should be false (alice still references)")
	}

	count, _ := db.GetImageRefCount("sha256:img1")
	if count != 1 {
		t.Errorf("ref count = %d, want 1 after bob's removal", count)
	}
}

func TestImageRefCount_LastUserDelete(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	_ = db.SetImageOwner("sha256:img1", alice, false, "pull")

	shouldDelete, err := db.RemoveUserImageAccess("sha256:img1", 1001)
	if err != nil {
		t.Fatal(err)
	}
	if !shouldDelete {
		t.Error("shouldDelete should be true (last reference removed)")
	}
}

func TestHasUserImageAccess(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	_ = db.SetImageOwner("sha256:img1", alice, false, "pull")

	has, err := db.HasUserImageAccess("sha256:img1", 1001)
	if err != nil || !has {
		t.Errorf("alice should have access: has=%v err=%v", has, err)
	}

	has, err = db.HasUserImageAccess("sha256:img1", 1002)
	if err != nil || has {
		t.Errorf("bob should not have access: has=%v err=%v", has, err)
	}
}

func TestGetImageRefUsers(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	_ = db.SetImageOwner("sha256:img1", alice, true, "pull")
	_ = db.EnsureImageAccess("sha256:img1", 1002)

	uids, err := db.GetImageRefUsers("sha256:img1")
	if err != nil {
		t.Fatal(err)
	}
	if len(uids) != 2 {
		t.Errorf("expected 2 ref users, got %d", len(uids))
	}
}

// ── 公共镜像引用计数阻止删除 ──────────────────────────────────────────────────

func TestPublicImage_CannotDeleteWithRefs(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	_ = db.SetImageOwner("sha256:pub1", alice, true, "pull")
	_ = db.EnsureImageAccess("sha256:pub1", 1002) // bob references it

	refCount, _ := db.GetImageRefCount("sha256:pub1")
	if refCount <= 1 {
		t.Fatalf("expected refCount > 1, got %d", refCount)
	}
	// Proxy should block deletion when refCount > 1 for public images
	// (tested at proxy layer; here we just verify the count is correct)
}

