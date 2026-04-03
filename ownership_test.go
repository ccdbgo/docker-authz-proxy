package main

import (
	"testing"
)

// ── 容器归属 CRUD ─────────────────────────────────────────────────────────────

func TestOwnershipDB_ContainerSetGet(t *testing.T) {
	db := newTestDB(t)
	alice := makeIdentity("alice", 1001, 1001)

	if err := db.SetContainerOwner("cont-1", alice); err != nil {
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
	alice := makeIdentity("alice", 1001, 1001)

	_ = db.SetContainerOwner("cont-del", alice)
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
	alice := makeIdentity("alice", 1001, 1001)
	bob := makeIdentity("bob", 1002, 1002)

	_ = db.SetContainerOwner("c1", alice)
	_ = db.SetContainerOwner("c2", alice)
	_ = db.SetContainerOwner("c3", bob)

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
	alice := makeIdentity("alice", 1001, 1001)

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
	root := makeIdentity("root", 0, 0)

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
	alice := makeIdentity("alice", 1001, 1001)

	_ = db.SetImageOwner("sha256:del-img", alice, false, "build")
	if err := db.DeleteImage("sha256:del-img"); err != nil {
		t.Fatalf("DeleteImage: %v", err)
	}

	_, _, found := db.GetImageOwner("sha256:del-img")
	if found {
		t.Error("image should be gone after delete")
	}
	// image_access も消えているはず（CanUseImage が true に戻る＝DBになければ許可）
	if !db.CanUseImage(1001, "sha256:del-img") {
		t.Error("after delete, image should be accessible (not-in-DB = allow)")
	}
}

// ── CanUseImage ───────────────────────────────────────────────────────────────

func TestCanUseImage_OwnImage(t *testing.T) {
	db := newTestDB(t)
	alice := makeIdentity("alice", 1001, 1001)
	_ = db.SetImageOwner("sha256:alice-img", alice, false, "pull")

	if !db.CanUseImage(1001, "sha256:alice-img") {
		t.Error("alice should be able to use her own image")
	}
}

func TestCanUseImage_OtherPrivateImage(t *testing.T) {
	db := newTestDB(t)
	bob := makeIdentity("bob", 1002, 1002)
	_ = db.SetImageOwner("sha256:bob-img", bob, false, "pull")

	// alice（uid=1001）无权使用 bob 的私有镜像
	if db.CanUseImage(1001, "sha256:bob-img") {
		t.Error("alice should NOT be able to use bob's private image")
	}
}

func TestCanUseImage_PublicImage(t *testing.T) {
	db := newTestDB(t)
	root := makeIdentity("root", 0, 0)
	_ = db.SetImageOwner("sha256:pub-img", root, true, "pull")

	// 任何用户都能使用公共镜像
	if !db.CanUseImage(1001, "sha256:pub-img") {
		t.Error("alice should be able to use public image")
	}
	if !db.CanUseImage(1002, "sha256:pub-img") {
		t.Error("bob should be able to use public image")
	}
}

func TestCanUseImage_NotInDB(t *testing.T) {
	db := newTestDB(t)
	// 不在 DB 中的镜像默认放行（兼容存量镜像）
	if !db.CanUseImage(1001, "sha256:legacy") {
		t.Error("image not in DB should be accessible to all")
	}
}

func TestCanUseImage_MultipleUsers(t *testing.T) {
	// alice 和 bob 都 pull 了同一个镜像
	db := newTestDB(t)
	alice := makeIdentity("alice", 1001, 1001)
	bob := makeIdentity("bob", 1002, 1002)

	_ = db.SetImageOwner("sha256:shared-img", alice, false, "pull")
	// bob 也 pull 同一镜像（INSERT OR IGNORE，alice 保持所有权，但 bob 在 image_access 中）
	_ = db.SetImageOwner("sha256:shared-img", bob, false, "pull")

	if !db.CanUseImage(1001, "sha256:shared-img") {
		t.Error("alice should be able to use image she pulled first")
	}
	if !db.CanUseImage(1002, "sha256:shared-img") {
		t.Error("bob should be able to use image he also pulled")
	}

	// charlie 从未 pull，不能使用
	if db.CanUseImage(1003, "sha256:shared-img") {
		t.Error("charlie should NOT be able to use image he never pulled")
	}

	// 所有权归 alice（第一个 pull）
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
	alice := makeIdentity("alice", 1001, 1001)
	_ = db.SetImageOwner("sha256:priv-img", alice, false, "build")

	// 标记为公共
	if err := db.MarkImagePublic("sha256:priv-img", true); err != nil {
		t.Fatalf("MarkImagePublic: %v", err)
	}

	_, isPublic, _ := db.GetImageOwner("sha256:priv-img")
	if !isPublic {
		t.Error("image should be public after MarkImagePublic(true)")
	}

	// 撤回公共
	_ = db.MarkImagePublic("sha256:priv-img", false)
	_, isPublic, _ = db.GetImageOwner("sha256:priv-img")
	if isPublic {
		t.Error("image should be private after MarkImagePublic(false)")
	}
}

// ── GetImageIDsByOwner ────────────────────────────────────────────────────────

func TestGetImageIDsByOwner(t *testing.T) {
	db := newTestDB(t)
	alice := makeIdentity("alice", 1001, 1001)
	root := makeIdentity("root", 0, 0)

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
