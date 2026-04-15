package isolation

import (
	"encoding/json"
	"strings"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

func newFilterTestDB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func makeFilterIdentity(username string, uid, gid int) *auth.CallerIdentity {
	return &auth.CallerIdentity{
		RealUsername:      username,
		RealUID:           uid,
		RealGID:           gid,
		EffectiveUsername: username,
		EffectiveUID:      uid,
		UserType:          auth.UserTypeRegular,
	}
}

// ── FilterContainerListResponse ───────────────────────────────────────────────

func TestFilterContainerListResponse_OwnedContainers(t *testing.T) {
	db := newFilterTestDB(t)
	alice := makeFilterIdentity("alice", 1001, 1001)
	bob := makeFilterIdentity("bob", 1002, 1002)

	_ = db.SetContainerOwner("cont-alice-1", alice, "")
	_ = db.SetContainerOwner("cont-alice-2", alice, "")
	_ = db.SetContainerOwner("cont-bob-1", bob, "")

	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": "cont-alice-1", "Labels": nil},
		{"Id": "cont-alice-2", "Labels": nil},
		{"Id": "cont-bob-1", "Labels": nil},
	})

	filtered, err := FilterContainerListResponse(body, alice.RealUID, alice.RealUsername, db)
	if err != nil {
		t.Fatal(err)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 {
		t.Errorf("alice should see 2 containers, got %d", len(result))
	}
	for _, c := range result {
		id := c["Id"].(string)
		if !strings.HasPrefix(id, "cont-alice") {
			t.Errorf("unexpected container %q in alice's list", id)
		}
	}
}

func TestFilterContainerListResponse_Empty(t *testing.T) {
	db := newFilterTestDB(t)
	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": "cont-bob-1", "Labels": nil},
	})

	filtered, err := FilterContainerListResponse(body, 1001, "alice", db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 containers, got %d", len(result))
	}
}

func TestFilterContainerListResponse_LabelFallback(t *testing.T) {
	db := newFilterTestDB(t)
	body := mustMarshalFilter(t, []map[string]interface{}{
		{
			"Id": "unlabeled-cont",
			"Labels": map[string]string{
				LabelOwnerUID: "1001",
			},
		},
	})

	filtered, err := FilterContainerListResponse(body, 1001, "alice", db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 container via label fallback, got %d", len(result))
	}
}

func TestFilterContainerListResponse_LabelForgery(t *testing.T) {
	db := newFilterTestDB(t)
	body := mustMarshalFilter(t, []map[string]interface{}{
		{
			"Id": "forged-cont",
			"Labels": map[string]string{
				LabelOwnerUID: "1001,1002",
			},
		},
	})

	filtered, err := FilterContainerListResponse(body, 1001, "alice", db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("alice should not see container with forged label, got %d", len(result))
	}
}

func TestFilterContainerListResponse_InvalidJSON(t *testing.T) {
	db := newFilterTestDB(t)
	body := []byte(`not json`)
	result, err := FilterContainerListResponse(body, 1001, "alice", db)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != string(body) {
		t.Error("invalid JSON should be returned unchanged")
	}
}

func TestFilterContainerListResponse_OwnerLabelFallback(t *testing.T) {
	// 容器未在 DB 中，但有 owner 标签，应通过标签归属判定
	db := newFilterTestDB(t)
	body := mustMarshalFilter(t, []map[string]interface{}{
		{
			"Id": "label-only-cont",
			"Labels": map[string]string{
				LabelOwner: "alice",
			},
		},
	})

	filtered, err := FilterContainerListResponse(body, 1001, "alice", db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Errorf("alice should see container via owner label, got %d", len(result))
	}
}

func TestFilterContainerListResponse_OwnerLabelForgery(t *testing.T) {
	// 用户伪造 owner 标签（"bob,alice"），末位值为 alice，但 bob 不应看到
	db := newFilterTestDB(t)
	body := mustMarshalFilter(t, []map[string]interface{}{
		{
			"Id": "forged-owner-cont",
			"Labels": map[string]string{
				LabelOwner: "bob,alice",
			},
		},
	})

	// bob 尝试访问：末位值是 alice，bob 不匹配
	filtered, err := FilterContainerListResponse(body, 1002, "bob", db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("bob should NOT see container with forged owner label, got %d", len(result))
	}
}

func TestFilterContainerListResponse_RootSeesAll(t *testing.T) {
	db := newFilterTestDB(t)
	alice := makeFilterIdentity("alice", 1001, 1001)
	_ = db.SetContainerOwner("cont-alice", alice, "")

	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": "cont-alice", "Labels": nil},
		{"Id": "cont-other", "Labels": nil},
	})

	// root (uid=0) 应看到所有容器
	filtered, err := FilterContainerListResponse(body, 0, "root", db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 {
		t.Errorf("root should see all 2 containers, got %d", len(result))
	}
}



func TestFilterImageListResponse_PrivateImages(t *testing.T) {
	db := newFilterTestDB(t)
	alice := makeFilterIdentity("alice", 1001, 1001)
	bob := makeFilterIdentity("bob", 1002, 1002)

	_ = db.SetImageOwner("sha256:alice-img", alice, false, "pull")
	_ = db.SetImageOwner("sha256:bob-img", bob, false, "pull")

	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": "sha256:alice-img"},
		{"Id": "sha256:bob-img"},
	})

	filtered, err := FilterImageListResponse(body, alice.RealUID, db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Errorf("alice should see 1 image, got %d", len(result))
	}
	if result[0]["Id"].(string) != "sha256:alice-img" {
		t.Errorf("alice should see her own image")
	}
}

func TestFilterImageListResponse_PublicImages(t *testing.T) {
	db := newFilterTestDB(t)
	root := makeFilterIdentity("root", 0, 0)

	_ = db.SetImageOwner("sha256:public-img", root, true, "pull")

	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": "sha256:public-img"},
	})

	filtered, err := FilterImageListResponse(body, 1001, db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Errorf("alice should see public image, got %d images", len(result))
	}
}

func TestFilterImageListResponse_NotInDB(t *testing.T) {
	db := newFilterTestDB(t)
	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": "sha256:legacy-img"},
	})
	filtered, err := FilterImageListResponse(body, 1001, db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatal(err)
	}
	// 未入库的镜像对非 root 不可见（严格模式：未授权=不可见）
	if len(result) != 0 {
		t.Errorf("legacy image (not in DB) should NOT be visible to non-root, got %d", len(result))
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func mustMarshalFilter(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}
