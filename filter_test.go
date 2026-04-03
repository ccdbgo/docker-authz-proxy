package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestDB 创建内存 SQLite 数据库（仅用于测试）
func newTestDB(t *testing.T) *OwnershipDB {
	t.Helper()
	db, err := newOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("newOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ── filterContainerListResponse ───────────────────────────────────────────────

func TestFilterContainerListResponse_OwnedContainers(t *testing.T) {
	db := newTestDB(t)
	alice := makeIdentity("alice", 1001, 1001)
	bob := makeIdentity("bob", 1002, 1002)

	_ = db.SetContainerOwner("cont-alice-1", alice)
	_ = db.SetContainerOwner("cont-alice-2", alice)
	_ = db.SetContainerOwner("cont-bob-1", bob)

	body := mustMarshal(t, []map[string]interface{}{
		{"Id": "cont-alice-1", "Labels": nil},
		{"Id": "cont-alice-2", "Labels": nil},
		{"Id": "cont-bob-1", "Labels": nil},
	})

	filtered, err := filterContainerListResponse(body, alice.RealUID, db)
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
	db := newTestDB(t)
	body := mustMarshal(t, []map[string]interface{}{
		{"Id": "cont-bob-1", "Labels": nil},
	})

	// alice 没有任何容器
	filtered, err := filterContainerListResponse(body, 1001, db)
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
	// 容器不在 DB 中，但有系统标签 —— 用标签兜底
	db := newTestDB(t)
	body := mustMarshal(t, []map[string]interface{}{
		{
			"Id": "unlabeled-cont",
			"Labels": map[string]string{
				labelOwnerUID: "1001",
			},
		},
	})

	filtered, err := filterContainerListResponse(body, 1001, db)
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
	// 用户伪造系统标签 uid=1001，但真实 uid 被追加为 1002
	// 逗号分隔，最后一个值为真实值
	db := newTestDB(t)
	body := mustMarshal(t, []map[string]interface{}{
		{
			"Id": "forged-cont",
			"Labels": map[string]string{
				labelOwnerUID: "1001,1002", // 伪造 1001，真实为 1002
			},
		},
	})

	// uid=1001 的 alice 不应看到该容器（最后一个值是 1002）
	filtered, err := filterContainerListResponse(body, 1001, db)
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
	db := newTestDB(t)
	body := []byte(`not json`)
	result, err := filterContainerListResponse(body, 1001, db)
	if err != nil {
		t.Fatal(err)
	}
	// 解析失败时原样返回
	if string(result) != string(body) {
		t.Error("invalid JSON should be returned unchanged")
	}
}

// ── filterImageListResponse ───────────────────────────────────────────────────

func TestFilterImageListResponse_PrivateImages(t *testing.T) {
	db := newTestDB(t)
	alice := makeIdentity("alice", 1001, 1001)
	bob := makeIdentity("bob", 1002, 1002)

	_ = db.SetImageOwner("sha256:alice-img", alice, false, "pull")
	_ = db.SetImageOwner("sha256:bob-img", bob, false, "pull")

	body := mustMarshal(t, []map[string]interface{}{
		{"Id": "sha256:alice-img"},
		{"Id": "sha256:bob-img"},
	})

	filtered, err := filterImageListResponse(body, alice.RealUID, db)
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
	db := newTestDB(t)
	root := makeIdentity("root", 0, 0)

	_ = db.SetImageOwner("sha256:public-img", root, true, "pull")

	body := mustMarshal(t, []map[string]interface{}{
		{"Id": "sha256:public-img"},
	})

	// alice（uid=1001）可以看到公共镜像
	filtered, err := filterImageListResponse(body, 1001, db)
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
	// 不在 DB 中的镜像（存量）：CanUseImage 返回 true，所有人可见
	db := newTestDB(t)
	body := mustMarshal(t, []map[string]interface{}{
		{"Id": "sha256:legacy-img"},
	})
	filtered, err := filterImageListResponse(body, 1001, db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Errorf("legacy image (not in DB) should be visible, got %d", len(result))
	}
}

// ── extractContainerIDFromCreateResponse ─────────────────────────────────────

func TestExtractContainerIDFromCreateResponse(t *testing.T) {
	body := []byte(`{"Id":"abc123def456","Warnings":null}`)
	id := extractContainerIDFromCreateResponse(body)
	if id != "abc123def456" {
		t.Errorf("got %q, want %q", id, "abc123def456")
	}
}

func TestExtractContainerIDFromCreateResponse_Invalid(t *testing.T) {
	id := extractContainerIDFromCreateResponse([]byte(`bad json`))
	if id != "" {
		t.Errorf("invalid JSON should return empty string, got %q", id)
	}
}

// ── streamAndCaptureLoadedImageIDs ───────────────────────────────────────────

func TestStreamAndCaptureLoadedImageIDs_Single(t *testing.T) {
	// docker load 单镜像输出
	ndjson := `{"stream":"Loading layer [==================================================>]  2.048kB/2.048kB\n"}
{"stream":"Loaded image ID: sha256:abc123def456\n"}
`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       fakebody(ndjson),
		Header:     http.Header{},
	}
	rw := httptest.NewRecorder()
	ids := streamAndCaptureLoadedImageIDs(rw, resp)

	if len(ids) != 1 {
		t.Fatalf("expected 1 image ID, got %d: %v", len(ids), ids)
	}
	if ids[0] != "sha256:abc123def456" {
		t.Errorf("got %q, want %q", ids[0], "sha256:abc123def456")
	}
	// 输出应被透明转发给客户端
	if rw.Body.Len() == 0 {
		t.Error("response body should be forwarded to client")
	}
}

func TestStreamAndCaptureLoadedImageIDs_Multiple(t *testing.T) {
	ndjson := `{"stream":"Loaded image ID: sha256:img1\n"}
{"stream":"Loaded image ID: sha256:img2\n"}
`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       fakebody(ndjson),
		Header:     http.Header{},
	}
	rw := httptest.NewRecorder()
	ids := streamAndCaptureLoadedImageIDs(rw, resp)

	if len(ids) != 2 {
		t.Errorf("expected 2 image IDs, got %d: %v", len(ids), ids)
	}
}

func TestStreamAndCaptureLoadedImageIDs_ByTag(t *testing.T) {
	// docker load 带 tag 的镜像不输出 "Loaded image ID:"，输出 "Loaded image: name:tag"
	// 验证不会误采集
	ndjson := `{"stream":"Loaded image: nginx:latest\n"}
`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       fakebody(ndjson),
		Header:     http.Header{},
	}
	rw := httptest.NewRecorder()
	ids := streamAndCaptureLoadedImageIDs(rw, resp)

	if len(ids) != 0 {
		t.Errorf("expected 0 IDs for tag-only load line, got %d: %v", len(ids), ids)
	}
}

// ── parseImageRefFromURI ──────────────────────────────────────────────────────

func TestParseImageRefFromURI(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"/images/create?fromImage=nginx", "nginx"},
		{"/images/create?fromImage=nginx&tag=latest", "nginx"},        // latest 不追加
		{"/images/create?fromImage=nginx&tag=1.25", "nginx:1.25"},     // 非 latest 追加
		{"/images/create?fromImage=registry.io/myimg&tag=v2", "registry.io/myimg:v2"},
		{"/images/create", ""},                                        // 无 query string
		{"/images/create?fromImage=", ""},                             // 空 fromImage
	}
	for _, tt := range tests {
		got := parseImageRefFromURI(tt.uri)
		if got != tt.want {
			t.Errorf("parseImageRefFromURI(%q) = %q, want %q", tt.uri, got, tt.want)
		}
	}
}

// ── truncID ───────────────────────────────────────────────────────────────────

func TestTruncID(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"sha256:abc123def456789", "abc123def456"},
		{"abc123def456789", "abc123def456"},
		{"short", "short"},
		{"", ""},
	}
	for _, tt := range tests {
		got := truncID(tt.input)
		if got != tt.want {
			t.Errorf("truncID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── 辅助 ──────────────────────────────────────────────────────────────────────

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

func fakebody(s string) *fakeReadCloser {
	return &fakeReadCloser{r: strings.NewReader(s)}
}

type fakeReadCloser struct {
	r *strings.Reader
}

func (f *fakeReadCloser) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *fakeReadCloser) Close() error               { return nil }

// 验证 fakeReadCloser 实现了 io.ReadCloser
var _ interface {
	Read([]byte) (int, error)
	Close() error
} = (*fakeReadCloser)(nil)
