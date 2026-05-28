package forward

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

// ── parseImageRefFromURI ──────────────────────────────────────────────────────

func TestParseImageRefFromURI(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"/images/create?fromImage=nginx", "nginx"},
		{"/images/create?fromImage=nginx&tag=latest", "nginx"},
		{"/images/create?fromImage=nginx&tag=1.25", "nginx:1.25"},
		{"/images/create?fromImage=registry.io/myimg&tag=v2", "registry.io/myimg:v2"},
		{"/images/create", ""},
		{"/images/create?fromImage=", ""},
	}
	for _, tt := range tests {
		got := parseImageRefFromURI(tt.uri)
		if got != tt.want {
			t.Errorf("parseImageRefFromURI(%q) = %q, want %q", tt.uri, got, tt.want)
		}
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
	ndjson := `{"stream":"Loading layer [==================================================>]  2.048kB/2.048kB\n"}
{"stream":"Loaded image ID: sha256:abc123def456\n"}
`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       fakeBodyForward(ndjson),
		Header:     http.Header{},
	}
	rw := httptest.NewRecorder()
	ids := streamAndCaptureLoadedImageIDs(rw, resp, nil)

	if len(ids) != 1 {
		t.Fatalf("expected 1 image ID, got %d: %v", len(ids), ids)
	}
	if ids[0] != "sha256:abc123def456" {
		t.Errorf("got %q, want %q", ids[0], "sha256:abc123def456")
	}
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
		Body:       fakeBodyForward(ndjson),
		Header:     http.Header{},
	}
	rw := httptest.NewRecorder()
	ids := streamAndCaptureLoadedImageIDs(rw, resp, nil)

	if len(ids) != 2 {
		t.Errorf("expected 2 image IDs, got %d: %v", len(ids), ids)
	}
}

func TestStreamAndCaptureLoadedImageIDs_ByTag(t *testing.T) {
	ndjson := `{"stream":"Loaded image: nginx:latest\n"}
`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       fakeBodyForward(ndjson),
		Header:     http.Header{},
	}
	rw := httptest.NewRecorder()
	var calledWith []string
	ids := streamAndCaptureLoadedImageIDs(rw, resp, func(tag string) {
		calledWith = append(calledWith, tag)
	})

	if len(ids) != 0 {
		t.Errorf("expected 0 IDs for tag-only load line, got %d: %v", len(ids), ids)
	}
	if len(calledWith) != 1 || calledWith[0] != "nginx:latest" {
		t.Errorf("onTagLoaded expected [nginx:latest], got %v", calledWith)
	}
}

// ── extractImageIDFromStreamLines ────────────────────────────────────────────

func TestExtractImageIDFromStreamLines_PullDigestStatus(t *testing.T) {
	// 标准 docker pull 流：{"status":"Digest: sha256:..."}
	lines := []string{
		`{"status":"Pulling from library/alpine"}`,
		`{"status":"Pull complete","progressDetail":{},"id":"abc123"}`,
		`{"status":"Digest: sha256:deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"}`,
		`{"status":"Status: Downloaded newer image for alpine:latest"}`,
	}
	got := extractImageIDFromStreamLines(lines, "pull")
	want := "sha256:deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExtractImageIDFromStreamLines_PullAux(t *testing.T) {
	// 旧版 aux 格式
	lines := []string{
		`{"status":"Pulling from library/nginx"}`,
		`{"aux":{"Tag":"latest","Digest":"sha256:aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd","Size":1234}}`,
	}
	got := extractImageIDFromStreamLines(lines, "pull")
	want := "sha256:aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExtractImageIDFromStreamLines_PullEmpty(t *testing.T) {
	// 没有 Digest 行时返回空
	lines := []string{
		`{"status":"Pulling from library/alpine"}`,
		`{"status":"Status: Image is up to date for alpine:latest"}`,
	}
	got := extractImageIDFromStreamLines(lines, "pull")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestExtractImageIDFromStreamLines_BuildAux(t *testing.T) {
	// BuildKit aux 格式
	lines := []string{
		`{"stream":"Step 1/2 : FROM alpine\n"}`,
		`{"aux":{"ID":"sha256:cafebabe1234567890abcdef1234567890abcdef1234567890abcdef12345678"}}`,
	}
	got := extractImageIDFromStreamLines(lines, "build")
	want := "cafebabe1234567890abcdef1234567890abcdef1234567890abcdef12345678"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExtractImageIDFromStreamLines_BuildSuccessfully(t *testing.T) {
	// 旧版 builder 格式
	lines := []string{
		`{"stream":"Step 2/2 : CMD [\"/bin/sh\"]\n"}`,
		`{"stream":"Successfully built ab12cd34ef56\n"}`,
	}
	got := extractImageIDFromStreamLines(lines, "build")
	want := "ab12cd34ef56"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func fakeBodyForward(s string) *fakeReadCloserForward {
	return &fakeReadCloserForward{r: strings.NewReader(s)}
}

type fakeReadCloserForward struct {
	r *strings.Reader
}

func (f *fakeReadCloserForward) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *fakeReadCloserForward) Close() error               { return nil }
