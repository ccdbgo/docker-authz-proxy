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
	ids := streamAndCaptureLoadedImageIDs(rw, resp)

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
	ids := streamAndCaptureLoadedImageIDs(rw, resp)

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
	ids := streamAndCaptureLoadedImageIDs(rw, resp)

	if len(ids) != 0 {
		t.Errorf("expected 0 IDs for tag-only load line, got %d: %v", len(ids), ids)
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
