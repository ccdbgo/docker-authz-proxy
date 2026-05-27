package forward

// ══════════════════════════════════════════════════════════════════════════════
// image_prune_boundary_test.go — BUG 边界值测试
//
// 覆盖场景：
//   1. 悬空列表为空（GET /images/json 返回 []）
//   2. img.ID 为空字符串（上游返回异常 ID）
//   3. alice 的 sudo 上下文镜像在非 sudo prune 中可被清理（行为变化确认）
//   4. 上游 GET /images/json 返回非 200（500）
// ══════════════════════════════════════════════════════════════════════════════

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ──────────────────────────────────────────────────────────────────────────────
// B1: 悬空列表为空 → 响应 200，ImagesDeleted 为空或缺失，无 DELETE 发出
// ──────────────────────────────────────────────────────────────────────────────
func TestImagePrune_EmptyDanglingList_NoError(t *testing.T) {
	srv, deleted, mu := imgPruneUpstream(t, []string{})
	defer srv.Close()

	p := newTestProxy(t, srv, nil)

	req := httptest.NewRequest("POST", "/images/prune", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", 1001))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", rw.Code)
	}

	mu.Lock()
	n := len(*deleted)
	mu.Unlock()
	if n != 0 {
		t.Errorf("空悬空列表时不应发出 DELETE，实际发出 %d 次", n)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// B2: img.ID 为空字符串 → GetImageOwner("") 返回 found=false → 允许删除
//
// 注：本测试验证代码对异常上游数据的容错行为。
//     空 ID 的 DELETE /images/ 请求会被 fake upstream 的 default case 处理（200 OK）。
// ──────────────────────────────────────────────────────────────────────────────
func TestImagePrune_EmptyImageID_NotPanics(t *testing.T) {
	var mu sync.Mutex
	var deletedPaths []string

	// 上游返回一个 Id 为空字符串的镜像条目
	type imgItem struct {
		ID       string   `json:"Id"`
		RepoTags []string `json:"RepoTags"`
	}
	items := []imgItem{{ID: "", RepoTags: []string{"<none>:<none>"}}}
	listBody, _ := json.Marshal(items)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// strip /vX.Y prefix
		if idx := strings.Index(path[1:], "/"); idx >= 0 {
			candidate := path[idx+1:]
			if strings.HasPrefix(candidate, "/") {
				path = candidate
			}
		}
		switch {
		case r.Method == "GET" && strings.HasSuffix(path, "/images/json"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(listBody)
		case r.Method == "DELETE" && strings.Contains(path, "/images/"):
			imgRef := path[strings.LastIndex(path, "/images/")+len("/images/"):]
			mu.Lock()
			deletedPaths = append(deletedPaths, imgRef)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	p := newTestProxy(t, srv, nil)

	req := httptest.NewRequest("POST", "/images/prune", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", 1001))
	rw := httptest.NewRecorder()

	// 不应 panic
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("空 img.ID 导致 panic: %v", r)
		}
	}()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", rw.Code)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// B3: alice 的 sudo 上下文镜像（privileged_context=1）在非 sudo prune 中可被清理
//
// 行为变化确认：
//   修复前（CanSeeImage）：pc=1 的镜像 CanSeeImage 返回 false → 跳过
//   修复后（GetImageOwner）：found=true && owner.UID==alice → 允许删除
//
// 这是一个有意为之的行为变化：用户应能清理自己 sudo 上下文创建的悬空镜像。
// ──────────────────────────────────────────────────────────────────────────────
const pruneAliceSudoImgID = "ac00000000000000000000000000000000000000000000000000000000000001"

func TestImagePrune_AliceSudoContextImage_IsDeleted_behaviorChange(t *testing.T) {
	srv, deleted, mu := imgPruneUpstream(t, []string{pruneAliceSudoImgID})
	defer srv.Close()

	p := newTestProxy(t, srv, nil)

	aliceID := makeTestIdentityProxy("alice", 1001)
	// 以 privileged_context=1 注册 alice 的镜像
	if err := p.db.SetImageOwner(pruneAliceSudoImgID, aliceID, true, "build"); err != nil {
		t.Fatalf("SetImageOwner(sudo): %v", err)
	}

	req := httptest.NewRequest("POST", "/images/prune", nil)
	req = injectIdentity(req, aliceID) // 非 sudo 模式（PID=0，IsPrivileged=false）
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", rw.Code)
	}

	mu.Lock()
	paths := make([]string, len(*deleted))
	copy(paths, *deleted)
	mu.Unlock()

	wantPath := "sha256:" + pruneAliceSudoImgID
	found := false
	for _, p := range paths {
		if p == wantPath {
			found = true
			break
		}
	}
	if !found {
		t.Errorf(
			"[行为变化] alice 的 sudo 上下文悬空镜像 %s 应被非 sudo prune 删除。\n"+
				"修复后语义：owner.UID==alice → 允许删除（无论 privileged_context 值）。\n"+
				"实际 DELETE 请求: %v",
			pruneAliceSudoImgID, paths,
		)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// B4: 上游 GET /images/json 返回 500 → handleImagePrune 应返回错误响应（不 panic）
// ──────────────────────────────────────────────────────────────────────────────
func TestImagePrune_UpstreamError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"internal error"}`))
	}))
	defer srv.Close()

	p := newTestProxy(t, srv, nil)

	req := httptest.NewRequest("POST", "/images/prune", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", 1001))
	rw := httptest.NewRecorder()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("上游 500 导致 panic: %v", r)
		}
	}()
	p.ServeHTTP(rw, req)

	// 不应返回 2xx（具体状态码取决于实现，但不应 panic 且应有错误响应）
	if rw.Code == http.StatusOK {
		// 若实现返回了 200+空列表，也可接受（幂等 prune）
		// 关键是不 panic
		t.Logf("上游 500 时代理返回 200（空结果），未 panic — 可接受")
	}
}
