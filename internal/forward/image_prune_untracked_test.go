package forward

// ══════════════════════════════════════════════════════════════════════════════
// image_prune_untracked_test.go — BUG 回归测试
//
// Bug 描述
// ─────────
//   alice 执行 `docker image prune -f` 后，悬空镜像未被清除。
//
// 根本原因
// ─────────
//   handleImagePrune 以 CanSeeImage 作为删除门控：
//     resolveImageIDInDB(img.ID) == "" → CanSeeImage 立即返回 false → continue（跳过）
//   DB 中无记录的镜像（代理部署前的历史镜像、构建流解析失败未注册的镜像）
//   永远无法通过此门控，即使 alice 是事实上的拥有者或镜像根本无人认领。
//
// 修复
// ────
//   将门控从 CanSeeImage 改为 GetImageOwner：
//     • !found（DB 无记录） → 无主镜像，允许 alice 清理
//     • found && owner.UID == alice → 自有镜像，允许清理
//     • found && owner.UID != alice → 他人镜像，跳过（隔离保留）
//
// 测试矩阵
// ─────────
//   1. [RED→GREEN] UntrackedDangling_IsDeleted  — 无主悬空镜像必须被删除（bug 核心）
//   2. [REGRESSION] TrackedOwn_IsDeleted        — 已注册自有镜像仍可 prune
//   3. [REGRESSION] OtherUserImage_IsSkipped    — 他人镜像不得被删除（隔离）
// ══════════════════════════════════════════════════════════════════════════════

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"docker-authz-proxy/internal/authz"
)

// 64 字节十六进制字符串模拟真实 Docker image content ID（无 sha256: 前缀，存 DB 用）
const (
	pruneUntrackedImgID = "cc00000000000000000000000000000000000000000000000000000000000001"
	pruneAliceImgID     = "aa11000000000000000000000000000000000000000000000000000000000001"
	pruneBobImgID       = "bb11000000000000000000000000000000000000000000000000000000000001"
)

// imgPruneUpstream 构建响应 GET /images/json 和 DELETE /images/{id} 的 fake Docker。
// danglingIDs：返回给 GET 的悬空镜像列表（不含 sha256: 前缀）。
// 返回：fake server、已收到的 DELETE path 列表（带锁保护）。
func imgPruneUpstream(t *testing.T, danglingIDs []string) (*httptest.Server, *[]string, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var deletedPaths []string

	// 构造 GET /images/json 响应（Docker 返回格式，Id 字段含 sha256: 前缀）
	type imgItem struct {
		ID       string   `json:"Id"`
		RepoTags []string `json:"RepoTags"`
	}
	items := make([]imgItem, len(danglingIDs))
	for i, id := range danglingIDs {
		items[i] = imgItem{ID: "sha256:" + id, RepoTags: []string{"<none>:<none>"}}
	}
	listBody, _ := json.Marshal(items)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := authz.StripAPIVersion(r.URL.Path)
		switch {
		case r.Method == "GET" && path == "/images/json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(listBody)

		case r.Method == "DELETE" && strings.HasPrefix(path, "/images/"):
			imgRef := strings.TrimPrefix(path, "/images/")
			mu.Lock()
			deletedPaths = append(deletedPaths, imgRef)
			mu.Unlock()
			// 模拟 Docker 删除成功响应
			resp := `[{"Deleted":"` + imgRef + `"}]`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(resp))

		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	return srv, &deletedPaths, &mu
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. [RED→GREEN] 无主悬空镜像（DB 无记录）必须被删除
//
// 修复前（CanSeeImage）：resolveImageIDInDB 返回 "" → false → continue → DELETE 未发出
// 修复后（GetImageOwner）：found=false → 无主 → 允许 → DELETE 发出 → 镜像被清理
// ══════════════════════════════════════════════════════════════════════════════
func TestImagePrune_UntrackedDanglingImage_IsDeleted_regression(t *testing.T) {
	srv, deleted, mu := imgPruneUpstream(t, []string{pruneUntrackedImgID})
	defer srv.Close()

	p := newTestProxy(t, srv, nil)
	// 不向 DB 写入任何镜像记录 → 模拟代理部署前已存在的悬空镜像

	req := httptest.NewRequest("POST", "/images/prune", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", 1001))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", rw.Code)
	}

	mu.Lock()
	paths := make([]string, len(*deleted))
	copy(paths, *deleted)
	mu.Unlock()

	wantPath := "sha256:" + pruneUntrackedImgID
	found := false
	for _, p := range paths {
		if p == wantPath {
			found = true
			break
		}
	}
	if !found {
		t.Errorf(
			"[BUG REPRODUCED] alice 的无主悬空镜像 %s 未被 prune 删除。\n"+
				"修复前原因：CanSeeImage 对 DB 无记录镜像返回 false，跳过删除。\n"+
				"实际收到的 DELETE 请求: %v",
			pruneUntrackedImgID, paths,
		)
	}

	// 响应体中 ImagesDeleted 应包含该镜像
	var resp struct {
		ImagesDeleted []struct {
			Deleted string `json:"Deleted"`
		} `json:"ImagesDeleted"`
	}
	if err := json.NewDecoder(rw.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.ImagesDeleted) == 0 {
		t.Errorf("响应 ImagesDeleted 为空，预期包含 %s", pruneUntrackedImgID)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. [REGRESSION] alice 已注册的自有悬空镜像仍可被 prune
// ══════════════════════════════════════════════════════════════════════════════
func TestImagePrune_TrackedOwnImage_IsDeleted_regression(t *testing.T) {
	srv, deleted, mu := imgPruneUpstream(t, []string{pruneAliceImgID})
	defer srv.Close()

	p := newTestProxy(t, srv, nil)

	aliceID := makeTestIdentityProxy("alice", 1001)
	// 预置 alice 的镜像归属（模拟通过代理构建或拉取的镜像）
	if err := p.db.SetImageOwner(pruneAliceImgID, aliceID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	req := httptest.NewRequest("POST", "/images/prune", nil)
	req = injectIdentity(req, aliceID)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", rw.Code)
	}

	mu.Lock()
	paths := make([]string, len(*deleted))
	copy(paths, *deleted)
	mu.Unlock()

	wantPath := "sha256:" + pruneAliceImgID
	found := false
	for _, p := range paths {
		if p == wantPath {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("回归：alice 自有已注册镜像 %s 应被 prune 删除，实际 DELETE 请求: %v",
			pruneAliceImgID, paths)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. [REGRESSION] bob 的镜像不得被 alice 的 prune 删除（隔离）
// ══════════════════════════════════════════════════════════════════════════════
func TestImagePrune_OtherUserImage_IsSkipped_regression(t *testing.T) {
	srv, deleted, mu := imgPruneUpstream(t, []string{pruneBobImgID})
	defer srv.Close()

	p := newTestProxy(t, srv, nil)

	bobID := makeTestIdentityProxy("bob", 1002)
	// 预置 bob 的镜像归属
	if err := p.db.SetImageOwner(pruneBobImgID, bobID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner(bob): %v", err)
	}

	// alice 发起 prune
	req := httptest.NewRequest("POST", "/images/prune", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", 1001))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", rw.Code)
	}

	mu.Lock()
	paths := make([]string, len(*deleted))
	copy(paths, *deleted)
	mu.Unlock()

	bobImgPath := "sha256:" + pruneBobImgID
	for _, p := range paths {
		if p == bobImgPath {
			t.Errorf(
				"[隔离失效] alice 的 prune 删除了 bob 的镜像 %s，跨越了用户边界。\n"+
					"实际收到的 DELETE 请求: %v",
				pruneBobImgID, paths,
			)
		}
	}
}
