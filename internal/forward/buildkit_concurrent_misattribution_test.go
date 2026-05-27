package forward

// ══════════════════════════════════════════════════════════════════════════════
// buildkit_concurrent_misattribution_test.go — BUG-25 回归测试
//
// Bug 描述
// ─────────
//   bob 执行 `docker build -t bob-prune-test:v1`，同一时间 root（绕过 proxy）
//   执行 `docker build -t prune-untracked-root:tmp`。trackBuildKitImages 在
//   300ms 快照窗口内看到 prune-untracked-root:tmp 的 SHA 变化，将其误归属给 bob。
//
// 根本原因
// ─────────
//   trackBuildKitImages tag 对比循环收集 ALL 变更 tag，未限制为命令行 -t 指定的 tag。
//   导致并发构建的其他镜像被错误注册为当前用户的构建产物。
//
// 修复
// ────
//   构建 expectedTags 集合（parseBuildxTags(id.CmdLine)）。
//   taggedIDs 分支：仅归属 expectedTags 中的 tag 对应的镜像。
//   otherIDs 分支：跳过在 post-snapshot 中有 tag 但 tag 不在 expectedTags 的镜像。
//
// 测试矩阵
// ─────────
//   1. [RED→GREEN] ConcurrentBuild_OnlyBobTagAttributed — 并发变更的其他 tag 不归属 bob
//   2. [REGRESSION] BobOwnTag_IsAttributed             — bob 自己的 tag 仍正确归属
//   3. [REGRESSION] UntaggedNewImage_IsAttributed       — bob 构建的无 tag 镜像仍归属
// ══════════════════════════════════════════════════════════════════════════════

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"docker-authz-proxy/internal/authz"
)

// ──────────────────────────────────────────────────────────────────────────────
// Fake Docker upstream for trackBuildKitImages tests
// ──────────────────────────────────────────────────────────────────────────────

type buildkitDockerState struct {
	mu     sync.Mutex
	images []bkFakeImage
}

type bkFakeImage struct {
	ID       string
	RepoTags []string
}

func (s *buildkitDockerState) set(imgs []bkFakeImage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.images = imgs
}

func (s *buildkitDockerState) listJSON() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	type item struct {
		ID       string   `json:"Id"`
		RepoTags []string `json:"RepoTags"`
	}
	items := make([]item, len(s.images))
	for i, img := range s.images {
		items[i] = item{ID: "sha256:" + img.ID, RepoTags: img.RepoTags}
	}
	b, _ := json.Marshal(items)
	return b
}

func newBKFakeUpstream(t *testing.T, state *buildkitDockerState) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := authz.StripAPIVersion(r.URL.Path)
		if r.Method == "GET" && path == "/images/json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(state.listJSON())
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}

// 64-char hex image IDs
const (
	bkBobBuildImgID       = "bb0000000000000000000000000000000000000000000000000000000000bb01"
	bkConcurrentRootImgID = "cc0000000000000000000000000000000000000000000000000000000000cc01"
	bkUntaggedBobImgID    = "uu0000000000000000000000000000000000000000000000000000000000uu01"
	bkOldRootImgID        = "rr0000000000000000000000000000000000000000000000000000000000rr01"
)

// ──────────────────────────────────────────────────────────────────────────────
// 1. [RED→GREEN] 并发变更的其他 tag 不应归属给 bob
// ──────────────────────────────────────────────────────────────────────────────
func TestBuildKitTrack_ConcurrentBuild_OnlyBobTagAttributed(t *testing.T) {
	const (
		bobTag    = "bob-build-test:v1"
		concurTag = "root-concurrent:latest"
	)

	state := &buildkitDockerState{}
	// pre-snapshot：只有 root 的旧镜像
	state.set([]bkFakeImage{
		{ID: bkOldRootImgID, RepoTags: []string{concurTag}},
	})

	srv := newBKFakeUpstream(t, state)
	defer srv.Close()

	p := newTestProxy(t, srv, nil)
	bobID := makeTestIdentityProxy("bob", 1002)
	bobID.CmdLine = fmt.Sprintf("/usr/libexec/docker/cli-plugins/docker-buildx buildx build -t %s -", bobTag)

	pre := p.snapshotImageState()
	if pre == nil {
		t.Fatal("snapshotImageState(pre) returned nil；fake upstream 未正确处理 /images/json")
	}

	// 模拟并发：root 改变了 concurTag 的 SHA，bob 的构建也完成产生 bobBuildImgID
	state.set([]bkFakeImage{
		{ID: bkConcurrentRootImgID, RepoTags: []string{concurTag}},
		{ID: bkBobBuildImgID, RepoTags: []string{bobTag}},
	})

	go p.trackBuildKitImages(bobID, pre)
	time.Sleep(600 * time.Millisecond)

	// bob 应拥有自己的镜像
	bobOwner, _, _, bobFound := p.db.GetImageOwner(bkBobBuildImgID)
	if !bobFound || bobOwner == nil || bobOwner.UID != 1002 {
		t.Errorf("bob 自己的镜像 %s 未正确归属（found=%v, owner=%v）", bkBobBuildImgID[:12], bobFound, bobOwner)
	}

	// root 的并发镜像不应归属给 bob
	concurOwner, _, _, concurFound := p.db.GetImageOwner(bkConcurrentRootImgID)
	if concurFound && concurOwner != nil && concurOwner.UID == 1002 {
		t.Errorf(
			"[BUG-25] 并发 root 构建的镜像 %s 被误归属给 bob（owner_uid=1002）。\n"+
				"修复前：taggedIDs 捕获所有 SHA 变更 tag → SetImageOwner(concurrentImg, bob)。\n"+
				"修复后：expectedTags 过滤，concurTag 不在 -t 列表 → 跳过。",
			bkConcurrentRootImgID[:12],
		)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// 2. [REGRESSION] bob 自己的 tag 在修复后仍正确归属
// ──────────────────────────────────────────────────────────────────────────────
func TestBuildKitTrack_BobOwnTag_IsAttributed(t *testing.T) {
	const bobTag = "bob-own-build:latest"

	state := &buildkitDockerState{}
	state.set([]bkFakeImage{}) // pre: 空

	srv := newBKFakeUpstream(t, state)
	defer srv.Close()

	p := newTestProxy(t, srv, nil)
	bobID := makeTestIdentityProxy("bob", 1002)
	bobID.CmdLine = fmt.Sprintf("/usr/libexec/docker/cli-plugins/docker-buildx buildx build -t %s -", bobTag)

	pre := p.snapshotImageState()
	if pre == nil {
		t.Fatal("snapshotImageState(pre) returned nil")
	}

	state.set([]bkFakeImage{
		{ID: bkBobBuildImgID, RepoTags: []string{bobTag}},
	})

	go p.trackBuildKitImages(bobID, pre)
	time.Sleep(600 * time.Millisecond)

	owner, _, _, found := p.db.GetImageOwner(bkBobBuildImgID)
	if !found || owner == nil || owner.UID != 1002 {
		t.Errorf("回归：bob 自己的镜像 %s 未正确归属（found=%v, owner=%v）", bkBobBuildImgID[:12], found, owner)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// 3. [REGRESSION] bob 构建的无 tag 镜像（构建前不存在）仍应归属
// ──────────────────────────────────────────────────────────────────────────────
func TestBuildKitTrack_UntaggedNewImage_IsAttributed(t *testing.T) {
	state := &buildkitDockerState{}
	state.set([]bkFakeImage{})

	srv := newBKFakeUpstream(t, state)
	defer srv.Close()

	p := newTestProxy(t, srv, nil)
	bobID := makeTestIdentityProxy("bob", 1002)
	// 无 -t 的 build
	bobID.CmdLine = "/usr/libexec/docker/cli-plugins/docker-buildx buildx build -"

	pre := p.snapshotImageState()
	if pre == nil {
		t.Fatal("snapshotImageState(pre) returned nil")
	}

	// 新的无 tag 镜像（<none>:<none>）
	state.set([]bkFakeImage{
		{ID: bkUntaggedBobImgID, RepoTags: []string{"<none>:<none>"}},
	})

	go p.trackBuildKitImages(bobID, pre)
	time.Sleep(600 * time.Millisecond)

	owner, _, _, found := p.db.GetImageOwner(bkUntaggedBobImgID)
	if !found || owner == nil || owner.UID != 1002 {
		t.Errorf("回归：bob 的无 tag 镜像 %s 未正确归属（found=%v, owner=%v）", bkUntaggedBobImgID[:12], found, owner)
	}
}
