package isolation

// storage_cleanup_test.go
//
// 针对 Bug：bob 执行 docker volume create bob-vol 后，清理协程（runCleanup）
// 将未被任何容器挂载的用户 volume 误判为"孤立 volume"并删除，
// 导致 docker volume ls 中该 volume 消失。
//
// 根本原因：runCleanup 只检查 isUserVolumePrefix()，未检查 DB 归属记录，
//           对"dangling（RefCount=0）"和"orphaned（DB 无归属）"概念混淆。
//
// 正确修复方向：清理前查 DB，跳过有归属记录的 volume，
//              只删除 DB 中无记录的真正孤立 volume。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"

	"go.uber.org/zap"
)

// ─── 测试辅助函数 ──────────────────────────────────────────────────────────────

// newCleanupTestDB 创建内存 SQLite DB，测试结束自动 Close。
func newCleanupTestDB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// registerVolumeOwner 向 DB 注册 volume 归属，模拟 proxy 在 VolumeCreate 响应 201 后的操作。
func registerVolumeOwner(t *testing.T, db *authz.OwnershipDB, internalVolName string, uid int, username string) {
	t.Helper()
	err := db.SetVolumeOwner(internalVolName, &auth.CallerIdentity{
		RealUID:      uid,
		RealUsername: username,
	})
	if err != nil {
		t.Fatalf("SetVolumeOwner(%q, uid=%d): %v", internalVolName, uid, err)
	}
}

// volumeExistsInDB 检查 volume 是否仍在 DB 中有归属记录。
func volumeExistsInDB(t *testing.T, db *authz.OwnershipDB, internalVolName string, uid int) bool {
	t.Helper()
	names, err := db.GetVolumeNamesByOwner(uid)
	if err != nil {
		t.Fatalf("GetVolumeNamesByOwner(uid=%d): %v", uid, err)
	}
	for _, n := range names {
		if n == internalVolName {
			return true
		}
	}
	return false
}

// redirectTransport 将 StorageManager 发出的 "http://docker/..." 请求
// 重定向到 httptest.Server，绕过 Unix socket 依赖。
type redirectTransport struct {
	baseURL string
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target, err := url.Parse(rt.baseURL + req.URL.RequestURI())
	if err != nil {
		return nil, err
	}
	newReq := req.Clone(req.Context())
	newReq.URL = target
	newReq.Host = target.Host
	return http.DefaultTransport.RoundTrip(newReq)
}

// newMockStorageManager 创建使用 mock HTTP 服务器的 StorageManager（不依赖真实 Docker socket）。
func newMockStorageManager(srv *httptest.Server) *StorageManager {
	return &StorageManager{
		storageBase: "",
		httpClient: &http.Client{
			Transport: &redirectTransport{baseURL: srv.URL},
		},
	}
}

// mockDockerServer 启动一个模拟 Docker daemon，danglingVolumes 为返回的悬空 volume 列表。
// 返回 server 本体和一个 deletedVols map（记录 DELETE 调用次数，键为 volume 名）。
func mockDockerServer(t *testing.T, danglingVolumes []string) (*httptest.Server, map[string]int) {
	t.Helper()
	deletedVols := map[string]int{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/volumes":
			items := make([]map[string]interface{}, 0, len(danglingVolumes))
			for _, name := range danglingVolumes {
				items = append(items, map[string]interface{}{
					"Name":      name,
					"UsageData": map[string]interface{}{"RefCount": 0},
				})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"Volumes": items})

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/volumes/"):
			name := r.URL.Path[len("/volumes/"):]
			name, _ = url.PathUnescape(name)
			deletedVols[name]++
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, deletedVols
}

// ─── RED TEST：复现 Bug ────────────────────────────────────────────────────────

// TestBug_UserVolumeDisappearsAfterCleanup 是专用于复现 Bug 的红色测试。
//
// 场景：bob 执行 docker volume create bob-vol。
//   - 代理内部将其命名为 user-1002-volume-bob-vol 并写入 DB。
//   - 此时 volume 未被任何容器挂载（RefCount=0，即 Docker 认为是 dangling）。
//   - 清理协程执行后：
//       修复前 → volume 被删除，docker volume ls 中消失（此测试断言失败，BUG 复现）。
//       修复后 → volume 仍在 DB 中，docker volume ls 正常显示（此测试通过）。
func TestBug_UserVolumeDisappearsAfterCleanup(t *testing.T) {
	const (
		bobUID             = 1002
		bobUsername        = "bob"
		internalVolName    = "user-1002-volume-bob-vol" // proxy 注入前缀后的内部名称
	)

	// 1. 准备 DB：模拟 bob 成功创建了 bob-vol，proxy 将归属写入 DB。
	db := newCleanupTestDB(t)
	registerVolumeOwner(t, db, internalVolName, bobUID, bobUsername)

	// 2. 启动 mock Docker daemon：bob 的 volume 出现在 dangling 列表中（RefCount=0，未挂载）。
	srv, deletedVols := mockDockerServer(t, []string{internalVolName})

	// 3. 触发清理（模拟定时协程执行一次）。
	mgr := newMockStorageManager(srv)
	mgr.runCleanup(context.Background(), db, zap.NewNop(), nil)

	// 4. 断言：bob 的 volume 不应被删除，DB 中归属记录应仍存在。
	//
	//    修复前此断言会失败，错误信息清楚说明了 Bug 的表现：
	//    volume 被意外从 DB 中删除，导致 FilterVolumeListResponse 无法展示给用户。
	if !volumeExistsInDB(t, db, internalVolName, bobUID) {
		t.Errorf(
			"[BUG REPRODUCED] volume %q 被清理协程从 DB 中删除！\n"+
				"  触发条件：bob 创建的 volume 未挂载（RefCount=0）时清理协程执行\n"+
				"  预期行为：DB 中有归属记录的 volume 应保留，不论是否被容器挂载\n"+
				"  实际行为：volume 被误判为孤立 volume 并删除（DELETE 调用 %d 次）\n"+
				"  修复方向：runCleanup 删除前需先查 DB，跳过有归属记录的 volume",
			internalVolName,
			deletedVols[internalVolName],
		)
	}
}

// ─── 回归测试矩阵 ─────────────────────────────────────────────────────────────

// TestCleanup_Regression_SkipsNonUserPrefixVolumes 验证核心过滤逻辑：
// 不符合 user-{digits}-volume-* 命名规范的悬空 volume 一律不处理，
// 防止修改 isUserVolumePrefix() 时引入越界删除。
func TestCleanup_Regression_SkipsNonUserPrefixVolumes(t *testing.T) {
	dangling := []string{
		"anonymous-abc123",      // 无前缀
		"myapp_data",            // 应用命名
		"usr-1001-volume-oops",  // 拼写错误（usr 非 user）
		"user-abc-volume-x",     // uid 非数字
	}

	db := newCleanupTestDB(t)
	srv, deletedVols := mockDockerServer(t, dangling)

	mgr := newMockStorageManager(srv)
	mgr.runCleanup(context.Background(), db, zap.NewNop(), nil)

	if len(deletedVols) != 0 {
		t.Errorf(
			"不符合用户 volume 命名规范的悬空 volume 不应被删除，\n"+
				"但以下 volume 遭到了删除：%v\n"+
				"检查 isUserVolumePrefix() 的匹配逻辑是否被意外放宽",
			deletedVols,
		)
	}
}

// TestCleanup_Regression_DeletesTrulyOrphanedVolume 验证孤立 volume 正常清理能力不退化：
// 有用户前缀、但 DB 中无归属记录的 volume（真正的孤立 volume）应被删除。
//
// 场景：某容器运行时自动创建了匿名 volume，容器已删除但 volume 未清理，
//       且 proxy 未向 DB 写入归属（例如容器由 root 直接创建绕过 proxy）。
//       修复后此类 volume 仍应被清理。
func TestCleanup_Regression_DeletesTrulyOrphanedVolume(t *testing.T) {
	const orphanVol = "user-1001-volume-orphan-lefover"
	// 关键：不向 DB 注册，模拟 DB 中无归属记录的孤立 volume

	db := newCleanupTestDB(t)
	srv, deletedVols := mockDockerServer(t, []string{orphanVol})

	mgr := newMockStorageManager(srv)
	mgr.runCleanup(context.Background(), db, zap.NewNop(), nil)

	if deletedVols[orphanVol] != 1 {
		t.Errorf(
			"DB 中无归属记录的孤立 volume %q 应被删除（期望 DELETE 调用 1 次），\n"+
				"实际调用 %d 次。\n"+
				"修复后，runCleanup 应仍能清理真正的孤立 volume，不应因修复而退化",
			orphanVol, deletedVols[orphanVol],
		)
	}
}

// TestCleanup_Regression_MultiUser_OnlyOrphanDeleted 多用户混合场景下的隔离验证：
// alice 和 bob 各有已注册的 volume（未挂载），同时存在一个孤立 volume。
// 期望：只有孤立 volume 被删除，alice/bob 的 volume 完全不受影响。
//
// 此测试在 Bug 修复前会失败（alice/bob volume 均被误删）。
func TestCleanup_Regression_MultiUser_OnlyOrphanDeleted(t *testing.T) {
	const (
		aliceUID = 1001
		bobUID   = 1002
	)

	aliceVol  := "user-1001-volume-project-data"
	bobVol    := "user-1002-volume-mydata"
	orphanVol := "user-9999-volume-leftover"

	db := newCleanupTestDB(t)
	registerVolumeOwner(t, db, aliceVol, aliceUID, "alice")
	registerVolumeOwner(t, db, bobVol, bobUID, "bob")
	// orphanVol 不注册，模拟真正孤立

	// 所有 volume 都是 dangling（RefCount=0）
	srv, deletedVols := mockDockerServer(t, []string{aliceVol, bobVol, orphanVol})

	mgr := newMockStorageManager(srv)
	mgr.runCleanup(context.Background(), db, zap.NewNop(), nil)

	// alice 的 volume 不应被删
	if !volumeExistsInDB(t, db, aliceVol, aliceUID) {
		t.Errorf(
			"alice 的 volume %q 被意外删除（DELETE 调用 %d 次）\n"+
				"有归属记录的 volume 不应被清理协程删除，无论是否被容器挂载",
			aliceVol, deletedVols[aliceVol],
		)
	}

	// bob 的 volume 不应被删
	if !volumeExistsInDB(t, db, bobVol, bobUID) {
		t.Errorf(
			"bob 的 volume %q 被意外删除（DELETE 调用 %d 次）\n"+
				"有归属记录的 volume 不应被清理协程删除，无论是否被容器挂载",
			bobVol, deletedVols[bobVol],
		)
	}

	// 孤立 volume 应被删
	if deletedVols[orphanVol] != 1 {
		t.Errorf(
			"孤立 volume %q（DB 无归属）应被删除，期望 DELETE 调用 1 次，实际 %d 次",
			orphanVol, deletedVols[orphanVol],
		)
	}

	// 总删除数量恰好为 1（只删孤立的）
	if n := len(deletedVols); n != 1 {
		t.Errorf("期望只删除 1 个孤立 volume，实际删除了 %d 个：%v", n, deletedVols)
	}
}

// TestCleanup_Regression_EmptyDanglingList_NoSideEffect 边界条件：
// Docker 返回空悬空列表时，清理协程不发出任何 DELETE 请求，
// DB 中已注册的 volume 完整保留。
func TestCleanup_Regression_EmptyDanglingList_NoSideEffect(t *testing.T) {
	db := newCleanupTestDB(t)
	registerVolumeOwner(t, db, "user-1001-volume-safe", 1001, "alice")

	srv, deletedVols := mockDockerServer(t, []string{} /* 无悬空 volume */)

	mgr := newMockStorageManager(srv)
	mgr.runCleanup(context.Background(), db, zap.NewNop(), nil)

	if len(deletedVols) != 0 {
		t.Errorf(
			"悬空列表为空时不应触发任何 DELETE，但调用了 %d 次：%v",
			len(deletedVols), deletedVols,
		)
	}

	if !volumeExistsInDB(t, db, "user-1001-volume-safe", 1001) {
		t.Error("悬空列表为空时，DB 中注册的 volume 不应被删除")
	}
}
