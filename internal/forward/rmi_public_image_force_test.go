// rmi_public_image_force_test.go
//
// [BUG-5] root 无法使用 -f 强制删除有其他用户引用的公共镜像
//
// 根本原因（proxy.go checkImageRemovePermission, 约 1349-1370 行）：
//
//	isOwner := id.IsPrivileged() || owner.UID == id.RealUID
//	if isOwner && isPublic {
//	    refCount, _ := p.db.GetImageRefCount(resolvedID)
//	    if refCount > 1 {
//	        writeDockerError(w, 409, "image '...' is still referenced by N other user(s)...")
//	        return false           // ← 此处直接 return，从不检查 ?force=1
//	    }
//	}
//
// Docker 客户端 `docker rmi -f <id>` 发送 DELETE /images/<id>?force=1，
// 但代理从未读取 r.URL.Query().Get("force")，导致 root 即使传 -f 也被 409 阻断。
//
// 修复方向：在进入引用计数检查前，当 id.IsPrivileged() && forceDelete 时跳过该检查。
//
// ── ID 说明 ──────────────────────────────────────────────────────────────────
//
// 生产流程中：
//   - Docker 以完整 64-char hex（不含 sha256: 前缀）存储镜像 ID
//   - resolveImageIDByRef(shortRef) 向 Docker 发 GET /images/{shortRef}/json，
//     得到 {"Id":"sha256:<fullID>"}
//   - GetImageOwner / GetImageRefCount 对该 fullID 调用 normalizeImageID（去掉 sha256: 前缀），
//     然后精确匹配 DB 中的 fullID
//
// 因此测试中必须用完整 64-char hex（bug5ImageFullHex）写入 DB，
// 而非 12-char 短 ID；否则 normalizeImageID 后的精确匹配会失败，
// 导致 refCount = 0（查不到），测试为"错误的绿"。
//
// 测试结构：
//
//	Red Test       — Bug 未修复时必定失败，修复后变绿。
//	Regression Suite (4 cases) — 覆盖正常路径与边界，防止修复引入新回归。

package forward

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"docker-authz-proxy/internal/auth"
)

// ─────────────────────────────────────────────────────────────────────────────
// 测试常量
// ─────────────────────────────────────────────────────────────────────────────

const (
	// bug5ShortRef  ： docker rmi 命令使用的短 ID（与 Bug 报告一致），仅用于 URL path
	bug5ShortRef = "3cb067eab609"

	// bug5ImageFullHex ：DB 中存储的完整 64-char hex（不含 sha256: 前缀），
	// 对应生产中 Docker 分配的真实 image ID。
	// 前 12 位与 bug5ShortRef 相同，确保 resolveImageIDByRef 的上游返回
	// "sha256:" + bug5ImageFullHex，经 normalizeImageID 后精确匹配 DB 中的记录。
	bug5ImageFullHex = "3cb067eab609abcdef0000000000000000000000000000000000000000000001"

	// bug5ImageFullID ：fake upstream 返回的完整 sha256 字符串
	bug5ImageFullID = "sha256:" + bug5ImageFullHex
)

// ─────────────────────────────────────────────────────────────────────────────
// 测试辅助
// ─────────────────────────────────────────────────────────────────────────────

// newBug5Upstream 构造可同时处理"镜像 inspect"与"镜像删除"两类请求的假上游：
//
//   - GET  /images/*/json        → 返回完整 image inspect JSON（供 resolveImageIDByRef 使用）
//   - DELETE /images/*[?force=1] → 返回删除成功 JSON（物理删除路径）
func newBug5Upstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/json"):
			// GET /images/<ref>/json — image inspect，返回完整 sha256 ID
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"Id":%q,"RepoTags":[],"Size":1024}`, bug5ImageFullID)
		case r.Method == http.MethodDelete:
			// DELETE /images/<ref>[?force=1] — image remove
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `[{"Deleted":%q}]`, bug5ImageFullID)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"message":"not found: %s %s"}`, r.Method, r.URL.Path)
		}
	}))
}

// setupBug5Scene 在 DB 中建立完整的公共镜像引用场景，返回已配置的 ProxyServer：
//
//	root（UID=0） → 属主（is_public=true），同时持有 image_access 引用（refCount 计 1）
//	bob（UID=1002） → 曾拉取过该镜像，持有 image_access 引用（refCount 计 2）
//
// 关键：DB 键使用完整 64-char hex（bug5ImageFullHex），与 normalizeImageID 后一致。
func setupBug5Scene(t *testing.T) *ProxyServer {
	t.Helper()
	upstream := newBug5Upstream(t)
	t.Cleanup(upstream.Close)

	p := newTestProxy(t, upstream, nil)

	rootIdentity := &auth.CallerIdentity{
		RealUID:      0,
		RealUsername: "root",
		RealGID:      0,
		UserType:     auth.UserTypeRoot,
	}
	// SetImageOwner：存入 images 表（key = bug5ImageFullHex）+ image_access(fullHex, 0)
	if err := p.db.SetImageOwner(bug5ImageFullHex, rootIdentity, true /*isPublic*/, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}
	// bob 拉取过该镜像，产生第二条 image_access 引用
	if err := p.db.EnsureImageAccess(bug5ImageFullHex, 1002); err != nil {
		t.Fatalf("EnsureImageAccess(bob, 1002): %v", err)
	}

	// 前置条件自检：引用计数必须 == 2（root + bob）
	refCount, err := p.db.GetImageRefCount(bug5ImageFullHex)
	if err != nil {
		t.Fatalf("GetImageRefCount: %v", err)
	}
	if refCount != 2 {
		t.Fatalf("场景初始化失败：refCount=%d（期望 2 = root + bob）", refCount)
	}
	return p
}

// ─────────────────────────────────────────────────────────────────────────────
// [BUG-5] Red Test
// ─────────────────────────────────────────────────────────────────────────────

// TestBug5_Root_ForceDelete_PublicImage_WithOtherRefs_ShouldSucceed
//
// 场景：root 执行 docker rmi -f 3cb067eab609
//
//	公共镜像（root 属主），bob 还有 image_access 引用（refCount=2）
//
// 期望（修复后）：HTTP 200 OK，镜像被物理删除，-f 跳过引用计数检查
// 实际（Bug）：HTTP 409 Conflict
//
//	"image '3cb067eab609' is still referenced by 1 other user(s);
//	 cannot delete until all references are removed"
//
// 此测试在 Bug 未修复时必定失败（t.Errorf），修复后变绿。
func TestBug5_Root_ForceDelete_PublicImage_WithOtherRefs_ShouldSucceed(t *testing.T) {
	p := setupBug5Scene(t)

	// root 发送 docker rmi -f 3cb067eab609
	req := httptest.NewRequest(http.MethodDelete,
		"/images/"+bug5ShortRef+"?force=1", nil)
	req = injectIdentity(req, makeTestIdentityProxy("root", 0))

	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	// ── 断言 ─────────────────────────────────────────────────────────────────
	if rw.Code != http.StatusOK {
		t.Errorf("[BUG-5 RED TEST FAIL] root -f rmi 公共镜像（有其他用户引用）:\n"+
			"  got  HTTP %d: %s\n"+
			"  want HTTP 200\n\n"+
			"根本原因：checkImageRemovePermission（proxy.go ~1351）\n"+
			"  isOwner && isPublic 分支直接 return false（409），从未读取 ?force=1 参数。\n"+
			"修复方向：在 refCount>1 检查前，若 id.IsPrivileged() && r.URL.Query().Get(\"force\")==\"1\" 则跳过。",
			rw.Code, strings.TrimSpace(rw.Body.String()))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// [BUG-5] Regression Suite
// ─────────────────────────────────────────────────────────────────────────────

// TestBug5_Reg1_Root_NoForce_PublicImage_WithOtherRefs_Returns409
//
// 回归：root 不带 -f 删除有其他引用的公共镜像 → 仍应被 409 阻止。
// 防止修复时把保护逻辑一并删掉，导致无 -f 也能删除（破坏多用户隔离保证）。
func TestBug5_Reg1_Root_NoForce_PublicImage_WithOtherRefs_Returns409(t *testing.T) {
	p := setupBug5Scene(t)

	req := httptest.NewRequest(http.MethodDelete,
		"/images/"+bug5ShortRef, nil) // 无 ?force=1
	req = injectIdentity(req, makeTestIdentityProxy("root", 0))

	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusConflict {
		t.Errorf("[BUG-5 Reg1] root 不带 -f rmi 有引用的公共镜像:\n"+
			"  got  HTTP %d: %s\n"+
			"  want HTTP 409 Conflict（保护：bob 仍在引用，不允许无感知删除）",
			rw.Code, strings.TrimSpace(rw.Body.String()))
	}
	if !strings.Contains(rw.Body.String(), "referenced") {
		t.Errorf("[BUG-5 Reg1] 响应体应包含 'referenced'，实际: %s", rw.Body.String())
	}
}

// TestBug5_Reg2_NonOwner_NoAccess_Delete_PublicImage_Returns403
//
// 回归：charlie 对 root 的公共镜像没有 image_access，尝试 rmi → 403 Forbidden。
// 防止修复时破坏非属主权限检查逻辑（proxy.go ~1278-1337）。
func TestBug5_Reg2_NonOwner_NoAccess_Delete_PublicImage_Returns403(t *testing.T) {
	upstream := newBug5Upstream(t)
	defer upstream.Close()
	p := newTestProxy(t, upstream, nil)

	// 仅 root 持有该公共镜像，charlie（UID=1003）无任何 image_access
	rootIdentity := &auth.CallerIdentity{
		RealUID: 0, RealUsername: "root", UserType: auth.UserTypeRoot,
	}
	if err := p.db.SetImageOwner(bug5ImageFullHex, rootIdentity, true, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}
	// 不为 charlie 调用 EnsureImageAccess

	req := httptest.NewRequest(http.MethodDelete,
		"/images/"+bug5ShortRef, nil)
	req = injectIdentity(req, makeTestIdentityProxy("charlie", 1003))

	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusForbidden {
		t.Errorf("[BUG-5 Reg2] charlie（无 image_access）rmi root 的公共镜像:\n"+
			"  got  HTTP %d: %s\n"+
			"  want HTTP 403 Forbidden",
			rw.Code, strings.TrimSpace(rw.Body.String()))
	}
	body := rw.Body.String()
	if !strings.Contains(body, "public") || !strings.Contains(body, "owner") {
		t.Errorf("[BUG-5 Reg2] 403 响应体应同时包含 'public' 和 'owner'，实际: %s", body)
	}
}

// TestBug5_Reg3_NonOwner_WithAccess_VirtualDelete_Returns200
//
// 回归：bob 持有 root 公共镜像的 image_access，执行 rmi → 虚拟删除，返回 200。
// 虚拟删除不物理删除镜像，只解除 bob 的引用；属主记录不受影响。
// 防止修复 -f 逻辑时意外破坏虚拟删除路径（proxy.go ~1305-1327）。
func TestBug5_Reg3_NonOwner_WithAccess_VirtualDelete_Returns200(t *testing.T) {
	p := setupBug5Scene(t) // root 属主，bob(1002) 有 image_access

	req := httptest.NewRequest(http.MethodDelete,
		"/images/"+bug5ShortRef, nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", 1002))

	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("[BUG-5 Reg3] bob（有 image_access）rmi root 公共镜像（应虚拟删除）:\n"+
			"  got  HTTP %d: %s\n"+
			"  want HTTP 200（虚拟删除：仅移除 bob 的 image_access 引用）",
			rw.Code, strings.TrimSpace(rw.Body.String()))
	}

	// bob 的 image_access 应已解除
	hasAccess, err := p.db.HasUserImageAccess(bug5ImageFullHex, 1002)
	if err != nil {
		t.Fatalf("HasUserImageAccess: %v", err)
	}
	if hasAccess {
		t.Errorf("[BUG-5 Reg3] 虚拟删除后 bob 的 image_access 应已解除，但记录仍存在")
	}

	// 公共镜像本体不应被删（root 仍是属主）
	_, _, found := p.db.GetImageOwner(bug5ImageFullHex)
	if !found {
		t.Errorf("[BUG-5 Reg3] 虚拟删除不应从 DB 删除公共镜像所有权记录（root 仍是属主）")
	}
}

// TestBug5_Reg5_Root_ForceTrue_PublicImage_WithOtherRefs_ShouldSucceed
//
// 回归：root 通过 Go SDK 发送 ?force=true（strconv.FormatBool 编码）强制删除 → 200。
// 确保 force=true 与 force=1 均被识别，防止 SDK 用户被误拦截（Review Issue A）。
func TestBug5_Reg5_Root_ForceTrue_PublicImage_WithOtherRefs_ShouldSucceed(t *testing.T) {
	p := setupBug5Scene(t)

	req := httptest.NewRequest(http.MethodDelete,
		"/images/"+bug5ShortRef+"?force=true", nil) // Go SDK 发送的格式
	req = injectIdentity(req, makeTestIdentityProxy("root", 0))

	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("[BUG-5 Reg5] root ?force=true rmi 公共镜像（有其他用户引用）:\n"+
			"  got  HTTP %d: %s\n"+
			"  want HTTP 200（Go SDK 使用 force=true，应与 force=1 等价）",
			rw.Code, strings.TrimSpace(rw.Body.String()))
	}
}

// TestBug5_Reg4_Root_NoForce_PublicImage_NoOtherRefs_Returns200
//
// 回归：root 不带 -f，公共镜像无其他用户引用（refCount==1，只有 root 自己）→ 200。
// 确保边界条件 refCount==1 时正确放行（> 1 判断不影响 == 1 的情况）。
func TestBug5_Reg4_Root_NoForce_PublicImage_NoOtherRefs_Returns200(t *testing.T) {
	upstream := newBug5Upstream(t)
	defer upstream.Close()
	p := newTestProxy(t, upstream, nil)

	// 仅 root 持有（refCount == 1）
	rootIdentity := &auth.CallerIdentity{
		RealUID: 0, RealUsername: "root", UserType: auth.UserTypeRoot,
	}
	if err := p.db.SetImageOwner(bug5ImageFullHex, rootIdentity, true, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	// 前置条件自检
	refCount, _ := p.db.GetImageRefCount(bug5ImageFullHex)
	if refCount != 1 {
		t.Fatalf("前置条件失败：refCount=%d（期望 1，仅 root）", refCount)
	}

	req := httptest.NewRequest(http.MethodDelete,
		"/images/"+bug5ShortRef, nil) // 无 ?force=1
	req = injectIdentity(req, makeTestIdentityProxy("root", 0))

	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("[BUG-5 Reg4] root 不带 -f rmi 无其他引用的公共镜像:\n"+
			"  got  HTTP %d: %s\n"+
			"  want HTTP 200（refCount==1，只有 root 自己引用，边界条件：> 1 不成立）",
			rw.Code, strings.TrimSpace(rw.Body.String()))
	}
}
