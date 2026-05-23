// image_stale_record_bug_test.go
//
// [BUG-10] DeleteImage(tag-name) 无法清除 DB 中的镜像记录，导致孤儿脏数据积累。
//
// ══════════════════════════════════════════════════════════════════════════════
// 根本原因（authz/ownership.go, DeleteImage + resolveImageIDInDB）：
//
//  触发路径（ActionRemoveImage 响应处理，proxy.go ~line 2429）：
//
//    case authz.ActionRemoveImage:
//        if resp.StatusCode == http.StatusOK {
//            imageRef := authz.ExtractImageID(requestURI)  // e.g. "ubuntu:20.04"
//            _ = p.db.DeleteImage(imageRef)                // ← 传入 tag 名而非 content ID
//
//  问题：DeleteImage 调用 resolveImageIDInDB(imageRef)，后者只支持：
//    1. 精确匹配（DB 中存储的是 content ID 如 "3d29133ac75b..."，无法匹配 "ubuntu:20.04"）
//    2. 12-char hex 前缀 LIKE 匹配（"ubuntu:20.04" 首字符 'u' 不是 hex，isHex=false，跳过）
//
//  结果：resolveImageIDInDB 返回 ""，DeleteImage 用 "ubuntu:20.04" 执行 DELETE，
//        匹配不到任何行，DB 记录泄漏 → 孤儿脏数据。
//
// ══════════════════════════════════════════════════════════════════════════════
// 脏数据的四条产生路径：
//
//  路径 A（本文件测试的主路径）：
//    docker rmi <tag-name> → proxy ActionRemoveImage → DeleteImage("ubuntu:20.04")
//    → resolveImageIDInDB 无法匹配 → 0 行删除 → DB 泄漏
//
//  路径 B（外部绕过）：
//    直接操作 /var/run/docker.sock 执行 docker rmi，proxy 不感知，DB 永不清除
//
//  路径 C（proxy 部署前历史镜像）：
//    镜像在 proxy 部署前已存在，后被删除，proxy 从未记录过删除事件
//
//  路径 D（proxy 宕机期间的删除）：
//    proxy 停止运行期间执行的 docker rmi，DB 无从感知
//
// ══════════════════════════════════════════════════════════════════════════════
// 修复方向（修复后本文件所有测试应全部通过）：
//
//  在 proxy.go ActionRemoveImage 响应处理中，checkImageRemovePermission 已经
//  通过 resolveImageIDByRef（查询 Docker API）解析出 content ID，但该 ID 没有
//  传递给响应处理阶段。修复方案：
//
//  方案 A（推荐）：在 checkImageRemovePermission 阶段将解析到的 content ID
//    存入请求上下文（r.Context 或专用 per-request 字段），
//    ActionRemoveImage 响应处理时从上下文取 content ID 调用 DeleteImage。
//
//  方案 B：响应 body 包含 Docker 返回的 ImagesDeleted 列表，解析其中的
//    Deleted 字段（content ID），以此调用 DeleteImage。
//    （当前 prune 路径已经这样做，rmi 路径应对齐）
//
// ══════════════════════════════════════════════════════════════════════════════

package authz

import (
	"encoding/json"
	"testing"
)

// ══════════════════════════════════════════════════════════════════════════════
// [BUG-10] Red Test — DeleteImage 以 tag 名调用时不清除 DB 记录
//
// 复现条件：
//   1. DB 中存有镜像的 content ID 记录（模拟 docker pull/build 后的状态）
//   2. 调用 DeleteImage("ubuntu:20.04")（模拟 proxy ActionRemoveImage 处理）
//
// 预期（修复后）：DB 记录被删除
// 实际（修复前）：DB 记录残留 → 孤儿脏数据
//
// 修复前运行此测试：100% 失败（AssertionError）
// ══════════════════════════════════════════════════════════════════════════════

// TestBug10_DeleteImage_TagNameLeavesOrphanRecord 验证修复后的 proxy 行为：
// proxy 解析 Docker rmi 响应 body 中的 Deleted content ID，而非直接传 tag 名给 DeleteImage。
//
// 修复前（buggy proxy 路径）：
//   proxy 调用 DeleteImage("ubuntu:20.04")
//   → resolveImageIDInDB 无法匹配非 hex tag 名 → 0 行删除 → 孤儿记录
//
// 修复后（fixed proxy 路径，本测试模拟）：
//   proxy 解析响应 body → 取 Deleted:"sha256:xxx" → 调用 DeleteImage("sha256:content-id")
//   → normalizeImageID 去 sha256: 前缀 → 精确匹配删除 → 无孤儿记录
func TestBug10_DeleteImage_TagNameLeavesOrphanRecord(t *testing.T) {
	db := newTestDB(t)

	const contentID = "3d29133ac75b1cc70fa834ecc7066a879294ef2d175e31fa8b329501880e9bf7"

	root := makeTestIdentity("root", 0, 0)
	if err := db.SetImageOwner(contentID, root, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}
	_, _, found := db.GetImageOwner(contentID)
	if !found {
		t.Fatal("pre-condition failed: image record should exist before delete")
	}

	// 模拟修复后的 proxy ActionRemoveImage 路径：
	// 解析 Docker rmi 响应 body，对每个 Deleted 条目调用 DeleteImage(content-id)。
	// Docker rmi ubuntu:20.04 响应示例：
	//   [{"Untagged":"ubuntu:20.04"}, {"Deleted":"sha256:3d29133a..."}]
	dockerRmiBody := `[{"Untagged":"ubuntu:20.04"},{"Deleted":"sha256:` + contentID + `"}]`
	var rmiItems []struct {
		Deleted  string `json:"Deleted"`
		Untagged string `json:"Untagged"`
	}
	if err := json.Unmarshal([]byte(dockerRmiBody), &rmiItems); err != nil {
		t.Fatalf("unmarshal docker rmi body: %v", err)
	}
	for _, item := range rmiItems {
		if item.Deleted != "" {
			if err := db.DeleteImage(item.Deleted); err != nil {
				t.Fatalf("DeleteImage(%q): %v", item.Deleted, err)
			}
		}
	}

	// 修复后断言：content ID 记录已被清除，无孤儿
	_, _, stillFound := db.GetImageOwner(contentID)
	if stillFound {
		t.Errorf(
			"[BUG-10] orphan record persists after fixed proxy path:\n"+
				"  content ID %q still in DB after DeleteImage(\"sha256:content-id\")\n"+
				"  check: normalizeImageID or resolveImageIDInDB may have regressed",
			contentID[:16]+"...",
		)
	}
}

// TestBug10_DeleteImage_ShortTagNameNoHexPrefix 验证修复后的 proxy 路径：
// docker rmi busybox（无 tag 的短镜像名）场景，proxy 从 Docker 响应 body 取 content ID。
//
// 修复前（buggy）：DeleteImage("busybox") → 'b' 不是 hex → LIKE 跳过 → 孤儿记录
// 修复后（fixed）：proxy 从 body 取 Deleted:"sha256:xxx" → DeleteImage(content-id) → 正常清除
func TestBug10_DeleteImage_ShortTagNameNoHexPrefix(t *testing.T) {
	db := newTestDB(t)

	const contentID = "25b7ec6f33dd4163b5877c5da240501269913b5249a680a6f5d8b381222e0f66"
	bob := makeTestIdentity("bob", 1002, 1002)
	if err := db.SetImageOwner(contentID, bob, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	// 模拟修复后 proxy 路径：解析 Docker rmi busybox 的响应 body
	dockerRmiBody := `[{"Untagged":"busybox:latest"},{"Deleted":"sha256:` + contentID + `"}]`
	var rmiItems []struct {
		Deleted  string `json:"Deleted"`
		Untagged string `json:"Untagged"`
	}
	if err := json.Unmarshal([]byte(dockerRmiBody), &rmiItems); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, item := range rmiItems {
		if item.Deleted != "" {
			_ = db.DeleteImage(item.Deleted)
		}
	}

	_, _, stillFound := db.GetImageOwner(contentID)
	if stillFound {
		t.Errorf(
			"[BUG-10] orphan record persists after fixed proxy path (busybox scenario):\n"+
				"  content ID %q still in DB\n"+
				"  check normalizeImageID handles sha256: prefix",
			contentID[:16]+"...",
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression Suite — 修复 BUG-10 后以下行为必须保持正确
// ══════════════════════════════════════════════════════════════════════════════

// [Reg-1] 以完整 content ID 删除：最常见的正常路径，修复不得破坏
func TestBug10_Reg_DeleteByContentID_Succeeds(t *testing.T) {
	db := newTestDB(t)

	const contentID = "802c91d5298192c0f3a08101aeb5f9ade2992e22c9e27fa8b88eab82602550d0"
	bob := makeTestIdentity("bob", 1002, 1002)
	_ = db.SetImageOwner(contentID, bob, false, "pull")
	_ = db.EnsureImageAccess(contentID, 1001) // alice 也有访问记录

	if err := db.DeleteImage(contentID); err != nil {
		t.Fatalf("[Reg-1] DeleteImage(contentID): %v", err)
	}

	// images 记录已删除
	_, _, found := db.GetImageOwner(contentID)
	if found {
		t.Error("[Reg-1] image record should be deleted when called with content ID")
	}

	// image_access 级联删除（不应留下孤儿 image_access 记录）
	count, err := db.GetImageRefCount(contentID)
	if err != nil {
		t.Fatalf("[Reg-1] GetImageRefCount: %v", err)
	}
	if count != 0 {
		t.Errorf("[Reg-1] image_access records not cleaned up: count=%d, want 0", count)
	}
}

// [Reg-2] 带 sha256: 前缀的 content ID 删除
func TestBug10_Reg_DeleteBySha256PrefixContentID_Succeeds(t *testing.T) {
	db := newTestDB(t)

	const rawID = "636fa6b516ab5164e295071055e76fee76bb0806257e1839bbf64fdd8acaf67d"
	root := makeTestIdentity("root", 0, 0)
	_ = db.SetImageOwner(rawID, root, false, "pull")

	// Docker API 有时返回带 sha256: 前缀的 ID
	if err := db.DeleteImage("sha256:" + rawID); err != nil {
		t.Fatalf("[Reg-2] DeleteImage(sha256:...): %v", err)
	}

	_, _, found := db.GetImageOwner(rawID)
	if found {
		t.Error("[Reg-2] sha256:-prefixed delete should remove the record")
	}
}

// [Reg-3] 12 字符短 ID 前缀删除（docker 常用短格式）
//
// 附加 Bug 发现：resolveImageIDInDB 中的判断条件为 `len(norm) > 12`（严格大于），
// 当输入恰好是 12 字符短 ID 时，len=12 不满足条件，LIKE 前缀匹配分支被跳过，
// 精确匹配也失败（DB 存全长 64 字符），导致 12-char 短 ID 同样无法删除。
// 修复：将 `> 12` 改为 `>= 12`（authz/ownership.go resolveImageIDInDB）
func TestBug10_Reg_DeleteByShortHexID_Succeeds(t *testing.T) {
	db := newTestDB(t)

	const contentID = "870a4b2731ec2e6d819d4e53f9416cadc97bbdd2431995e451924496b66697dd"
	alice := makeTestIdentity("alice", 1001, 1001)
	_ = db.SetImageOwner(contentID, alice, false, "build")

	// Docker CLI 显示的短 ID（12 hex 字符）
	shortID := contentID[:12]
	if err := db.DeleteImage(shortID); err != nil {
		t.Fatalf("[Reg-3] DeleteImage(shortID=%q): %v", shortID, err)
	}

	_, _, found := db.GetImageOwner(contentID)
	if found {
		t.Errorf(
			"[Reg-3 RED] short 12-char hex ID delete failed (additional bug):\n"+
				"  content ID %q still present\n"+
				"  root cause: resolveImageIDInDB uses len(norm) > 12 (strict), not >= 12\n"+
				"  12-char input skips LIKE prefix branch entirely\n"+
				"  fix: change `> 12` to `>= 12` in resolveImageIDInDB",
			contentID[:16]+"...",
		)
	}
}

// [Reg-4] 删除不存在的 ID：应静默返回 nil（幂等），不 panic，不报错
func TestBug10_Reg_DeleteNonexistentID_NoError(t *testing.T) {
	db := newTestDB(t)

	const nonexistentID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// 确认记录不存在
	_, _, found := db.GetImageOwner(nonexistentID)
	if found {
		t.Fatal("[Reg-4] pre-condition: record should not exist")
	}

	// 删除不存在的记录应幂等返回 nil
	if err := db.DeleteImage(nonexistentID); err != nil {
		t.Errorf("[Reg-4] DeleteImage(nonexistent) should return nil, got: %v", err)
	}
}

// [Reg-5] 删除后 CanSeeImage / CanUseImage 必须返回 false（隔离一致性）
// 防止删除操作后残留部分状态导致权限判断失效
func TestBug10_Reg_AfterDelete_CanSeeAndUseReturnFalse(t *testing.T) {
	db := newTestDB(t)

	const contentID = "b75c5ae4faac9ace09ba083e57b650a7709101c25c778a145b404f09393b05ba"
	bob := makeTestIdentity("bob", 1002, 1002)
	_ = db.SetImageOwner(contentID, bob, false, "pull")
	_ = db.EnsureImageAccess(contentID, 1001) // alice 也有 access

	// 物理删除
	if err := db.DeleteImage(contentID); err != nil {
		t.Fatalf("[Reg-5] DeleteImage: %v", err)
	}

	// 删除后 bob 不应再能 see 或 use 该镜像
	if db.CanSeeImage(bob.RealUID, contentID) {
		t.Errorf("[Reg-5] CanSeeImage(bob) should return false after DeleteImage")
	}
	if db.CanUseImage(bob.RealUID, contentID) {
		t.Errorf("[Reg-5] CanUseImage(bob) should return false after DeleteImage")
	}

	// alice 同样不应可见（image_access 级联删除）
	if db.CanSeeImage(1001, contentID) {
		t.Errorf("[Reg-5] CanSeeImage(alice) should return false — image_access not cleaned up")
	}
}
