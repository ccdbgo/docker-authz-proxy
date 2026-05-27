package isolation

// TestContainerPS_SudoContextContainer_NotVisibleToNonSudo_regression
//
// BUG 描述：
//   sudo_test 以非 sudo 方式执行 docker ps -a 时，
//   sudo 上下文（LabelCallerType=sudo）创建的容器也出现在列表中。
//
// 根本原因：
//   FilterContainerListResponse 的 path② / path③ 仅做 UID/用户名匹配，
//   未检查 LabelCallerType，导致 sudo 上下文容器通过标签 fallback 路径泄漏。
//
// RED TEST（修复前必然失败）：
//   sudoContextContainerID 出现在过滤结果中。
//
// 修复后（GREEN）：
//   path② / path③ 前置 LabelCallerType=="sudo" 守卫，
//   sudo 上下文容器被排除，行为与 DB path①（AND privileged_context=0）对齐。

import (
	"encoding/json"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

func TestContainerPS_SudoContextContainer_NotVisibleToNonSudo_regression(t *testing.T) {
	const sudoTestUID = 1005
	const sudoTestUsername = "sudo_test"

	// 容器 ID（无需在 DB 中注册，依赖标签 fallback 路径复现 Bug）
	const (
		sudoContextContainerID    = "dd100000000000000000000000000000000000000000000000000000000001"
		regularContextContainerID = "dd200000000000000000000000000000000000000000000000000000000002"
		legacyContainerID         = "dd300000000000000000000000000000000000000000000000000000000003"
	)

	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// 只把非 sudo 上下文容器注册进 DB（privileged_context=0）
	regularCaller := &auth.CallerIdentity{
		RealUID:      sudoTestUID,
		RealUsername: sudoTestUsername,
		UserType:     auth.UserTypeRegular,
	}
	if err := db.SetContainerOwner(regularContextContainerID, regularCaller, ""); err != nil {
		t.Fatalf("SetContainerOwner(regular): %v", err)
	}

	// 构造上游 docker ps 响应，包含三个容器：
	//   1. sudoContextContainerID    — 无 DB 记录，标签含 LabelCallerType="sudo"
	//   2. regularContextContainerID — 有 DB 记录（privileged_context=0）
	//   3. legacyContainerID         — 无 DB 记录，标签无 LabelCallerType（遗留容器兜底场景）
	body := mustMarshalFilter(t, []map[string]interface{}{
		{
			"Id": sudoContextContainerID,
			"Labels": map[string]string{
				LabelOwnerUID:   "1005",
				LabelOwner:      sudoTestUsername,
				LabelCallerType: "sudo",
			},
		},
		{
			"Id":     regularContextContainerID,
			"Labels": nil,
		},
		{
			"Id": legacyContainerID,
			"Labels": map[string]string{
				LabelOwnerUID: "1005",
				LabelOwner:    sudoTestUsername,
				// 无 LabelCallerType：遗留容器，代理上线前已存在
			},
		},
	})

	filtered, err := FilterContainerListResponse(body, sudoTestUID, sudoTestUsername, false, db)
	if err != nil {
		t.Fatalf("FilterContainerListResponse: %v", err)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	seen := make(map[string]bool, len(result))
	for _, c := range result {
		if id, ok := c["Id"].(string); ok {
			seen[id] = true
		}
	}

	// ── 断言 A：sudo 上下文容器不得出现 ───────────────────────────────────
	// Bug 行为（修复前）：sudoContextContainerID 出现（path② UID 匹配通过）
	// 修复后：LabelCallerType=="sudo" 守卫在 path② 之前 continue，排除该容器
	if seen[sudoContextContainerID] {
		t.Errorf("[A] FAIL (BUG REPRODUCED): sudo 上下文容器（%s）对非 sudo 用户可见。\n"+
			"根因：path② / path③ 未检查 LabelCallerType，sudo 容器 UID 标签与非 sudo 相同导致泄漏。\n"+
			"结果集：%v", sudoContextContainerID, seen)
	}

	// ── 断言 B：非 sudo 上下文容器（DB path①）应出现 ─────────────────────
	if !seen[regularContextContainerID] {
		t.Errorf("[B] FAIL: 非 sudo 上下文容器（%s）未出现，DB path① 异常。结果集：%v",
			regularContextContainerID, seen)
	}

	// ── 断言 C：遗留容器（无 LabelCallerType）应通过 fallback 正常出现 ────
	// 确保修复没有破坏向后兼容（代理上线前已存在的容器仍可见）
	if !seen[legacyContainerID] {
		t.Errorf("[C] FAIL: 遗留容器（%s，无 LabelCallerType）未出现，向后兼容破坏。结果集：%v",
			legacyContainerID, seen)
	}

	// ── 断言 D：结果精确为 2 个容器 ──────────────────────────────────────
	if len(result) != 2 {
		t.Errorf("[D] FAIL: 预期 2 个容器（regular + legacy），got %d：%v", len(result), seen)
	}
}
