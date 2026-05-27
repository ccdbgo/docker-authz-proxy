package forward

// TestNetworkPrune_SudoContextNetwork_NotDeletedByNonSudo_regression
//
// BUG 描述：
//   普通用户（或 sudo 用户以非 sudo 方式运行）执行 docker network prune 时，
//   sudo 上下文（privileged_context=1）创建的网络也被删除。
//   而 container prune / volume prune 对 pc=1 资源正确跳过，行为不一致。
//
// 根本原因：
//   GetNetworkIDsByOwner 缺少 AND privileged_context = 0 过滤，
//   与 GetContainerIDsByOwner、GetVolumeNamesByOwner 行为不对齐。
//
// RED TEST（修复前必然失败）：
//   handleNetworkPrune 发出了 DELETE sudoNetID 的请求。
//
// 修复后（GREEN）：
//   GetNetworkIDsByOwner 只返回 privileged_context=0 的网络，
//   sudo 网络不出现在删除请求中。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"docker-authz-proxy/internal/auth"
)

func TestNetworkPrune_SudoContextNetwork_NotDeletedByNonSudo_regression(t *testing.T) {
	// 与 network_peer_test.go 中的 aliceUID/bobUID 不冲突，使用独立 UID
	const sudoTestUID = 1005

	// 使用 network_prune_test.go 未占用的 ID 段（CC 段）
	const (
		sudoContextNetID    = "cc10000000000000000000000000000000000000000000000000000000000001"
		regularContextNetID = "cc20000000000000000000000000000000000000000000000000000000000002"
	)

	var mu sync.Mutex
	var deletedNetIDs []string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/networks/") {
			id := strings.TrimPrefix(r.URL.Path, "/networks/")
			mu.Lock()
			deletedNetIDs = append(deletedNetIDs, id)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// sudo_test 以 sudo 方式创建的网络（privileged_context=1）
	sudoCallerID := &auth.CallerIdentity{
		RealUID:      sudoTestUID,
		RealUsername: "sudo_test",
		UserType:     auth.UserTypeSudo,
	}
	if err := p.db.SetNetworkOwner(sudoContextNetID, "sudo_test_u1005_sudo_net", sudoCallerID); err != nil {
		t.Fatalf("SetNetworkOwner(sudo): %v", err)
	}

	// sudo_test 以非 sudo 方式创建的网络（privileged_context=0）
	regularCallerID := &auth.CallerIdentity{
		RealUID:      sudoTestUID,
		RealUsername: "sudo_test",
		UserType:     auth.UserTypeRegular,
	}
	if err := p.db.SetNetworkOwner(regularContextNetID, "sudo_test_u1005_regular_net", regularCallerID); err != nil {
		t.Fatalf("SetNetworkOwner(regular): %v", err)
	}

	// sudo_test 以非 sudo 方式执行 network prune（退化为 Case 2：普通用户行为）
	req := httptest.NewRequest("POST", "/networks/prune", nil)
	req = injectIdentity(req, &auth.CallerIdentity{
		RealUID:           sudoTestUID,
		RealUsername:      "sudo_test",
		EffectiveUID:      sudoTestUID,
		EffectiveUsername: "sudo_test",
		UserType:          auth.UserTypeRegular,
		AuthSource:        auth.AuthSourceOS,
	})
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", rw.Code)
	}

	mu.Lock()
	got := make([]string, len(deletedNetIDs))
	copy(got, deletedNetIDs)
	mu.Unlock()

	// ── 断言 A：sudo 上下文网络不得被删除 ────────────────────────────────────
	// Bug 行为（修复前）：sudoContextNetID 出现在 got 中
	//   — GetNetworkIDsByOwner 无 privileged_context 过滤，返回全部网络
	// 修复后：sudoContextNetID 不出现
	//   — GetNetworkIDsByOwner 加上 AND privileged_context=0，行为与 container/volume prune 对齐
	for _, id := range got {
		if id == sudoContextNetID {
			t.Errorf("[A] FAIL (BUG REPRODUCED): sudo 上下文网络（%s）被非 sudo prune 删除。\n"+
				"与 container/volume prune 行为不一致：后者对 privileged_context=1 资源正确跳过。\n"+
				"根因：GetNetworkIDsByOwner 缺少 AND privileged_context=0 过滤。\n"+
				"所有 DELETE 请求：%v", sudoContextNetID, got)
		}
	}

	// ── 断言 B：非 sudo 上下文网络应被正常删除 ───────────────────────────────
	foundRegular := false
	for _, id := range got {
		if id == regularContextNetID {
			foundRegular = true
			break
		}
	}
	if !foundRegular {
		t.Errorf("[B] FAIL: 非 sudo 上下文网络（%s）未被删除，prune 应清除普通上下文资源。\n"+
			"所有 DELETE 请求：%v", regularContextNetID, got)
	}

	// ── 断言 C：DELETE 请求总数精确为 1（只删非 sudo 网络）────────────────────
	if len(got) != 1 {
		t.Errorf("[C] FAIL: want 1 DELETE 请求（仅非 sudo 网络），got %d：%v", len(got), got)
	}
}
