package forward

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/user"
	"strconv"
	"testing"

	"docker-authz-proxy/internal/auth"
)

// currentUserForPriv 解析当前进程用户（可 LookupUID）用于构造 privileged_users 名单。
func currentUserForPriv(t *testing.T) (username string, uid int) {
	t.Helper()
	cur, err := user.Current()
	if err != nil {
		t.Skipf("cannot resolve current user: %v", err)
	}
	u, err := strconv.Atoi(cur.Uid)
	if err != nil {
		t.Skipf("non-numeric uid %q: %v", cur.Uid, err)
	}
	return cur.Username, u
}

// twoContainersUpstream 返回两个容器：一个属别人、一个无标签孤儿。
func twoContainersUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	containers := []map[string]interface{}{
		{"Id": "cont-other-1", "Labels": map[string]string{}}, // 属另一用户
		{"Id": "cont-orphan-1", "Labels": map[string]string{}}, // 历史孤儿：无归属无标签
	}
	body, _ := json.Marshal(containers)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
}

// TestConfigPrivileged_SeesAllIncludingOrphan 命中 privileged_users 的普通用户（非 root/非 sudo）
// 经 proxy 应看到全部容器，含无归属的历史孤儿——正对历史管理员迁移诉求。
func TestConfigPrivileged_SeesAllIncludingOrphan(t *testing.T) {
	username, uid := currentUserForPriv(t)
	if uid == 0 {
		t.Skip("current user is root; test needs a non-root uid to prove config-priv (not root) path")
	}

	upstream := twoContainersUpstream(t)
	defer upstream.Close()

	policy := mustLoadPolicyYAML(t, ""+
		"version: 1\n"+
		"default_action: allow\n"+
		"privileged_users:\n"+
		"  users: ["+username+"]\n")
	p := newTestProxy(t, upstream, policy)

	// cont-other-1 归属另一个 uid；当前用户对它无归属
	other := &auth.CallerIdentity{RealUID: uid + 1000, RealUsername: "someone-else"}
	_ = p.db.SetContainerOwner("cont-other-1", other, "")

	req := httptest.NewRequest("GET", "/containers/json", nil)
	// 注入的身份 ConfigPrivileged 默认 false；ServeHTTP 会按 policy 重算
	req = injectIdentity(req, makeTestIdentityProxy(username, uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rw.Code)
	}
	var result []map[string]interface{}
	_ = json.Unmarshal(rw.Body.Bytes(), &result)
	if len(result) != 2 {
		t.Errorf("config-privileged user should see all 2 containers (incl orphan), got %d", len(result))
	}
}

// TestConfigPrivileged_NonListedUser_StillFiltered 未列入名单的普通用户仍被归属过滤——零回归。
func TestConfigPrivileged_NonListedUser_StillFiltered(t *testing.T) {
	username, uid := currentUserForPriv(t)

	upstream := twoContainersUpstream(t)
	defer upstream.Close()

	// 名单里放一个【不存在】的用户，确保当前用户不在名单
	policy := mustLoadPolicyYAML(t, ""+
		"version: 1\n"+
		"default_action: allow\n"+
		"privileged_users:\n"+
		"  users: [nosuchuser99999]\n")
	p := newTestProxy(t, upstream, policy)

	req := httptest.NewRequest("GET", "/containers/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy(username, uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rw.Code)
	}
	var result []map[string]interface{}
	_ = json.Unmarshal(rw.Body.Bytes(), &result)
	// 当前用户对两个容器都无归属 → 应看到 0 个（root 特例下会看到全部，故非 root 才断言）
	if uid != 0 && len(result) != 0 {
		t.Errorf("non-privileged user should see 0 owned containers, got %d", len(result))
	}
}

// TestConfigPrivileged_RevocationImmediate 撤销（重载移出名单）后，同一身份下一请求即回落隔离。
// 验证 ServeHTTP 用 = 每请求重算 ConfigPrivileged 的语义。
func TestConfigPrivileged_RevocationImmediate(t *testing.T) {
	username, uid := currentUserForPriv(t)
	if uid == 0 {
		t.Skip("current user is root; revocation test needs non-root uid")
	}

	upstream := twoContainersUpstream(t)
	defer upstream.Close()

	granted := mustLoadPolicyYAML(t, ""+
		"version: 1\n"+
		"default_action: allow\n"+
		"privileged_users:\n"+
		"  users: ["+username+"]\n")
	p := newTestProxy(t, upstream, granted)

	other := &auth.CallerIdentity{RealUID: uid + 1000, RealUsername: "someone-else"}
	_ = p.db.SetContainerOwner("cont-other-1", other, "")

	do := func() int {
		req := httptest.NewRequest("GET", "/containers/json", nil)
		req = injectIdentity(req, makeTestIdentityProxy(username, uid))
		rw := httptest.NewRecorder()
		p.ServeHTTP(rw, req)
		var result []map[string]interface{}
		_ = json.Unmarshal(rw.Body.Bytes(), &result)
		return len(result)
	}

	if n := do(); n != 2 {
		t.Fatalf("before revocation: should see all 2, got %d", n)
	}

	// 热重载为空名单（模拟 SIGHUP 后 UpdatePolicy）
	p.UpdatePolicy(mustLoadPolicyYAML(t, "version: 1\ndefault_action: allow\n"))

	if n := do(); n != 0 {
		t.Errorf("after revocation: should be filtered back to 0, got %d", n)
	}
}

// TestConfigPrivileged_WritePath_CanActOnOthersContainer 命中名单用户在写路径亦为特权：
// DELETE 别人的容器不被 container_not_owned 拦截（转发到上游）。
func TestConfigPrivileged_WritePath_CanActOnOthersContainer(t *testing.T) {
	username, uid := currentUserForPriv(t)
	if uid == 0 {
		t.Skip("current user is root; test targets non-root config-priv write path")
	}

	// 上游对 DELETE 返回 204
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	policy := mustLoadPolicyYAML(t, ""+
		"version: 1\n"+
		"default_action: allow\n"+
		"privileged_users:\n"+
		"  users: ["+username+"]\n")
	p := newTestProxy(t, upstream, policy)

	// 容器归属另一个 uid
	other := &auth.CallerIdentity{RealUID: uid + 1000, RealUsername: "someone-else"}
	_ = p.db.SetContainerOwner("cont-other-1", other, "")

	req := httptest.NewRequest("DELETE", "/containers/cont-other-1", nil)
	req = injectIdentity(req, makeTestIdentityProxy(username, uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	// 非特权用户此处会得到 404 container_not_owned；特权用户应放行到上游（204）
	if rw.Code == http.StatusNotFound {
		t.Errorf("config-privileged user must NOT be blocked by container_not_owned on others' container; got 404")
	}
	if rw.Code != http.StatusNoContent {
		t.Errorf("expected upstream 204 to pass through, got %d", rw.Code)
	}
}
