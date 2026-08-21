package authz

import (
	"os"
	"os/user"
	"strconv"
	"testing"

	"docker-authz-proxy/internal/auth"
)

// ── Policy.IsConfigPrivileged（受治理特权名单）───────────────────────────────

// TestIsConfigPrivileged_DirectUIDMatch 命中名单的 uid 返回 true，未命中返回 false。
func TestIsConfigPrivileged_DirectUIDMatch(t *testing.T) {
	p := &Policy{
		Config:   PolicyConfig{DefaultAction: "allow"},
		privUIDs: map[int]bool{1001: true},
	}

	admin := makeCallerIdentity("admin", 1001, 1001)
	if !p.IsConfigPrivileged(admin) {
		t.Error("uid 1001 in privileged_users should be config-privileged")
	}

	tenant := makeCallerIdentity("rpcu_x", 5000, 5000)
	if p.IsConfigPrivileged(tenant) {
		t.Error("uid 5000 not in privileged_users should NOT be config-privileged")
	}
}

// TestIsConfigPrivileged_NilAndNegativeUID 防御性：nil policy / nil id / RealUID<0 一律 false。
func TestIsConfigPrivileged_NilAndNegativeUID(t *testing.T) {
	var nilPolicy *Policy
	if nilPolicy.IsConfigPrivileged(makeCallerIdentity("x", 1001, 1001)) {
		t.Error("nil policy must return false")
	}

	p := &Policy{privUIDs: map[int]bool{1001: true}}
	if p.IsConfigPrivileged(nil) {
		t.Error("nil identity must return false")
	}

	// 认证失败身份 RealUID=-1，即使 -1 被误放进集合也必须拒绝
	p2 := &Policy{privUIDs: map[int]bool{-1: true}}
	failed := &auth.CallerIdentity{RealUsername: "unknown", RealUID: -1, UserType: auth.UserTypeRegular}
	if p2.IsConfigPrivileged(failed) {
		t.Error("RealUID<0 (auth failure) must never be config-privileged")
	}
}

// TestIsConfigPrivileged_DefaultPolicyEmpty DefaultAllowPolicy 未解析名单 → 谁都不是特权。
func TestIsConfigPrivileged_DefaultPolicyEmpty(t *testing.T) {
	p := DefaultAllowPolicy()
	if p.IsConfigPrivileged(makeCallerIdentity("anyone", 5000, 5000)) {
		t.Error("default allow-all policy has empty privileged_users; nobody is privileged")
	}
}

// TestLoadPolicy_PrivilegedUsers_ResolvesCurrentUser 用当前进程用户名验证 users→uid 解析。
func TestLoadPolicy_PrivilegedUsers_ResolvesCurrentUser(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skipf("cannot resolve current user: %v", err)
	}
	uid, err := strconv.Atoi(cur.Uid)
	if err != nil {
		t.Skipf("non-numeric uid %q (windows?): %v", cur.Uid, err)
	}

	yaml := "" +
		"version: 1\n" +
		"default_action: allow\n" +
		"privileged_users:\n" +
		"  users: [" + cur.Username + "]\n"

	f, err := os.CreateTemp("", "policy-priv-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(yaml)
	f.Close()

	p, err := LoadPolicy(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	id := makeCallerIdentity(cur.Username, uid, uid)
	if !p.IsConfigPrivileged(id) {
		t.Errorf("current user %q (uid=%d) listed in privileged_users should resolve and match", cur.Username, uid)
	}
}

// TestLoadPolicy_PrivilegedUsers_UnresolvedName 无法解析的用户名进 UnresolvedNames，不误授特权。
func TestLoadPolicy_PrivilegedUsers_UnresolvedName(t *testing.T) {
	yaml := "" +
		"version: 1\n" +
		"default_action: allow\n" +
		"privileged_users:\n" +
		"  users: [nosuchuser99999]\n"

	f, err := os.CreateTemp("", "policy-priv-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(yaml)
	f.Close()

	p, err := LoadPolicy(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range p.UnresolvedNames {
		if n == "nosuchuser99999" {
			found = true
		}
	}
	if !found {
		t.Error("expected nosuchuser99999 in UnresolvedNames")
	}
	if len(p.privUIDs) != 0 {
		t.Errorf("unresolved name must not populate privUIDs, got %v", p.privUIDs)
	}
}
