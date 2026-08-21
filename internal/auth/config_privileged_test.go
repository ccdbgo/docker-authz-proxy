//go:build linux

package auth

import "testing"

// TestIsPrivileged_ConfigPrivileged 验证 ConfigPrivileged 使普通用户身份也被判为特权，
// 且不影响其它字段语义。
func TestIsPrivileged_ConfigPrivileged(t *testing.T) {
	// 普通用户（非 root、非 sudo），未命中名单 → 非特权
	regular := &CallerIdentity{RealUID: 1001, UserType: UserTypeRegular}
	if regular.IsPrivileged() {
		t.Error("regular user without ConfigPrivileged must not be privileged")
	}

	// 同一普通用户命中 config 名单 → 特权
	regular.ConfigPrivileged = true
	if !regular.IsPrivileged() {
		t.Error("regular user with ConfigPrivileged must be privileged")
	}

	// root 恒特权，与 ConfigPrivileged 无关
	root := &CallerIdentity{RealUID: 0, UserType: UserTypeRoot}
	if !root.IsPrivileged() {
		t.Error("root must always be privileged")
	}

	// sudo 恒特权
	sudo := &CallerIdentity{RealUID: 1002, UserType: UserTypeSudo}
	if !sudo.IsPrivileged() {
		t.Error("sudo user must always be privileged")
	}
}
