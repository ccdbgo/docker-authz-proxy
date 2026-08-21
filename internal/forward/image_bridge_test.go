//go:build linux

package forward

import (
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"

	"go.uber.org/zap"
)

func TestRefImageDigest(t *testing.T) {
	cases := map[string]string{
		"10.1.0.100:8082/alpine@sha256:6a3236": "sha256:6a3236",
		"repo@sha256:abc":                      "sha256:abc",
		"alpine:latest":                        "",
		"":                                     "",
	}
	for in, want := range cases {
		if got := refImageDigest(in); got != want {
			t.Errorf("refImageDigest(%q)=%q want %q", in, got, want)
		}
	}
}

// TestBridgeImageAccessByRefDigest 复现并验证修复:pull 把归属记在 ref 的 manifest digest 上,
// create 却按 daemon config 镜像 ID 查 → 原本误判 No such image。桥接后:拥有 digest 的用户
// 可用 config id;不拥有的用户仍被拒(无泄漏)。
func TestBridgeImageAccessByRefDigest(t *testing.T) {
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := &ProxyServer{db: db, logger: zap.NewNop()}

	alice := &auth.CallerIdentity{RealUID: 200056, RealUsername: "rpcu_56", UserType: auth.UserTypeRegular}
	bob := &auth.CallerIdentity{RealUID: 200099, RealUsername: "rpcu_99", UserType: auth.UserTypeRegular}

	// 场景:alice 按 digest 拉取,归属被记在 manifest digest 上(pull 兜底路径)。
	digestID := "sha256:6a3236160f31bb355d61f52fad0cf8985b8af0d77dc21f74a792d674e3ab4c9e"
	configID := "sha256:3cb067eab609612d81b4d82ff8ad71d73482bb3059a87b642d7e14f0ed659cde"
	ref := "10.1.0.100:8082/alpine@" + digestID
	if err := db.SetImageOwner(digestID, alice, false, "pull"); err != nil {
		t.Fatal(err)
	}

	// 修复前:config id 未跟踪,create 会 404。桥接应成功并把 config id 登记给 alice。
	if !p.bridgeImageAccessByRefDigest(alice, ref, configID) {
		t.Fatal("alice 拥有 ref digest → 桥接应成功")
	}
	if !db.CanUseImage(200056, configID) {
		t.Error("桥接后 alice 应能按 config id 使用镜像")
	}

	// 不拥有该 digest 的 bob:桥接必须失败,且不得获得 config id 访问权(无泄漏)。
	if p.bridgeImageAccessByRefDigest(bob, ref, configID) {
		t.Error("bob 不拥有 ref digest → 桥接必须失败")
	}
	if db.CanUseImage(200099, configID) {
		t.Error("bob 不得因此获得 config id 访问权")
	}

	// 无 digest 的引用:不桥接。
	if p.bridgeImageAccessByRefDigest(alice, "alpine:latest", configID) {
		t.Error("引用无 digest → 不应桥接")
	}
}

// TestBridgeImageAccessByRefDigest_ConfigIDOwnedByOther config id 已被他人拥有时,
// 拥有同一 digest 的用户应通过补访问权(而非夺属主)获得使用权。
func TestBridgeImageAccessByRefDigest_ConfigIDOwnedByOther(t *testing.T) {
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := &ProxyServer{db: db, logger: zap.NewNop()}

	first := &auth.CallerIdentity{RealUID: 200500, RealUsername: "rpcu_test", UserType: auth.UserTypeRegular}
	second := &auth.CallerIdentity{RealUID: 200056, RealUsername: "rpcu_56", UserType: auth.UserTypeRegular}

	digestID := "sha256:6a3236160f31bb355d61f52fad0cf8985b8af0d77dc21f74a792d674e3ab4c9e"
	configID := "sha256:3cb067eab609612d81b4d82ff8ad71d73482bb3059a87b642d7e14f0ed659cde"
	ref := "10.1.0.100:8082/alpine@" + digestID

	// config id 已被 first(另一租户)拥有;second 亲自拉过同一 digest。
	if err := db.SetImageOwner(configID, first, false, "pull"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetImageOwner(digestID, second, false, "pull"); err != nil {
		t.Fatal(err)
	}

	if !p.bridgeImageAccessByRefDigest(second, ref, configID) {
		t.Fatal("second 拥有 ref digest → 桥接应成功(补访问权)")
	}
	if !db.CanUseImage(200056, configID) {
		t.Error("second 应能使用 config id")
	}
	// 属主不应被夺走:first 仍可用。
	if !db.CanUseImage(200500, configID) {
		t.Error("原属主 first 仍应可用 config id")
	}
}
