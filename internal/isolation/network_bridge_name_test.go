package isolation

// ── network_bridge_name_test.go ──────────────────────────────────────────────
//
// BUG-6 复现与回归测试套件
//
// Bug 表现
// ─────────
//   bob 执行 `docker network create mynet` 后，在宿主机运行
//   `brctl show mynet` 报错 "bridge mynet does not exist!"。
//
// 根本原因
// ─────────
//   代理注入了用户前缀（bob_u1002_mynet），Docker 依此命名网络，
//   但 OS 层桥接器名称默认为 `br-<networkID前12位>`（如 br-40ba5cd269f4），
//   而非用户可见的 `mynet`。
//   `brctl show mynet` 查找名为 "mynet" 的 Linux 网桥接口，找不到因此报错。
//
// 修复方案
// ─────────
//   InjectNetworkNamePrefixWithName 在重写 Name 字段时，同步注入
//   Options["com.docker.network.bridge.name"] = <用户可见名称>，
//   使 Docker 以用户可见名（而非 br-<hex>）作为 OS 层桥接器名称。
//
// 注入条件（三者同时满足）：
//   1. Driver 为 "bridge" 或缺省（Docker 默认为 bridge）
//   2. 用户未通过 --opt com.docker.network.bridge.name=... 显式设置
//   3. 用户可见名称非空且 ≤ 15 字节（Linux IFNAMSIZ=16 含 null，上限 15 字节）

import (
	"encoding/json"
	"strings"
	"testing"

	"docker-authz-proxy/internal/auth"
)

// bobIdentity 是测试用的固定身份：bob / uid=1002
func bobIdentity() *auth.CallerIdentity {
	return &auth.CallerIdentity{RealUID: 1002, RealUsername: "bob"}
}

// getOptions 从 InjectNetworkNamePrefixWithName 结果中提取 Options map。
// Options 值为 json.RawMessage，以便兼容任意值类型（布尔、数字、字符串）。
func getOptions(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("解析结果 JSON 失败: %v — body: %q", err, body)
	}
	optsRaw, ok := req["Options"]
	if !ok || string(optsRaw) == "null" {
		return nil
	}
	var opts map[string]json.RawMessage
	if err := json.Unmarshal(optsRaw, &opts); err != nil {
		t.Fatalf("解析 Options 失败: %v — raw: %q", err, optsRaw)
	}
	return opts
}

// getStringOpt 返回 Options map 中指定键的字符串值；不存在时返回 ""。
func getStringOpt(t *testing.T, opts map[string]json.RawMessage, key string) string {
	t.Helper()
	raw, ok := opts[key]
	if !ok {
		return ""
	}
	var val string
	if err := json.Unmarshal(raw, &val); err != nil {
		t.Fatalf("解析 Options[%q] 失败: %v — raw: %q", key, err, raw)
	}
	return val
}

// ══════════════════════════════════════════════════════════════════════════════
// [BUG-6] Red Test #1 — 缺省 Driver 时应注入 bridge.name
//
// 场景：bob 执行 docker network create mynet（不指定 --driver，默认 bridge）
// 期望：Options["com.docker.network.bridge.name"] = "mynet"（用户可见名）
// 修复前：此字段不存在 → brctl show mynet 报 "bridge does not exist"
// ══════════════════════════════════════════════════════════════════════════════
func TestInjectNetworkNamePrefix_DefaultDriver_BridgeNameInjected(t *testing.T) {
	input := `{"Name":"mynet","Options":{}}`

	result, _, err := InjectNetworkNamePrefixWithName([]byte(input), bobIdentity())
	if err != nil {
		t.Fatalf("InjectNetworkNamePrefixWithName 返回错误: %v", err)
	}

	opts := getOptions(t, result)
	const key = "com.docker.network.bridge.name"

	if opts == nil {
		t.Fatalf(
			"[BUG-6 RED] Options 为 nil，bridge.name 未注入\n"+
				"  期望：Options[%q] = %q\n"+
				"  根本原因：InjectNetworkNamePrefixWithName 未设置 bridge.name，\n"+
				"  Docker 使用默认 br-<hex> 命名网桥，brctl show mynet 报 bridge does not exist",
			key, "mynet",
		)
	}

	bridgeName := getStringOpt(t, opts, key)
	if bridgeName == "" {
		t.Errorf(
			"[BUG-6 RED] 缺省 driver 时未注入 bridge.name:\n"+
				"  got  Options[%q] = %q\n"+
				"  want %q（用户可见名称）\n"+
				"  修复前：InjectNetworkNamePrefixWithName 未设置 bridge.name，\n"+
				"  导致 Docker 使用默认 br-<hex> 命名网桥，brctl show mynet 报错",
			key, bridgeName, "mynet",
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// [BUG-6] Red Test #2 — 显式指定 Driver="bridge" 时应注入 bridge.name
//
// 场景：bob 执行 docker network create --driver bridge mynet
// 期望：Options["com.docker.network.bridge.name"] = "mynet"
// ══════════════════════════════════════════════════════════════════════════════
func TestInjectNetworkNamePrefix_ExplicitBridgeDriver_BridgeNameInjected(t *testing.T) {
	input := `{"Name":"mynet","Driver":"bridge","Options":{}}`

	result, _, err := InjectNetworkNamePrefixWithName([]byte(input), bobIdentity())
	if err != nil {
		t.Fatalf("InjectNetworkNamePrefixWithName 返回错误: %v", err)
	}

	opts := getOptions(t, result)
	const key = "com.docker.network.bridge.name"

	if opts == nil {
		t.Fatalf(
			"[BUG-6 RED] driver=bridge 时 Options 为 nil，bridge.name 未注入\n"+
				"  期望：Options[%q] = %q",
			key, "mynet",
		)
	}

	bridgeName := getStringOpt(t, opts, key)
	if bridgeName == "" {
		t.Errorf(
			"[BUG-6 RED] driver=bridge 时未注入 bridge.name:\n"+
				"  got  Options[%q] = %q\n"+
				"  want %q（用户可见名称）",
			key, bridgeName, "mynet",
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// [BUG-6] Red Test #3 — name 正好 15 字节（IFNAMSIZ 边界）时应注入
//
// 场景：网络名恰好 15 字节（IFNAMSIZ=16，含 null，最大有效长度=15）
// 期望：仍注入 bridge.name（边界值应包含在内，≤15 均注入）
// 对比：name=16字节时不注入（见 REG-2）
// ══════════════════════════════════════════════════════════════════════════════
func TestInjectNetworkNamePrefix_Name15Bytes_BridgeNameInjected(t *testing.T) {
	name15 := "abcdefghijklmno" // 正好 15 字节
	if len(name15) != 15 {
		t.Fatalf("测试用例错误：name15 长度应为 15，got %d", len(name15))
	}

	input := `{"Name":"` + name15 + `","Options":{}}`

	result, _, err := InjectNetworkNamePrefixWithName([]byte(input), bobIdentity())
	if err != nil {
		t.Fatalf("InjectNetworkNamePrefixWithName 返回错误: %v", err)
	}

	opts := getOptions(t, result)
	const key = "com.docker.network.bridge.name"

	if opts == nil {
		t.Fatalf(
			"[BUG-6 RED] name=15字节时 Options 为 nil，bridge.name 未注入\n"+
				"  期望：Options[%q] = %q（边界值 ≤ 15 字节应注入）",
			key, name15,
		)
	}

	bridgeName := getStringOpt(t, opts, key)
	if bridgeName == "" {
		t.Errorf(
			"[BUG-6 RED] name=15字节（边界值）时未注入 bridge.name:\n"+
				"  got  Options[%q] = %q\n"+
				"  want %q（用户可见名称，正好 ≤ 15 字节，应注入）\n"+
				"  注：name=16字节时不注入（REG-2），15字节是注入上限边界",
			key, bridgeName, name15,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// [BUG-6] Red Test #4 — 注入 bridge.name 时已有 Options 不应丢失
//
// 场景：用户通过 --opt 设置了其他 Options 字段（如 enable_icc）
// 期望：注入 bridge.name 后，原有字段保持不变
// 防止：修复实现中覆盖整个 Options map 导致已有字段丢失
// ══════════════════════════════════════════════════════════════════════════════
func TestInjectNetworkNamePrefix_ExistingOptions_NotLost(t *testing.T) {
	input := `{"Name":"mynet","Driver":"bridge","Options":{"com.docker.network.bridge.enable_icc":"false"}}`

	result, _, err := InjectNetworkNamePrefixWithName([]byte(input), bobIdentity())
	if err != nil {
		t.Fatalf("InjectNetworkNamePrefixWithName 返回错误: %v", err)
	}

	opts := getOptions(t, result)
	if opts == nil {
		t.Fatalf("[BUG-6 RED] Options 不应为 nil（原有 Options 字段丢失）")
	}

	// 已有字段不应丢失
	const iccKey = "com.docker.network.bridge.enable_icc"
	iccVal := getStringOpt(t, opts, iccKey)
	if iccVal != "false" {
		t.Errorf(
			"[BUG-6 RED] 注入 bridge.name 时原有 Options 字段丢失:\n"+
				"  Options[%q] = %q (want %q)\n"+
				"  修复实现不应覆盖整个 Options map",
			iccKey, iccVal, "false",
		)
	}

	// bridge.name 同时应被注入
	const bridgeKey = "com.docker.network.bridge.name"
	bridgeName := getStringOpt(t, opts, bridgeKey)
	if bridgeName == "" {
		t.Errorf(
			"[BUG-6 RED] 有已有 Options 时 bridge.name 仍应注入:\n"+
				"  got  Options[%q] = %q\n"+
				"  want %q（用户可见名称）",
			bridgeKey, bridgeName, "mynet",
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// [REG-1] 用户已显式设置 bridge.name → 代理不覆盖（幂等保护）
// ══════════════════════════════════════════════════════════════════════════════
func TestInjectNetworkNamePrefix_UserSetBridgeName_NotOverridden(t *testing.T) {
	input := `{"Name":"mynet","Driver":"bridge","Options":{"com.docker.network.bridge.name":"custom"}}`

	result, _, err := InjectNetworkNamePrefixWithName([]byte(input), bobIdentity())
	if err != nil {
		t.Fatalf("InjectNetworkNamePrefixWithName 返回错误: %v", err)
	}

	opts := getOptions(t, result)
	if opts == nil {
		t.Fatalf("[REG-1] Options 不应为 nil（用户已设置 Options）")
	}

	const key = "com.docker.network.bridge.name"
	bridgeName := getStringOpt(t, opts, key)
	if bridgeName != "custom" {
		t.Errorf(
			"[REG-1] 用户显式设置 bridge.name 后被代理覆盖:\n"+
				"  got  Options[%q] = %q\n"+
				"  want %q\n"+
				"  代理不应覆盖用户通过 --opt 显式指定的桥接器名称",
			key, bridgeName, "custom",
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// [REG-2] 名称 > 15 字节 → 不注入 bridge.name（超出 IFNAMSIZ 限制）
// ══════════════════════════════════════════════════════════════════════════════
func TestInjectNetworkNamePrefix_NameOver15Bytes_BridgeNameNotInjected(t *testing.T) {
	longName := "sixteen_chars_xx"
	if len(longName) <= 15 {
		t.Fatalf("测试用例错误：longName 长度应 > 15，got %d", len(longName))
	}

	input := `{"Name":"` + longName + `","Options":{}}`

	result, _, err := InjectNetworkNamePrefixWithName([]byte(input), bobIdentity())
	if err != nil {
		t.Fatalf("InjectNetworkNamePrefixWithName 返回错误: %v", err)
	}

	opts := getOptions(t, result)
	const key = "com.docker.network.bridge.name"
	if opts != nil {
		if _, injected := opts[key]; injected {
			t.Errorf(
				"[REG-2] 名称长度 %d > 15 时不应注入 bridge.name:\n"+
					"  Options[%q] = %q\n"+
					"  超过 IFNAMSIZ-1 的接口名会被内核拒绝，导致网络创建失败",
				len(longName), key, getStringOpt(t, opts, key),
			)
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// [REG-4] Driver = "overlay" → 不注入 bridge.name（非 bridge 驱动）
// ══════════════════════════════════════════════════════════════════════════════
func TestInjectNetworkNamePrefix_OverlayDriver_BridgeNameNotInjected(t *testing.T) {
	input := `{"Name":"mynet","Driver":"overlay","Options":{}}`

	result, _, err := InjectNetworkNamePrefixWithName([]byte(input), bobIdentity())
	if err != nil {
		t.Fatalf("InjectNetworkNamePrefixWithName 返回错误: %v", err)
	}

	opts := getOptions(t, result)
	const key = "com.docker.network.bridge.name"
	if opts != nil {
		if _, injected := opts[key]; injected {
			t.Errorf(
				"[REG-4] driver=overlay 时不应注入 bridge.name:\n"+
					"  Options[%q] = %q\n"+
					"  overlay 网络不使用 Linux 桥接器，此选项对其无意义且可能导致错误",
				key, getStringOpt(t, opts, key),
			)
		}
	}
}

// suppress unused import warning
var _ = strings.Repeat
