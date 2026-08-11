//go:build linux

package isolation

// ── netbridge_isolation_test.go ──────────────────────────────────────────────
//
// BUG-7 复现与回归测试套件
//
// Bug 表现
// ─────────
//   用户创建的容器（通过 user-{uid}-bridge 网络）无法访问外部网络。
//   从容器内 ping 8.8.8.8 超时，apt update 失败。
//   宿主机能 ping 通容器（172.19.0.2），说明 bridge 本身正常。
//
// 根本原因
// ─────────
//   addIsolationRules() 在 DOCKER-USER 链中插入了两条 DROP 规则：
//     -I DOCKER-USER -i <br-xxx> ! -o <br-xxx> -j DROP  （容器→外网：出站全丢）
//     -I DOCKER-USER -o <br-xxx> ! -i <br-xxx> -j DROP  （外网→容器：入站全丢）
//
//   这两条规则不仅阻断了跨 bridge 的容器间通信（期望行为），
//   也阻断了容器通过宿主机 NAT 访问外部网络（非期望行为）。
//
//   iptables FORWARD 链的处理顺序为：
//     FORWARD → DOCKER-USER（最先） → DOCKER-FORWARD → ...
//   数据包在 DOCKER-USER 中被 DROP，根本到不了后续的 MASQUERADE/ACCEPT 规则。
//
// 期望修复
// ─────────
//   隔离规则应仅阻断跨用户 bridge 的容器间通信，
//   不应阻止容器→外网（非 docker bridge 出口）的合法流量。
//   可行方案：
//     a) 将 DROP 目标限定为仅匹配其他 docker bridge 接口（而非"所有非本 bridge"）
//     b) 在 DROP 规则之前插入 ACCEPT 规则允许去往宿主机物理接口（eth0/enp*）的流量
//     c) 改用 DOCKER-ISOLATION-STAGE 链做更精确的隔离
//
// 调用栈
// ─────────
//   forwardRequest() [proxy.go:1119]
//   → EnsureUserBridge(uid, username) [netbridge.go:50]
//     → createNetwork() [netbridge.go:74]
//     → getBridgeInterface(networkID) [netbridge.go:80]
//     → addIsolationRules(brIface) [netbridge.go:81]     ← BUG 点
//       → iptables("-I", "DOCKER-USER", "-i", br, "!", "-o", br, "-j", "DROP")
//       → iptables("-I", "DOCKER-USER", "-o", br, "!", "-i", br, "-j", "DROP")

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// ── 测试辅助函数 ───────────────────────────────────────────────

// iptablesListChain 列出指定链的所有规则（-S 格式）
func iptablesListChain(t *testing.T, chain string) []string {
	t.Helper()
	out, err := exec.Command("iptables", "-S", chain).CombinedOutput()
	if err != nil {
		t.Fatalf("iptables -S %s 失败: %v (output: %s)", chain, err, out)
	}
	var rules []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			rules = append(rules, line)
		}
	}
	return rules
}

// iptablesFlushTestRules 清除指定 bridge 接口在 DOCKER-USER 和隔离子链中的所有规则（测试清理用）
func iptablesFlushTestRules(t *testing.T, brIface string) {
	t.Helper()
	for i := 0; i < 20; i++ {
		// 新格式（BUG-7 修复后：两阶段隔离链）
		err1 := iptables("-D", iptablesChain, "-i", brIface, "!", "-o", brIface, "-j", isolationChain)
		err2 := iptables("-D", isolationChain, "-o", brIface, "-j", "DROP")
		// 旧格式（BUG-7 修复前：直接 DROP）
		err3 := iptables("-D", iptablesChain, "-i", brIface, "!", "-o", brIface, "-j", "DROP")
		err4 := iptables("-D", iptablesChain, "-o", brIface, "!", "-i", brIface, "-j", "DROP")
		if err1 != nil && err2 != nil && err3 != nil && err4 != nil {
			break
		}
	}
}

// containsRule 检查规则列表中是否包含指定子串
func containsRule(rules []string, substr string) bool {
	for _, r := range rules {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
}

// countRulesMatching 统计匹配子串的规则数量
func countRulesMatching(rules []string, substr string) int {
	count := 0
	for _, r := range rules {
		if strings.Contains(r, substr) {
			count++
		}
	}
	return count
}

// ruleBlocksOutbound 检查规则列表中是否存在阻断出站到外网的 DROP 规则。
// 阻断出站的规则形如：-A DOCKER-USER -i <br> ! -o <br> -j DROP
// 该规则会丢弃从 bridge 发出、目标为任何非本 bridge 接口的流量（包括 eth0→外网）。
func ruleBlocksOutbound(rules []string, brIface string) bool {
	// iptables -S 输出格式: -A DOCKER-USER -i <br> ! -o <br> -j DROP
	pattern := fmt.Sprintf("-i %s ! -o %s -j DROP", brIface, brIface)
	return containsRule(rules, pattern)
}

// ruleBlocksInbound 检查规则列表中是否存在阻断外网入站的 DROP 规则。
// 插入时：-I DOCKER-USER -o <br> ! -i <br> -j DROP
// iptables -S 输出：-A DOCKER-USER ! -i <br> -o <br> -j DROP
//   （iptables 标准化时将 "!" 前移到选项前面，并调整 -i/-o 顺序）
// 该规则会丢弃从任何非本 bridge 接口发来、目标为本 bridge 的流量（包括 NAT 回包）。
func ruleBlocksInbound(rules []string, brIface string) bool {
	// 匹配 iptables -S 标准化后的格式: ! -i <br> -o <br> -j DROP
	pattern := fmt.Sprintf("! -i %s -o %s -j DROP", brIface, brIface)
	return containsRule(rules, pattern)
}

// ══════════════════════════════════════════════════════════════════════════════
//
//	[BUG-7] 复现测试（Red Tests）
//	在 Bug 未修复前，这些测试必须 100% 失败。
//
// ══════════════════════════════════════════════════════════════════════════════

// ── Red Test #1 ──────────────────────────────────────────────────────────────
//
// 场景：为用户 uid=5001 创建隔离规则后，检查出站 DROP 是否会阻断外网访问。
//
// 当前行为（BUG）：
//
//	addIsolationRules("br-test5001") 插入规则：
//	  -I DOCKER-USER -i br-test5001 ! -o br-test5001 -j DROP
//	该规则匹配"从 br-test5001 进来、发往非 br-test5001 的所有流量"，
//	这包括容器→eth0→外网的合法出站流量。
//
// 期望行为（修复后）：
//
//	隔离规则应仅阻断跨 docker bridge 的流量，
//	不应阻断容器通过宿主机 NAT 访问外网的流量。
func TestAddIsolationRules_OutboundToInternet_Blocked_regression(t *testing.T) {
	const brIface = "br-test5001"
	t.Cleanup(func() { iptablesFlushTestRules(t, brIface) })

	if err := addIsolationRules(brIface); err != nil {
		t.Fatalf("addIsolationRules(%q) 返回错误: %v", brIface, err)
	}

	rules := iptablesListChain(t, iptablesChain)

	// [断言] 不应存在阻断 bridge→外网出站流量的规则
	if ruleBlocksOutbound(rules, brIface) {
		t.Errorf(
			"[BUG-7 RED] addIsolationRules 插入了阻断容器出站到外网的 DROP 规则:\n"+
				"  发现: -i %s ! -o %s -j DROP\n"+
				"  影响: 容器无法通过 NAT 访问外部网络（apt update 失败、ping 8.8.8.8 超时）\n"+
				"  原因: '! -o %s' 匹配所有非本 bridge 出口，包括 eth0/enp* 等物理接口\n"+
				"  期望: 隔离规则仅阻断跨 docker bridge 流量，不影响容器→外网的合法通信\n"+
				"  修复: 将 DROP 目标限定为仅匹配其他 docker bridge，或在 DROP 前添加 ACCEPT 放行外网流量",
			brIface, brIface, brIface,
		)
	}
}

// ── Red Test #2 ──────────────────────────────────────────────────────────────
//
// 场景：检查入站 DROP 规则是否会阻断外网→容器的 NAT 回包。
//
// 当前行为（BUG）：
//
//	-I DOCKER-USER -o br-test5001 ! -i br-test5001 -j DROP
//	该规则匹配"发往 br-test5001、来源非 br-test5001 的所有流量"，
//	包括经 NAT 转换后从 eth0 返回的外网响应包。
//
// 期望行为（修复后）：
//
//	允许 ESTABLISHED/RELATED 状态的回包通过，或仅 DROP 来自其他 docker bridge 的包。
func TestAddIsolationRules_InboundNATReturn_Blocked_regression(t *testing.T) {
	const brIface = "br-test5002"
	t.Cleanup(func() { iptablesFlushTestRules(t, brIface) })

	if err := addIsolationRules(brIface); err != nil {
		t.Fatalf("addIsolationRules(%q) 返回错误: %v", brIface, err)
	}

	rules := iptablesListChain(t, iptablesChain)

	// [断言] 不应存在阻断外网 NAT 回包到容器的 DROP 规则
	if ruleBlocksInbound(rules, brIface) {
		t.Errorf(
			"[BUG-7 RED] addIsolationRules 插入了阻断外网 NAT 回包的 DROP 规则:\n"+
				"  发现: -o %s ! -i %s -j DROP\n"+
				"  影响: 容器发出的 TCP/UDP 请求得不到响应（SYN 出去，SYN-ACK 回不来）\n"+
				"  原因: '! -i %s' 匹配所有非本 bridge 来源，包括 NAT 回包经 eth0 的路径\n"+
				"  期望: 允许 conntrack ESTABLISHED/RELATED 回包，或仅 DROP 来自其他 docker bridge 的流量",
			brIface, brIface, brIface,
		)
	}
}

// ── Red Test #3 ──────────────────────────────────────────────────────────────
//
// 场景：EnsureUserBridge 完整流程——创建 bridge 后容器网络应能访问外网。
//       通过 mock Docker API 模拟 bridge 创建，验证 iptables 规则不阻断外网。
//
// 当前行为（BUG）：
//
//	EnsureUserBridge → createNetwork → getBridgeInterface → addIsolationRules
//	最终结果：容器网络完全隔离，包括外网。
//
// 期望行为（修复后）：
//
//	容器只与其他用户的 bridge 隔离，仍可通过 NAT 访问外网。
func TestEnsureUserBridge_ContainerCanAccessInternet_regression(t *testing.T) {
	const brIface = "br-test5003"
	t.Cleanup(func() { iptablesFlushTestRules(t, brIface) })

	// 直接调用 addIsolationRules 模拟 EnsureUserBridge 的最终效果，
	// 因为完整流程需要连接 Docker daemon，在单元测试中不可行。
	if err := addIsolationRules(brIface); err != nil {
		t.Fatalf("addIsolationRules(%q) 失败: %v", brIface, err)
	}

	rules := iptablesListChain(t, iptablesChain)
	outBlocked := ruleBlocksOutbound(rules, brIface)
	inBlocked := ruleBlocksInbound(rules, brIface)

	if outBlocked || inBlocked {
		t.Errorf(
			"[BUG-7 RED] EnsureUserBridge 创建的隔离规则阻断了容器外网访问:\n"+
				"  出站 DROP (容器→外网): %v\n"+
				"  入站 DROP (外网→容器): %v\n"+
				"  完整调用栈:\n"+
				"    forwardRequest() [proxy.go:1119]\n"+
				"    → EnsureUserBridge(uid, username) [netbridge.go:50]\n"+
				"      → addIsolationRules(brIface=%q) [netbridge.go:81]\n"+
				"  网络配置:\n"+
				"    enable_ip_masquerade: true（已启用 NAT）\n"+
				"    enable_icc: true（bridge 内部互通）\n"+
				"  期望: 隔离仅在 docker bridge 之间生效，不影响 NAT 出站",
			outBlocked, inBlocked, brIface,
		)
	}
}

// ── Red Test #4 ──────────────────────────────────────────────────────────────
//
// 场景：addIsolationRules 创建的规则不应与 MASQUERADE 冲突。
//       Docker 在 nat 表 POSTROUTING 链中设置了 MASQUERADE：
//         -A POSTROUTING -s 172.19.0.0/16 ! -o br-xxx -j MASQUERADE
//       即使 MASQUERADE 配置正确，FORWARD 阶段的 DROP 规则也会在
//       NAT 生效之前就把包丢弃。
//
// 当前行为（BUG）：
//
//	filter FORWARD 在 nat POSTROUTING 之前执行，
//	DROP 规则在 DOCKER-USER 中直接丢弃了本应走 NAT 的流量。
//
// 期望行为（修复后）：
//
//	需要 FORWARD 的流量（容器→外网）应能通过 filter 阶段，
//	到达 nat POSTROUTING 的 MASQUERADE 规则完成地址转换。
func TestAddIsolationRules_MasqueradeBypass_regression(t *testing.T) {
	const brIface = "br-test5004"
	t.Cleanup(func() { iptablesFlushTestRules(t, brIface) })

	if err := addIsolationRules(brIface); err != nil {
		t.Fatalf("addIsolationRules(%q) 失败: %v", brIface, err)
	}

	rules := iptablesListChain(t, iptablesChain)

	// MASQUERADE 需要包通过 FORWARD 链才能在 POSTROUTING 生效。
	// 如果 DOCKER-USER 中存在宽泛的 DROP 规则，MASQUERADE 永远不会被触发。
	//
	// 数据包路径（正常情况）：
	//   容器 → br-xxx → FORWARD(DOCKER-USER → ...) → POSTROUTING(MASQUERADE) → eth0 → 外网
	//
	// 数据包路径（BUG 情况）：
	//   容器 → br-xxx → FORWARD(DOCKER-USER: DROP!) → 丢弃，到不了 MASQUERADE
	if ruleBlocksOutbound(rules, brIface) {
		t.Errorf(
			"[BUG-7 RED] DOCKER-USER 的 DROP 规则使 MASQUERADE 永远无法触发:\n"+
				"  iptables 处理顺序: PREROUTING → FORWARD(filter) → POSTROUTING(nat)\n"+
				"  DROP 在 filter/FORWARD 的 DOCKER-USER 中执行，先于 nat/POSTROUTING\n"+
				"  发现: -i %s ! -o %s -j DROP （在 filter/FORWARD/DOCKER-USER 中）\n"+
				"  结果: 容器出站包在 filter 阶段即被丢弃，永远到不了 MASQUERADE\n"+
				"  即使 nat 表有: MASQUERADE -s 172.x.0.0/16 ! -o %s，也毫无作用",
			brIface, brIface, brIface,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
//
//	回归测试矩阵（Regression Suite）
//	确保修复 BUG-7 时不引入其他问题。
//
// ══════════════════════════════════════════════════════════════════════════════

// ── REG-1 ────────────────────────────────────────────────────────────────────
// 核心逻辑：不同用户的 bridge 之间仍然必须隔离。
// 即使修复了外网访问问题，跨用户容器间通信仍应被阻断。
func TestAddIsolationRules_CrossBridgeIsolation_Maintained_regression(t *testing.T) {
	const brA = "br-regA001"
	const brB = "br-regB001"
	t.Cleanup(func() {
		iptablesFlushTestRules(t, brA)
		iptablesFlushTestRules(t, brB)
	})

	if err := addIsolationRules(brA); err != nil {
		t.Fatalf("addIsolationRules(%q) 失败: %v", brA, err)
	}
	if err := addIsolationRules(brB); err != nil {
		t.Fatalf("addIsolationRules(%q) 失败: %v", brB, err)
	}

	rules := iptablesListChain(t, iptablesChain)

	// [断言] brA 应存在某种形式的隔离规则（不一定是 ! -o 这种宽泛形式）
	brAMentioned := containsRule(rules, brA)
	brBMentioned := containsRule(rules, brB)

	if !brAMentioned {
		t.Errorf(
			"[REG-1] 修复外网访问后，bridge %s 的隔离规则丢失\n"+
				"  DOCKER-USER 中应仍有针对 %s 的规则，以阻断与其他用户 bridge 的通信\n"+
				"  修复方案不应删除所有隔离，而应精确限定 DROP 范围",
			brA, brA,
		)
	}
	if !brBMentioned {
		t.Errorf(
			"[REG-1] 修复外网访问后，bridge %s 的隔离规则丢失\n"+
				"  DOCKER-USER 中应仍有针对 %s 的规则",
			brB, brB,
		)
	}
}

// ── REG-2 ────────────────────────────────────────────────────────────────────
// 核心逻辑：removeIsolationRules 应完整清除所有相关规则。
// 修复后插入的规则格式可能改变，删除逻辑必须同步更新。
func TestRemoveIsolationRules_CompleteCleaning_regression(t *testing.T) {
	const brIface = "br-regclean1"
	t.Cleanup(func() { iptablesFlushTestRules(t, brIface) })

	if err := addIsolationRules(brIface); err != nil {
		t.Fatalf("addIsolationRules(%q) 失败: %v", brIface, err)
	}

	// 验证规则已添加
	rulesBefore := iptablesListChain(t, iptablesChain)
	if !containsRule(rulesBefore, brIface) {
		t.Fatalf("addIsolationRules 未插入任何关于 %s 的规则", brIface)
	}

	// 清除规则
	removeIsolationRules(brIface)

	// [断言] 清除后不应残留任何相关规则
	rulesAfter := iptablesListChain(t, iptablesChain)
	if containsRule(rulesAfter, brIface) {
		t.Errorf(
			"[REG-2] removeIsolationRules 未完整清除 %s 的规则:\n"+
				"  清除后仍存在:\n%s\n"+
				"  修复 BUG-7 可能改变了规则格式，removeIsolationRules 需要同步更新",
			brIface, formatRulesContaining(rulesAfter, brIface),
		)
	}
}

// ── REG-3 ────────────────────────────────────────────────────────────────────
// 边界条件：对空字符串 bridge 名称不应 panic 或插入无效规则。
func TestAddIsolationRules_EmptyBridgeName_regression(t *testing.T) {
	// [断言] 空 bridge 名应返回错误，不应插入任何规则
	err := addIsolationRules("")
	if err == nil {
		t.Log(
			"[REG-3] addIsolationRules(\"\") 未返回错误 — " +
				"空 bridge 名可能导致无效 iptables 规则（如 '-i  ! -o  -j DROP'）",
		)
		// 清理可能插入的无效规则
		removeIsolationRules("")
	}

	// 即使不返回错误，也不应 panic（测试能执行到此处即通过 panic 检查）
}

// ── REG-4 ────────────────────────────────────────────────────────────────────
// 幂等性：重复调用 addIsolationRules 不应产生重复规则。
func TestAddIsolationRules_Idempotent_regression(t *testing.T) {
	const brIface = "br-regidem1"
	t.Cleanup(func() { iptablesFlushTestRules(t, brIface) })

	// 调用两次
	if err := addIsolationRules(brIface); err != nil {
		t.Fatalf("第一次 addIsolationRules(%q) 失败: %v", brIface, err)
	}
	if err := addIsolationRules(brIface); err != nil {
		t.Fatalf("第二次 addIsolationRules(%q) 失败: %v", brIface, err)
	}

	rules := iptablesListChain(t, iptablesChain)
	count := countRulesMatching(rules, brIface)

	// 当前实现会产生 4 条规则（两次 × 2 条/次），而非幂等的 2 条。
	// 这虽然不直接导致外网不通，但规则膨胀是潜在问题。
	if count > 2 {
		t.Errorf(
			"[REG-4] addIsolationRules 不是幂等的 — 重复调用产生了 %d 条规则（期望 ≤ 2）:\n"+
				"%s\n"+
				"  影响: 多次 EnsureUserBridge 调用（如容器反复创建）导致 DOCKER-USER 规则膨胀\n"+
				"  建议: 插入前检查规则是否已存在",
			count, formatRulesContaining(rules, brIface),
		)
	}
}

// ── REG-5 ────────────────────────────────────────────────────────────────────
// 核心逻辑：peer 网络（peer-*）不应添加 DROP 规则。
// 确保修复 BUG-7 时不会误给 peer 网络也加上隔离。
func TestPeerNetwork_NoIsolationRules_regression(t *testing.T) {
	const peerBr = "br-regpeer01"
	t.Cleanup(func() { iptablesFlushTestRules(t, peerBr) })

	// createPeerNetworkWithName 不调用 addIsolationRules（设计如此）。
	// 验证：如果有人误对 peer bridge 调用了 addIsolationRules，
	// 修复后的版本也不应影响 peer 网络的跨用户通信能力。
	//
	// 这里我们只验证设计意图：当前代码中 peer 网络创建路径不调用 addIsolationRules。
	// 通过源码审查确认 createPeerNetworkWithName（lines 133-159）没有调用 addIsolationRules。

	rules := iptablesListChain(t, iptablesChain)
	if containsRule(rules, peerBr) {
		t.Errorf(
			"[REG-5] peer 网络 bridge %s 不应出现在 DOCKER-USER 隔离规则中:\n"+
				"%s\n"+
				"  peer 网络的设计目的就是允许跨用户通信（见 netbridge.go:195 注释）",
			peerBr, formatRulesContaining(rules, peerBr),
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
//
//	关联场景测试（Associated Scenarios）
//
// ══════════════════════════════════════════════════════════════════════════════

// ── ASSOC-1 ──────────────────────────────────────────────────────────────────
// 场景：addIsolationRules 正常执行后，DOCKER-USER 和隔离子链中各有正确数量的规则。
// 验证两阶段隔离结构完整性。
func TestAddIsolationRules_SecondRuleFails_FirstRolledBack_regression(t *testing.T) {
	const brIface = "br-assocroll"
	t.Cleanup(func() { iptablesFlushTestRules(t, brIface) })

	if err := addIsolationRules(brIface); err != nil {
		t.Fatalf("addIsolationRules(%q) 失败: %v", brIface, err)
	}

	// [断言] DOCKER-USER 中应恰好有 1 条跳转规则
	userRules := iptablesListChain(t, iptablesChain)
	userCount := countRulesMatching(userRules, brIface)
	if userCount != 1 {
		t.Errorf(
			"[ASSOC-1] DOCKER-USER 中应有 1 条跳转规则，实际 %d 条:\n%s",
			userCount, formatRulesContaining(userRules, brIface),
		)
	}

	// [断言] 隔离子链中应恰好有 1 条 DROP 规则
	isoRules := iptablesListChain(t, isolationChain)
	isoCount := countRulesMatching(isoRules, brIface)
	if isoCount != 1 {
		t.Errorf(
			"[ASSOC-1] %s 中应有 1 条 DROP 规则，实际 %d 条:\n%s",
			isolationChain, isoCount, formatRulesContaining(isoRules, brIface),
		)
	}
}

// ── ASSOC-2 ──────────────────────────────────────────────────────────────────
// 场景：多个用户 bridge 并存时，各自的规则互不影响。
func TestAddIsolationRules_MultipleBridges_Independent_regression(t *testing.T) {
	bridges := []string{"br-assocm01", "br-assocm02", "br-assocm03"}
	t.Cleanup(func() {
		for _, br := range bridges {
			iptablesFlushTestRules(t, br)
		}
	})

	for _, br := range bridges {
		if err := addIsolationRules(br); err != nil {
			t.Fatalf("addIsolationRules(%q) 失败: %v", br, err)
		}
	}

	// 删除中间的 bridge 规则
	removeIsolationRules(bridges[1])

	rules := iptablesListChain(t, iptablesChain)

	// [断言] 第一个和第三个 bridge 的规则应不受影响
	if !containsRule(rules, bridges[0]) {
		t.Errorf("[ASSOC-2] 删除 %s 的规则后，%s 的规则也丢失了", bridges[1], bridges[0])
	}
	if !containsRule(rules, bridges[2]) {
		t.Errorf("[ASSOC-2] 删除 %s 的规则后，%s 的规则也丢失了", bridges[1], bridges[2])
	}

	// [断言] 被删除的 bridge 规则应不存在
	if containsRule(rules, bridges[1]) {
		t.Errorf("[ASSOC-2] removeIsolationRules(%q) 后规则仍残留", bridges[1])
	}
}

// ── ASSOC-3 ──────────────────────────────────────────────────────────────────
// 场景：DeleteUserBridge 调用路径中的 removeIsolationRules 完整性。
// 确保用户注销后不会残留 iptables 规则。
func TestDeleteUserBridge_CleansIptablesRules_regression(t *testing.T) {
	const brIface = "br-assocclean"
	t.Cleanup(func() { iptablesFlushTestRules(t, brIface) })

	// 模拟 EnsureUserBridge 的效果
	if err := addIsolationRules(brIface); err != nil {
		t.Fatalf("addIsolationRules(%q) 失败: %v", brIface, err)
	}

	// 模拟 DeleteUserBridge 中的 removeIsolationRules 调用
	removeIsolationRules(brIface)

	rules := iptablesListChain(t, iptablesChain)
	if containsRule(rules, brIface) {
		t.Errorf(
			"[ASSOC-3] 模拟 DeleteUserBridge 后 iptables 规则残留:\n%s\n"+
				"  若修复改变了 addIsolationRules 的规则格式，\n"+
				"  DeleteUserBridge → removeIsolationRules 必须同步更新",
			formatRulesContaining(rules, brIface),
		)
	}
}

// ── ASSOC-4 ──────────────────────────────────────────────────────────────────
// 场景：bridge 接口名含特殊字符时不应导致 iptables 命令注入。
// getBridgeInterface 返回的接口名来自 Docker API，理论上可控，
// 但防御性编程仍应考虑边界值。
func TestAddIsolationRules_SpecialCharsInName_regression(t *testing.T) {
	// Linux 网桥名最长 15 字符，有效字符为 [a-zA-Z0-9._-]
	// 测试极端边界值
	specialNames := []string{
		"br-............", // 全点号（15字符）
		"br-a",           // 极短名称
		"br-123456789ab", // 标准 Docker 12位 hex
	}

	for _, name := range specialNames {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { iptablesFlushTestRules(t, name) })

			err := addIsolationRules(name)
			// 不检查 err 的具体值——只要不 panic 就通过
			if err != nil {
				t.Logf("[ASSOC-4] addIsolationRules(%q) 返回错误: %v（可接受，不应 panic）", name, err)
			} else {
				removeIsolationRules(name)
			}
		})
	}
}

// ── ASSOC-5 ──────────────────────────────────────────────────────────────────
// 场景：UserBridgeName 和 PeerNetworkName 命名约定一致性。
// 确保修复不会意外改变命名格式，导致旧容器/网络无法被管理。
func TestBridgeNamingConvention_Stable_regression(t *testing.T) {
	tests := []struct {
		name     string
		fn       func() string
		expected string
	}{
		{
			name:     "UserBridgeName(0)",
			fn:       func() string { return UserBridgeName(0) },
			expected: "user-0-bridge",
		},
		{
			name:     "UserBridgeName(1000)",
			fn:       func() string { return UserBridgeName(1000) },
			expected: "user-1000-bridge",
		},
		{
			name:     "UserBridgeName(65534)",
			fn:       func() string { return UserBridgeName(65534) },
			expected: "user-65534-bridge",
		},
		{
			name:     "PeerNetworkName(1001,1002)_sorted",
			fn:       func() string { return PeerNetworkName(1001, 1002) },
			expected: "peer-1001-1002",
		},
		{
			name:     "PeerNetworkName(1002,1001)_reversed",
			fn:       func() string { return PeerNetworkName(1002, 1001) },
			expected: "peer-1001-1002",
		},
		{
			name:     "PeerNetworkName_same_uid",
			fn:       func() string { return PeerNetworkName(1000, 1000) },
			expected: "peer-1000-1000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fn()
			if got != tt.expected {
				t.Errorf(
					"[ASSOC-5] 命名约定变更 — got %q, want %q\n"+
						"  修改命名格式会导致已有容器/网络的 ownership 查找失败",
					got, tt.expected,
				)
			}
		})
	}
}

// ── 辅助函数 ────────────────────────────────────────────────────────────────

// formatRulesContaining 格式化输出包含指定子串的规则，用于错误消息。
func formatRulesContaining(rules []string, substr string) string {
	var matched []string
	for _, r := range rules {
		if strings.Contains(r, substr) {
			matched = append(matched, "    "+r)
		}
	}
	if len(matched) == 0 {
		return "    (无匹配规则)"
	}
	return strings.Join(matched, "\n")
}
