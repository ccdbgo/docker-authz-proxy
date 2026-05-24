package isolation

// ── Bug：未指定 --cpus 时代理注入用户配额上限而非系统默认值 ──────────────────
//
// 触发场景：
//   bob 配额 cpu_cores:4.0（配额上限），系统默认 defaults.cpu_cores:2.0，
//   服务器物理 CPU 仅 2 核。bob 执行：
//     docker run --memory 2048m alpine sleep 10   ← 未指定 --cpus
//
// 错误信息：
//   "range of CPUs is from 0.01 to 2.00, as there are only 2 CPUs available"
//
// 根本原因（injectQuotaLimits, quota.go）：
//
//   CheckAndInjectQuota 签名：
//     func CheckAndInjectQuota(body []byte, quota UserQuota, uid int, db ...) (...)
//   仅接收 quota UserQuota（用户有效配额），不携带 defaults 信息。
//
//   quota.CPUCores 同时承担了两种语义：
//     1. 配额上限（enforcement）：用户显式指定 --cpus 时不得超过 4.0  ← 正确
//     2. 默认注入值（injection）：用户未指定 --cpus 时注入 4.0         ← 错误！
//
//   执行路径（reqNano == 0，未指定 --cpus）：
//     Step 3  quota check：条件 reqNano > 0 → FALSE，跳过
//     Step 3b physical check：条件 reqNano > 0 → FALSE，跳过
//     injectQuotaLimits：
//       quotaNano = int64(4.0 * 1e9) = 4_000_000_000   ← bob 的配额上限
//       hostConfig["NanoCpus"] = 4_000_000_000          ← 直接注入上限
//     Docker daemon 校验：NanaCpus(4e9) > physCPU(2e9) → 拒绝
//
//   预期行为：
//     未指定 --cpus → 注入 defaults.cpu_cores * 1e9 = 2_000_000_000
//     bob 的 cpu_cores:4.0 仅作为"bob 可以显式请求最多 4 核"的上限
//
// 修复方向：
//   CheckAndInjectQuota / injectQuotaLimits 需额外接收 defaultCPUCores float64
//   或在 UserQuota 中增加 DefaultCPUCores 字段（由 GetQuota 填入 defaults.CPUCores）。
//   injection 分支改为：
//     injectedNano = int64(defaultCPUCores * 1e9)  ← 注入默认值，不是 quota 上限

import (
	"encoding/json"
	"fmt"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// ── YAML 固定配置 ──────────────────────────────────────────────────────────────

// bob 配额上限 4 核（超过物理机 2 核），系统默认 2 核
const yamlBobQuota4_Default2 = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
users:
  bob:
    cpu_cores: 4.0
    mem_mb: 3072
`

// bob 配额上限 1 核（低于物理机，验证正常路径）
const yamlBobQuota1_Default2 = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
users:
  bob:
    cpu_cores: 1.0
    mem_mb: 3072
`

// 无用户条目，仅有默认配额
const yamlDefaultOnly_CPU2 = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
`

// ── 辅助 ──────────────────────────────────────────────────────────────────────

func newBobTestDB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mustLoadBobQM(t *testing.T, yaml string) *QuotaManager {
	t.Helper()
	path := writeTempQuotaYAML(t, yaml)
	qm, err := LoadQuotaManager(path)
	if err != nil {
		t.Fatalf("LoadQuotaManager: %v", err)
	}
	return qm
}

// injectedNanoCPUs 从响应体中解析 HostConfig.NanoCPUs
func injectedNanoCPUs(t *testing.T, body []byte) int64 {
	t.Helper()
	var req containerCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal injected body: %v", err)
	}
	return req.HostConfig.NanoCPUs
}

// ── 1. Red Test：未指定 --cpus 时注入了用户配额上限而非系统默认值 ────────────
//
// 预期行为：注入 defaults.cpu_cores = 2.0e9
// 当前行为：注入 quota.CPUCores  = 4.0e9（bug）
// 断言失败：说明 Bug 存在
// 断言通过：说明 Bug 已修复

func TestBug_BobNoCPUFlag_InjectsQuotaCeilingInsteadOfDefault_Red(t *testing.T) {
	db := newBobTestDB(t)
	qm := mustLoadBobQM(t, yamlBobQuota4_Default2)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)

	// 确认前置条件：bob 配额确实是 4.0
	if quota.CPUCores != 4.0 {
		t.Fatalf("precondition: bob CPUCores = %.2f, want 4.0", quota.CPUCores)
	}

	// bob 仅指定内存，未指定 --cpus（复现生产场景）
	body := []byte(`{"HostConfig":{"Memory":2147483648}}`) // 2048m

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores)
	if err != nil {
		t.Fatalf("CheckAndInjectQuota error: %v", err)
	}
	if !qr.Allowed {
		t.Fatalf("request should be allowed (2048m <= bob 3072m quota): %s", qr.DeniedResource)
	}

	got := injectedNanoCPUs(t, newBody)

	// ── 断言（RED）：应注入 defaults.cpu_cores = 2.0，而非 quota.CPUCores = 4.0 ─
	//
	// 修复前：got = 4_000_000_000（bob 的配额上限被当作注入值）
	// 修复后：got = 2_000_000_000（系统默认值，Docker 接受）
	wantDefault := int64(2.0 * 1e9)
	buggyValue := int64(4.0 * 1e9)

	if got == buggyValue {
		t.Errorf(
			"[BUG] injected NanaCpus = %d (%.2f cores) = bob's quota ceiling\n"+
				"  want NanaCpus = %d (%.2f cores) = defaults.cpu_cores\n"+
				"\n"+
				"  bob's cpu_cores:4.0 is a quota CEILING (max bob can explicitly request).\n"+
				"  When --cpus is NOT specified, proxy should inject defaults.cpu_cores=2.0,\n"+
				"  not bob's quota maximum.\n"+
				"\n"+
				"  Current execution path (reqNano==0, no --cpus flag):\n"+
				"    Step 3 quota check:    reqNano>0 → FALSE → SKIPPED\n"+
				"    Step 3b physical check:reqNano>0 → FALSE → SKIPPED\n"+
				"    injectQuotaLimits: quotaNano = quota.CPUCores*1e9 = 4e9  ← injected\n"+
				"    Docker daemon:     NanaCpus(4e9) > physCPU(2e9)  → REJECTED\n"+
				"\n"+
				"  Fix: injection branch should use defaultCPUCores*1e9, not quota.CPUCores*1e9",
			got, float64(got)/1e9,
			wantDefault, float64(wantDefault)/1e9,
		)
	} else if got != wantDefault {
		t.Errorf(
			"injected NanaCpus = %d (%.2f cores), want %d (%.2f cores = defaults.cpu_cores)",
			got, float64(got)/1e9, wantDefault, float64(wantDefault)/1e9,
		)
	}
}

// ── 2. Red Test：端到端复现生产报错 ─────────────────────────────────────────
//
// 验证：注入 4.0e9 > physNano 时，Docker 会返回 CPU 错误
// （此处通过断言 NanaCpus > physNano 来模拟 Docker 的拒绝条件）

func TestBug_BobMemOnly_InjectedNanaCpusWouldBeRejectedByDocker_Red(t *testing.T) {
	db := newBobTestDB(t)
	qm := mustLoadBobQM(t, yamlBobQuota4_Default2)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)
	body := []byte(`{"HostConfig":{"Memory":2147483648}}`)

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores)
	if err != nil {
		t.Fatalf("CheckAndInjectQuota error: %v", err)
	}
	if !qr.Allowed {
		t.Fatalf("quota check denied unexpectedly: %s", qr.DeniedResource)
	}

	got := injectedNanoCPUs(t, newBody)
	defaultNano := int64(2.0 * 1e9)

	// ── 断言（RED）：注入值应等于系统默认（2e9），而非 quota 上限（4e9）────────
	//
	// 修复前：got = 4e9（注入 bob 的配额上限）
	// 修复后：got = 2e9（注入系统默认值，Docker daemon 接受）
	if got != defaultNano {
		t.Errorf(
			"[BUG] injected NanaCpus = %d (%.2f cores)\n"+
				"  want = %d (%.2f cores = defaults.cpu_cores)\n"+
				"\n"+
				"  Production error reproduced:\n"+
				"    docker run --memory 2048m alpine sleep 10\n"+
				"    → 'range of CPUs is from 0.01 to 2.00, as there are only 2 CPUs available'\n"+
				"\n"+
				"  Proxy injected bob's quota ceiling (4.0 cores) instead of defaults (2.0 cores).\n"+
				"  Docker daemon rejects: injected NanaCpus exceeds physical CPU capacity.\n"+
				"  A pure memory request should never trigger a CPU error.",
			got, float64(got)/1e9,
			defaultNano, float64(defaultNano)/1e9,
		)
	}
}

// ── 3. 回归 #1：bob 显式指定 --cpus 3（在配额 4.0 内）→ 保留请求值 ─────────
//
// 确保修复后显式指定的 CPU 值被原样保留，不被默认值覆盖。

func TestRegression_BobExplicitCPU3_WithinQuota4_Preserved(t *testing.T) {
	db := newBobTestDB(t)
	qm := mustLoadBobQM(t, yamlBobQuota4_Default2)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)

	// bob 显式指定 3 核（在配额 4.0 内，高于默认 2.0）
	requestedNano := int64(3.0 * 1e9)
	body := []byte(fmt.Sprintf(`{"HostConfig":{"NanoCpus":%d}}`, requestedNano))

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores)
	if err != nil {
		t.Fatalf("CheckAndInjectQuota error: %v", err)
	}
	if !qr.Allowed {
		t.Fatalf("3 cores within quota 4.0 should be allowed, denied: %s", qr.DeniedResource)
	}

	got := injectedNanoCPUs(t, newBody)
	if got != requestedNano {
		t.Errorf(
			"explicit --cpus 3 not preserved: got NanaCpus=%d (%.2f), want %d (3.00)\n"+
				"  Explicit user requests should never be overridden by defaults injection",
			got, float64(got)/1e9, requestedNano,
		)
	}
}

// ── 4. 回归 #2：bob 显式指定 --cpus 5（超出配额 4.0）→ 被拒绝 ───────────────
//
// 确保配额上限强制执行不受修复影响。

func TestRegression_BobExplicitCPU5_ExceedsQuota4_Denied(t *testing.T) {
	db := newBobTestDB(t)
	qm := mustLoadBobQM(t, yamlBobQuota4_Default2)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)

	// bob 显式请求 5 核（超出 quota.CPUCores = 4.0）
	body := []byte(fmt.Sprintf(`{"HostConfig":{"NanoCpus":%d}}`, int64(5.0*1e9)))

	_, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores)

	if err == nil || qr.Allowed {
		t.Errorf(
			"5 cores > quota 4.0 should be denied, but got Allowed=true\n"+
				"  Quota ceiling enforcement must not be affected by the default-injection fix",
		)
	}
	if qr != nil && qr.DeniedResource != "cpu" {
		t.Errorf("DeniedResource = %q, want \"cpu\"", qr.DeniedResource)
	}
}

// ── 5. 回归 #3：无用户条目（charlie）→ 注入系统默认 2.0 ─────────────────────
//
// 确保无用户条目时，未指定 --cpus 的容器注入 defaults.cpu_cores。

func TestRegression_NoUserEntry_NoCPUFlag_InjectsDefault(t *testing.T) {
	db := newBobTestDB(t)
	qm := mustLoadBobQM(t, yamlBobQuota4_Default2) // bob 有条目，charlie 没有
	charlie := &auth.CallerIdentity{RealUsername: "charlie", RealUID: 1003}

	quota := qm.GetQuota(charlie)

	// charlie 无专属配额，应回退到 defaults：cpu_cores=2.0, mem_mb=2048
	if quota.CPUCores != 2.0 {
		t.Fatalf("precondition: charlie CPUCores = %.2f, want 2.0 (defaults)", quota.CPUCores)
	}

	body := []byte(`{"HostConfig":{}}`) // 未指定任何资源

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1003, db, qm.GetDefaultQuota().CPUCores)
	if err != nil {
		t.Fatalf("CheckAndInjectQuota error: %v", err)
	}
	if !qr.Allowed {
		t.Fatalf("charlie (defaults) empty request should be allowed: %s", qr.DeniedResource)
	}

	got := injectedNanoCPUs(t, newBody)
	wantNano := int64(2.0 * 1e9)
	if got != wantNano {
		t.Errorf(
			"charlie (no user entry): injected NanaCpus = %d (%.2f cores), want %d (2.00 cores = defaults)\n"+
				"  Users without explicit quota entries should get defaults.cpu_cores injected",
			got, float64(got)/1e9, wantNano,
		)
	}
}

// ── 6. 回归 #4：bob 配额 1.0（低于默认 2.0）→ 注入 defaults，不超配额 ──────
//
// 验证：当 user.cpu_cores < defaults.cpu_cores 时的注入行为。
// 注入值应使用默认值（2.0），但不得超过用户配额上限（1.0）。
// 即：injected = min(defaults.cpu_cores, quota.CPUCores)。
//
// 注意：这个测试关注"用户配额上限 < 默认值"的边界情况，
// 确保修复不会引入"注入默认值反而超出用户自己的配额上限"的问题。

func TestRegression_BobQuota1_LessThanDefault2_NoCPUFlag_NotExceedQuota(t *testing.T) {
	db := newBobTestDB(t)
	qm := mustLoadBobQM(t, yamlBobQuota1_Default2)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)

	// 前置确认：bob 配额 1.0（低于默认 2.0）
	if quota.CPUCores != 1.0 {
		t.Fatalf("precondition: bob CPUCores = %.2f, want 1.0", quota.CPUCores)
	}

	body := []byte(`{"HostConfig":{}}`)

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores)
	if err != nil {
		t.Fatalf("CheckAndInjectQuota error: %v", err)
	}
	if !qr.Allowed {
		t.Fatalf("request should be allowed: %s", qr.DeniedResource)
	}

	got := injectedNanoCPUs(t, newBody)
	quotaMaxNano := int64(1.0 * 1e9)

	// 注入值不得超过 bob 的配额上限（1.0），否则违反隔离策略
	if got > quotaMaxNano {
		t.Errorf(
			"injected NanaCpus = %d (%.2f cores) exceeds bob's quota ceiling %d (1.00 core)\n"+
				"  When defaults.cpu_cores(2.0) > user quota(1.0), injection must respect the lower ceiling\n"+
				"  Correct injection: min(defaults=2.0, quota=1.0) = 1.0 core = %d NanaCpus",
			got, float64(got)/1e9, quotaMaxNano, quotaMaxNano,
		)
	}
}

// ── 7. 回归 #5：bob 未指定 --cpus，内存正常注入，请求应成功 ──────────────────
//
// 确保修复后"无 --cpus + 有 --memory"的请求整体成功，内存值被正确保留。

func TestRegression_BobMemOnly_AfterFix_MemoryPreserved_CPUFromDefault(t *testing.T) {
	db := newBobTestDB(t)
	qm := mustLoadBobQM(t, yamlBobQuota4_Default2)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)

	// 2048m（在 bob 3072m 配额内，复现生产命令）
	memBytes := int64(2048 * 1024 * 1024)
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, memBytes))

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores)

	// ── 断言 1：整体请求必须成功 ────────────────────────────────────────────
	if err != nil {
		t.Errorf(
			"CheckAndInjectQuota error: %v\n"+
				"  A pure memory request (--memory 2048m) must never fail with a CPU error\n"+
				"  after the fix: proxy should inject defaults.cpu_cores(2.0), Docker accepts it",
			err,
		)
		return
	}
	if !qr.Allowed {
		t.Errorf(
			"Allowed=false, DeniedResource=%q\n"+
				"  2048m <= bob quota 3072m: should be allowed",
			qr.DeniedResource,
		)
		return
	}

	var req containerCreateRequest
	if e := json.Unmarshal(newBody, &req); e != nil {
		t.Fatalf("unmarshal result: %v", e)
	}

	// ── 断言 2：内存值保留（不被覆盖） ─────────────────────────────────────
	if req.HostConfig.Memory != memBytes {
		t.Errorf(
			"Memory = %d, want %d (2048m must be preserved)",
			req.HostConfig.Memory, memBytes,
		)
	}

	// ── 断言 3：CPU 来自默认值，而非 quota 上限 ─────────────────────────────
	wantNano := int64(2.0 * 1e9)
	if req.HostConfig.NanoCPUs != wantNano {
		t.Errorf(
			"NanaCpus = %d (%.2f cores), want %d (%.2f cores = defaults.cpu_cores)\n"+
				"  Injected CPU must be defaults value, not bob's quota ceiling 4.0",
			req.HostConfig.NanoCPUs, float64(req.HostConfig.NanoCPUs)/1e9,
			wantNano, float64(wantNano)/1e9,
		)
	}
}
