package isolation

// ══════════════════════════════════════════════════════════════════════════════
// Bug 复现与回归测试：内存注入与 CPU 注入的语义对称性缺失
// ──────────────────────────────────────────────────────────────────────────────
//
// 【触发场景】
//   docker container run -d --rm --name test_mem_limit3 \
//       --memory 1000m alpine:latest sleep 10
//   用户 bob，配额 cpu_cores:4.0, mem_mb:3072
//   系统默认 defaults: cpu_cores:2.0, mem_mb:2048
//
// 【预期行为】
//   容器创建成功，内存设置为 1000m（用户显式指定，在配额 3072m 内）
//
// 【实际错误行为】
//   容器创建成功，docker inspect test_mem_limit3 查看内存为 2048m（= defaults.mem_mb）
//
// ──────────────────────────────────────────────────────────────────────────────
// 【根本原因 — 内存注入与 CPU 注入的对称性缺失】
//
//   CPU 注入（BUG-13 修复后，quota.go injectQuotaLimits）：
//     未指定 --cpus:
//       defaultNano = min(defaults.cpu_cores, quota.CPUCores) * 1e9
//       注入 defaultNano  ← 注入"系统默认值"，而非"配额上限"
//     已指定 --cpus：保留用户值
//
//   内存注入（当前实现，存在缺陷）：
//     未指定 --memory:
//       finalMemBytes = quota.MemMB * 1024 * 1024  ← 注入"配额上限 3072m"
//     已指定 --memory:
//       finalMemBytes = req.HostConfig.Memory       ← 理论上保留用户值
//
//   缺陷 A（主要 Bug，与 BUG-13 对称）：
//     用户未指定 --memory 时，应注入 defaults.mem_mb（2048m），而非配额上限（3072m）。
//     对应 Red Test 1 + 2。
//
//   缺陷 B（用户描述的 Bug）：
//     用户指定 --memory 1000m（低于 defaults 2048m，在配额 3072m 内）时，
//     若注入逻辑错误地将 defaults.mem_mb 视为"兜底最低值"，会将 1000m 覆盖为 2048m。
//     修复原则：用户显式指定的内存值，只要不超过配额上限，必须原样保留。
//     对应 Red Test 3。
//
// 【本文件测试结构】
//   Red Test 1 — 缺陷A：未指定 --memory，注入配额上限而非系统默认值
//   Red Test 2 — 缺陷A：QuotaCheckResult.InjectedMemMB 应反映 defaults，而非配额
//   Red Test 3 — 缺陷B：用户指定 --memory 1000m（< defaults）必须原样保留
//   Regression 1 — 用户指定 1500m（< defaults 2048m，在配额内）→ 保留 1500m
//   Regression 2 — 用户指定 2049m（> defaults，< quota）→ 保留 2049m
//   Regression 3 — 用户指定 3072m（= quota 上限）→ 保留 3072m
//   Regression 4 — 用户指定 2048m（= defaults）→ 保留 2048m
//   Regression 5 — 超出配额（3073m > quota 3072m）→ 被拒绝
//   Regression 6 — GetQuota(bob) 返回正确的用户配额（3072m，非 defaults 2048m）
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"encoding/json"
	"fmt"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// ── YAML 固定配置 ──────────────────────────────────────────────────────────────

// bob 配额 mem_mb:3072（高于系统默认 2048），cpu_cores:4.0（高于物理机 2 核）
const yamlBobMemQuota3072_Default2048 = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
users:
  bob:
    cpu_cores: 4.0
    mem_mb: 3072
`

// 无用户条目，仅有默认配额（供对照）
const yamlDefaultMemOnly_2048 = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
`

// ── 辅助 ──────────────────────────────────────────────────────────────────────

func newMemBelowDefaultDB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mustLoadMemBobQM(t *testing.T, yaml string) *QuotaManager {
	t.Helper()
	path := writeTempQuotaYAML(t, yaml)
	qm, err := LoadQuotaManager(path)
	if err != nil {
		t.Fatalf("LoadQuotaManager: %v", err)
	}
	return qm
}

// injectedMemBytes 从注入后的请求体中读取 HostConfig.Memory（字节）
func injectedMemBytes(t *testing.T, body []byte) int64 {
	t.Helper()
	var req containerCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal injected body: %v", err)
	}
	return req.HostConfig.Memory
}

// ══════════════════════════════════════════════════════════════════════════════
// Red Test 1 — 缺陷A：未指定 --memory 时，注入了配额上限而非系统默认值
// ──────────────────────────────────────────────────────────────────────────────
//
// 精确复现：bob 仅指定 --memory 1000m（在配额内），代理应注入 1000m。
// 此测试同时覆盖 "未指定内存时注入系统默认而非配额上限" 的行为期望。
//
// 当前代码行为（缺陷）：
//   未指定 --memory → finalMemBytes = quota.MemMB * 1024 * 1024 = 3072m（配额上限）
//   正确行为：finalMemBytes = defaults.mem_mb * 1024 * 1024 = 2048m（系统默认）
//
// 断言失败：说明 Bug 存在（当前代码注入了 3072m）
// 断言通过：说明 Bug 已修复（注入 2048m = defaults.mem_mb）

func TestBug_BobNoMemFlag_InjectsQuotaCeilingInsteadOfDefault_Red(t *testing.T) {
	db := newMemBelowDefaultDB(t)
	qm := mustLoadMemBobQM(t, yamlBobMemQuota3072_Default2048)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)

	// 前置确认：bob 配额 3072m，defaults 2048m
	if quota.MemMB != 3072 {
		t.Fatalf("precondition: bob MemMB = %d, want 3072", quota.MemMB)
	}
	defaultMemMB := qm.GetDefaultQuota().MemMB
	if defaultMemMB != 2048 {
		t.Fatalf("precondition: defaults MemMB = %d, want 2048", defaultMemMB)
	}

	// bob 未指定 --memory（空 HostConfig，模拟无内存参数的容器创建请求）
	body := []byte(`{"HostConfig":{}}`)

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores, qm.GetDefaultQuota().MemMB)
	if err != nil {
		t.Fatalf("CheckAndInjectQuota error: %v", err)
	}
	if !qr.Allowed {
		t.Fatalf("empty request should be allowed: %s", qr.DeniedResource)
	}

	got := injectedMemBytes(t, newBody)
	wantDefault := int64(defaultMemMB) * 1024 * 1024 // 2048m（系统默认）
	buggyValue := int64(quota.MemMB) * 1024 * 1024   // 3072m（配额上限）

	// ── 断言（RED）：应注入 defaults.mem_mb = 2048m，而非 quota.MemMB = 3072m ─────
	//
	// 修复前（当前代码）：got = 3072m（注入配额上限，与 CPU BUG-13 修复前行为相同）
	// 修复后：got = 2048m（注入 min(defaults.mem_mb, quota.MemMB) = min(2048,3072) = 2048m）
	if got == buggyValue {
		t.Errorf(
			"[BUG] 未指定 --memory 时，注入了配额上限而非系统默认值\n"+
				"  injected Memory = %d bytes (%dM) = quota.MemMB（配额上限）\n"+
				"  want             = %d bytes (%dM) = defaults.mem_mb（系统默认）\n"+
				"\n"+
				"  bob.mem_mb:3072 是配额上限（用户可显式请求的最大值），\n"+
				"  不指定 --memory 时应注入系统默认值（2048m），而非配额上限（3072m）。\n"+
				"  这与 CPU BUG-13 修复的语义一致：\n"+
				"    未指定 --cpus → 注入 min(defaults.cpu_cores, quota.CPUCores)\n"+
				"    未指定 --memory → 应注入 min(defaults.mem_mb, quota.MemMB)\n"+
				"\n"+
				"  修复方向：injectQuotaLimits 增加 defaultMemMB float64 参数，\n"+
				"  未指定内存时注入 min(defaultMemMB, quota.MemMB)，而非 quota.MemMB",
			got, got/1024/1024,
			wantDefault, wantDefault/1024/1024,
		)
	} else if got != wantDefault {
		t.Errorf(
			"injected Memory = %d bytes (%dM), want %d bytes (%dM = defaults.mem_mb)\n"+
				"  未指定内存时应注入系统默认值，不超过用户配额上限",
			got, got/1024/1024, wantDefault, wantDefault/1024/1024,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Red Test 2 — 缺陷A：QuotaCheckResult.InjectedMemMB 应反映 defaults，而非配额上限
// ──────────────────────────────────────────────────────────────────────────────
//
// 验证 QuotaCheckResult 中的审计字段也正确反映注入值。
// 修复前：InjectedMemMB = 3072（quota.MemMB，配额上限）
// 修复后：InjectedMemMB = 2048（defaults.mem_mb，系统默认）

func TestBug_BobNoMemFlag_QuotaResultInjectedMemMB_ShouldBeDefault_Red(t *testing.T) {
	db := newMemBelowDefaultDB(t)
	qm := mustLoadMemBobQM(t, yamlBobMemQuota3072_Default2048)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)
	body := []byte(`{"HostConfig":{}}`) // 未指定 --memory

	_, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores, qm.GetDefaultQuota().MemMB)
	if err != nil {
		t.Fatalf("CheckAndInjectQuota error: %v", err)
	}
	if !qr.Allowed {
		t.Fatalf("empty request should be allowed: %s", qr.DeniedResource)
	}

	wantInjectedMB := int64(2048) // defaults.mem_mb
	buggyValue := int64(3072)     // quota.MemMB（配额上限，注入值错误）

	// ── 断言（RED）：InjectedMemMB 应为 defaults.mem_mb = 2048，而非 quota.MemMB = 3072 ─
	//
	// 修复前：qr.InjectedMemMB = 3072（配额上限）
	// 修复后：qr.InjectedMemMB = 2048（系统默认值）
	if qr.InjectedMemMB == buggyValue {
		t.Errorf(
			"[BUG] QuotaCheckResult.InjectedMemMB = %d (quota.MemMB，配额上限)\n"+
				"  want = %d (defaults.mem_mb，系统默认)\n"+
				"  审计日志将记录错误的注入值，掩盖内存注入行为",
			qr.InjectedMemMB, wantInjectedMB,
		)
	} else if qr.InjectedMemMB != wantInjectedMB {
		t.Errorf(
			"qr.InjectedMemMB = %d, want %d (defaults.mem_mb)",
			qr.InjectedMemMB, wantInjectedMB,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Red Test 3 — 缺陷B：用户指定 --memory 1000m（低于 defaults 2048m）被覆盖为 2048m
// ──────────────────────────────────────────────────────────────────────────────
//
// 精确复现用户命令：
//   docker container run -d --rm --name test_mem_limit3 --memory 1000m alpine:latest sleep 10
//
// 关键条件：1000m < defaults.mem_mb(2048m) < quota.MemMB(3072m)
//
// 修复原则：用户显式指定内存值，只要不超过配额上限，必须原样保留。
// 代理不应将 defaults.mem_mb 视为"注入兜底下限"。
//
// 断言失败（[BUG] 分支）：注入了 2048m（defaults），而非用户请求的 1000m
// 断言通过：注入了 1000m（用户指定值被正确保留）

func TestBug_BobMemory1000m_BelowDefault2048m_MustBePreserved_Red(t *testing.T) {
	db := newMemBelowDefaultDB(t)
	qm := mustLoadMemBobQM(t, yamlBobMemQuota3072_Default2048)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)

	// 前置确认：满足触发条件 1000m < 2048m < 3072m
	if quota.MemMB != 3072 {
		t.Fatalf("precondition: bob MemMB = %d, want 3072", quota.MemMB)
	}
	defaultMemMB := qm.GetDefaultQuota().MemMB
	if defaultMemMB != 2048 {
		t.Fatalf("precondition: defaults MemMB = %d, want 2048", defaultMemMB)
	}

	// 模拟 docker container run --memory 1000m
	// Docker CLI 将 1000m 转换为字节: 1000 * 1024 * 1024 = 1048576000
	const requestedMB = int64(1000)
	requestedBytes := requestedMB * 1024 * 1024
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, requestedBytes))

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores, qm.GetDefaultQuota().MemMB)

	// ── 断言 1：代理层必须允许（1000m < quota 3072m）──────────────────────────
	if err != nil {
		t.Fatalf(
			"request denied: %v\n"+
				"  bob quota=3072m, requested=1000m: must be allowed\n"+
				"  denial indicates quota check is using wrong MemMB",
			err,
		)
	}
	if qr != nil && !qr.Allowed {
		t.Fatalf(
			"Allowed=false, DeniedResource=%q\n"+
				"  1000m << bob quota 3072m: should be allowed",
			qr.DeniedResource,
		)
	}

	got := injectedMemBytes(t, newBody)
	defaultBytes := int64(defaultMemMB) * 1024 * 1024 // 2048m

	// ── 断言 2（RED）：用户指定值 1000m 必须保留，不得被 defaults 2048m 覆盖 ─────
	//
	// 修复前（BUG 路径）：
	//   某些注入实现将 defaults.mem_mb 作为"兜底最低值"：
	//     if req.Memory < defaultMemBytes { finalMemBytes = defaultMemBytes }
	//   → 1000m < 2048m → 注入 2048m ← BUG（用户指定值被覆盖）
	//
	// 修复后（正确行为）：
	//   用户显式指定了 --memory 1000m → 保留 1000m
	//   代理只在未指定时注入默认值，不做"最低值强制"
	if got == defaultBytes {
		t.Errorf(
			"[BUG] 用户指定 --memory 1000m，但内存被覆盖为 defaults.mem_mb 2048m\n"+
				"  injected Memory = %d bytes = %dM (defaults.mem_mb)\n"+
				"  want             = %d bytes = %dM (user requested)\n"+
				"\n"+
				"  复现命令:\n"+
				"    docker container run --memory 1000m alpine:latest sleep 10\n"+
				"    docker inspect ... → 内存显示 2048M（而非 1000M）\n"+
				"\n"+
				"  根本原因：注入逻辑错误地将 defaults.mem_mb 当作最低内存下限，\n"+
				"  覆盖了用户的显式请求。\n"+
				"  修复：只有在用户未指定 --memory（Memory==0）时才注入默认值，\n"+
				"  不对用户已指定的值做下限强制",
			got, got/1024/1024,
			requestedBytes, requestedMB,
		)
	} else if got != requestedBytes {
		t.Errorf(
			"injected Memory = %d bytes (%dM), want %d bytes (%dM)\n"+
				"  user specified --memory 1000m: injected value must match exactly",
			got, got/1024/1024, requestedBytes, requestedMB,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 1 — 用户指定 1500m（< defaults 2048m，在配额 3072m 内）→ 保留 1500m
// ──────────────────────────────────────────────────────────────────────────────
//
// 边界：1500m 低于 defaults 但在 quota 内，代理必须原样保留。

func TestRegression_BobMemory1500m_BelowDefault_WithinQuota_Preserved(t *testing.T) {
	db := newMemBelowDefaultDB(t)
	qm := mustLoadMemBobQM(t, yamlBobMemQuota3072_Default2048)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)
	const wantMB = int64(1500)
	wantBytes := wantMB * 1024 * 1024
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, wantBytes))

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores, qm.GetDefaultQuota().MemMB)
	if err != nil {
		t.Fatalf(
			"request denied: %v\n"+
				"  bob quota=3072m, requested=1500m: must be allowed",
			err,
		)
	}
	if qr != nil && !qr.Allowed {
		t.Fatalf("Allowed=false: resource=%s", qr.DeniedResource)
	}

	got := injectedMemBytes(t, newBody)
	if got != wantBytes {
		t.Errorf(
			"injected Memory = %d bytes (%dM), want %d bytes (%dM)\n"+
				"  --memory 1500m (< defaults 2048m, within quota 3072m) must be preserved\n"+
				"  proxy must not override user value with defaults or quota ceiling",
			got, got/1024/1024, wantBytes, wantMB,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 2 — 用户指定 2049m（> defaults 2048m，< quota 3072m）→ 保留 2049m
// ──────────────────────────────────────────────────────────────────────────────
//
// 验证高于 defaults 但低于 quota 的值被正确保留（基础功能，不受 Bug 影响）。

func TestRegression_BobMemory2049m_AboveDefault_WithinQuota_Preserved(t *testing.T) {
	db := newMemBelowDefaultDB(t)
	qm := mustLoadMemBobQM(t, yamlBobMemQuota3072_Default2048)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)
	const wantMB = int64(2049)
	wantBytes := wantMB * 1024 * 1024
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, wantBytes))

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores, qm.GetDefaultQuota().MemMB)
	if err != nil {
		t.Fatalf("request denied for 2049m (within quota 3072m): %v", err)
	}
	if qr != nil && !qr.Allowed {
		t.Fatalf("Allowed=false: %s", qr.DeniedResource)
	}

	got := injectedMemBytes(t, newBody)
	if got != wantBytes {
		t.Errorf(
			"injected Memory = %d bytes (%dM), want %d bytes (%dM)\n"+
				"  --memory 2049m (> defaults 2048m, within quota 3072m) must be preserved",
			got, got/1024/1024, wantBytes, wantMB,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 3 — 用户指定 3072m（= quota 上限）→ 保留 3072m（不被拒绝）
// ──────────────────────────────────────────────────────────────────────────────
//
// 边界：恰好等于配额上限，必须允许（inclusive 边界）。

func TestRegression_BobMemory3072m_EqualQuota_Preserved(t *testing.T) {
	db := newMemBelowDefaultDB(t)
	qm := mustLoadMemBobQM(t, yamlBobMemQuota3072_Default2048)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)
	const wantMB = int64(3072)
	wantBytes := wantMB * 1024 * 1024
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, wantBytes))

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores, qm.GetDefaultQuota().MemMB)
	if err != nil {
		t.Fatalf(
			"request denied for 3072m = quota ceiling: %v\n"+
				"  quota boundary is inclusive: 3072m must be allowed",
			err,
		)
	}
	if qr != nil && !qr.Allowed {
		t.Fatalf("Allowed=false at quota ceiling 3072m: %s", qr.DeniedResource)
	}

	got := injectedMemBytes(t, newBody)
	if got != wantBytes {
		t.Errorf(
			"injected Memory = %d bytes (%dM), want %d bytes (%dM)\n"+
				"  --memory 3072m (= quota ceiling) must be preserved exactly",
			got, got/1024/1024, wantBytes, wantMB,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 4 — 用户指定 2048m（= defaults.mem_mb）→ 保留 2048m
// ──────────────────────────────────────────────────────────────────────────────
//
// 验证：恰好等于 defaults 的内存值也被正确保留（不被注入逻辑干扰）。

func TestRegression_BobMemory2048m_EqualDefault_Preserved(t *testing.T) {
	db := newMemBelowDefaultDB(t)
	qm := mustLoadMemBobQM(t, yamlBobMemQuota3072_Default2048)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)
	const wantMB = int64(2048)
	wantBytes := wantMB * 1024 * 1024
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, wantBytes))

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores, qm.GetDefaultQuota().MemMB)
	if err != nil {
		t.Fatalf("request denied for 2048m = defaults: %v", err)
	}
	if qr != nil && !qr.Allowed {
		t.Fatalf("Allowed=false at defaults boundary: %s", qr.DeniedResource)
	}

	got := injectedMemBytes(t, newBody)
	if got != wantBytes {
		t.Errorf(
			"injected Memory = %d bytes (%dM), want %d bytes (%dM)\n"+
				"  --memory 2048m (= defaults.mem_mb) must be preserved",
			got, got/1024/1024, wantBytes, wantMB,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 5 — 超出配额（3073m > quota 3072m）→ 必须被拒绝
// ──────────────────────────────────────────────────────────────────────────────
//
// 确保修复不影响配额上限强制执行（防止"按下葫芦起了瓢"）。

func TestRegression_BobMemory3073m_ExceedsQuota_Denied(t *testing.T) {
	db := newMemBelowDefaultDB(t)
	qm := mustLoadMemBobQM(t, yamlBobMemQuota3072_Default2048)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, int64(3073)*1024*1024))

	_, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores, qm.GetDefaultQuota().MemMB)

	if err == nil {
		t.Errorf(
			"3073m > quota 3072m should be denied, but got nil error\n"+
				"  quota ceiling enforcement must not be affected by any fix",
		)
		return
	}
	if qr != nil && qr.DeniedResource != "memory" {
		t.Errorf(
			"DeniedResource = %q, want \"memory\"\n"+
				"  memory exceeded quota, denial resource must be memory",
			qr.DeniedResource,
		)
	}

	var qe *QuotaExceededError
	if !isQuotaExceededError(err, &qe) {
		t.Errorf("error type = %T, want *QuotaExceededError: %v", err, err)
		return
	}
	if qe.Resource != "memory" {
		t.Errorf("QuotaExceededError.Resource = %q, want \"memory\"", qe.Resource)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 6 — GetQuota(bob) 返回正确的用户配额（3072m，非 defaults 2048m）
// ──────────────────────────────────────────────────────────────────────────────
//
// 验证：quota.yaml 中 bob.mem_mb:3072 被正确加载并覆盖 defaults.mem_mb:2048。
// 若此测试失败，说明 GetQuota 配额加载本身有问题，是 Bug 根源之一。

func TestRegression_GetQuota_BobMemMB_Returns3072_NotDefault(t *testing.T) {
	qm := mustLoadMemBobQM(t, yamlBobMemQuota3072_Default2048)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	got := qm.GetQuota(bob)

	// ── 断言 1：内存配额必须使用 bob 的用户条目（3072），非 defaults（2048）──────
	if got.MemMB != 3072 {
		t.Errorf(
			"GetQuota(bob).MemMB = %d, want 3072\n"+
				"  bob.mem_mb:3072 in quota.yaml should override defaults.mem_mb:2048\n"+
				"  If 2048: GetQuota is not applying user-level quota override",
			got.MemMB,
		)
	}

	// ── 断言 2：CPU 配额同样使用 bob 的条目（4.0），非 defaults（2.0）──────────
	if got.CPUCores != 4.0 {
		t.Errorf(
			"GetQuota(bob).CPUCores = %.2f, want 4.0\n"+
				"  bob.cpu_cores:4.0 should override defaults.cpu_cores:2.0",
			got.CPUCores,
		)
	}

	// ── 断言 3：defaults 不受 bob 用户条目影响（隔离验证）────────────────────
	defaults := qm.GetDefaultQuota()
	if defaults.MemMB != 2048 {
		t.Errorf(
			"GetDefaultQuota().MemMB = %d, want 2048\n"+
				"  defaults must not be modified by user entries",
			defaults.MemMB,
		)
	}
}
