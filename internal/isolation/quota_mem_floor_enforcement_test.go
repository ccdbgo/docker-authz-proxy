package isolation

// ══════════════════════════════════════════════════════════════════════════════
// Bug 复现与回归测试：用户指定 --memory 1024m 被 defaults.mem_mb(2048m) 错误覆盖
// ──────────────────────────────────────────────────────────────────────────────
//
// 【触发场景】
//   docker container run --memory 1024m alpine:latest sleep 10
//   用户 bob：quota.mem_mb=3072，defaults.mem_mb=2048
//   1024m < defaults(2048m) < quota(3072m)  ← 关键触发条件
//
// 【预期行为】
//   docker inspect 显示 Memory = 1073741824 bytes（= 1024m）
//
// 【实际错误行为】
//   docker inspect 显示 Memory = 2147483648 bytes（= 2048m = defaults.mem_mb）
//
// ──────────────────────────────────────────────────────────────────────────────
// 【根本原因 — defaults.mem_mb 被错误当作注入下限（floor）】
//
//   触发路径：
//     req.HostConfig.Memory = 1024 * 1024 * 1024 = 1,073,741,824 bytes
//     defaults.mem_mb       = 2048 MB            = 2,147,483,648 bytes
//     1,073,741,824 < 2,147,483,648  ← True！
//
//   错误实现（BUG-15 修复时可能引入的错误）：
//     if req.HostConfig.Memory == 0 {
//         finalMemBytes = min(defaultMemBytes, quotaBytes)  // 未指定，OK
//     } else if req.HostConfig.Memory < defaultMemBytes {
//         finalMemBytes = defaultMemBytes   // ← BUG：把 defaults 当最低值
//     } else {
//         finalMemBytes = req.HostConfig.Memory  // 保留用户值
//     }
//     结果：1024m < 2048m → finalMemBytes = 2048m ← 错误！
//
//   正确实现：
//     用户显式指定的内存值（Memory != 0），只要 ≤ quota 上限，
//     必须原样保留，不受 defaults.mem_mb 影响。
//     defaults.mem_mb 只作为"未指定时的注入基准值"，不是最低限制。
//
// ──────────────────────────────────────────────────────────────────────────────
// 【字节边界分析】
//   1024m = 1024 * 1024 * 1024 = 2^30 = 1,073,741,824 bytes  (1 GiB)
//   2048m = 2048 * 1024 * 1024 = 2^31 = 2,147,483,648 bytes  (2 GiB)
//   3072m = 3072 * 1024 * 1024         = 3,221,225,472 bytes  (3 GiB)
//
//   1024m 恰好是 2^30，是最易触发"幂次对齐检查"或"位运算 Bug"的值。
//   1024m 恰好是 defaults 2048m 的一半，可能触发误写的"半量检查"。
//
// 【本文件测试结构】
//   Red Test 1 — 核心复现：--memory 1024m 必须被保留，不被 2048m 覆盖
//   Red Test 2 — 字节精度：断言精确到字节，排除舍入误差
//   Regression 1 — 512m（< defaults 一半）→ 保留 512m
//   Regression 2 — 1023m（< defaults，非幂次）→ 保留 1023m
//   Regression 3 — 2047m（= defaults - 1m，边界-1）→ 保留 2047m
//   Regression 4 — 2048m（= defaults，边界值）→ 保留 2048m
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

// bob 配额 mem_mb:3072（> defaults:2048），cpu_cores:4.0
const yamlBobMem3072_Default2048_Floor = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
users:
  bob:
    cpu_cores: 4.0
    mem_mb: 3072
`

// ── 辅助 ──────────────────────────────────────────────────────────────────────

func newFloorTestDB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mustLoadFloorQM(t *testing.T, yaml string) *QuotaManager {
	t.Helper()
	path := writeTempQuotaYAML(t, yaml)
	qm, err := LoadQuotaManager(path)
	if err != nil {
		t.Fatalf("LoadQuotaManager: %v", err)
	}
	return qm
}

// assertMemoryPreserved 通用断言：注入后的 Memory 等于请求值
func assertMemoryPreserved(t *testing.T, newBody []byte, requestedBytes int64, label string) {
	t.Helper()
	var req containerCreateRequest
	if err := json.Unmarshal(newBody, &req); err != nil {
		t.Fatalf("unmarshal injected body: %v", err)
	}
	got := req.HostConfig.Memory
	if got != requestedBytes {
		t.Errorf(
			"[%s] injected Memory = %d bytes (%dM)\n"+
				"  want              = %d bytes (%dM)\n"+
				"  user-specified memory must be preserved exactly\n"+
				"  proxy must NOT use defaults.mem_mb as a minimum floor",
			label,
			got, got/1024/1024,
			requestedBytes, requestedBytes/1024/1024,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Red Test 1 — 核心复现：--memory 1024m 必须保留为 1024m，不得被 2048m 覆盖
// ──────────────────────────────────────────────────────────────────────────────
//
// 触发条件：1024m < defaults.mem_mb(2048m) < quota.MemMB(3072m)
//
// 修复前（BUG 路径）：
//   1073741824 < 2147483648（defaults）→ finalMemBytes = 2147483648 = 2048m ← BUG
// 修复后（正确行为）：
//   Memory != 0 → finalMemBytes = req.HostConfig.Memory = 1073741824 = 1024m ✓

func TestBug_BobMemory1024m_BelowDefault2048m_MustBePreserved_Red(t *testing.T) {
	db := newFloorTestDB(t)
	qm := mustLoadFloorQM(t, yamlBobMem3072_Default2048_Floor)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)
	defaultQM := qm.GetDefaultQuota()

	// ── 前置：验证触发条件成立 ──────────────────────────────────────────────
	if quota.MemMB != 3072 {
		t.Fatalf("precondition: bob MemMB = %d, want 3072", quota.MemMB)
	}
	if defaultQM.MemMB != 2048 {
		t.Fatalf("precondition: defaults MemMB = %d, want 2048", defaultQM.MemMB)
	}

	// 1024m = 2^30 bytes = 1 GiB
	// 关键：1024m < defaults(2048m) < quota(3072m)
	const requestedMB = int64(1024)
	requestedBytes := requestedMB * 1024 * 1024 // 1,073,741,824

	defaultBytes := int64(defaultQM.MemMB) * 1024 * 1024 // 2,147,483,648
	if requestedBytes >= defaultBytes {
		t.Fatalf("precondition failed: 1024m should be less than defaults 2048m")
	}

	// 模拟 docker container run --memory 1024m
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, requestedBytes))

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, defaultQM.CPUCores, defaultQM.MemMB)

	// ── 断言 1：代理必须允许（1024m < quota 3072m）──────────────────────────
	if err != nil {
		t.Fatalf(
			"request denied: %v\n"+
				"  bob quota=3072m, requested=1024m: must be allowed\n"+
				"  denial indicates quota MemMB may be wrong (%d, want 3072)",
			err, quota.MemMB,
		)
	}
	if qr != nil && !qr.Allowed {
		t.Fatalf(
			"Allowed=false, DeniedResource=%q\n"+
				"  1024m << quota 3072m: should always be allowed",
			qr.DeniedResource,
		)
	}

	// ── 断言 2（RED）：注入值必须是 1024m，不得是 defaults 2048m ──────────
	//
	// BUG 路径：
	//   req.Memory(1024m) < defaultMemBytes(2048m)
	//   → finalMemBytes = defaultMemBytes = 2147483648  ← 错误注入 defaults
	//   → docker inspect 显示 2048M（而非用户请求的 1024M）
	//
	// 正确路径：
	//   req.Memory != 0 → finalMemBytes = req.Memory = 1073741824
	//   → docker inspect 显示 1024M ✓
	var req containerCreateRequest
	if e := json.Unmarshal(newBody, &req); e != nil {
		t.Fatalf("unmarshal injected body: %v", e)
	}

	got := req.HostConfig.Memory

	if got == defaultBytes {
		t.Errorf(
			"[BUG] --memory 1024m 被 defaults.mem_mb 覆盖为 2048m\n"+
				"  injected Memory = %d bytes = %dM (defaults.mem_mb)\n"+
				"  want             = %d bytes = %dM (user requested)\n"+
				"\n"+
				"  触发条件：1024m < defaults.mem_mb(2048m) < quota.MemMB(3072m)\n"+
				"  字节分析：1073741824 < 2147483648（defaults floor）→ 错误覆盖\n"+
				"\n"+
				"  错误的修复方案（会引入此 Bug）：\n"+
				"    } else if req.HostConfig.Memory < defaultMemBytes {\n"+
				"        finalMemBytes = defaultMemBytes  // ← 这是 floor 逻辑，不应存在\n"+
				"\n"+
				"  正确修复方案：\n"+
				"    defaults.mem_mb 只用于「未指定 --memory 时的注入基准」，\n"+
				"    不是已指定值的最低限制。Memory!=0 时必须原样保留。",
			got, got/1024/1024,
			requestedBytes, requestedMB,
		)
	} else if got != requestedBytes {
		t.Errorf(
			"injected Memory = %d bytes (%dM), want %d bytes (%dM)\n"+
				"  user-specified --memory 1024m must be preserved exactly",
			got, got/1024/1024, requestedBytes, requestedMB,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Red Test 2 — 字节精度验证：QuotaCheckResult.InjectedMemMB 精确等于 1024
// ──────────────────────────────────────────────────────────────────────────────
//
// 验证审计记录层面：InjectedMemMB 必须准确反映注入的实际值（1024），
// 不能被 defaults 截断为 2048。
//
// 修复前：qr.InjectedMemMB = 2048（floor 强制后的值）
// 修复后：qr.InjectedMemMB = 1024（用户指定值）

func TestBug_BobMemory1024m_QuotaResult_InjectedMemMB_MustBe1024_Red(t *testing.T) {
	db := newFloorTestDB(t)
	qm := mustLoadFloorQM(t, yamlBobMem3072_Default2048_Floor)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)
	defaultQM := qm.GetDefaultQuota()

	requestedBytes := int64(1024) * 1024 * 1024
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, requestedBytes))

	_, qr, err := CheckAndInjectQuota(body, quota, 1002, db, defaultQM.CPUCores, defaultQM.MemMB)
	if err != nil {
		t.Fatalf("CheckAndInjectQuota error: %v", err)
	}
	if qr == nil || !qr.Allowed {
		t.Fatalf("request should be allowed")
	}

	wantInjectedMB := int64(1024)
	buggyValue := int64(2048) // defaults.mem_mb

	// ── 断言（RED）：InjectedMemMB 应为 1024，而非被 floor 强制为 2048 ────────
	if qr.InjectedMemMB == buggyValue {
		t.Errorf(
			"[BUG] QuotaCheckResult.InjectedMemMB = %d (= defaults.mem_mb，被 floor 强制)\n"+
				"  want = %d (= user requested 1024m)\n"+
				"  审计日志将记录 2048 而非用户实际请求的 1024，掩盖内存覆盖行为",
			qr.InjectedMemMB, wantInjectedMB,
		)
	} else if qr.InjectedMemMB != wantInjectedMB {
		t.Errorf(
			"qr.InjectedMemMB = %d, want %d (user specified 1024m)",
			qr.InjectedMemMB, wantInjectedMB,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 1 — --memory 512m（< defaults 一半）→ 保留 512m
// ──────────────────────────────────────────════════════════════════════════════
//
// 边界：512m = 1/4 * defaults(2048m)，是典型的"明显低于 defaults"的请求。
// 若代码有 floor 逻辑，此值最容易被覆盖为 defaults。

func TestRegression_BobMemory512m_FarBelowDefault_Preserved(t *testing.T) {
	db := newFloorTestDB(t)
	qm := mustLoadFloorQM(t, yamlBobMem3072_Default2048_Floor)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)
	requestedBytes := int64(512) * 1024 * 1024 // 512m
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, requestedBytes))

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores, qm.GetDefaultQuota().MemMB)
	if err != nil {
		t.Fatalf("request denied for 512m (< defaults 2048m, << quota 3072m): %v", err)
	}
	if qr != nil && !qr.Allowed {
		t.Fatalf("Allowed=false for 512m: %s", qr.DeniedResource)
	}

	assertMemoryPreserved(t, newBody, requestedBytes, "--memory 512m")
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 2 — --memory 1023m（< defaults，非 2 的幂次）→ 保留 1023m
// ──────────────────────────────────────────────────────────────────────────────
//
// 验证：非幂次边界值的保留行为。
// 排除因"幂次对齐检查"引入的潜在 Bug。

func TestRegression_BobMemory1023m_NonPowerOf2_BelowDefault_Preserved(t *testing.T) {
	db := newFloorTestDB(t)
	qm := mustLoadFloorQM(t, yamlBobMem3072_Default2048_Floor)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)
	requestedBytes := int64(1023) * 1024 * 1024 // 1023m（非 2 的幂次）
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, requestedBytes))

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores, qm.GetDefaultQuota().MemMB)
	if err != nil {
		t.Fatalf("request denied for 1023m: %v", err)
	}
	if qr != nil && !qr.Allowed {
		t.Fatalf("Allowed=false for 1023m: %s", qr.DeniedResource)
	}

	assertMemoryPreserved(t, newBody, requestedBytes, "--memory 1023m")
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 3 — --memory 2047m（= defaults - 1m，极限边界）→ 保留 2047m
// ──────────────────────────────────────────────────────────────────────────────
//
// 边界：defaults - 1m，最容易被 off-by-one 的 floor 逻辑覆盖为 defaults。
// 若 floor 使用 >=（而非 >），则 2047m 不会被覆盖；若使用 >，则 2048m 也不会被覆盖。

func TestRegression_BobMemory2047m_JustBelowDefault_Preserved(t *testing.T) {
	db := newFloorTestDB(t)
	qm := mustLoadFloorQM(t, yamlBobMem3072_Default2048_Floor)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)
	requestedBytes := int64(2047) * 1024 * 1024 // defaults(2048m) - 1m
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, requestedBytes))

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores, qm.GetDefaultQuota().MemMB)
	if err != nil {
		t.Fatalf("request denied for 2047m (= defaults-1m): %v", err)
	}
	if qr != nil && !qr.Allowed {
		t.Fatalf("Allowed=false for 2047m: %s", qr.DeniedResource)
	}

	assertMemoryPreserved(t, newBody, requestedBytes, "--memory 2047m")
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 4 — --memory 2048m（= defaults，精确等于边界）→ 保留 2048m
// ──────────────────────────────────────────────────────────────────────────────
//
// 边界：精确等于 defaults.mem_mb。
// floor 逻辑若使用严格小于（<），此值通过；若使用小于等于（<=），此值被"覆盖"但值不变（偶然正确）。
// 本测试确保此值不引起误判。

func TestRegression_BobMemory2048m_ExactlyDefault_Preserved(t *testing.T) {
	db := newFloorTestDB(t)
	qm := mustLoadFloorQM(t, yamlBobMem3072_Default2048_Floor)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)
	requestedBytes := int64(2048) * 1024 * 1024 // 精确等于 defaults.mem_mb
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, requestedBytes))

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores, qm.GetDefaultQuota().MemMB)
	if err != nil {
		t.Fatalf("request denied for 2048m (= defaults): %v", err)
	}
	if qr != nil && !qr.Allowed {
		t.Fatalf("Allowed=false for 2048m: %s", qr.DeniedResource)
	}

	assertMemoryPreserved(t, newBody, requestedBytes, "--memory 2048m")

	// 额外确认：InjectedMemMB 审计字段精确等于 2048
	_, qr2, _ := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores, qm.GetDefaultQuota().MemMB)
	if qr2 != nil && qr2.InjectedMemMB != 2048 {
		t.Errorf(
			"qr.InjectedMemMB = %d, want 2048\n"+
				"  --memory 2048m (= defaults exactly) must be preserved, not rounded",
			qr2.InjectedMemMB,
		)
	}
}
