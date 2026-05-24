package isolation

// ── 针对"--cpu-period/--cpu-quota 绕过物理核数上限"的测试套件 ─────────────────
//
// ┌──────────────────────────────────────────────────────────────────────────┐
// │ 根本原因                                                                  │
// │                                                                          │
// │ 触发命令：                                                                │
// │   docker container create --cpu-period 50000 --cpu-quota 150000 alpine  │
// │   （等价于请求 3.0 核，服务器物理核数 = 2，alice 配额 = 4.0）              │
// │                                                                          │
// │ Docker Daemon 的物理核数检查存在盲区：                                     │
// │   --cpus 3.0       → 写入 NanoCpus=3e9  → Daemon 校验 → ❌ 拒绝          │
// │   --cpu-period/quota → 裸写 CpuQuota/CpuPeriod → Daemon 不做等价校验     │
// │                        → ✅ 放行（3.0 核容器跑在 2 核机器上）              │
// │                                                                          │
// │ 代理层面：                                                                │
// │   effectiveCPUNanos() 正确将 CpuQuota/CpuPeriod 换算为等价 NanoCPUs      │
// │   但 injectQuotaLimits() "已指定不超限"分支直接透传原始参数，              │
// │   不转换为 NanoCpus，导致 Daemon 的物理核数检查被完全绕过。                │
// │                                                                          │
// │ 关键触发条件：用户配额 > 物理核数                                          │
// │   alice.cpu_cores = 4.0（高于物理 2 核），请求 3.0 核                     │
// │   3.0 < 4.0 → 用户配额检查通过，BUT 3.0 > 2 物理核 → 应被拒绝            │
// │   若测试将配额也设为 physicalCores，则配额检查先拦截，物理核绕过路径未触达  │
// │                                                                          │
// │ 修复方案：                                                                │
// │   CheckAndInjectQuota 在放行含 CpuQuota/CpuPeriod 的请求时，              │
// │   将等价核数与 runtime.NumCPU() 比较，超过物理核数则拒绝；                 │
// │   或将 CpuQuota/CpuPeriod 统一转换为 NanoCpus 写入请求体，                │
// │   让 Docker Daemon 的原生校验生效。                                        │
// └──────────────────────────────────────────────────────────────────────────┘

import (
	"encoding/json"
	"runtime"
	"testing"

	"docker-authz-proxy/internal/authz"
)

// ── 辅助 ─────────────────────────────────────────────────────────────────────

func newPeriodTestDB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// cpuPeriodBody 构造携带 --cpu-period / --cpu-quota 的请求体
func cpuPeriodBody(period, quota int64) []byte {
	b, _ := json.Marshal(map[string]any{
		"HostConfig": map[string]any{
			"CpuPeriod": period,
			"CpuQuota":  quota,
		},
	})
	return b
}

// physicalCores 返回测试机物理 CPU 核数（等价于 Docker daemon 的上限）
func physicalCores() int { return runtime.NumCPU() }

// ── 1. Red Test：CpuQuota/CpuPeriod 超物理核数，代理未拦截 ───────────────────
//
// 关键：alice 配额 = 物理核数 * 2（高于物理上限），请求 = 物理核数 + 1
//
//	3.0 < 4.0 → 用户配额检查通过（BUG：代理放行了超物理上限的请求）
//	3.0 > 2 物理核 → 代理应拦截，防止 Daemon 的物理核数检查被绕过
//
// 修复前此测试 FAIL（err=nil，容器被放行）。
// 修复后（代理加入物理核数检查）此测试 PASS。
func TestBug_CpuPeriodQuota_ExceedsPhysicalCores_Red(t *testing.T) {
	if physicalCores() < 2 {
		t.Skipf("test requires at least 2 physical CPUs, got %d", physicalCores())
	}

	db := newPeriodTestDB(t)

	// alice 配额 = 物理核数 × 2（高于物理上限，如 4.0）
	// 这是触发 BUG 的必要条件：用户配额 > 物理核数
	userQuota := UserQuota{CPUCores: float64(physicalCores()) * 2}

	// 请求 physicalCores+1 核（如 3.0），via period=100000 / quota=N*100000
	// 3.0 < 4.0（用户配额检查通过），3.0 > 2（物理上限，应被拦截）
	requestedCores := int64(physicalCores() + 1) // e.g., 3 for 2-core machine
	body := cpuPeriodBody(100000, requestedCores*100000)

	_, _, err := CheckAndInjectQuota(body, userQuota, 1001, db, 0, 0)

	// ── 断言：必须被拒绝 ──────────────────────────────────────────────────────
	if err == nil {
		t.Fatalf(
			"BUG REPRODUCED: container create should be DENIED\n"+
				"\n"+
				"  请求参数 : --cpu-period=100000 --cpu-quota=%d\n"+
				"  等价核数 : %d 核（physicalCores+1）\n"+
				"  物理上限 : %d cores (runtime.NumCPU)\n"+
				"  用户配额 : %.1f cores（physicalCores×2，故用户配额检查通过）\n"+
				"  预期结果 : QuotaExceededError{Resource:\"cpu\"}\n"+
				"  实际结果 : err=nil（请求被透传，Docker Daemon 的物理核数检查被绕过）\n"+
				"\n"+
				"  根本原因 :\n"+
				"    --cpus %d.0 会写入 NanoCpus，Daemon 会做物理核数校验并拒绝。\n"+
				"    --cpu-period/quota 裸透传 CpuQuota/CpuPeriod，\n"+
				"    Daemon 不对该组合做等价换算校验，%d 核容器在 %d 核机器上被创建。\n"+
				"    代理在放行时未将等价核数与物理核数对比，形成校验盲区。",
			requestedCores*100000, requestedCores,
			physicalCores(), float64(physicalCores())*2,
			requestedCores, requestedCores, physicalCores(),
		)
	}

	qErr, ok := err.(*QuotaExceededError)
	if !ok {
		t.Fatalf("error type = %T, want *QuotaExceededError; err=%v", err, err)
	}
	if qErr.Resource != "cpu" {
		t.Errorf("QuotaExceededError.Resource = %q, want \"cpu\"", qErr.Resource)
	}
}

// ── 2. Regression #1：CpuQuota/CpuPeriod 未超物理核数 → 应放行 ───────────────
//
// period=100000, quota=100000 → 1.0 核（低于物理上限和用户配额，均放行）
func TestRegression_CpuPeriodQuota_WithinPhysicalLimit_Allowed(t *testing.T) {
	db := newPeriodTestDB(t)
	// 用户配额高于物理核数（与 Red Test 保持相同的配置背景）
	quota := UserQuota{CPUCores: float64(physicalCores()) * 2}

	// period=100000, quota=100000 → 1.0 核（低于物理上限）
	body := cpuPeriodBody(100000, 100000)

	_, qr, err := CheckAndInjectQuota(body, quota, 1001, db, 0, 0)

	if err != nil {
		t.Errorf(
			"1.0 core request (period=100000, quota=100000) should be ALLOWED under %d-core physical limit\n"+
				"  got err=%v",
			physicalCores(), err,
		)
	}
	if !qr.Allowed {
		t.Errorf("QuotaCheckResult.Allowed = false, want true (1.0 core within limit)")
	}
	if qr.RequestedCPUCores != 1.0 {
		t.Errorf(
			"RequestedCPUCores = %.4f, want 1.0\n"+
				"  100000*1e9/100000 = 1.0，effectiveCPUNanos 计算有误",
			qr.RequestedCPUCores,
		)
	}
}

// ── 3. Regression #2：--cpus（NanoCpus）超用户配额 → 代理拦截
//
// --cpus 3.0 → NanoCpus=3e9，用户配额 2.0 → 代理拦截
// 验证 NanoCpus 路径的配额拦截未被本次物理核数检查改动所影响
func TestRegression_NanoCpus_ExceedsQuota_Denied(t *testing.T) {
	db := newPeriodTestDB(t)
	quota := UserQuota{CPUCores: 2.0}

	body, _ := json.Marshal(map[string]any{
		"HostConfig": map[string]any{
			"NanoCpus": int64(3e9), // 3.0 核
		},
	})

	_, _, err := CheckAndInjectQuota(body, quota, 1001, db, 0, 0)

	if err == nil {
		t.Errorf(
			"NanoCpus=3e9 (3.0 cores) should be DENIED by quota (limit=2.0)\n" +
				"  NanoCpus 路径的配额拦截不应受本次修复影响",
		)
	}
	qErr, ok := err.(*QuotaExceededError)
	if !ok {
		t.Fatalf("error type = %T, want *QuotaExceededError", err)
	}
	if qErr.Resource != "cpu" {
		t.Errorf("QuotaExceededError.Resource = %q, want \"cpu\"", qErr.Resource)
	}
}

// ── 4. Regression #3：CpuPeriod 未指定（=0），使用默认 100000 ─────────────────
//
// --cpu-quota 150000（不带 --cpu-period）
// effectiveCPUNanos 内部默认 period=100000 → 150000*1e9/100000 = 1.5 核
// 1.5 < physicalCores（≥2）→ 应放行
func TestRegression_CpuQuotaOnly_DefaultPeriod_1p5Cores_Allowed(t *testing.T) {
	db := newPeriodTestDB(t)
	quota := UserQuota{CPUCores: float64(physicalCores()) * 2}

	// CpuPeriod=0 → 内部使用 Docker 默认 100000
	body := cpuPeriodBody(0, 150000)

	_, qr, err := CheckAndInjectQuota(body, quota, 1001, db, 0, 0)

	if err != nil {
		t.Errorf(
			"default period + quota=150000 → 1.5 cores should be ALLOWED (physical=%d, user_quota=%.1f)\n"+
				"  got err=%v",
			physicalCores(), float64(physicalCores())*2, err,
		)
	}
	if qr.RequestedCPUCores != 1.5 {
		t.Errorf(
			"RequestedCPUCores = %.4f, want 1.5\n"+
				"  默认 period=100000，CpuQuota=150000 → 150000/100000 = 1.5 核",
			qr.RequestedCPUCores,
		)
	}
}

// ── 5. Regression #4：NanoCpus 优先级高于 CpuQuota/CpuPeriod ────────────────
//
// 同时指定 NanoCpus=1e9（1.0 核）和超限的 CpuQuota=300000/Period=50000（6.0 核）
// effectiveCPUNanos 应以 NanoCpus 优先 → 1.0 核 → 放行
func TestRegression_NanoCpus_TakesPriorityOver_CpuPeriodQuota(t *testing.T) {
	db := newPeriodTestDB(t)
	quota := UserQuota{CPUCores: 2.0}

	body, _ := json.Marshal(map[string]any{
		"HostConfig": map[string]any{
			"NanoCpus":  int64(1e9),   // 1.0 核（优先）
			"CpuPeriod": int64(50000),
			"CpuQuota":  int64(300000), // 若被采用 → 6.0 核（超限）
		},
	})

	_, qr, err := CheckAndInjectQuota(body, quota, 1001, db, 0, 0)

	if err != nil {
		t.Errorf(
			"NanoCpus=1.0 should take priority over CpuQuota(6.0 cores)\n"+
				"  got err=%v\n"+
				"  effectiveCPUNanos 优先级逻辑: NanoCpus > CpuQuota/CpuPeriod",
			err,
		)
	}
	if qr.RequestedCPUCores != 1.0 {
		t.Errorf(
			"RequestedCPUCores = %.2f, want 1.0 (NanoCpus should win)\n"+
				"  若为 6.0 说明 CpuQuota 优先级被错误提升",
			qr.RequestedCPUCores,
		)
	}
}

// ── 6. Regression #5：恰好等于物理核数 → 应放行（边界值，> 而非 >=）─────────
//
// 请求恰好等于物理核数（如 period=100000, quota=200000 → 2.0 核 = physicalCores）
// 等于不超过，应放行（CheckAndInjectQuota 用 > 判断）
func TestRegression_CpuPeriodQuota_ExactlyAtPhysicalLimit_Allowed(t *testing.T) {
	db := newPeriodTestDB(t)
	cores := float64(physicalCores())
	// 用户配额设为物理核数的两倍，确保只有物理上限会触发
	quota := UserQuota{CPUCores: cores * 2}

	// 恰好等于物理核数：period=100000, quota=physicalCores*100000
	body := cpuPeriodBody(100000, int64(cores)*100000)

	_, _, err := CheckAndInjectQuota(body, quota, 1001, db, 0, 0)

	if err != nil {
		t.Errorf(
			"request exactly at physical CPU limit (%.1f cores) should be ALLOWED\n"+
				"  got err=%v\n"+
				"  校验应使用严格大于(>)，不应拒绝恰好等于上限的请求",
			cores, err,
		)
	}
}
