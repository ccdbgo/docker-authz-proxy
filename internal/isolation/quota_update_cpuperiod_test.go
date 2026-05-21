package isolation

// ── 针对 "docker container update --cpu-period/--cpu-quota 绕过物理核数上限" 的测试套件 ─
//
// ┌──────────────────────────────────────────────────────────────────────────────┐
// │ 根本原因                                                                      │
// │                                                                              │
// │ 触发命令：                                                                    │
// │   docker container update --cpu-period 50000 --cpu-quota 150000 <container> │
// │   （等价于请求 3.0 核，服务器物理核数 = 2，alice 配额 = 4.0）                  │
// │                                                                              │
// │ container create 路径（已修复）：                                              │
// │   走 CheckAndInjectQuota()，步骤 3b 已加入物理核数检查 → 正确拒绝             │
// │                                                                              │
// │ container update 路径（本 Bug）：                                             │
// │   走 proxy.go 内联逻辑，只做用户配额检查（reqNano > limitNano），              │
// │   完全没有物理核数检查 → 3.0 < 4.0（用户配额通过），3.0 > 2 物理核被放行     │
// │                                                                              │
// │ 请求体格式差异：                                                               │
// │   container create : {"HostConfig": {"CpuPeriod": ..., "CpuQuota": ...}}    │
// │   container update : {"CpuPeriod": ..., "CpuQuota": ...}  ← 顶层 flat JSON  │
// │                                                                              │
// │ 修复方案：                                                                    │
// │   将 proxy.go 内联校验提取为 isolation.CheckUpdateQuota()，                   │
// │   在用户配额检查之后加入与 create 路径相同的物理核数检查逻辑。                   │
// └──────────────────────────────────────────────────────────────────────────────┘

import (
	"encoding/json"
	"runtime"
	"testing"
)

// updatePhysicalCores 返回测试机物理 CPU 核数（等价于 Docker daemon 的上限）
func updatePhysicalCores() int { return runtime.NumCPU() }

// updateBody 构造 container update 请求体（顶层 flat JSON，无 HostConfig 包裹）
func updateBody(nanoCpus, cpuPeriod, cpuQuota, memBytes int64) []byte {
	m := map[string]any{}
	if nanoCpus > 0 {
		m["NanoCpus"] = nanoCpus
	}
	if cpuPeriod != 0 {
		m["CpuPeriod"] = cpuPeriod
	}
	if cpuQuota != 0 {
		m["CpuQuota"] = cpuQuota
	}
	if memBytes > 0 {
		m["Memory"] = memBytes
	}
	b, _ := json.Marshal(m)
	return b
}

// ── 1. Red Test：container update CpuQuota/CpuPeriod 超物理核数，代理未拦截 ──────
//
// 关键配置（与 create 路径的 Red Test 完全对称）：
//   alice 配额 = physicalCores × 2（高于物理上限），请求 physicalCores+1 核
//   3.0 < 4.0（用户配额检查通过）
//   3.0 > 2 物理核（代理应拦截，BUG 下被放行）
//
// 修复前此测试 FAIL（err=nil）。
// 修复后（CheckUpdateQuota 加入物理核数检查）此测试 PASS。
func TestBug_UpdateCpuPeriodQuota_ExceedsPhysicalCores_Red(t *testing.T) {
	if updatePhysicalCores() < 2 {
		t.Skipf("test requires at least 2 physical CPUs, got %d", updatePhysicalCores())
	}

	// alice 配额 = 物理核数 × 2（如 4.0）——触发 BUG 的必要条件：用户配额 > 物理核数
	userQuota := UserQuota{CPUCores: float64(updatePhysicalCores()) * 2}

	// 请求 physicalCores+1 核（如 3.0）via period=100000 / quota=N*100000
	// 3.0 < 4.0（用户配额检查通过），3.0 > 2 物理核（应被拦截）
	requestedCores := int64(updatePhysicalCores() + 1) // e.g., 3 on a 2-core machine
	body := updateBody(0, 100000, requestedCores*100000, 0)

	qr, err := CheckUpdateQuota(body, userQuota)

	// ── 断言：必须被拒绝 ─────────────────────────────────────────────────────
	if err == nil {
		t.Fatalf(
			"BUG REPRODUCED: container update should be DENIED\n"+
				"\n"+
				"  请求参数 : --cpu-period=100000 --cpu-quota=%d\n"+
				"  等价核数 : %d 核（physicalCores+1）\n"+
				"  物理上限 : %d cores (runtime.NumCPU)\n"+
				"  用户配额 : %.1f cores（physicalCores×2，故用户配额检查通过）\n"+
				"  预期结果 : QuotaExceededError{Resource:\"cpu\"}\n"+
				"  实际结果 : err=nil（请求被透传，Docker Daemon 的物理核数检查被绕过）\n"+
				"\n"+
				"  根本原因 :\n"+
				"    container create 路径已修复（CheckAndInjectQuota 步骤 3b）。\n"+
				"    container update 走 proxy.go 内联逻辑，只做用户配额检查，\n"+
				"    CheckUpdateQuota 未加入物理核数检查，形成与 create 对称的校验盲区。",
			requestedCores*100000, requestedCores,
			updatePhysicalCores(), float64(updatePhysicalCores())*2,
		)
	}
	if qr.Allowed {
		t.Errorf("QuotaCheckResult.Allowed = true, want false")
	}

	qErr, ok := err.(*QuotaExceededError)
	if !ok {
		t.Fatalf("error type = %T, want *QuotaExceededError; err=%v", err, err)
	}
	if qErr.Resource != "cpu" {
		t.Errorf("QuotaExceededError.Resource = %q, want \"cpu\"", qErr.Resource)
	}
}

// ── 2. Regression #1：CpuQuota/CpuPeriod 未超物理核数 → 应放行 ─────────────────
//
// period=100000, quota=100000 → 1.0 核（低于物理上限和用户配额，均放行）
func TestRegression_Update_CpuPeriodQuota_WithinPhysicalLimit_Allowed(t *testing.T) {
	quota := UserQuota{CPUCores: float64(updatePhysicalCores()) * 2}

	// 1.0 核，低于任何限制
	body := updateBody(0, 100000, 100000, 0)

	qr, err := CheckUpdateQuota(body, quota)

	if err != nil {
		t.Errorf(
			"1.0 core update (period=100000, quota=100000) should be ALLOWED under %d-core physical limit\n"+
				"  got err=%v",
			updatePhysicalCores(), err,
		)
	}
	if !qr.Allowed {
		t.Errorf("QuotaCheckResult.Allowed = false, want true")
	}
	if qr.RequestedCPUCores != 1.0 {
		t.Errorf(
			"RequestedCPUCores = %.4f, want 1.0\n"+
				"  100000*1e9/100000 = 1.0，effectiveUpdateCPUNanos 计算有误",
			qr.RequestedCPUCores,
		)
	}
}

// ── 3. Regression #2：恰好等于物理核数 → 应放行（边界值，> 而非 >=）──────────
//
// 请求恰好等于物理核数（如 period=100000, quota=physicalCores*100000）→ 放行
func TestRegression_Update_CpuPeriodQuota_ExactlyAtPhysicalLimit_Allowed(t *testing.T) {
	cores := float64(updatePhysicalCores())
	quota := UserQuota{CPUCores: cores * 2}

	// 恰好等于物理核数
	body := updateBody(0, 100000, int64(cores)*100000, 0)

	_, err := CheckUpdateQuota(body, quota)

	if err != nil {
		t.Errorf(
			"request exactly at physical CPU limit (%.1f cores) should be ALLOWED\n"+
				"  got err=%v\n"+
				"  校验应使用严格大于(>)，不应拒绝恰好等于上限的请求",
			cores, err,
		)
	}
}

// ── 4. Regression #3：用户配额（非物理）超限 → 代理拦截 ───────────────────────
//
// 请求 3.0 核，用户配额 2.0 核（低于物理上限），用户配额检查先拦截
func TestRegression_Update_ExceedsUserQuota_Denied(t *testing.T) {
	quota := UserQuota{CPUCores: 2.0}

	// 3.0 核 > 用户配额 2.0 → 应被拒绝
	body := updateBody(0, 100000, 300000, 0) // 300000/100000 = 3.0 核

	qr, err := CheckUpdateQuota(body, quota)

	if err == nil {
		t.Errorf(
			"3.0 cores update should be DENIED (user quota=2.0)\n"+
				"  用户配额检查路径（reqNano > limitNano）应先于物理核数检查触发",
		)
	}
	if qr.Allowed {
		t.Errorf("QuotaCheckResult.Allowed = true, want false")
	}
	qErr, ok := err.(*QuotaExceededError)
	if !ok {
		t.Fatalf("error type = %T, want *QuotaExceededError", err)
	}
	if qErr.Resource != "cpu" {
		t.Errorf("QuotaExceededError.Resource = %q, want \"cpu\"", qErr.Resource)
	}
}

// ── 5. Regression #4：NanoCpus 超用户配额 → 代理拦截（update NanoCpus 路径） ──
//
// NanoCpus=3e9（3.0 核），用户配额 2.0 → 被拒绝
// 验证 NanoCpus 路径在 container update 中同样被正确处理
func TestRegression_Update_NanoCpus_ExceedsQuota_Denied(t *testing.T) {
	quota := UserQuota{CPUCores: 2.0}

	body := updateBody(int64(3e9), 0, 0, 0) // NanoCpus=3e9 → 3.0 核

	_, err := CheckUpdateQuota(body, quota)

	if err == nil {
		t.Errorf(
			"NanoCpus=3e9 (3.0 cores) update should be DENIED by quota (limit=2.0)\n"+
				"  NanoCpus 路径在 update 中同样应受用户配额约束",
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

// ── 6. Regression #5：内存超配额 → 被拒绝 ────────────────────────────────────
//
// 请求 4096MB，用户配额 2048MB → 被拒绝
// 验证内存校验路径不受本次物理核数修复影响
func TestRegression_Update_Memory_ExceedsQuota_Denied(t *testing.T) {
	quota := UserQuota{MemMB: 2048}

	body := updateBody(0, 0, 0, 4096*1024*1024) // 4096 MB

	qr, err := CheckUpdateQuota(body, quota)

	if err == nil {
		t.Errorf(
			"4096MB update should be DENIED (memory quota=2048MB)\n"+
				"  内存校验路径应不受 CPU 物理核数修复影响",
		)
	}
	if qr.Allowed {
		t.Errorf("QuotaCheckResult.Allowed = true, want false")
	}
	qErr, ok := err.(*QuotaExceededError)
	if !ok {
		t.Fatalf("error type = %T, want *QuotaExceededError", err)
	}
	if qErr.Resource != "memory" {
		t.Errorf("QuotaExceededError.Resource = %q, want \"memory\"", qErr.Resource)
	}
	if qr.RequestedMemMB != 4096 {
		t.Errorf("RequestedMemMB = %d, want 4096", qr.RequestedMemMB)
	}
}

// ── 7. Regression #6：CpuPeriod=0（默认 100000），CpuQuota=150000 → 1.5 核 → 放行 ─
//
// --cpu-quota 150000（不带 --cpu-period）
// effectiveUpdateCPUNanos 内部默认 period=100000 → 150000/100000 = 1.5 核
// 1.5 < physicalCores（≥2）→ 应放行
func TestRegression_Update_CpuQuotaOnly_DefaultPeriod_Allowed(t *testing.T) {
	quota := UserQuota{CPUCores: float64(updatePhysicalCores()) * 2}

	// CpuPeriod=0 → 内部使用 Docker 默认 100000
	body := updateBody(0, 0, 150000, 0)

	qr, err := CheckUpdateQuota(body, quota)

	if err != nil {
		t.Errorf(
			"default period + quota=150000 → 1.5 cores should be ALLOWED (physical=%d, user_quota=%.1f)\n"+
				"  got err=%v",
			updatePhysicalCores(), float64(updatePhysicalCores())*2, err,
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
