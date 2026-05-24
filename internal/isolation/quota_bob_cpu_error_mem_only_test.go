package isolation

// ══════════════════════════════════════════════════════════════════════════════
// 复现测试套件：injectQuotaLimits 注入 NanaCpus 时缺少物理 CPU 上限保护
// ──────────────────────────────────────────────────────────────────────────────
//
// 【触发场景（用户命令）】
//   docker container run -d --rm --name test_mem_limit3 --memory 2048m alpine:latest sleep 10
//   → 用户 bob 配额：cpu_cores:4.0, mem_mb:3072（显式配置，无继承问题）
//   → 系统默认配额：cpu_cores:2.0, mem_mb:2048
//   → 服务器物理 CPU：2 核（physNano = 2,000,000,000）
//   → 预期：容器创建成功（bob 未指定 --cpus，代理应注入不超物理上限的默认值）
//   → 实际：Error response from daemon: range of CPUs is from 0.01 to 2.00,
//            as there are only 2 CPUs available
//
// 【根本原因】
//
//  完整执行路径追踪（CheckAndInjectQuota）：
//
//    reqNano = effectiveCPUNanos(req) = 0   ← 用户未指定 --cpus，无 CPU 参数
//
//    Step 3  CPU 配额校验：
//      条件：quota.CPUCores > 0 && reqNano > 0
//            = 4.0 > 0 && 0 > 0  ← reqNano=0，条件为 FALSE
//      结果：整个 CPU 校验**跳过**（因为用户没有明确请求 CPU）
//
//    Step 3b 物理核数检查：
//      条件：req.NanoCPUs == 0 && req.CpuQuota > 0 && reqNano > 0
//            = true && 0 > 0 && 0 > 0  ← CpuQuota=0 且 reqNano=0，条件为 FALSE
//      注释："NanaCpus 路径已由 Daemon 自身校验物理核数"
//      结果：物理核数检查**跳过**
//      缺陷：Step 3b 只保护"用户指定 CpuQuota 超物理"路径；
//            但当代理**自身**在注入阶段写入超物理上限的 NanaCpus 时，没有任何保护
//
//    Step 4  内存校验：
//      2048m ≤ 3072m（bob 配额）→ 通过，继续执行注入
//
//    injectQuotaLimits（核心缺陷）：
//      quota.CPUCores = 4.0 > 0  →  进入 CPU 注入分支
//      quotaNano = int64(4.0 * 1e9) = 4,000,000,000
//      currentNano = 0（用户未指定，取代理注入路径）
//      → hostConfig["NanaCpus"] = 4,000,000,000   ← 注入 4.0 CPU，无物理上限保护
//
//    Docker daemon 校验：
//      4,000,000,000 > physNano(2 * 1e9 = 2,000,000,000) → 拒绝
//      "range of CPUs is from 0.01 to 2.00, as there are only 2 CPUs available"
//
//  缺陷定位：injectQuotaLimits（quota.go 第 761-765 行）
//    if currentNano == 0 {
//        b, _ := json.Marshal(quotaNano)          // quotaNano = 4e9，超物理上限
//        hostConfig["NanaCpus"] = b               // ← 无物理 CPU 上限校验
//        result.cpuCores = quota.CPUCores
//    }
//
// 【修复方向】
//  在 injectQuotaLimits 注入 NanaCpus 前，将 quotaNano 限制在物理核数以内：
//
//    physNano := int64(runtime.NumCPU()) * 1e9
//    injectedNano := quotaNano
//    if physNano > 0 && injectedNano > physNano {
//        injectedNano = physNano   // 注入值 = min(quota, physical)
//    }
//    b, _ := json.Marshal(injectedNano)
//    hostConfig["NanaCpus"] = b
//    result.cpuCores = float64(injectedNano) / 1e9
//
//  修复后：injectedNano = min(4e9, 2e9) = 2e9（2.0 核），Docker 接受
//
// 【本文件测试结构】
//  Red Tests（修复前必定失败）：
//    1. 注入层核心：quota=4.0 时注入 NanaCpus=4e9 > physNano=2e9（BUG 直接复现）
//    2. 端到端：bob --memory 2048m 不应产生 CPU 错误
//
//  Regression Tests（修复后始终通过）：
//    3. 不变式：注入的 NanaCpus 始终 <= runtime.NumCPU() * 1e9
//    4. 修复完整性：内存原值保留，NanaCpus 注入值合法
//    5. quota <= 物理核数时，注入值等于 quotaNano（正常路径不受影响）
//    6. 用户显式 --cpus 超配额时，仍然被拒绝（修复不绕过配额检查）
//    7. 内存超配额时 DeniedResource 必须是 "memory"，与 CPU 无关
//    8. 用户显式 --cpus 在物理范围内且低于配额时，原值保留
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"encoding/json"
	"fmt"
	"runtime"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// ── 测试用 YAML 配置 ──────────────────────────────────────────────────────────

// yamlBobCPU4ExceedsPhysical: 精确对应 Bug 触发场景
//   defaults.cpu_cores = 2.0（系统默认，等于物理核数）
//   bob.cpu_cores = 4.0（bob 专属配额，超过物理 2 核）
//   bob.mem_mb = 3072（bob 内存配额，高于 default 2048）
const yamlBobCPU4ExceedsPhysical = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
users:
  bob:
    cpu_cores: 4.0
    mem_mb: 3072
`

// yamlBobCPU1WithinPhysical: 对照组，bob cpu 在物理范围内
const yamlBobCPU1WithinPhysical = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
users:
  bob:
    cpu_cores: 1.0
    mem_mb: 3072
`

// ── 辅助 ─────────────────────────────────────────────────────────────────────

func newBobPhysDB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func loadPhysQM(t *testing.T, yaml string) *QuotaManager {
	t.Helper()
	path := writeTempQuotaYAML(t, yaml)
	qm, err := LoadQuotaManager(path)
	if err != nil {
		t.Fatalf("LoadQuotaManager: %v", err)
	}
	return qm
}

// physNano 返回服务器物理 CPU 上限（NanoCPUs）
func physNano() int64 { return int64(runtime.NumCPU()) * 1e9 }

// ══════════════════════════════════════════════════════════════════════════════
// Red Test 1 — 注入层核心：quota.CPUCores=4.0 → 注入 NanaCpus=4e9 > 物理上限
// ──────────────────────────────────────────────────────────────────────────────
//
// 直接定位 injectQuotaLimits 缺陷：
//   用户未指定 --cpus → currentNano = 0 → 进入注入分支
//   quotaNano = int64(4.0 * 1e9) = 4,000,000,000
//   无物理上限保护 → 注入 4e9
//   Docker: 4e9 > physNano(2e9) → 拒绝（与用户实际请求无关的 CPU 错误）
//
// 修复前：injected NanaCpus = 4e9 > physNano = 2e9 → 断言失败
// 修复后：injected NanaCpus = min(4e9, 2e9) = 2e9 → 断言通过

func TestBug_InjectQuota_NanaCpusExceedsPhysical_Red(t *testing.T) {
	phys := physNano() // 当前服务器物理 CPU NanoCPUs 上限

	qm := loadPhysQM(t, yamlBobCPU4ExceedsPhysical)
	db := newBobPhysDB(t)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)

	// 前置：确认测试配置满足触发条件（quota.CPUCores > 物理核数）
	quotaNano := int64(quota.CPUCores * 1e9)
	if quotaNano <= phys {
		t.Skipf("skip: bob quota (%.1f cores) does not exceed physical (%d cores); "+
			"this test requires quota > physical",
			quota.CPUCores, runtime.NumCPU())
	}

	// 用户只请求内存，不指定 --cpus（Bug 触发路径：reqNano = 0）
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, int64(2048*1024*1024)))
	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db)
	if err != nil {
		t.Fatalf("CheckAndInjectQuota error (should pass memory check): %v (DeniedResource=%q)",
			err, func() string {
				if qr != nil {
					return qr.DeniedResource
				}
				return "<nil>"
			}())
	}

	var injected containerCreateRequest
	if e := json.Unmarshal(newBody, &injected); e != nil {
		t.Fatalf("unmarshal: %v", e)
	}

	nano := injected.HostConfig.NanoCPUs

	// ── 核心断言（RED）：注入的 NanaCpus 不得超过物理 CPU 上限 ────────────
	//
	// 修复前：nano = quotaNano = 4,000,000,000
	//         4e9 > physNano(2e9) → Docker 拒绝
	//         错误信息："range of CPUs is from 0.01 to 2.00, as there are only 2 CPUs available"
	//
	// 修复后：nano = min(quotaNano, physNano) = 2,000,000,000
	//         2e9 ≤ physNano(2e9) → Docker 接受
	if nano > phys {
		t.Errorf(
			"[BUG] injected NanaCpus = %d (%.2f cores) > physNano = %d (%.2f cores)\n"+
				"\n"+
				"  Root cause（injectQuotaLimits, quota.go）:\n"+
				"    reqNano = 0（user did not specify --cpus）\n"+
				"    → enters injection branch\n"+
				"    → quotaNano = int64(%.1f * 1e9) = %d\n"+
				"    → hostConfig[\"NanaCpus\"] = %d  ← no physical CPU cap\n"+
				"\n"+
				"  Step 3b physical check was SKIPPED because:\n"+
				"    req.CpuQuota == 0 && reqNano == 0  → condition FALSE\n"+
				"    (Step 3b only guards user-specified CpuQuota/CpuPeriod path,\n"+
				"     not the proxy's own NanaCpus injection path)\n"+
				"\n"+
				"  Docker daemon error:\n"+
				"    'range of CPUs is from 0.01 to %.2f, as there are only %d CPUs available'\n"+
				"\n"+
				"  Fix: injectedNano = min(quotaNano, physNano) before writing NanaCpus\n"+
				"    → min(%d, %d) = %d (%.2f cores) — Docker accepts",
			nano, float64(nano)/1e9,
			phys, float64(phys)/1e9,
			quota.CPUCores, quotaNano,
			nano,
			float64(phys)/1e9, runtime.NumCPU(),
			quotaNano, phys, phys, float64(phys)/1e9,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Red Test 2 — 端到端：bob --memory 2048m 不应产生任何 CPU 相关错误
// ──────────────────────────────────────────────────────────────────────────────
//
// 精确复现用户命令：
//   docker container run -d --rm --name test_mem_limit3 --memory 2048m alpine:latest sleep 10
//   bob 配额：cpu_cores:4.0, mem_mb:3072
//
// 分析：
//   内存检查：2048m < 3072m（bob 配额）→ PASS
//   CPU 检查：reqNano=0 → 两个 CPU 检查均 SKIP（无用户指定 CPU）
//   注入：NanaCpus = 4e9（超物理）→ Docker 拒绝 → 用户看到莫名 CPU 错误

func TestBug_BobMem2048m_NoCPURequest_ShouldNotFailWithCPUError_Red(t *testing.T) {
	phys := physNano()

	qm := loadPhysQM(t, yamlBobCPU4ExceedsPhysical)
	db := newBobPhysDB(t)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)

	if int64(quota.CPUCores*1e9) <= phys {
		t.Skipf("skip: quota CPUCores(%.1f) <= physical(%d cores); bug requires quota > physical",
			quota.CPUCores, runtime.NumCPU())
	}
	if quota.MemMB < 2048 {
		t.Fatalf("precondition: bob MemMB = %d, want >= 2048", quota.MemMB)
	}

	// 精确复现：docker run --memory 2048m（无 --cpus）
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, int64(2048*1024*1024)))
	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db)

	// ── 断言 1：代理层应允许此请求（内存未超配额）────────────────────────
	if err != nil {
		t.Errorf(
			"[BUG] request denied: %v\n"+
				"  Context: bob quota={cpu:%.1f, mem:%dMB}, requested={mem:2048MB, no cpu}\n"+
				"  Memory check: 2048MB < %dMB quota → should PASS at proxy layer\n"+
				"  DeniedResource=%q — expected empty (memory check passes, no cpu specified)\n"+
				"\n"+
				"  Execution path that caused this:\n"+
				"    reqNano = 0 (no --cpus) → Step3/3b CPU checks SKIPPED\n"+
				"    injectQuotaLimits: quotaNano=%.0fe9 > physNano=%.0fe9\n"+
				"    proxy injects NanaCpus=%.0fe9 → Docker daemon rejects\n"+
				"\n"+
				"  User command: docker run --memory 2048m (no --cpus)\n"+
				"  Expected: container created\n"+
				"  Actual:   CPU error unrelated to user's request",
			err,
			quota.CPUCores, quota.MemMB,
			quota.MemMB,
			func() string {
				if qr != nil {
					return qr.DeniedResource
				}
				return "<nil>"
			}(),
			quota.CPUCores, float64(phys)/1e9,
			quota.CPUCores,
		)
	}

	// ── 断言 2：注入后的 NanaCpus 不超物理上限 ──────────────────────────
	if newBody != nil {
		var injected containerCreateRequest
		if e := json.Unmarshal(newBody, &injected); e == nil {
			if injected.HostConfig.NanoCPUs > phys {
				t.Errorf(
					"[BUG] injected NanaCpus = %d (%.2f cores) > physNano = %d (%.2f cores)\n"+
						"  This is the DIRECT cause of Docker's CPU error:\n"+
						"    'range of CPUs is from 0.01 to %.2f, as there are only %d CPUs available'\n"+
						"  Fix: NanaCpus = min(quotaNano=%.0fe9, physNano=%.0fe9) = %.0fe9",
					injected.HostConfig.NanoCPUs, float64(injected.HostConfig.NanoCPUs)/1e9,
					phys, float64(phys)/1e9,
					float64(phys)/1e9, runtime.NumCPU(),
					quota.CPUCores, float64(phys)/1e9, float64(phys)/1e9,
				)
			}
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 1 — 不变式：注入的 NanaCpus 始终 <= runtime.NumCPU() * 1e9
// ──────────────────────────────────────────────────────────────────────────────
//
// 无论 quota.CPUCores 设置多高，注入到 Docker 的 NanaCpus 不得超过物理上限。
// 超过后 Docker daemon 必然拒绝，产生与用户请求无关的 CPU 错误。

func TestRegression_InjectedNanaCpus_NeverExceedsPhysicalLimit(t *testing.T) {
	phys := physNano()

	qm := loadPhysQM(t, yamlBobCPU4ExceedsPhysical)
	db := newBobPhysDB(t)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)

	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, int64(2048*1024*1024)))
	newBody, _, err := CheckAndInjectQuota(body, quota, 1002, db)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var injected containerCreateRequest
	if e := json.Unmarshal(newBody, &injected); e != nil {
		t.Fatalf("unmarshal: %v", e)
	}

	nano := injected.HostConfig.NanoCPUs

	if nano > phys {
		t.Errorf(
			"INVARIANT VIOLATED: injected NanaCpus = %d (%.2f cores) > physNano = %d (%.2f cores)\n"+
				"  Proxy must never inject NanaCpus > numCPU * 1e9\n"+
				"  This ALWAYS causes Docker daemon to reject the request:\n"+
				"    'range of CPUs is from 0.01 to %.2f, as there are only %d CPUs available'\n"+
				"  Regardless of what resource the user actually requested",
			nano, float64(nano)/1e9,
			phys, float64(phys)/1e9,
			float64(phys)/1e9, runtime.NumCPU(),
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 2 — 修复完整性：内存原值保留，NanaCpus 注入值合法
// ──────────────────────────────────────────────────────────────────────────────
//
// 验证修复不引入副作用：
//   - Memory 保留用户指定值（2048m）
//   - NanaCpus 在 Docker 合法范围 [1e7, physNano] 内

func TestRegression_BobMem2048m_MemoryPreservedNanaCpusLegal(t *testing.T) {
	phys := physNano()

	qm := loadPhysQM(t, yamlBobCPU4ExceedsPhysical)
	db := newBobPhysDB(t)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)

	wantMemBytes := int64(2048 * 1024 * 1024)
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, wantMemBytes))
	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db)

	if err != nil {
		t.Fatalf("2048m < 3072m quota, should be allowed: %v (DeniedResource=%q)",
			err, func() string {
				if qr != nil {
					return qr.DeniedResource
				}
				return "<nil>"
			}())
	}
	if !qr.Allowed {
		t.Fatalf("Allowed=false, DeniedResource=%q", qr.DeniedResource)
	}

	var injected containerCreateRequest
	if e := json.Unmarshal(newBody, &injected); e != nil {
		t.Fatalf("unmarshal: %v", e)
	}

	// 内存原值必须保留
	if injected.HostConfig.Memory != wantMemBytes {
		t.Errorf("Memory = %d (%dMB), want %d (2048MB)",
			injected.HostConfig.Memory, injected.HostConfig.Memory/1024/1024, wantMemBytes)
	}

	nano := injected.HostConfig.NanoCPUs

	// NanaCpus 不超物理上限
	if nano > phys {
		t.Errorf("injected NanaCpus = %d (%.2f cores) > physNano = %d; Docker will reject",
			nano, float64(nano)/1e9, phys)
	}
	// NanaCpus > 0 时不低于 Docker 下界（0.01 核 = 1e7）
	if nano != 0 && nano < int64(1e7) {
		t.Errorf("injected NanaCpus = %d < Docker minimum 1e7 (0.01 cores); Docker will reject",
			nano)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 3 — 正常路径：quota.CPUCores <= 物理核数时，注入值等于 quotaNano
// ──────────────────────────────────────────────────────────────────────────────
//
// 修复只影响 quota > physical 场景，不应改变 quota <= physical 时的注入行为。
// bob cpu=1.0 <= 物理 2 核 → 注入 1.0（原有行为不变）

func TestRegression_BobCPUWithinPhysical_InjectedEqualsQuota(t *testing.T) {
	qm := loadPhysQM(t, yamlBobCPU1WithinPhysical) // bob: {cpu:1.0, mem:3072}
	db := newBobPhysDB(t)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)
	if quota.CPUCores != 1.0 {
		t.Fatalf("precondition: CPUCores = %.1f, want 1.0", quota.CPUCores)
	}

	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, int64(2048*1024*1024)))
	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db)

	if err != nil {
		t.Fatalf("unexpected error: %v (DeniedResource=%q)",
			err, func() string {
				if qr != nil {
					return qr.DeniedResource
				}
				return "<nil>"
			}())
	}

	var injected containerCreateRequest
	if e := json.Unmarshal(newBody, &injected); e != nil {
		t.Fatalf("unmarshal: %v", e)
	}

	wantNano := int64(1.0 * 1e9)
	if injected.HostConfig.NanoCPUs != wantNano {
		t.Errorf(
			"injected NanaCpus = %d (%.2f cores), want %d (1.00 cores)\n"+
				"  quota.CPUCores=1.0 <= physical=%d → inject quotaNano unchanged\n"+
				"  Fix must NOT alter injection when quota <= physical",
			injected.HostConfig.NanoCPUs, float64(injected.HostConfig.NanoCPUs)/1e9,
			wantNano, runtime.NumCPU(),
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 4 — 用户显式 --cpus 超出 bob 配额时，仍然被拒绝
// ──────────────────────────────────────────────────────────────────────────────
//
// 修复只改变"未指定 --cpus"时的注入行为，不应影响配额校验逻辑。
// bob 显式请求 --cpus 5.0 > quota 4.0 → 代理应拒绝（不因修复而漏检）

func TestRegression_BobExplicitCPU_ExceedsQuota_StillDenied(t *testing.T) {
	qm := loadPhysQM(t, yamlBobCPU4ExceedsPhysical) // bob: {cpu:4.0, mem:3072}
	db := newBobPhysDB(t)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)
	if quota.CPUCores != 4.0 {
		t.Fatalf("precondition: CPUCores = %.1f, want 4.0", quota.CPUCores)
	}

	// 用户显式 --cpus 5.0 > quota 4.0
	body := []byte(fmt.Sprintf(`{"HostConfig":{"NanoCpus":%d,"Memory":%d}}`,
		int64(5.0*1e9), int64(2048*1024*1024)))

	_, qr, err := CheckAndInjectQuota(body, quota, 1002, db)

	if err == nil {
		t.Errorf("expected denial for --cpus 5.0 > quota 4.0, got nil\n"+
			"  Fix must not bypass quota enforcement for user-specified CPU")
		return
	}
	if qr != nil && qr.DeniedResource != "cpu" {
		t.Errorf("DeniedResource = %q, want \"cpu\"\n"+
			"  --cpus 5.0 exceeded quota 4.0: must deny as cpu quota exceeded",
			qr.DeniedResource)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 5 — 内存超配额时 DeniedResource 必须是 "memory"，与 CPU 配额无关
// ──────────────────────────────────────────────────────────────────────────────
//
// 即使 quota.CPUCores 超物理核数，超内存配额的拒绝原因必须是 "memory"。
// 修复不应改变内存校验逻辑。

func TestRegression_BobMemExceedsQuota_DeniedAsMemory(t *testing.T) {
	qm := loadPhysQM(t, yamlBobCPU4ExceedsPhysical) // bob: {cpu:4.0, mem:3072}
	db := newBobPhysDB(t)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)

	// 请求 3073m > bob 3072m 配额
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, int64(3073*1024*1024)))
	_, qr, err := CheckAndInjectQuota(body, quota, 1002, db)

	if err == nil {
		t.Errorf("expected denial for 3073m > bob quota 3072m, got nil")
		return
	}
	if qr != nil && qr.DeniedResource != "memory" {
		t.Errorf("DeniedResource = %q, want \"memory\"\n"+
			"  request exceeded memory quota (3073m > 3072m)\n"+
			"  CPU quota (%.1f) is irrelevant to this denial",
			qr.DeniedResource, quota.CPUCores)
	}

	qe, ok := err.(*QuotaExceededError)
	if !ok {
		t.Errorf("error type = %T, want *QuotaExceededError", err)
		return
	}
	if qe.Resource != "memory" {
		t.Errorf("QuotaExceededError.Resource = %q, want \"memory\"", qe.Resource)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression 6 — 用户显式 --cpus 在物理范围内且低于配额时，原值保留
// ──────────────────────────────────────────────────────────────────────────────
//
// 场景：bob 显式 --cpus 1.5 --memory 2048m
//   1.5 < quota 4.0 → 不超配额 → 允许
//   1.5 < physical 2.0 → 不超物理 → 原值保留（不被修复逻辑改变）

func TestRegression_BobExplicitCPU_WithinBothLimits_Preserved(t *testing.T) {
	phys := physNano()
	userNano := int64(1.5 * 1e9)

	if userNano > phys {
		t.Skipf("skip: userNano(1.5 cores) > physical(%d NanoCPUs); not applicable on this server",
			phys)
	}

	qm := loadPhysQM(t, yamlBobCPU4ExceedsPhysical) // bob: {cpu:4.0, mem:3072}
	db := newBobPhysDB(t)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)

	// docker run --cpus 1.5 --memory 2048m
	body := []byte(fmt.Sprintf(`{"HostConfig":{"NanoCpus":%d,"Memory":%d}}`,
		userNano, int64(2048*1024*1024)))

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1002, db)
	if err != nil {
		t.Fatalf("--cpus 1.5 within quota(4.0) and physical(%.1f): %v (DeniedResource=%q)",
			float64(phys)/1e9, err, func() string {
				if qr != nil {
					return qr.DeniedResource
				}
				return "<nil>"
			}())
	}
	if !qr.Allowed {
		t.Fatalf("Allowed=false, DeniedResource=%q", qr.DeniedResource)
	}

	var injected containerCreateRequest
	if e := json.Unmarshal(newBody, &injected); e != nil {
		t.Fatalf("unmarshal: %v", e)
	}

	// 用户显式指定且在两个限制内，原值必须保留
	if injected.HostConfig.NanoCPUs != userNano {
		t.Errorf(
			"injected NanaCpus = %d (%.2f cores), want %d (1.50 cores)\n"+
				"  user specified --cpus 1.5 within quota(4.0) and physical(%.1f)\n"+
				"  proxy must preserve user's explicit value",
			injected.HostConfig.NanoCPUs, float64(injected.HostConfig.NanoCPUs)/1e9,
			userNano, float64(phys)/1e9,
		)
	}
}
