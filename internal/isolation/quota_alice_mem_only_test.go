package isolation

// ══════════════════════════════════════════════════════════════════════════════
// 复现测试套件：alice 仅设 mem_mb 时 --memory 2049m 触发 CPU 错误
// ──────────────────────────────────────────────────────────────────────────────
//
// 【触发场景（用户命令）】
//   docker container create --rm --name test_mem_limit1 --memory 2049m alpine:latest sleep 10
//   → 用户 alice，内存配额 4096m，系统默认 2048m
//   → 预期：成功（2049m < 4096m）
//   → 实际：Error response from daemon: range of CPUs is from 0.01 to 2.00,
//            as there are only 2 CPUs available
//
// 【根本原因 — 三层调用链】
//
//  Layer 1  quota.yaml 解析（GetQuota）
//  ──────────────────────────────────
//  alice 的 YAML 条目只写了 mem_mb: 4096，没有写 cpu_cores。
//  旧代码使用 QuotaEntry（非指针字段），Go YAML 将缺省字段解析为零值：
//    ue.CPUCores = 0.0
//  GetQuota 无条件执行覆盖：
//    q.CPUCores = ue.CPUCores   // 0.0 覆盖了 defaults.cpu_cores = 2.0 ← BUG
//  结果：alice 的有效 CPUCores = 0（本意：继承 defaults=2.0）
//
//  Layer 2  配额注入（injectQuotaLimits）
//  ──────────────────────────────────────
//  旧代码的注入逻辑缺少 > 0 守卫：
//    quotaNano := int64(quota.CPUCores * 1e9)  // = 0
//    hostConfig["NanoCpus"] = json.Marshal(quotaNano) // 显式写入 "NanoCpus":0
//  代理把 {"NanoCpus":0, "Memory":2149580800} 转发给 Docker daemon。
//
//  Layer 3  Docker daemon 校验（Docker 29.x 行为）
//  ─────────────────────────────────────────────
//  NanoCpus 字段存在且值为 0，Docker 解析为"0 核"，触发范围校验：
//    if NanoCpus > 0 && (NanoCpus < 1e7 || NanoCpus > physCPUs*1e9) → error
//  0 < 最小值 1e7 (0.01 核) → 抛出
//    "range of CPUs is from 0.01 to 2.00, as there are only 2 CPUs available"
//
// 【现有修复方案（已合并到主干）】
//  ① quotaEntryRaw 使用 *float64/*int 指针区分"未填写 nil"与"显式 0"
//  ② GetQuota 用户覆盖段只覆盖 != nil 的字段（nil → 继承上级配额）
//  ③ injectQuotaLimits 增加 if quota.CPUCores > 0 守卫（防御兜底）
//
// 【本文件测试结构】
//  1. Red Test — 核心复现：alice 仅设 mem_mb，--memory 2049m 被错误拒绝
//  2. Red Test — 注入验证：NanoCpus 被注入为显式 0，触发 Docker 范围错误
//  3. Regression — 正确路径：alice 仅设 mem_mb，请求应被允许且注入合法 NanoCpus
//  4. Regression — 拒绝原因正确：超出内存配额时错误类型必须是 memory，非 cpu
//  5. Regression — 用户显式 CPU 保留：指定 --cpus 0.5 时原值不被覆盖
//  6. Regression — 无用户条目继承默认：bob 无专属配额，受 defaults 约束
//  7. Regression — 显式 0 语义保留：alice 显式 cpu_cores:0 表示"不限制"
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"encoding/json"
	"fmt"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// ── 测试用 YAML 配置 ──────────────────────────────────────────────────────────

// yamlBugAliceMemOnly: 复现场景 — alice 仅设 mem_mb:4096，未设 cpu_cores
// 对应用户实际 quota.yaml 配置
const yamlBugAliceMemOnly = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
users:
  alice:
    mem_mb: 4096
`

// yamlBugAliceFullQuota: 正确配置基准 — alice 同时设置两个字段
const yamlBugAliceFullQuota = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
users:
  alice:
    cpu_cores: 1.0
    mem_mb: 4096
`

// yamlBugAliceExplicitZeroCPU: alice 显式 cpu_cores:0 表示"不限制 CPU"
const yamlBugAliceExplicitZeroCPU = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
users:
  alice:
    cpu_cores: 0
    mem_mb: 4096
`

// ── 辅助 ─────────────────────────────────────────────────────────────────────

func newBugTestDB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func loadQMForBug(t *testing.T, yaml string) *QuotaManager {
	t.Helper()
	path := writeTempQuotaYAML(t, yaml)
	qm, err := LoadQuotaManager(path)
	if err != nil {
		t.Fatalf("LoadQuotaManager: %v", err)
	}
	return qm
}

// memOnlyBody 构造仅包含 Memory 字段的容器创建请求体（模拟 --memory Xm，无 --cpus）
func memOnlyBody(memMB int64) []byte {
	return []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, memMB*1024*1024))
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. Red Test — 核心复现
// ──────────────────────────────────────────────────────────────────────────────
//
// 精确复现用户命令：
//   docker container create --rm --name test_mem_limit1 --memory 2049m alpine:latest sleep 10
//
// 期望行为：alice 内存配额 4096m > 请求 2049m → 代理层应当允许
// Bug 行为：代理允许（不报错），但注入了 NanoCpus=0，Docker 返回 CPU 范围错误
//
// 本测试验证代理层的决策正确性（Allowed=true）以及注入体合法性（NanoCpus 不为 0）
// ── 修复前：TestBug.1 和 TestBug.2 至少一个断言失败
// ── 修复后：两个断言全部通过

func TestBug_AliceMemOnly_Request2049m_ShouldBeAllowed(t *testing.T) {
	// alice 的 quota.yaml 只有 mem_mb:4096，管理员未写 cpu_cores
	qm := loadQMForBug(t, yamlBugAliceMemOnly)
	db := newBugTestDB(t)
	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}

	quota := qm.GetQuota(alice)

	// ── 前置断言：检查 GetQuota 返回值是否合理 ──────────────────────────────
	//
	// 修复前（YAML 零值 Bug）：quota.CPUCores = 0（ue.CPUCores=0 覆盖 defaults 2.0）
	// 修复后：quota.CPUCores = 2.0（nil 指针 → 继承 defaults.cpu_cores）
	if quota.CPUCores == 0 {
		t.Errorf(
			"[BUG Layer-1] GetQuota(alice).CPUCores = 0\n"+
				"  alice's yaml entry only has mem_mb:4096 (no cpu_cores field)\n"+
				"  YAML zero-value 0.0 overwrote defaults.cpu_cores=2.0\n"+
				"  Fix: use quotaEntryRaw with *float64 to distinguish nil vs explicit-0",
		)
		// 不 t.Fatal：继续执行后续注入测试，给出更完整的失败信息
	}

	if quota.MemMB != 4096 {
		t.Fatalf("precondition: alice MemMB = %d, want 4096", quota.MemMB)
	}

	// ── 主体：模拟 docker container create --memory 2049m ──────────────────
	body := memOnlyBody(2049)
	newBody, qr, err := CheckAndInjectQuota(body, quota, 1001, db)

	// ── 断言 1：代理层不应返回 error ─────────────────────────────────────
	//
	// 2049m < alice 4096m 配额，代理层必须允许
	if err != nil {
		t.Errorf(
			"[BUG] CheckAndInjectQuota returned error: %v\n"+
				"  alice quota=4096m, requested=2049m: should be allowed\n"+
				"  If memory quota check is wrong, GetQuota may have returned default 2048m",
			err,
		)
	}
	if qr != nil && !qr.Allowed {
		t.Errorf(
			"[BUG] Allowed=false, DeniedResource=%q requested=%q limit=%q\n"+
				"  alice quota=4096m > requested=2049m, must pass\n"+
				"  If DeniedResource=cpu: GetQuota returned wrong CPUCores",
			qr.DeniedResource, qr.DeniedRequested, qr.DeniedLimit,
		)
	}

	// ── 断言 2：注入后的 NanoCpus 不能为显式 0 ──────────────────────────
	//
	// Docker 29.x 行为：JSON 中 "NanoCpus":0 触发范围检查（0 < 最小值 0.01核）
	//   → "range of CPUs is from 0.01 to 2.00, as there are only 2 CPUs available"
	//
	// 修复前（旧注入代码无 > 0 守卫）：
	//   quotaNano = int64(0 * 1e9) = 0
	//   hostConfig["NanoCpus"] = json.Marshal(0)   ← 显式写入 0，Docker 报错
	//
	// 修复后（quotaEntryRaw + 守卫）：
	//   CPUCores = 2.0（继承 defaults）→ quotaNano = 2e9
	//   或 CPUCores = 0（显式不限制）→ if quota.CPUCores > 0 = false → 不注入
	//   两种情况 Docker 均不会报 CPU 范围错误
	if newBody != nil {
		var injected containerCreateRequest
		if e := json.Unmarshal(newBody, &injected); e == nil {
			if injected.HostConfig.NanoCPUs == 0 {
				// CPUCores=0 时，注入逻辑应跳过（守卫保护），不写 "NanoCpus":0
				// 检查原始 JSON 中是否真的出现了 "NanoCpus":0
				var raw map[string]json.RawMessage
				var hc map[string]json.RawMessage
				_ = json.Unmarshal(newBody, &raw)
				_ = json.Unmarshal(raw["HostConfig"], &hc)
				if _, exists := hc["NanoCpus"]; exists {
					t.Errorf(
						"[BUG Layer-2+3] injected NanoCpus field exists and = 0\n"+
							"  Docker 29.x rejects NanoCpus=0 with:\n"+
							"  'range of CPUs is from 0.01 to 2.00, as there are only 2 CPUs available'\n"+
							"  Root cause: quota.CPUCores=0 → quotaNano=0 → hostConfig[NanoCpus]=0\n"+
							"  Fix: add 'if quota.CPUCores > 0' guard in injectQuotaLimits",
					)
				}
			} else if injected.HostConfig.NanoCPUs > 0 {
				// 修复后的正确路径：NanoCpus = defaults.cpu_cores * 1e9 = 2e9
				wantNano := int64(2.0 * 1e9) // defaults.cpu_cores = 2.0
				if injected.HostConfig.NanoCPUs != wantNano {
					t.Errorf(
						"injected NanoCpus = %d (%.2f cores), want %d (2.00 cores)\n"+
							"  alice's cpu_cores not set → should inherit defaults.cpu_cores=2.0\n"+
							"  Injected value should equal defaults * 1e9",
						injected.HostConfig.NanoCPUs,
						float64(injected.HostConfig.NanoCPUs)/1e9,
						wantNano,
					)
				}
			}
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. Red Test — GetQuota 层独立验证
// ──────────────────────────────────────────────────────────────────────────────
//
// 单独测试 GetQuota 的 CPUCores 继承行为，与注入层解耦。
// 这是 Bug 的源头（Layer 1），修复此处可防止问题传播到注入层。

func TestBug_GetQuota_AliceMemOnly_CPUCoresInheritsDefault(t *testing.T) {
	qm := loadQMForBug(t, yamlBugAliceMemOnly)
	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}

	got := qm.GetQuota(alice)

	// 内存：alice 用户条目指定了 4096，必须生效
	if got.MemMB != 4096 {
		t.Errorf("MemMB = %d, want 4096 (alice's user entry should override default)", got.MemMB)
	}

	// CPU：alice 未指定 → 必须继承 defaults.cpu_cores = 2.0
	//
	// 修复前：got.CPUCores = 0（YAML 零值 ue.CPUCores=0 无条件覆盖 defaults 2.0）
	// 修复后：got.CPUCores = 2.0（nil 指针跳过覆盖，保持 defaults 值）
	if got.CPUCores == 0 {
		t.Errorf(
			"[BUG] GetQuota(alice).CPUCores = 0, want 2.0 (inherited from defaults)\n"+
				"  alice's yaml: {mem_mb: 4096} — no cpu_cores field\n"+
				"  Before fix: YAML parsed missing cpu_cores as 0.0, overwrote defaults.cpu_cores=2.0\n"+
				"  After fix:  *float64 nil pointer → inherit defaults → CPUCores=2.0\n"+
				"  Impact: CPUCores=0 → inject NanoCpus=0 → Docker rejects with CPU range error",
		)
	}
	if got.CPUCores != 0 && got.CPUCores != 2.0 {
		t.Errorf(
			"GetQuota(alice).CPUCores = %.2f, want 2.0\n"+
				"  alice has no cpu_cores entry, should inherit defaults.cpu_cores=2.0",
			got.CPUCores,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. Regression — 正确路径完整验证
// ──────────────────────────────────────────────────────────────────────────────
//
// alice 仅设 mem_mb:4096，请求 --memory 2049m：
//   ✓ 代理允许（2049m < 4096m）
//   ✓ 注入 NanoCpus = 2.0e9（继承 defaults）
//   ✓ 注入 Memory = 2049m（用户指定值保留）
//   ✓ 无 CPU 相关错误

func TestRegression_AliceMemOnly_Request2049m_AllowedWithCorrectInjection(t *testing.T) {
	qm := loadQMForBug(t, yamlBugAliceMemOnly)
	db := newBugTestDB(t)
	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}

	quota := qm.GetQuota(alice)
	if quota.MemMB != 4096 {
		t.Fatalf("precondition: alice MemMB = %d, want 4096", quota.MemMB)
	}

	body := memOnlyBody(2049)
	newBody, qr, err := CheckAndInjectQuota(body, quota, 1001, db)

	if err != nil {
		t.Fatalf(
			"request denied: %v\n"+
				"  alice quota=4096m, requested=2049m: must be allowed\n"+
				"  DeniedResource=%q (should be empty, not 'cpu')",
			err,
			func() string {
				if qr != nil {
					return qr.DeniedResource
				}
				return "<nil qr>"
			}(),
		)
	}
	if qr == nil || !qr.Allowed {
		t.Fatalf(
			"Allowed=false, DeniedResource=%q\n"+
				"  request 2049m must pass alice's 4096m quota",
			func() string {
				if qr != nil {
					return qr.DeniedResource
				}
				return "<nil qr>"
			}(),
		)
	}

	var injected containerCreateRequest
	if e := json.Unmarshal(newBody, &injected); e != nil {
		t.Fatalf("unmarshal injected body: %v", e)
	}

	// 注入 NanoCpus 应为 defaults.cpu_cores * 1e9 = 2e9
	wantNano := int64(2.0 * 1e9)
	if injected.HostConfig.NanoCPUs != wantNano {
		t.Errorf(
			"injected NanoCpus = %d (%.2f cores), want %d (2.00 cores)\n"+
				"  alice's cpu_cores not set → inherit defaults 2.0 → inject 2e9\n"+
				"  If 0: Layer-1 bug not fixed (CPUCores still 0)\n"+
				"  If >2e9: defaults.cpu_cores exceeds physical CPUs → Docker will reject",
			injected.HostConfig.NanoCPUs,
			float64(injected.HostConfig.NanoCPUs)/1e9,
			wantNano,
		)
	}

	// 内存原值保留
	wantMemBytes := int64(2049 * 1024 * 1024)
	if injected.HostConfig.Memory != wantMemBytes {
		t.Errorf(
			"injected Memory = %d bytes (%dMB), want %d bytes (2049MB)\n"+
				"  user-specified memory value must be preserved",
			injected.HostConfig.Memory,
			injected.HostConfig.Memory/1024/1024,
			wantMemBytes,
		)
	}

	// QuotaCheckResult 应记录正确的配额值
	if qr.QuotaCPUCores != quota.CPUCores {
		t.Errorf("qr.QuotaCPUCores = %.2f, want %.2f", qr.QuotaCPUCores, quota.CPUCores)
	}
	if qr.QuotaMemMB != 4096 {
		t.Errorf("qr.QuotaMemMB = %d, want 4096", qr.QuotaMemMB)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. Regression — 超出内存配额时拒绝原因必须是 memory，不能是 cpu
// ──────────────────────────────────────────────────────────────────────────────
//
// Bug 存在时，Layer-1 返回 CPUCores=0，可能引起后续链路误判拒绝原因。
// 本测试确保：超出内存配额时 DeniedResource="memory"，不污染为 cpu。

func TestRegression_AliceMemOnly_ExceedsMemQuota_DeniedWithMemoryError(t *testing.T) {
	qm := loadQMForBug(t, yamlBugAliceMemOnly)
	db := newBugTestDB(t)
	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}

	quota := qm.GetQuota(alice)

	// 请求 4097m，超出 alice 4096m 配额
	body := memOnlyBody(4097)
	_, qr, err := CheckAndInjectQuota(body, quota, 1001, db)

	// 必须被拒绝
	if err == nil {
		t.Errorf(
			"expected denial for 4097m > alice quota 4096m, got nil\n"+
				"  alice must not exceed her own memory quota",
		)
		return
	}

	// 拒绝原因必须是 memory，不能是 cpu
	if qr != nil && qr.DeniedResource != "memory" {
		t.Errorf(
			"DeniedResource = %q, want \"memory\"\n"+
				"  request was over memory quota (4097m > 4096m), not CPU quota\n"+
				"  If DeniedResource=cpu: GetQuota incorrectly returned CPUCores that caused CPU check to fire",
			qr.DeniedResource,
		)
	}

	// 错误类型必须是 QuotaExceededError
	var qe *QuotaExceededError
	if !isQuotaExceededError(err, &qe) {
		t.Errorf("error type = %T, want *QuotaExceededError: %v", err, err)
		return
	}
	if qe.Resource != "memory" {
		t.Errorf(
			"QuotaExceededError.Resource = %q, want \"memory\"\n"+
				"  memory request 4097m exceeded quota 4096m",
			qe.Resource,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. Regression — 用户显式指定 --cpus 0.5 时，原值不被配额覆盖
// ──────────────────────────────────────────────────────────────────────────────
//
// alice 有 mem_mb:4096（无 cpu_cores），用户命令同时指定 --cpus 0.5 --memory 2049m。
// 0.5 核 < 继承后的 quota 2.0 核：代理应保留用户指定的 0.5 核，不覆盖为 2.0。

func TestRegression_AliceMemOnly_ExplicitCPU_PreservedWhenWithinQuota(t *testing.T) {
	qm := loadQMForBug(t, yamlBugAliceMemOnly)
	db := newBugTestDB(t)
	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}

	quota := qm.GetQuota(alice)

	// 模拟 docker create --cpus 0.5 --memory 2049m
	userNanoCPUs := int64(0.5 * 1e9) // 500000000
	body := []byte(fmt.Sprintf(
		`{"HostConfig":{"NanoCpus":%d,"Memory":%d}}`,
		userNanoCPUs,
		int64(2049*1024*1024),
	))

	newBody, qr, err := CheckAndInjectQuota(body, quota, 1001, db)
	if err != nil {
		t.Fatalf(
			"request denied: %v\n"+
				"  alice quota: cpu=2.0 mem=4096m, requested: cpu=0.5 mem=2049m\n"+
				"  both within quota, must be allowed",
			err,
		)
	}
	if !qr.Allowed {
		t.Fatalf("Allowed=false, DeniedResource=%q", qr.DeniedResource)
	}

	var injected containerCreateRequest
	if e := json.Unmarshal(newBody, &injected); e != nil {
		t.Fatalf("unmarshal: %v", e)
	}

	// 用户指定了 0.5 核且在配额内，代理必须保留该值，不应覆盖为配额上限 2.0
	if injected.HostConfig.NanoCPUs != userNanoCPUs {
		t.Errorf(
			"injected NanoCpus = %d (%.2f cores), want %d (0.50 cores)\n"+
				"  user specified --cpus 0.5 (within quota 2.0), value must be preserved\n"+
				"  proxy should not override user value with quota ceiling",
			injected.HostConfig.NanoCPUs,
			float64(injected.HostConfig.NanoCPUs)/1e9,
			userNanoCPUs,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 6. Regression — 无专属配额的用户继承 defaults，不受 alice 配额影响
// ──────────────────────────────────────────────────────────────────────────────
//
// bob 没有用户专属条目，应严格受 defaults 约束（cpu:2.0, mem:2048m）。
// 验证：alice 的 mem_mb 扩展不会"污染"其他用户。

func TestRegression_BobNoEntry_InheritsDefaultsUnaffectedByAlice(t *testing.T) {
	// 使用含 alice 扩展配额的 YAML，但测试 bob
	qm := loadQMForBug(t, yamlBugAliceMemOnly)
	db := newBugTestDB(t)
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}

	quota := qm.GetQuota(bob)

	// bob 应严格继承 defaults
	if quota.CPUCores != 2.0 {
		t.Errorf("bob CPUCores = %.2f, want 2.0 (default)", quota.CPUCores)
	}
	if quota.MemMB != 2048 {
		t.Errorf("bob MemMB = %d, want 2048 (default)", quota.MemMB)
	}

	// bob 请求 2049m > defaults 2048m → 必须拒绝（alice 的 4096m 配额不适用于 bob）
	body := memOnlyBody(2049)
	_, qr, err := CheckAndInjectQuota(body, quota, 1002, db)
	if err == nil {
		t.Errorf(
			"bob should be denied 2049m (> default 2048m)\n"+
				"  alice's 4096m quota must not leak to other users",
		)
	}
	if qr != nil && qr.DeniedResource != "memory" {
		t.Errorf("DeniedResource = %q, want \"memory\"", qr.DeniedResource)
	}

	// bob 请求 2048m = defaults → 应被允许
	body2048 := memOnlyBody(2048)
	_, qr2, err2 := CheckAndInjectQuota(body2048, quota, 1002, db)
	if err2 != nil {
		t.Errorf("bob 2048m (= default) should be allowed: %v", err2)
	}
	if qr2 != nil && !qr2.Allowed {
		t.Errorf("Allowed=false for bob at default boundary: resource=%s", qr2.DeniedResource)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 7. Regression — alice 显式 cpu_cores:0 语义（不限制 CPU）
// ──────────────────────────────────────────────────────────────────────────────
//
// 与 Bug 场景的关键区别：
//   Bug 场景: cpu_cores 字段缺失 → 应继承 defaults（2.0）
//   本场景:   cpu_cores: 0 显式写入 → 表示"不限制 CPU"，覆盖 defaults（0 > 2.0 的语义）
//
// 修复后的 quotaEntryRaw 必须正确区分这两种情况：
//   缺失字段  → *float64 = nil → 继承 defaults.cpu_cores = 2.0
//   显式 0    → *float64 = &0  → 覆盖为 0（不限制）

func TestRegression_AliceExplicitZeroCPU_MeansUnlimited_NotInherited(t *testing.T) {
	qm := loadQMForBug(t, yamlBugAliceExplicitZeroCPU)
	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}

	got := qm.GetQuota(alice)

	// 显式 cpu_cores:0 必须为 0（不限制），不能被 defaults.cpu_cores=2.0 覆盖
	if got.CPUCores != 0 {
		t.Errorf(
			"CPUCores = %.2f, want 0 (explicit unlimited)\n"+
				"  alice.cpu_cores=0 explicitly overrides defaults.cpu_cores=2.0\n"+
				"  Must NOT inherit default when user explicitly wrote '0'\n"+
				"  If 2.0: fix incorrectly treats explicit-0 same as missing field",
			got.CPUCores,
		)
	}

	// 内存仍然生效
	if got.MemMB != 4096 {
		t.Errorf("MemMB = %d, want 4096", got.MemMB)
	}

	// 当 CPUCores=0（不限制）时，注入层不应写入 NanoCpus 字段
	db := newBugTestDB(t)
	body := memOnlyBody(2049)
	newBody, qr, err := CheckAndInjectQuota(body, got, 1001, db)
	if err != nil {
		t.Fatalf("unexpected error for cpu_cores=0 (unlimited): %v", err)
	}
	if !qr.Allowed {
		t.Fatalf("Allowed=false: %s", qr.DeniedResource)
	}

	var injected containerCreateRequest
	if e := json.Unmarshal(newBody, &injected); e != nil {
		t.Fatalf("unmarshal: %v", e)
	}

	// CPUCores=0（不限制）→ 注入层必须跳过 NanoCpus（不写入 0，否则 Docker 报错）
	if injected.HostConfig.NanoCPUs != 0 {
		t.Errorf(
			"injected NanoCpus = %d, want 0 (no injection when unlimited)\n"+
				"  cpu_cores=0 means unlimited, proxy must NOT inject any NanoCpus value",
			injected.HostConfig.NanoCPUs,
		)
	}
	// 同时确认 NanoCpus 字段不存在于 JSON 中（不是写入 0，而是完全不写）
	var raw map[string]json.RawMessage
	var hc map[string]json.RawMessage
	_ = json.Unmarshal(newBody, &raw)
	_ = json.Unmarshal(raw["HostConfig"], &hc)
	if _, exists := hc["NanoCpus"]; exists {
		t.Errorf(
			"NanoCpus field present in injected JSON, want absent\n"+
				"  cpu_cores=0 (unlimited): proxy must omit NanoCpus, not write 0\n"+
				"  Docker 29.x treats 'NanoCpus:0' as invalid (< 0.01 minimum)",
		)
	}
}

// ── 辅助：errors.As 等效实现（避免引入 errors 包 ） ──────────────────────────

func isQuotaExceededError(err error, target **QuotaExceededError) bool {
	if qe, ok := err.(*QuotaExceededError); ok {
		if target != nil {
			*target = qe
		}
		return true
	}
	return false
}
