package isolation

// ── Bug：GetQuota 用户条目部分字段覆盖 defaults 零值问题 ────────────────────
//
// 根本原因（GetQuota，第 217-227 行）：
//   当用户 YAML 条目只指定了部分字段（如 mem_mb: 4096，未写 cpu_cores），
//   Go YAML 解析给未出现的字段赋零值（ue.CPUCores = 0.0）。
//   GetQuota 在应用用户覆盖时无条件执行：
//
//     q.CPUCores = ue.CPUCores   // 0.0 覆盖了 defaults 的 2.0 ← BUG
//     q.MemMB    = ue.MemMB      // 4096 ✓
//
//   结果：alice 有效配额 = {CPUCores:0 (无限制!), MemMB:4096}
//   预期：alice 有效配额 = {CPUCores:2.0 (继承 default), MemMB:4096}
//
// 影响：
//   1. alice 创建容器时，CPU 不被限制（管理员仅想扩大内存配额）
//   2. injectQuotaLimits 跳过 CPU 注入（CPUCores==0），
//      容器以无限 CPU 运行，违背隔离策略
//
// 修复方向：
//   GetQuota 用户覆盖段只覆盖非零字段：
//     if ue.CPUCores != 0 { q.CPUCores = ue.CPUCores }
//     if ue.MemMB    != 0 { q.MemMB    = ue.MemMB    }
//   注意：0=不限制 的显式意图需通过其他方式区分（如指针类型 *float64）。

import (
	"encoding/json"
	"fmt"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// ── 辅助 ──────────────────────────────────────────────────────────────────────

func newMemInheritDB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mustLoadQM(t *testing.T, yaml string) *QuotaManager {
	t.Helper()
	path := writeTempQuotaYAML(t, yaml)
	qm, err := LoadQuotaManager(path)
	if err != nil {
		t.Fatalf("LoadQuotaManager: %v", err)
	}
	return qm
}

// alice 只有 mem_mb，无 cpu_cores
const yamlAliceMemOnly = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
users:
  alice:
    mem_mb: 4096
`

// alice 同时指定 cpu_cores 和 mem_mb（正常配置，回归基准）
const yamlAliceFullQuota = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
users:
  alice:
    cpu_cores: 2.0
    mem_mb: 4096
`

// ── 1. Red Test：仅设 mem_mb 时，CPUCores 被错误置为 0 ──────────────────────
//
// 预期行为：alice 未指定 cpu_cores → 应继承 defaults.cpu_cores = 2.0
// 当前行为：q.CPUCores = ue.CPUCores = 0（YAML 零值覆盖 default）
// 断言失败：说明 Bug 存在
// 断言通过：说明 Bug 已修复

func TestBug_GetQuota_MemOnlyEntry_CPUCoresBecomesZero_Red(t *testing.T) {
	qm := mustLoadQM(t, yamlAliceMemOnly)
	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}

	got := qm.GetQuota(alice)

	// ── 断言 1：内存配额应为 4096（用户配置生效，这部分正确）────────────────
	if got.MemMB != 4096 {
		t.Errorf("MemMB = %d, want 4096 (alice's user entry should override default)", got.MemMB)
	}

	// ── 断言 2（RED）：CPU 应继承 default=2.0，而非被 0 覆盖 ────────────────
	//
	// 修复前：got.CPUCores = 0（ue.CPUCores=0 覆盖了 default 2.0）
	// 修复后：got.CPUCores = 2.0（未指定字段继承 default）
	if got.CPUCores == 0 {
		t.Errorf(
			"[BUG] GetQuota(alice).CPUCores = 0, want 2.0 (should inherit defaults)\n"+
				"  alice's user entry only sets mem_mb:4096, not cpu_cores.\n"+
				"  YAML zero-value 0.0 overwrote defaults.cpu_cores=2.0\n"+
				"  Effect: alice gets NO CPU limit, bypassing the 2-core quota",
		)
	}
}

// ── 2. Red Test：CPUCores=0 导致容器无 CPU 注入 ───────────────────────────────
//
// 当 GetQuota 错误返回 CPUCores=0 时，injectQuotaLimits 跳过 CPU 注入，
// 容器以无限 CPU 运行，违背隔离策略。

func TestBug_GetQuota_MemOnlyEntry_ContainerGetsNoCPULimit_Red(t *testing.T) {
	db := newMemInheritDB(t)
	qm := mustLoadQM(t, yamlAliceMemOnly)
	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}

	quota := qm.GetQuota(alice)

	// alice 只请求内存，不指定 CPU（正常使用场景）
	body := []byte(`{"HostConfig":{"Memory":2149580800}}`) // 2049m
	newBody, qr, err := CheckAndInjectQuota(body, quota, 1001, db, qm.GetDefaultQuota().CPUCores)
	if err != nil {
		t.Fatalf("CheckAndInjectQuota error: %v", err)
	}
	if !qr.Allowed {
		t.Fatalf("request should be allowed (2049m <= alice 4096m quota): %s", qr.DeniedResource)
	}

	var req containerCreateRequest
	if e := json.Unmarshal(newBody, &req); e != nil {
		t.Fatalf("unmarshal result: %v", e)
	}

	// ── 断言（RED）：因 CPUCores=0，NanoCpus 未被注入 ────────────────────────
	//
	// 修复前：CPUCores=0 → injectQuotaLimits 跳过 CPU 段 → NanoCpus=0（无限制）
	// 修复后：CPUCores=2.0 → 注入 NanoCpus=2000000000
	wantNano := int64(2.0 * 1e9)
	if req.HostConfig.NanoCPUs == 0 {
		t.Errorf(
			"[BUG] injected NanoCpus = 0 (no CPU limit applied)\n"+
				"  Expected NanoCpus = %d (%.2f cores from defaults)\n"+
				"  Root cause: alice.cpu_cores not set → CPUCores=0 → CPU injection skipped\n"+
				"  Risk: alice can use 100%% CPU on all %d physical cores",
			wantNano, float64(wantNano)/1e9, 2, // 2 = 服务器物理核数
		)
	}
}

// ── 3. 回归 #1：alice 使用 2049m 请求（在 4096m 配额内）应被允许 ─────────────
//
// 核心业务逻辑：alice 内存配额 4096m > 系统默认 2048m。
// 请求 2049m（高于默认，低于 alice 专属配额）必须通过。

func TestRegression_AliceMemQuota_Request2049m_Allowed(t *testing.T) {
	db := newMemInheritDB(t)
	qm := mustLoadQM(t, yamlAliceFullQuota) // alice: {cpu_cores:2.0, mem_mb:4096}
	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}

	quota := qm.GetQuota(alice)
	if quota.MemMB != 4096 {
		t.Fatalf("precondition: alice MemMB = %d, want 4096", quota.MemMB)
	}

	memBytes := int64(2049 * 1024 * 1024) // 2049m，高于 default 2048m
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, memBytes))

	_, qr, err := CheckAndInjectQuota(body, quota, 1001, db, qm.GetDefaultQuota().CPUCores)

	// ── 断言：必须允许 ──────────────────────────────────────────────────────
	if err != nil {
		t.Errorf(
			"request denied: %v\n"+
				"  alice quota=4096m, requested=2049m: should be allowed\n"+
				"  If denied, GetQuota may have returned default 2048m instead of alice's 4096m",
			err,
		)
	}
	if qr != nil && !qr.Allowed {
		t.Errorf(
			"Allowed=false, DeniedResource=%q, requested=%q, limit=%q\n"+
				"  alice quota=4096m > requested=2049m, must pass",
			qr.DeniedResource, qr.DeniedRequested, qr.DeniedLimit,
		)
	}
}

// ── 4. 回归 #2：alice 请求恰好等于 default（2048m）时也必须通过 ───────────────

func TestRegression_AliceMemQuota_RequestExactDefault_Allowed(t *testing.T) {
	db := newMemInheritDB(t)
	qm := mustLoadQM(t, yamlAliceFullQuota)
	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}
	quota := qm.GetQuota(alice)

	memBytes := int64(2048 * 1024 * 1024) // 恰好 default
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, memBytes))

	_, qr, err := CheckAndInjectQuota(body, quota, 1001, db, qm.GetDefaultQuota().CPUCores)
	if err != nil {
		t.Errorf("request at default 2048m denied: %v", err)
	}
	if qr != nil && !qr.Allowed {
		t.Errorf("Allowed=false at default boundary: resource=%s", qr.DeniedResource)
	}
}

// ── 5. 回归 #3：alice 超出自己配额（4097m > 4096m）时必须拒绝 ─────────────────

func TestRegression_AliceMemQuota_RequestExceedsOwnQuota_Denied(t *testing.T) {
	db := newMemInheritDB(t)
	qm := mustLoadQM(t, yamlAliceFullQuota)
	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}
	quota := qm.GetQuota(alice)

	memBytes := int64(4097 * 1024 * 1024) // 超出 alice 4096m 配额
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, memBytes))

	_, _, err := CheckAndInjectQuota(body, quota, 1001, db, qm.GetDefaultQuota().CPUCores)
	if err == nil {
		t.Errorf(
			"expected denial for 4097m > alice quota 4096m, got nil\n"+
				"  alice should not exceed her own quota",
		)
	}
}

// ── 6. 回归 #4：无用户条目的普通用户受系统默认 2048m 限制 ────────────────────

func TestRegression_DefaultUser_MemLimit2048_Enforced(t *testing.T) {
	db := newMemInheritDB(t)
	qm := mustLoadQM(t, yamlAliceMemOnly)                               // alice 有条目，bob 没有
	bob := &auth.CallerIdentity{RealUsername: "bob", RealUID: 1002}
	quota := qm.GetQuota(bob)

	if quota.MemMB != 2048 {
		t.Fatalf("precondition: bob MemMB = %d, want 2048 (default)", quota.MemMB)
	}

	// bob 请求 2049m > default 2048m，应被拒绝
	memBytes := int64(2049 * 1024 * 1024)
	body := []byte(fmt.Sprintf(`{"HostConfig":{"Memory":%d}}`, memBytes))
	_, _, err := CheckAndInjectQuota(body, quota, 1002, db, qm.GetDefaultQuota().CPUCores)
	if err == nil {
		t.Errorf(
			"bob (no user entry) should be denied 2049m > default 2048m\n"+
				"  only alice has a 4096m override",
		)
	}
}

// ── 7. 回归 #5：修复后 alice 的 CPUCores 应等于 default，而非 0 ─────────────
//
// 这是 Bug 1 的修复验证测试。
// 验证修复方案：GetQuota 用户覆盖段只覆盖非零字段。
// 修复后此测试通过；修复前（当前代码）此测试失败。

func TestRegression_AliceMemOnlyEntry_CPUInheritsDefault(t *testing.T) {
	qm := mustLoadQM(t, yamlAliceMemOnly)
	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}
	got := qm.GetQuota(alice)

	// 内存：来自 alice 用户条目
	if got.MemMB != 4096 {
		t.Errorf("MemMB = %d, want 4096", got.MemMB)
	}
	// CPU：alice 未指定，应继承 defaults.cpu_cores = 2.0
	if got.CPUCores != 2.0 {
		t.Errorf(
			"CPUCores = %.2f, want 2.0 (should inherit defaults when not set in user entry)\n"+
				"  Current bug: 0.0 (YAML zero-value overwrites default)",
			got.CPUCores,
		)
	}
}
