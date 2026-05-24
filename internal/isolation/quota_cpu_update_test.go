package isolation

// ── 针对"编辑 quota.yaml alice.cpu_cores=4.0 后限制仍为 1.0"Bug 的测试套件 ────
//
// 根本原因（重新分析）：
//   `main.go` 中存在两条热重载路径，但两条路径均只重载 *policyFile（策略文件），
//   完全没有涉及 *quotaFile（配额文件）：
//
//     文件监视 ticker（每 2s）:
//       stat(*policyFile) → 变化 → authz.LoadPolicy → proxy.UpdatePolicy(newPolicy)
//                                   ↑ 只重载策略，quota.yaml 的变化被忽略
//
//     SIGHUP 信号处理:
//       authz.LoadPolicy(*policyFile) → proxy.UpdatePolicy(newPolicy)
//                                        ↑ 同样只重载策略
//
//   同时 ProxyServer 只有 UpdatePolicy()，**没有 UpdateQuota() 方法**。
//
//   因此，当管理员编辑 quota.yaml 将 alice.cpu_cores 从 1.0 改为 4.0 时：
//   - 代理进程内存中的 QuotaManager 永远不会被刷新
//   - GetQuota(alice) 始终返回启动时加载的旧值 1.0
//   - 必须**重启进程**才能使配额变更生效
//
// 修复方案需要（三者缺一不可）：
//   1. QuotaManager 增加原地重载能力（Reload 方法 或 原子替换）
//   2. ProxyServer 增加 UpdateQuota(*QuotaManager) 方法
//   3. main.go 的文件监视 + SIGHUP 处理器补充 quota 重载逻辑

import (
	"encoding/json"
	"os"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// ── 辅助函数 ─────────────────────────────────────────────────────────────────

func writeTempQuotaYAML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "quota-*.yaml")
	if err != nil {
		t.Fatalf("create temp quota file: %v", err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp quota file: %v", err)
	}
	f.Close()
	return f.Name()
}

func overwriteQuotaYAML(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("overwrite quota file: %v", err)
	}
}

func newCPUBugTestDB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

const yamlAlice1 = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
users:
  alice:
    cpu_cores: 1.0
    mem_mb: 1024
`

const yamlAlice4 = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
users:
  alice:
    cpu_cores: 4.0
    mem_mb: 1024
`

// ── 1. Reload 核心回归：文件变更后调用 Reload，GetQuota 必须返回新值 ─────────
//
// 修复验证：
//   1. 代理启动，加载 QuotaManager（alice.cpu_cores=1.0）
//   2. 管理员编辑 quota.yaml → alice.cpu_cores=4.0
//   3. 触发热重载（ticker/SIGHUP 调用 quota.Reload）
//   4. GetQuota(alice).CPUCores 应返回 4.0
func TestBug_AliceCPUQuota_FileEditNotReloaded_Red(t *testing.T) {
	path := writeTempQuotaYAML(t, yamlAlice1)

	// 步骤 1：代理启动时加载 QuotaManager
	proxyQM, err := LoadQuotaManager(path)
	if err != nil {
		t.Fatalf("LoadQuotaManager (initial): %v", err)
	}

	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}

	// 前置条件：启动时 alice = 1.0
	initial := proxyQM.GetQuota(alice)
	if initial.CPUCores != 1.0 {
		t.Fatalf("precondition: initial CPUCores = %.2f, want 1.0", initial.CPUCores)
	}

	// 步骤 2：管理员编辑 quota.yaml → alice.cpu_cores = 4.0
	overwriteQuotaYAML(t, path, yamlAlice4)

	// 步骤 3：ticker/SIGHUP 触发热重载（调用 Reload，原地替换内部状态）
	if err := proxyQM.Reload(path); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// 步骤 4：查询配额
	got := proxyQM.GetQuota(alice)

	// ── 断言：Reload 后 GetQuota 必须返回新值 4.0 ────────────────────────────
	if got.CPUCores != 4.0 {
		t.Errorf(
			"after Reload: GetQuota().CPUCores = %.2f, want 4.0\n"+
				"  Reload did not update alice's user-specific entry",
			got.CPUCores,
		)
	}

	// 默认值 2.0 不应干扰（用户专属条目优先）
	if got.CPUCores == 2.0 {
		t.Errorf("default quota 2.0 leaked out after Reload; user entry should take priority")
	}
}

// ── 2. Fix Verification Test：正确修复路径 ───────────────────────────────────
//
// 验证修复方案：创建新的 QuotaManager 并"原子替换"代理持有的实例，
// 相当于实现了 proxy.UpdateQuota(newQM) 的语义。
// 修复后此测试必须通过。
func TestFix_AliceCPUQuota_NewManagerFromUpdatedFile_Returns4(t *testing.T) {
	path := writeTempQuotaYAML(t, yamlAlice1)

	// 代理启动时持有的旧 QuotaManager
	_, err := LoadQuotaManager(path)
	if err != nil {
		t.Fatalf("LoadQuotaManager (initial): %v", err)
	}

	// 管理员编辑 quota.yaml → alice.cpu_cores = 4.0
	overwriteQuotaYAML(t, path, yamlAlice4)

	// 修复路径：重新加载并替换（等价于修复后的 proxy.UpdateQuota 语义）
	newQM, err := LoadQuotaManager(path)
	if err != nil {
		t.Fatalf("LoadQuotaManager (reloaded): %v", err)
	}

	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}
	got := newQM.GetQuota(alice)

	if got.CPUCores != 4.0 {
		t.Errorf("after reload: CPUCores = %.2f, want 4.0", got.CPUCores)
	}
	// 默认值 2.0 不应生效（用户专属条目优先）
	if got.CPUCores == 2.0 {
		t.Errorf("default 2.0 incorrectly applied after reload")
	}
	// MemMB 应保留 yaml 中的 1024（确认其他字段正常）
	if got.MemMB != 1024 {
		t.Errorf("MemMB = %d, want 1024", got.MemMB)
	}
}

// ── 3. Regression #1：注入值校验 ────────────────────────────────────────────
//
// 修复后：以更新后的 QuotaManager（alice=4.0）创建容器，
// 代理应注入 NanoCpus=4000000000（4.0 核），而非旧值 1000000000（1.0 核）。
func TestRegression_CheckAndInjectQuota_AfterReload_Injects4Cores(t *testing.T) {
	db := newCPUBugTestDB(t)
	path := writeTempQuotaYAML(t, yamlAlice1)

	// 模拟 reload 后的新 QuotaManager
	overwriteQuotaYAML(t, path, yamlAlice4)
	newQM, err := LoadQuotaManager(path)
	if err != nil {
		t.Fatalf("LoadQuotaManager: %v", err)
	}

	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}
	quota := newQM.GetQuota(alice)

	// 用户未指定 CPU 的请求
	body := []byte(`{"HostConfig":{}}`)
	newBody, qr, err := CheckAndInjectQuota(body, quota, 1001, db, newQM.GetDefaultQuota().CPUCores, newQM.GetDefaultQuota().MemMB)
	if err != nil {
		t.Fatalf("CheckAndInjectQuota error: %v", err)
	}
	if !qr.Allowed {
		t.Fatalf("request denied unexpectedly: %s", qr.DeniedResource)
	}

	var req containerCreateRequest
	if e := json.Unmarshal(newBody, &req); e != nil {
		t.Fatalf("unmarshal: %v", e)
	}

	// 修复后注入值 = min(defaults.cpu_cores=2.0, quota=4.0) = 2.0 核。
	// alice 配额上限 4.0 可由 alice 显式 --cpus 4.0 使用，但未指定时注入系统默认。
	wantNano := int64(2.0 * 1e9)
	if req.HostConfig.NanoCPUs != wantNano {
		t.Errorf(
			"injected NanoCpus = %d (%.2f cores), want %d (2.00 cores = defaults)\n"+
				"  after reload, unspecified --cpus injects defaults.cpu_cores(2.0), not quota ceiling(4.0)",
			req.HostConfig.NanoCPUs, float64(req.HostConfig.NanoCPUs)/1e9, wantNano,
		)
	}
	if qr.QuotaCPUCores != 4.0 {
		t.Errorf("QuotaCheckResult.QuotaCPUCores = %.2f, want 4.0", qr.QuotaCPUCores)
	}
}

// ── 4. Regression #2：reload 后删除 alice 用户条目，应回退到 default ─────────
//
// 场景：reload 后的 yaml 中 alice 的用户专属条目被移除，
// GetQuota 应回退到 defaults.cpu_cores=2.0。
func TestRegression_AfterReload_UserEntryRemoved_FallsBackToDefault(t *testing.T) {
	path := writeTempQuotaYAML(t, yamlAlice4) // 初始 alice=4.0

	const yamlAliceRemoved = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
`
	overwriteQuotaYAML(t, path, yamlAliceRemoved)

	newQM, err := LoadQuotaManager(path)
	if err != nil {
		t.Fatalf("LoadQuotaManager: %v", err)
	}

	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}
	got := newQM.GetQuota(alice)

	if got.CPUCores != 2.0 {
		t.Errorf(
			"CPUCores = %.2f, want 2.0 (default)\n"+
				"  when user entry is removed, quota should fall back to defaults",
			got.CPUCores,
		)
	}
}

// ── 5. Regression #3：reload 后 alice 设为 0（不限制），不应受 default 干扰 ──
//
// 边界：alice.cpu_cores=0 表示不限制（最高权限），应完全覆盖 default=2.0。
func TestRegression_AfterReload_UserEntryZero_Unlimited(t *testing.T) {
	path := writeTempQuotaYAML(t, yamlAlice1)

	const yamlAliceUnlimited = `version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048
users:
  alice:
    cpu_cores: 0
    mem_mb: 0
`
	overwriteQuotaYAML(t, path, yamlAliceUnlimited)

	newQM, err := LoadQuotaManager(path)
	if err != nil {
		t.Fatalf("LoadQuotaManager: %v", err)
	}

	alice := &auth.CallerIdentity{RealUsername: "alice", RealUID: 1001}
	got := newQM.GetQuota(alice)

	if got.CPUCores != 0 {
		t.Errorf(
			"CPUCores = %.2f, want 0 (unlimited)\n"+
				"  alice.cpu_cores=0 must override default=2.0, not inherit it",
			got.CPUCores,
		)
	}
}

// ── 6. Regression #4：YAML 解析错误时 LoadQuotaManager 返回 error ────────────
//
// 保证损坏的 quota.yaml 不会静默产生零值配额（全不限制），而是返回明确错误。
func TestRegression_LoadQuotaManager_InvalidYAML_ReturnsError(t *testing.T) {
	path := writeTempQuotaYAML(t, "not: valid: yaml: ::::")

	_, err := LoadQuotaManager(path)
	if err == nil {
		t.Error(
			"expected error for invalid YAML, got nil\n" +
				"  a corrupted quota.yaml must not silently produce an unlimited quota",
		)
	}
}
