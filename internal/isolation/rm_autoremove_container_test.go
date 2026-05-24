package isolation

// ── 针对"docker create --rm 容器一会儿就消失"Bug 的测试套件 ──────────────────
//
// ┌──────────────────────────────────────────────────────────────────────────┐
// │ 根本原因                                                                  │
// │                                                                          │
// │ 触发命令：                                                                │
// │   docker container create --rm --name test_cpu_limit3 \                 │
// │     --cpu-period 50000 --cpu-quota 250000 alpine:latest sleep 10        │
// │                                                                          │
// │ 代理行为（当前 BUG）：                                                    │
// │   injectQuotaLimits() 使用 json.Unmarshal 将原始 HostConfig 整体读入     │
// │   map[string]json.RawMessage，随后只修改 CPU/内存/存储相关字段，并把      │
// │   整个 map 重新 marshal 回请求体。AutoRemove=true 作为"无关字段"被完      │
// │   整保留，随请求体透传给 Docker Daemon。                                  │
// │                                                                          │
// │   Docker Daemon 收到 AutoRemove=true 的容器创建请求后：                  │
// │     1. 容器以 Created 状态进入 DB                ✓                       │
// │     2. 用户（或测试脚本）执行 docker start       ✓                       │
// │     3. sleep 10 运行约 10 秒后进程退出                                   │
// │     4. Docker 触发 "die" 事件 → 代理无操作       ✓                       │
// │     5. AutoRemove=true 触发 Docker 自动删除容器                          │
// │     6. "destroy" 事件到达 → 代理删除 DB 记录     ✓                       │
// │   结果：bob 执行 docker ps -a 时容器已消失，表现为"一会儿就消失"。        │
// │                                                                          │
// │ 关键触发条件：                                                            │
// │   · --rm 将 HostConfig.AutoRemove 设为 true                              │
// │   · --cpu-period 50000（非默认 100000）使 effectiveCPUNanos ≠ 0          │
// │     → injectQuotaLimits 进入"已指定不超限"分支，跳过 NanoCpus 注入       │
// │     → 整个 HostConfig 回写路径中，AutoRemove=true 无任何过滤步骤         │
// │                                                                          │
// │ 修复方案：                                                                │
// │   在 injectQuotaLimits()（或其上层调用链中）对非特权用户强制设置          │
// │   hostConfig["AutoRemove"] = false，确保容器只能通过显式 docker rm       │
// │   删除，而非因 --rm 自动消失，从而保持代理对容器生命周期的完整管控。      │
// │                                                                          │
// │ 修复后预期：                                                              │
// │   docker container create --rm ... 产生的容器持久存在（AutoRemove=false）│
// │   用户须显式 docker rm 方可删除，与"容器持久存在，除非删除"的预期一致。  │
// └──────────────────────────────────────────────────────────────────────────┘

import (
	"encoding/json"
	"testing"

	"docker-authz-proxy/internal/authz"
)

// ── 辅助 ─────────────────────────────────────────────────────────────────────

func newAutoRemoveTestDB(t *testing.T) *authz.OwnershipDB {
	t.Helper()
	db, err := authz.NewOwnershipDB(":memory:")
	if err != nil {
		t.Fatalf("NewOwnershipDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// autoRemoveField 从处理后的请求体中提取 HostConfig.AutoRemove 字段。
// 返回 (value, exists)：exists=false 表示字段不存在（等价于 false）。
func autoRemoveField(t *testing.T, body []byte) (bool, bool) {
	t.Helper()
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(body, &outer); err != nil {
		t.Fatalf("unmarshal outer body: %v", err)
	}
	hcRaw, ok := outer["HostConfig"]
	if !ok {
		return false, false
	}
	var hc map[string]json.RawMessage
	if err := json.Unmarshal(hcRaw, &hc); err != nil {
		t.Fatalf("unmarshal HostConfig: %v", err)
	}
	raw, exists := hc["AutoRemove"]
	if !exists {
		return false, false
	}
	var v bool
	_ = json.Unmarshal(raw, &v)
	return v, true
}

// rmBody 构造携带 --rm + --cpu-period/quota 的容器创建请求体
func rmBody(autoRemove bool, period, quota int64) []byte {
	b, _ := json.Marshal(map[string]any{
		"Image": "alpine:latest",
		"Cmd":   []string{"sleep", "10"},
		"HostConfig": map[string]any{
			"AutoRemove": autoRemove,
			"CpuPeriod":  period,
			"CpuQuota":   quota,
		},
	})
	return b
}

// ── 1. Red Test：AutoRemove=true 被完整保留，透传给 Docker ──────────────────
//
// 触发路径：
//   --cpu-period 50000 --cpu-quota 250000 → effectiveCPUNanos=5e9 ≠ 0
//   → injectQuotaLimits 进入"已指定不超限"分支，不注入 NanoCpus
//   → HostConfig 回写时 AutoRemove=true 无任何清理步骤
//
// 修复前此测试 FAIL（AutoRemove 仍为 true，容器启动后自动消失）。
// 修复后（代理强制 AutoRemove=false）此测试 PASS。
func TestBug_AutoRemove_NotStripped_WithCpuPeriodQuota_Red(t *testing.T) {
	db := newAutoRemoveTestDB(t)

	// bob 的配额远高于请求的 5.0 核，配额本身不会触发拒绝
	quota := UserQuota{CPUCores: 8.0, MemMB: 2048}

	// 构造 --rm --cpu-period 50000 --cpu-quota 250000 的请求体
	// 等价 5.0 核（250000/50000），在配额（8.0）内，用户配额检查放行
	body := rmBody(true, 50000, 250000)

	outBody, _, err := CheckAndInjectQuota(body, quota, 1001, db, 0, 0)
	if err != nil {
		t.Fatalf("CheckAndInjectQuota 不应返回错误（5.0核 < 配额 8.0核）: %v", err)
	}

	autoRemove, _ := autoRemoveField(t, outBody)

	// ── 断言：代理必须将 AutoRemove 置为 false ────────────────────────────────
	if autoRemove {
		t.Fatalf(
			"BUG 已复现：AutoRemove=true 被完整透传给 Docker Daemon\n"+
				"\n"+
				"  触发命令 : docker container create --rm"+
				" --cpu-period 50000 --cpu-quota 250000 alpine:latest sleep 10\n"+
				"  等价核数 : 250000/50000 = 5.0 核（在用户配额 8.0 核内，请求被放行）\n"+
				"  实际结果 : injectQuotaLimits() 输出体中 AutoRemove=%v\n"+
				"             容器创建后一旦被 docker start 启动，sleep 10 退出即自动删除\n"+
				"  预期结果 : AutoRemove=false（代理应强制设置，阻止容器自动消失）\n"+
				"\n"+
				"  根本原因 :\n"+
				"    injectQuotaLimits() 将原始 HostConfig 整体 unmarshal 进 map 后，\n"+
				"    只修改 NanoCpus/Memory/MemorySwap/MemorySwappiness/StorageOpt，\n"+
				"    AutoRemove 作为未处理字段被保留并 marshal 回输出体，\n"+
				"    最终以 AutoRemove=true 透传给 Docker Daemon，\n"+
				"    触发 Docker 的自动删除行为（die → destroy → proxy DB 记录清除）。\n"+
				"  修复方案 : hostConfig[\"AutoRemove\"] = json.Marshal(false)",
			autoRemove,
		)
	}
}

// ── 2. Regression #1：无 CPU 限制的 --rm 容器，同样需被剥除 ─────────────────
//
// 验证：--rm 与 CPU 配置无关，AutoRemove 剥除逻辑不依赖 CpuPeriod/CpuQuota 的存在。
// 若只在 CpuQuota>0 分支剥除，本测试可捕获遗漏。
func TestRegression_AutoRemove_WithoutCpuLimit_MustBeStripped(t *testing.T) {
	db := newAutoRemoveTestDB(t)
	quota := UserQuota{MemMB: 512} // 只有内存配额，无 CPU 配额

	body, _ := json.Marshal(map[string]any{
		"Image": "alpine:latest",
		"Cmd":   []string{"echo", "hello"},
		"HostConfig": map[string]any{
			"AutoRemove": true,
			// 不指定 CpuPeriod/CpuQuota/NanoCpus
		},
	})

	outBody, _, err := CheckAndInjectQuota(body, quota, 1002, db, 0, 0)
	if err != nil {
		t.Fatalf("CheckAndInjectQuota 不应返回错误: %v", err)
	}

	autoRemove, _ := autoRemoveField(t, outBody)

	if autoRemove {
		t.Errorf(
			"Regression FAIL：无 CPU 限制的 --rm 容器，AutoRemove 仍为 true\n"+
				"  测试意图：AutoRemove 剥除逻辑不应仅在 CpuQuota>0 分支执行\n"+
				"  实际结果：AutoRemove=%v（未被剥除，容器启动后将自动消失）\n"+
				"  预期结果：AutoRemove=false",
			autoRemove,
		)
	}
}

// ── 3. Regression #2：不含 --rm 的普通容器，AutoRemove 不应被错误置为 true ──
//
// 验证：修复逻辑的反向不变性。
// 若修复错误地将所有容器的 AutoRemove 强制设为 true，本测试可捕获。
func TestRegression_NoAutoRemove_Container_RemainsUnchanged(t *testing.T) {
	db := newAutoRemoveTestDB(t)
	quota := UserQuota{CPUCores: 2.0, MemMB: 1024}

	// 普通容器，不含 --rm，AutoRemove 字段明确为 false
	body, _ := json.Marshal(map[string]any{
		"Image": "alpine:latest",
		"Cmd":   []string{"sh"},
		"HostConfig": map[string]any{
			"AutoRemove": false,
			"CpuPeriod":  int64(50000),
			"CpuQuota":   int64(100000), // 2.0 核，在配额内
		},
	})

	outBody, _, err := CheckAndInjectQuota(body, quota, 1003, db, 0, 0)
	if err != nil {
		t.Fatalf("CheckAndInjectQuota 不应返回错误: %v", err)
	}

	autoRemove, _ := autoRemoveField(t, outBody)

	if autoRemove {
		t.Errorf(
			"Regression FAIL：AutoRemove=false 的容器，修复后被错误置为 true\n"+
				"  实际结果：AutoRemove=true（修复逻辑存在反向副作用）\n"+
				"  预期结果：AutoRemove=false（或字段不存在）",
		)
	}
}

// ── 4. Regression #3：--rm + 内存注入同时工作，字段互不干扰 ─────────────────
//
// 验证：内存配额注入（Memory/MemorySwap/MemorySwappiness）与 AutoRemove 剥除
// 同时执行时，内存字段正确注入，AutoRemove 正确剥除，二者不互相破坏。
func TestRegression_AutoRemove_MemoryInjection_BothCorrect(t *testing.T) {
	db := newAutoRemoveTestDB(t)
	quota := UserQuota{CPUCores: 4.0, MemMB: 512}

	body := rmBody(true, 50000, 100000) // 2.0 核，在配额 4.0 内

	outBody, _, err := CheckAndInjectQuota(body, quota, 1004, db, 0, 0)
	if err != nil {
		t.Fatalf("CheckAndInjectQuota 不应返回错误: %v", err)
	}

	// ① AutoRemove 应已被剥除
	autoRemove, _ := autoRemoveField(t, outBody)
	if autoRemove {
		t.Errorf(
			"AutoRemove 未被剥除（与内存注入同时执行时存在遗漏）\n"+
				"  实际：AutoRemove=true  预期：AutoRemove=false",
		)
	}

	// ② 内存配额应已注入
	var outer map[string]json.RawMessage
	_ = json.Unmarshal(outBody, &outer)
	var hc map[string]json.RawMessage
	_ = json.Unmarshal(outer["HostConfig"], &hc)

	var mem int64
	if err := json.Unmarshal(hc["Memory"], &mem); err != nil {
		t.Fatalf("Memory 字段解析失败: %v", err)
	}
	wantMem := int64(512) * 1024 * 1024
	if mem != wantMem {
		t.Errorf(
			"内存注入值错误：Memory=%d，want %d（512 MiB）\n"+
				"  内存注入与 AutoRemove 剥除不应相互干扰",
			mem, wantMem,
		)
	}

	// ③ MemorySwap 应与 Memory 相同（禁止 swap）
	var swap int64
	_ = json.Unmarshal(hc["MemorySwap"], &swap)
	if swap != wantMem {
		t.Errorf(
			"MemorySwap 注入值错误：MemorySwap=%d，want %d（应等于 Memory）",
			swap, wantMem,
		)
	}
}

// ── 5. Regression #4：非标准 CpuPeriod 的正常容器（无 --rm），配额检查仍生效 ─
//
// 验证：AutoRemove 剥除修复不应影响 CpuPeriod/CpuQuota 的物理核数检查逻辑。
// 若有 2 个以上物理核：请求 physicalCores+1 核应被物理上限拒绝（配额>物理）。
func TestRegression_CpuPeriodQuota_NoAutoRemove_QuotaStillEnforced(t *testing.T) {
	if physicalCores() < 2 {
		t.Skipf("需要至少 2 个物理 CPU，当前：%d", physicalCores())
	}
	db := newAutoRemoveTestDB(t)
	// 配额高于物理核数，确保只有物理上限会触发拒绝
	quota := UserQuota{CPUCores: float64(physicalCores()) * 2}

	// 请求 physicalCores+1 核，无 --rm
	requestedCores := int64(physicalCores() + 1)
	body := cpuPeriodBody(100000, requestedCores*100000) // 复用 quota_cpuperiod_test.go 中的辅助函数

	_, _, err := CheckAndInjectQuota(body, quota, 1005, db, 0, 0)

	if err == nil {
		t.Errorf(
			"Regression FAIL：超物理核数的请求应被拒绝，但 AutoRemove 修复引入了回归\n"+
				"  请求核数：%d  物理上限：%d  用户配额：%.1f\n"+
				"  实际：err=nil（请求被放行）  预期：QuotaExceededError{Resource:\"cpu\"}",
			requestedCores, physicalCores(), float64(physicalCores())*2,
		)
	}
	if err != nil {
		qErr, ok := err.(*QuotaExceededError)
		if !ok {
			t.Fatalf("错误类型 = %T，want *QuotaExceededError；err=%v", err, err)
		}
		if qErr.Resource != "cpu" {
			t.Errorf("QuotaExceededError.Resource = %q，want \"cpu\"", qErr.Resource)
		}
	}
}
