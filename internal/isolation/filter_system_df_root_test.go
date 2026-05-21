package isolation

// filter_system_df_root_test.go — 针对 root 用户（uid=0）的 system df vs volume ls 计数一致性测试
//
// ── Bug 描述 ──────────────────────────────────────────────────────────────────
//
//   用户 root 执行 `docker system df -v` 时，显示的 volume 数量与
//   `docker volume ls` 不一致。
//
//   触发条件：
//     root 在 Docker 中拥有带前缀 "user-0-volume-X" 的 volume，
//     但该 volume 未注册到归属 DB（例如 DB 被重置、服务崩溃、历史遗留数据）。
//
// ── 根因分析 ──────────────────────────────────────────────────────────────────
//
//   FilterVolumeListResponse（docker volume ls 路径）采用 双条件 OR 逻辑：
//     可见 ← volume 在 DB 中归属于 root (uid=0)
//           OR  volume 名称带前缀 "user-0-volume-"（前缀兜底）
//
//   FilterSystemDFResponse verbose 路径（docker system df -v），修复前：
//     可见 ← volume 在 DB 中归属于 root（仅 DB 单条件）
//
//   两条路径的判断逻辑不对称，导致：
//     - docker volume ls   → 通过前缀兜底显示 N 个卷
//     - docker system df -v → 仅查 DB，无前缀兜底 → 显示 0 个卷
//     → 两个命令数量不一致
//
//   verbose 模式（-v）的特殊性：
//     Docker 29.x daemon 在 ?verbose=1 时返回的格式不同于非 verbose：
//     顶层只有 *Usage 字段（含 Items 数组），无独立的 Images[]/Volumes[] 顶层数组。
//     FilterSystemDFResponse 需先从 VolumeUsage.Items 提取条目，
//     再应用（修复后的）双条件过滤逻辑。
//     修复前：verbose 路径提取 Items 后的过滤仍然只检查 DB，缺少前缀兜底。
//
// ── 修复方案 ──────────────────────────────────────────────────────────────────
//
//   在 FilterSystemDFResponse 卷过滤循环中，补充前缀匹配条件：
//
//     if ownedVols[v.Name] || strings.HasPrefix(v.Name, volPrefix) {
//         filteredVolumes = append(filteredVolumes, rawItem)
//     }
//
//   与 FilterVolumeListResponse 保持逻辑对齐，确保两条路径行为一致。

import (
	"encoding/json"
	"testing"
)

// ══════════════════════════════════════════════════════════════════════════════
// 1. 复现测试（Red Test）
//    未修复时运行此测试必须 100% 断言失败；修复后变为绿色通过。
// ══════════════════════════════════════════════════════════════════════════════

// TestFilterSystemDF_BUG_RootUser_VerboseVolumeCountInconsistency_PrefixFallbackMissing
//
// 复现 Bug：root 用户（uid=0，non-privileged）在 verbose 模式下，
// 带前缀但未注册 DB 的 volume，FilterVolumeListResponse 通过前缀兜底可见，
// 而 FilterSystemDFResponse verbose 路径（旧代码）只查 DB，无前缀兜底，
// 导致 docker system df -v 与 docker volume ls 数量不一致。
//
// 未修复前：
//   FilterVolumeListResponse   → 2 个卷（前缀兜底）
//   FilterSystemDFResponse -v  → 0 个卷（仅 DB 查询，空结果）
//   → 断言失败，差值 = 2（Bug 复现成功）
//
// 修复后（FilterSystemDFResponse 卷过滤补充前缀兜底后）：
//   两者均返回 2 → 断言通过
func TestFilterSystemDF_BUG_RootUser_VerboseVolumeCountInconsistency_PrefixFallbackMissing(t *testing.T) {
	db := newFilterTestDB(t)

	// root 用户 uid=0，前缀为 "user-0-volume-"
	rootUID := 0
	rootPrefix := UserVolumePrefix(rootUID) // "user-0-volume-"

	// 关键前提：Docker 中存在带正确前缀的 volume，但归属 DB 中没有任何记录。
	// 模拟：DB 被清空 / 服务崩溃后重启 / 历史遗留未注册 volume。
	vol1 := rootPrefix + "workspace" // "user-0-volume-workspace"
	vol2 := rootPrefix + "logs"      // "user-0-volume-logs"
	// 故意不调用 db.SetVolumeOwner → DB 完全为空

	// ── 对照组：docker volume ls（FilterVolumeListResponse） ─────────────────
	volListBody := buildVolumeListBody(t, []map[string]interface{}{
		{"Name": vol1, "Driver": "local",
			"Mountpoint": "/var/lib/docker/volumes/" + vol1 + "/_data"},
		{"Name": vol2, "Driver": "local",
			"Mountpoint": "/var/lib/docker/volumes/" + vol2 + "/_data"},
	})
	filteredVolumeLS, err := FilterVolumeListResponse(volListBody, rootUID, false, db)
	if err != nil {
		t.Fatalf("FilterVolumeListResponse: %v", err)
	}
	volumeLSCount := parseVolumeListCount(t, filteredVolumeLS)

	// ── 被测组：docker system df -v（FilterSystemDFResponse，verbose 格式）───
	// verbose 格式：顶层只有 *Usage 字段，无独立 Volumes[] 数组
	verboseBody := buildSystemDFVerboseBody(t,
		nil, nil,
		[]map[string]interface{}{
			{"Name": vol1, "Driver": "local",
				"UsageData": map[string]interface{}{"RefCount": 0, "Size": 1024}},
			{"Name": vol2, "Driver": "local",
				"UsageData": map[string]interface{}{"RefCount": 0, "Size": 2048}},
		},
	)
	filteredDF, err := FilterSystemDFResponse(verboseBody, rootUID, false /*non-privileged*/, db)
	if err != nil {
		t.Fatalf("FilterSystemDFResponse verbose: %v", err)
	}
	dfCounts := parseSystemDFVerboseCounts(t, filteredDF)

	// ── 核心断言：verbose 模式下两命令数量必须一致 ────────────────────────────
	// 未修复前：volumeLSCount=2, dfCounts.Volumes=0 → FAIL（Bug 复现）
	if dfCounts.Volumes != volumeLSCount {
		t.Errorf(
			"[BUG REPRODUCED] root 用户:\n"+
				"  docker system df -v 显示 %d 个卷\n"+
				"  docker volume ls   显示 %d 个卷\n"+
				"  两者必须一致，差值 = %d\n\n"+
				"根因：FilterSystemDFResponse verbose 路径卷过滤\n"+
				"  只检查归属 DB（ownedVols[v.Name]），\n"+
				"  缺少 FilterVolumeListResponse 中的前缀兜底逻辑：\n"+
				"  strings.HasPrefix(v.Name, \"user-%d-volume-\")\n\n"+
				"修复方案：在 FilterSystemDFResponse 卷过滤循环中添加：\n"+
				"  if ownedVols[v.Name] || strings.HasPrefix(v.Name, volPrefix) { ... }",
			dfCounts.Volumes, volumeLSCount,
			volumeLSCount-dfCounts.Volumes,
			rootUID,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. 回归测试矩阵（Regression Suite）
//    覆盖正常路径、边界条件及相邻逻辑，防止修复后出现回归。
// ══════════════════════════════════════════════════════════════════════════════

// TestFilterSystemDF_Regression_RootUser_DBRegisteredVolumes_VerboseNonVerboseConsistency
//
// 正常路径：root 的 volume 已注册 DB，则 verbose 与非 verbose 两条路径
// 均应显示正确数量，且两者一致；其他用户的 volume 不可见。
func TestFilterSystemDF_Regression_RootUser_DBRegisteredVolumes_VerboseNonVerboseConsistency(t *testing.T) {
	db := newFilterTestDB(t)
	root := makeFilterIdentity("root", 0, 0)
	alice := makeFilterIdentity("alice", 1001, 1001)

	rootPrefix := UserVolumePrefix(0)
	vol1 := rootPrefix + "data"    // root 的卷
	vol2 := rootPrefix + "cache"   // root 的卷
	aliceVol := "user-1001-volume-alice-work" // alice 的卷

	_ = db.SetVolumeOwner(vol1, root)
	_ = db.SetVolumeOwner(vol2, root)
	_ = db.SetVolumeOwner(aliceVol, alice)

	allVolumeData := []map[string]interface{}{
		{"Name": vol1, "Driver": "local"},
		{"Name": vol2, "Driver": "local"},
		{"Name": aliceVol, "Driver": "local"},
	}

	// ── docker volume ls ──────────────────────────────────────────────────────
	volListBody := buildVolumeListBody(t, allVolumeData)
	filteredVolumeLS, err := FilterVolumeListResponse(volListBody, 0, false, db)
	if err != nil {
		t.Fatalf("FilterVolumeListResponse: %v", err)
	}
	volumeLSCount := parseVolumeListCount(t, filteredVolumeLS)

	// ── docker system df（非 verbose） ────────────────────────────────────────
	nonVerboseBody := buildSystemDFBody(t, nil, nil, allVolumeData)
	filteredNonVerbose, err := FilterSystemDFResponse(nonVerboseBody, 0, false, db)
	if err != nil {
		t.Fatalf("非 verbose FilterSystemDFResponse: %v", err)
	}
	nonVerboseCounts := parseSystemDFCounts(t, filteredNonVerbose)

	// ── docker system df -v（verbose） ────────────────────────────────────────
	verboseBody := buildSystemDFVerboseBody(t, nil, nil, allVolumeData)
	filteredVerbose, err := FilterSystemDFResponse(verboseBody, 0, false, db)
	if err != nil {
		t.Fatalf("verbose FilterSystemDFResponse: %v", err)
	}
	verboseCounts := parseSystemDFVerboseCounts(t, filteredVerbose)

	// root 应看到自己的 2 个卷，alice 的卷不可见
	if volumeLSCount != 2 {
		t.Errorf("docker volume ls 期望 2（root 自己的 2 个卷），实际 %d", volumeLSCount)
	}
	if nonVerboseCounts.Volumes != 2 {
		t.Errorf("非 verbose docker system df 期望 2，实际 %d（alice 的卷不应出现）",
			nonVerboseCounts.Volumes)
	}
	if verboseCounts.Volumes != 2 {
		t.Errorf("verbose docker system df -v 期望 2，实际 %d（alice 的卷不应出现）",
			verboseCounts.Volumes)
	}
	if nonVerboseCounts.Volumes != verboseCounts.Volumes {
		t.Errorf(
			"root 用户非 verbose(%d) 与 verbose(%d) volume 数量不一致，两者必须相同",
			nonVerboseCounts.Volumes, verboseCounts.Volumes,
		)
	}
	if verboseCounts.Volumes != volumeLSCount {
		t.Errorf(
			"root 用户 docker system df -v(%d) 与 docker volume ls(%d) 数量不一致",
			verboseCounts.Volumes, volumeLSCount,
		)
	}
}

// TestFilterSystemDF_Regression_RootUser_Privileged_FullPassthrough
//
// 边界条件：root 以特权模式（privileged=true）运行时，
// FilterSystemDFResponse 和 FilterVolumeListResponse 均应原样透传 daemon 响应，
// 不过滤任何资源，两命令数量与 daemon 返回一致。
func TestFilterSystemDF_Regression_RootUser_Privileged_FullPassthrough(t *testing.T) {
	db := newFilterTestDB(t)

	allVolumeData := []map[string]interface{}{
		{"Name": "user-0-volume-root-data", "Driver": "local"},
		{"Name": "user-1001-volume-alice-work", "Driver": "local"},
		{"Name": "user-1002-volume-bob-cache", "Driver": "local"},
		{"Name": "anonymous-vol-abc123", "Driver": "local"}, // 无前缀的匿名卷
	}

	// ── 特权用户：FilterVolumeListResponse 原样透传 ───────────────────────────
	volListBody := buildVolumeListBody(t, allVolumeData)
	filteredVolumeLS, err := FilterVolumeListResponse(volListBody, 0, true /*privileged*/, db)
	if err != nil {
		t.Fatalf("特权 FilterVolumeListResponse: %v", err)
	}
	volumeLSCount := parseVolumeListCount(t, filteredVolumeLS)

	// ── 特权用户：verbose FilterSystemDFResponse 原样透传 ────────────────────
	verboseBody := buildSystemDFVerboseBody(t, nil, nil, allVolumeData)
	filteredDF, err := FilterSystemDFResponse(verboseBody, 0, true /*privileged*/, db)
	if err != nil {
		t.Fatalf("特权 verbose FilterSystemDFResponse: %v", err)
	}

	// 特权用户 system df -v 的输出必须与 verbose 输入完全一致（原样透传）
	if string(filteredDF) != string(verboseBody) {
		t.Errorf(
			"root 特权用户 verbose 模式应原样透传响应：\n输入: %s\n输出: %s",
			verboseBody, filteredDF,
		)
	}

	// 特权用户 docker volume ls 也应透传：看到全部 4 个卷
	if volumeLSCount != 4 {
		t.Errorf("特权用户 docker volume ls = %d，期望 4（所有用户的卷均可见）", volumeLSCount)
	}
}

// TestFilterSystemDF_Regression_RootUser_MixedDBAndPrefixOnlyVolumes
//
// 核心逻辑验证：root 用户同时拥有"DB 已注册卷"和"仅有前缀未注册卷"时，
// 两种卷都应被 verbose 模式的 docker system df -v 和 docker volume ls 计数，
// 且两者计数相同。
//
// 此测试防止：修复前缀兜底时，意外破坏 DB 注册卷的显示逻辑（"按下葫芦起了瓢"）。
func TestFilterSystemDF_Regression_RootUser_MixedDBAndPrefixOnlyVolumes(t *testing.T) {
	db := newFilterTestDB(t)
	root := makeFilterIdentity("root", 0, 0)

	rootPrefix := UserVolumePrefix(0)

	// vol1: 在 DB 中有记录（正常注册的卷）
	vol1 := rootPrefix + "db-registered"
	_ = db.SetVolumeOwner(vol1, root)

	// vol2, vol3: 只有前缀，DB 无记录（历史遗留 / DB 重置）
	vol2 := rootPrefix + "legacy-one"
	vol3 := rootPrefix + "legacy-two"

	// vol4: 其他用户的卷，root 不应见
	otherUserVol := "user-1001-volume-alice-private"

	allVolumeData := []map[string]interface{}{
		{"Name": vol1, "Driver": "local"},
		{"Name": vol2, "Driver": "local"},
		{"Name": vol3, "Driver": "local"},
		{"Name": otherUserVol, "Driver": "local"},
	}

	// ── docker volume ls ──────────────────────────────────────────────────────
	volListBody := buildVolumeListBody(t, allVolumeData)
	filteredVolumeLS, err := FilterVolumeListResponse(volListBody, 0, false, db)
	if err != nil {
		t.Fatalf("FilterVolumeListResponse: %v", err)
	}
	volumeLSCount := parseVolumeListCount(t, filteredVolumeLS)

	// ── docker system df -v（verbose） ────────────────────────────────────────
	verboseBody := buildSystemDFVerboseBody(t, nil, nil, allVolumeData)
	filteredDF, err := FilterSystemDFResponse(verboseBody, 0, false, db)
	if err != nil {
		t.Fatalf("verbose FilterSystemDFResponse: %v", err)
	}
	dfCounts := parseSystemDFVerboseCounts(t, filteredDF)

	// root 应看到 3 个卷（1 DB注册 + 2 前缀兜底），alice 的卷不可见
	wantCount := 3
	if volumeLSCount != wantCount {
		t.Errorf(
			"docker volume ls = %d，期望 %d（DB 注册卷 1 + 前缀兜底卷 2；alice 的卷不应出现）",
			volumeLSCount, wantCount,
		)
	}
	if dfCounts.Volumes != wantCount {
		t.Errorf(
			"verbose docker system df -v Volumes = %d，期望 %d（DB 注册卷 1 + 前缀兜底卷 2；alice 的卷不应出现）",
			dfCounts.Volumes, wantCount,
		)
	}
	if dfCounts.Volumes != volumeLSCount {
		t.Errorf(
			"[REGRESSION] docker system df -v(%d) 与 docker volume ls(%d) 数量不一致，"+
				"修复前缀兜底后两者必须相同。\n"+
				"请检查是否只修复了一条路径而遗漏了另一条。",
			dfCounts.Volumes, volumeLSCount,
		)
	}

	// 进一步验证：verbose 输出中不含 alice 的卷名
	var verboseResult struct {
		VolumeUsage struct {
			Items []struct {
				Name string `json:"Name"`
			} `json:"Items"`
		} `json:"VolumeUsage"`
	}
	if err := json.Unmarshal(filteredDF, &verboseResult); err != nil {
		t.Fatalf("解析 verbose VolumeUsage.Items 失败: %v\nbody=%s", err, filteredDF)
	}
	for _, item := range verboseResult.VolumeUsage.Items {
		if item.Name == otherUserVol || item.Name == "alice-private" {
			t.Errorf(
				"alice 的卷（%q）不应出现在 root 的 verbose 结果中，"+
					"检查前缀过滤是否正确限定为 \"user-0-volume-\" 前缀",
				item.Name,
			)
		}
	}
}

// TestFilterSystemDF_Regression_RootUser_EmptyVolumes_VerboseMode
//
// 边界条件：root 用户无任何 volume（Docker 返回空列表）时，
// verbose 模式下 VolumeUsage.Items 应为空数组，
// 不 panic，不报错，与 docker volume ls 行为完全一致。
func TestFilterSystemDF_Regression_RootUser_EmptyVolumes_VerboseMode(t *testing.T) {
	db := newFilterTestDB(t)

	// docker volume ls：无卷
	volListBody := buildVolumeListBody(t, nil)
	filteredVolumeLS, err := FilterVolumeListResponse(volListBody, 0, false, db)
	if err != nil {
		t.Fatalf("FilterVolumeListResponse: %v", err)
	}
	volumeLSCount := parseVolumeListCount(t, filteredVolumeLS)

	// docker system df -v：无卷（verbose 格式，VolumeUsage.Items=[]）
	verboseBody := buildSystemDFVerboseBody(t, nil, nil, nil)
	filteredDF, err := FilterSystemDFResponse(verboseBody, 0 /*root*/, false, db)
	if err != nil {
		t.Fatalf("FilterSystemDFResponse verbose 空列表返回错误: %v", err)
	}
	dfCounts := parseSystemDFVerboseCounts(t, filteredDF)

	if volumeLSCount != 0 {
		t.Errorf("空输入时 docker volume ls count = %d，期望 0", volumeLSCount)
	}
	if dfCounts.Volumes != 0 {
		t.Errorf(
			"空输入时 root verbose VolumeUsage.Items = %d，期望 0（无卷时不应有任何条目）",
			dfCounts.Volumes,
		)
	}
	if dfCounts.Volumes != volumeLSCount {
		t.Errorf(
			"空输入时 verbose(%d) 与 volume ls(%d) 数量不一致，空值边界必须对齐",
			dfCounts.Volumes, volumeLSCount,
		)
	}
}
