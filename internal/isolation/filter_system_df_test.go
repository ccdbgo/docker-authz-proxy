package isolation

// filter_system_df_test.go — FilterSystemDFResponse 的复现测试与回归测试套件
//
// Bug 背景：
//   用户 bob 执行 `docker system df` 时，Images 数量与 `docker image ls` 不一致，
//   Volumes 数量与 `docker volume ls` 不一致。
//
// ── 根因分析 ──────────────────────────────────────────────────────────────────
//
//   【BUG-1 卷数量不一致 — 主 Bug，可稳定复现】
//
//   FilterVolumeListResponse（docker volume ls 路径，filter.go:168）使用 双条件 OR 逻辑：
//     包含 ← volume 在 DB 中归属于该用户
//           OR  volume 名称带有该用户前缀 (user-{uid}-volume-)
//
//   FilterSystemDFResponse（docker system df 路径，filter.go:415）只有 单条件：
//     包含 ← volume 在 DB 中归属于该用户
//
//   触发条件：volume 以正确前缀存在于 Docker 内，但 未注册到归属 DB 中
//   （如：DB 被重置、服务崩溃、历史遗留数据）
//
//   结果：docker volume ls 通过前缀兜底显示该卷（count=1），
//         docker system df 不显示（count=0）→ 数量不一致。
//
//   【BUG-2 镜像过滤死代码 — 次 Bug，不直接影响计数但产生误导性代码】
//
//   filter.go:388-397 存在一段死循环：遍历 raw.Images 并调用 CanSeeImage，
//   但 if 块体为空（只有注释），结果完全被丢弃。
//   filter.go:399-410 的第二次循环才是真正执行过滤的代码。
//   由于两次循环调用了相同的 CanSeeImage 逻辑，镜像计数功能上目前是正确的，
//   但死代码掩盖了重构意图，增加了未来出错的风险。
//
//   【BUG-3 verbose 模式（docker system df -v）显示为空 — 主 Bug，可稳定复现】
//
//   触发条件：用户执行 `docker system df -v`
//
//   Docker 29.x daemon 在 ?verbose=1 时返回的格式与非 verbose 完全不同：
//     - 只有 *Usage 字段（ImageUsage/ContainerUsage/VolumeUsage/BuildCacheUsage），
//       每个字段内含 Items 数组存放详细条目。
//     - 顶层不含 Images[]/Containers[]/Volumes[]/BuildCache[] 数组。
//   FilterSystemDFResponse 只从顶层 Images[]/Containers[]/Volumes[] 过滤，
//   verbose 格式下这些数组为空，因此过滤结果也为空。
//   重建后的 *Usage.Items=[] → Docker CLI 29.x verbose 读 ImageUsage.Items 渲染详情表格 → 显示空行。
//
//   修复方案：检测 verbose 格式（顶层无 Images key），从 *Usage.Items 提取条目再过滤，
//   过滤后重建 *Usage 字段并以相同格式（仅 *Usage 字段）输出。

import (
	"encoding/json"
	"testing"
)

// buildSystemDFVerboseBody 构造 Docker 29.x ?verbose=1 的原始响应体。
// verbose 格式与非 verbose 完全不同：顶层只有 *Usage 字段（含 Items 数组），
// 无独立的 Images[]/Containers[]/Volumes[]/BuildCache[] 顶层数组。
func buildSystemDFVerboseBody(t *testing.T,
	images []map[string]interface{},
	containers []map[string]interface{},
	volumes []map[string]interface{},
) []byte {
	t.Helper()
	toSlice := func(s []map[string]interface{}) []interface{} {
		result := make([]interface{}, len(s))
		for i, v := range s {
			result[i] = v
		}
		return result
	}
	empty := []interface{}{}
	imgs := toSlice(images)
	ctrs := toSlice(containers)
	vols := toSlice(volumes)
	if imgs == nil {
		imgs = empty
	}
	if ctrs == nil {
		ctrs = empty
	}
	if vols == nil {
		vols = empty
	}
	// 严格模拟 daemon verbose=1 响应：只有 *Usage 字段，无顶层数组
	body, err := json.Marshal(map[string]interface{}{
		"ImageUsage": map[string]interface{}{
			"Items":       imgs,
			"TotalCount":  len(imgs),
			"ActiveCount": 0,
			"TotalSize":   int64(0),
		},
		"ContainerUsage": map[string]interface{}{
			"Items":       ctrs,
			"TotalCount":  len(ctrs),
			"Reclaimable": int64(0),
			"TotalSize":   int64(0),
		},
		"VolumeUsage": map[string]interface{}{
			"Items":       vols,
			"TotalCount":  len(vols),
			"ActiveCount": 0,
			"TotalSize":   int64(0),
		},
		"BuildCacheUsage": map[string]interface{}{
			"Items":      empty,
			"TotalCount": 0,
		},
	})
	if err != nil {
		t.Fatalf("buildSystemDFVerboseBody: %v", err)
	}
	return body
}

// parseSystemDFVerboseCounts 解析 verbose 模式的 FilterSystemDFResponse 输出，
// 从 *Usage.Items 中提取各类资源数量（verbose 输出无顶层 Images[]/Containers[]/Volumes[]）。
func parseSystemDFVerboseCounts(t *testing.T, body []byte) systemDFCounts {
	t.Helper()
	var r struct {
		ImageUsage     struct{ Items []json.RawMessage `json:"Items"` } `json:"ImageUsage"`
		ContainerUsage struct{ Items []json.RawMessage `json:"Items"` } `json:"ContainerUsage"`
		VolumeUsage    struct{ Items []json.RawMessage `json:"Items"` } `json:"VolumeUsage"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("parseSystemDFVerboseCounts: unmarshal failed: %v\nbody=%s", err, body)
	}
	return systemDFCounts{
		Images:     len(r.ImageUsage.Items),
		Containers: len(r.ContainerUsage.Items),
		Volumes:    len(r.VolumeUsage.Items),
	}
}

// ── 测试辅助函数 ───────────────────────────────────────────────────────────────

// buildSystemDFBody 构造一个合法的 Docker GET /system/df 响应体（非 verbose）。
// images/containers/volumes 传 nil 时自动替换为空列表。
func buildSystemDFBody(t *testing.T,
	images []map[string]interface{},
	containers []map[string]interface{},
	volumes []map[string]interface{},
) []byte {
	t.Helper()
	toSlice := func(s []map[string]interface{}) []map[string]interface{} {
		if s == nil {
			return []map[string]interface{}{}
		}
		return s
	}
	body, err := json.Marshal(map[string]interface{}{
		"LayersSize": int64(9_999_999),
		"Images":     toSlice(images),
		"Containers": toSlice(containers),
		"Volumes":    toSlice(volumes),
		"BuildCache": []interface{}{},
	})
	if err != nil {
		t.Fatalf("buildSystemDFBody: %v", err)
	}
	return body
}

// systemDFCounts 存放从 system df 响应中解析出的各类资源数量。
type systemDFCounts struct {
	Images, Containers, Volumes int
}

// parseSystemDFCounts 解析非 verbose 模式的 FilterSystemDFResponse 返回值，
// 从顶层数组（Images/Containers/Volumes）提取资源数量。
func parseSystemDFCounts(t *testing.T, body []byte) systemDFCounts {
	t.Helper()
	var r struct {
		Images     []json.RawMessage `json:"Images"`
		Containers []json.RawMessage `json:"Containers"`
		Volumes    []json.RawMessage `json:"Volumes"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("parseSystemDFCounts: unmarshal failed: %v\nbody=%s", err, body)
	}
	return systemDFCounts{
		Images:     len(r.Images),
		Containers: len(r.Containers),
		Volumes:    len(r.Volumes),
	}
}

// buildVolumeListBody 构造 GET /volumes 的原始响应（FilterVolumeListResponse 的输入）。
func buildVolumeListBody(t *testing.T, volumes []map[string]interface{}) []byte {
	t.Helper()
	if volumes == nil {
		volumes = []map[string]interface{}{}
	}
	body, err := json.Marshal(map[string]interface{}{
		"Volumes":  volumes,
		"Warnings": []string{},
	})
	if err != nil {
		t.Fatalf("buildVolumeListBody: %v", err)
	}
	return body
}

// parseVolumeListCount 从 FilterVolumeListResponse 的返回值中提取卷数量。
func parseVolumeListCount(t *testing.T, body []byte) int {
	t.Helper()
	var r struct {
		Volumes []json.RawMessage `json:"Volumes"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("parseVolumeListCount: %v\nbody=%s", err, body)
	}
	return len(r.Volumes)
}

// ── 1. 复现测试（Red Test）──────────────────────────────────────────────────────
//
// 运行条件：未修复时必须 100% 失败；修复后变为绿色通过。

// TestFilterSystemDFResponse_BUG_VolumeCountInconsistency_PrefixFallbackMissing
// 复现 Bug：带用户前缀但未注册到归属 DB 的卷，FilterVolumeListResponse 能通过前缀兜底
// 显示（docker volume ls 可见），但 FilterSystemDFResponse 只查 DB，无前缀兜底，
// 导致 docker system df 中该卷消失，两个命令卷数量不一致。
//
// 未修复前：
//
//	FilterVolumeListResponse 返回 1 个卷（前缀兜底）
//	FilterSystemDFResponse   返回 0 个卷（仅 DB 查询，空结果）
//	→ 断言失败，差值 = -1
//
// 修复后（在 FilterSystemDFResponse 卷过滤中补充前缀兜底逻辑后）：
//
//	两者均返回 1 → 断言通过
func TestFilterSystemDFResponse_BUG_VolumeCountInconsistency_PrefixFallbackMissing(t *testing.T) {
	db := newFilterTestDB(t)
	bob := makeFilterIdentity("bob", 1002, 1002)

	// 关键前提：构造 Docker 侧存在、但归属 DB 中没有记录的卷
	// （模拟：DB 被清空 / 服务崩溃 / 历史遗留卷）
	bobPrefix := UserVolumePrefix(bob.RealUID)   // "user-1002-volume-"
	internalName := bobPrefix + "mydata"         // Docker 内部存储名
	// 故意不调用 db.SetVolumeOwner → DB 中无该卷记录

	// ── 对照组：docker volume ls（通过 FilterVolumeListResponse 过滤）────────
	volListBody := buildVolumeListBody(t, []map[string]interface{}{
		{"Name": internalName, "Driver": "local",
			"Mountpoint": "/var/lib/docker/volumes/" + internalName + "/_data"},
	})
	filteredVolumeLS, err := FilterVolumeListResponse(volListBody, bob.RealUID, false, db)
	if err != nil {
		t.Fatalf("FilterVolumeListResponse: %v", err)
	}
	volumeLSCount := parseVolumeListCount(t, filteredVolumeLS)

	// ── 被测组：docker system df（通过 FilterSystemDFResponse 过滤）──────────
	systemDFBody := buildSystemDFBody(t, nil, nil,
		[]map[string]interface{}{
			{"Name": internalName, "Driver": "local"},
		},
	)
	filteredDF, err := FilterSystemDFResponse(systemDFBody, bob.RealUID, false, db)
	if err != nil {
		t.Fatalf("FilterSystemDFResponse: %v", err)
	}
	dfCounts := parseSystemDFCounts(t, filteredDF)

	// 断言：两个命令显示的卷数量必须一致
	// 未修复时：volumeLSCount=1, dfCounts.Volumes=0 → FAIL（Bug 复现成功）
	if dfCounts.Volumes != volumeLSCount {
		t.Errorf(
			"[BUG REPRODUCED] docker system df 显示 %d 个卷，docker volume ls 显示 %d 个卷，两者必须一致。\n"+
				"根因：FilterSystemDFResponse 卷过滤只查归属 DB（ownedVols[v.Name]），\n"+
				"缺少 FilterVolumeListResponse 中的前缀兜底逻辑 "+
				"(strings.HasPrefix(name, \"user-%d-volume-\"))。\n"+
				"修复方案：在 FilterSystemDFResponse 卷过滤中补充前缀匹配条件。",
			dfCounts.Volumes, volumeLSCount, bob.RealUID,
		)
	}
}

// ── 2. 回归测试矩阵（Regression Suite）───────────────────────────────────────

// TestFilterSystemDFResponse_Regression_PrivilegedUserSeesAll
// 特权用户（管理员 / root）应原样返回未经过滤的响应体，不丢失任何资源。
func TestFilterSystemDFResponse_Regression_PrivilegedUserSeesAll(t *testing.T) {
	db := newFilterTestDB(t)
	body := buildSystemDFBody(t,
		[]map[string]interface{}{
			{"Id": "sha256:img-aaa"},
			{"Id": "sha256:img-bbb"},
		},
		[]map[string]interface{}{
			{"Id": "ctr-001"},
		},
		[]map[string]interface{}{
			{"Name": "user-1001-volume-vol1"},
			{"Name": "user-1002-volume-vol2"},
		},
	)

	filtered, err := FilterSystemDFResponse(body, 0 /*root uid*/, true /*privileged*/, db)
	if err != nil {
		t.Fatalf("特权用户 FilterSystemDFResponse 失败: %v", err)
	}

	counts := parseSystemDFCounts(t, filtered)
	if counts.Images != 2 {
		t.Errorf("特权用户 Images = %d，期望 2（应看到全部镜像）", counts.Images)
	}
	if counts.Containers != 1 {
		t.Errorf("特权用户 Containers = %d，期望 1（应看到全部容器）", counts.Containers)
	}
	if counts.Volumes != 2 {
		t.Errorf("特权用户 Volumes = %d，期望 2（应看到全部卷）", counts.Volumes)
	}
}

// TestFilterSystemDFResponse_Regression_NormalUser_DBRegisteredResources
// 正常路径：普通用户只能看到 DB 中归属于自己的资源；
// 其他用户的镜像、容器、卷均不可见。
// 同时验证镜像过滤路径（filter.go:387-413）功能上与 FilterImageListResponse 一致。
func TestFilterSystemDFResponse_Regression_NormalUser_DBRegisteredResources(t *testing.T) {
	db := newFilterTestDB(t)
	alice := makeFilterIdentity("alice", 1001, 1001)
	bob := makeFilterIdentity("bob", 1002, 1002)

	_ = db.SetContainerOwner("ctr-bob-001", bob, "")
	_ = db.SetContainerOwner("ctr-alice-001", alice, "")
	_ = db.SetImageOwner("sha256:bob-private-img", bob, false, "pull")
	_ = db.SetImageOwner("sha256:alice-private-img", alice, false, "pull")
	_ = db.SetVolumeOwner("user-1002-volume-data", bob)
	_ = db.SetVolumeOwner("user-1001-volume-stuff", alice)

	body := buildSystemDFBody(t,
		[]map[string]interface{}{
			{"Id": "sha256:bob-private-img"},
			{"Id": "sha256:alice-private-img"},
		},
		[]map[string]interface{}{
			{"Id": "ctr-bob-001"},
			{"Id": "ctr-alice-001"},
		},
		[]map[string]interface{}{
			{"Name": "user-1002-volume-data"},
			{"Name": "user-1001-volume-stuff"},
		},
	)

	filtered, err := FilterSystemDFResponse(body, bob.RealUID, false, db)
	if err != nil {
		t.Fatalf("bob 的 FilterSystemDFResponse 失败: %v", err)
	}
	counts := parseSystemDFCounts(t, filtered)

	if counts.Images != 1 {
		t.Errorf("bob Images = %d，期望 1（仅自己的私有镜像；alice 的镜像不应可见）",
			counts.Images)
	}
	if counts.Containers != 1 {
		t.Errorf("bob Containers = %d，期望 1（仅自己的容器；alice 的容器不应可见）",
			counts.Containers)
	}
	if counts.Volumes != 1 {
		t.Errorf("bob Volumes = %d，期望 1（仅自己的卷；alice 的卷不应可见）",
			counts.Volumes)
	}
}

// TestFilterSystemDFResponse_Regression_PublicImageVisibleToAll
// 公共镜像（is_public=true）对所有非特权用户均可见，
// 行为必须与 FilterImageListResponse 保持一致。
func TestFilterSystemDFResponse_Regression_PublicImageVisibleToAll(t *testing.T) {
	db := newFilterTestDB(t)
	root := makeFilterIdentity("root", 0, 0)
	bob := makeFilterIdentity("bob", 1002, 1002)

	_ = db.SetImageOwner("sha256:public-base", root, true /*isPublic*/, "pull")
	_ = db.SetImageOwner("sha256:bob-private", bob, false, "pull")
	// sha256:alice-unregistered 未入库

	body := buildSystemDFBody(t,
		[]map[string]interface{}{
			{"Id": "sha256:public-base"},
			{"Id": "sha256:bob-private"},
			{"Id": "sha256:alice-unregistered"},
		},
		nil, nil,
	)

	filtered, err := FilterSystemDFResponse(body, bob.RealUID, false, db)
	if err != nil {
		t.Fatalf("FilterSystemDFResponse 失败: %v", err)
	}
	counts := parseSystemDFCounts(t, filtered)

	// bob 应看到：1 个公共镜像 + 1 个自己的私有镜像 = 2 个
	// alice 的未入库镜像不应出现
	if counts.Images != 2 {
		t.Errorf("bob Images = %d，期望 2（1 个公共镜像 + 1 个自己的私有镜像；"+
			"未入库镜像不应可见）",
			counts.Images)
	}
}

// TestFilterSystemDFResponse_Regression_EmptyResourceLists
// 边界条件：所有资源列表均为空时，函数应正常返回空结果而不 panic 或报错。
func TestFilterSystemDFResponse_Regression_EmptyResourceLists(t *testing.T) {
	db := newFilterTestDB(t)

	body := buildSystemDFBody(t, nil, nil, nil)
	filtered, err := FilterSystemDFResponse(body, 1002, false, db)
	if err != nil {
		t.Fatalf("空列表时 FilterSystemDFResponse 返回错误: %v", err)
	}

	counts := parseSystemDFCounts(t, filtered)
	if counts.Images != 0 || counts.Containers != 0 || counts.Volumes != 0 {
		t.Errorf("空输入时期望 Images/Containers/Volumes 全为 0，实际 (%d/%d/%d)",
			counts.Images, counts.Containers, counts.Volumes)
	}
}

// TestFilterSystemDFResponse_Regression_LayersSizeResetToZero
// 边界条件：非特权用户的响应中 LayersSize 必须被重置为 0，
// 因为无法精确计算用户级别的 layer 共享大小。
func TestFilterSystemDFResponse_Regression_LayersSizeResetToZero(t *testing.T) {
	db := newFilterTestDB(t)
	bob := makeFilterIdentity("bob", 1002, 1002)
	_ = db.SetImageOwner("sha256:bob-img-xyz", bob, false, "pull")

	// 构造 LayersSize 为一个很大的非零值
	raw := map[string]interface{}{
		"LayersSize": int64(99_999_999_999),
		"Images":     []map[string]interface{}{{"Id": "sha256:bob-img-xyz"}},
		"Containers": []map[string]interface{}{},
		"Volumes":    []map[string]interface{}{},
		"BuildCache": []interface{}{},
	}
	body, _ := json.Marshal(raw)

	filtered, err := FilterSystemDFResponse(body, bob.RealUID, false, db)
	if err != nil {
		t.Fatalf("FilterSystemDFResponse 失败: %v", err)
	}

	var result struct {
		LayersSize int64 `json:"LayersSize"`
	}
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatalf("解析 LayersSize 失败: %v", err)
	}
	if result.LayersSize != 0 {
		t.Errorf("非特权用户 LayersSize = %d，期望 0（不能泄露全局共享层大小）",
			result.LayersSize)
	}
}

// TestFilterSystemDFResponse_Regression_InvalidJSONPassthrough
// 边界条件：非法 JSON 输入时应原样透传而不返回错误，
// 保持与 FilterContainerListResponse 等函数一致的容错行为。
func TestFilterSystemDFResponse_Regression_InvalidJSONPassthrough(t *testing.T) {
	db := newFilterTestDB(t)
	badInput := []byte(`this is { not valid json at all`)

	result, err := FilterSystemDFResponse(badInput, 1002, false, db)
	if err != nil {
		t.Fatalf("非法 JSON 不应返回 error，实际: %v", err)
	}
	if string(result) != string(badInput) {
		t.Errorf("非法 JSON 输入必须原样返回，\n实际: %q\n期望: %q",
			result, badInput)
	}
}

// TestFilterSystemDFResponse_Regression_ImageCountConsistencyWithImageListFilter
// 回归验证：FilterSystemDFResponse 中的镜像过滤路径与 FilterImageListResponse
// 使用相同的 CanSeeImage 逻辑，在相同 DB 状态下两个函数返回的镜像数量必须一致。
//
// 此测试防止 filter.go:388-397 的死代码被"修复"时误改真正的过滤逻辑，
// 导致 system df 与 image ls 镜像计数出现新的偏差。
func TestFilterSystemDFResponse_Regression_ImageCountConsistencyWithImageListFilter(t *testing.T) {
	db := newFilterTestDB(t)
	bob := makeFilterIdentity("bob", 1002, 1002)
	alice := makeFilterIdentity("alice", 1001, 1001)
	root := makeFilterIdentity("root", 0, 0)

	_ = db.SetImageOwner("sha256:img-bob-1", bob, false, "pull")
	_ = db.SetImageOwner("sha256:img-bob-2", bob, false, "build")
	_ = db.SetImageOwner("sha256:img-alice-1", alice, false, "pull")
	_ = db.SetImageOwner("sha256:img-public", root, true /*public*/, "pull")
	// sha256:img-orphan 故意不注册

	allImages := []map[string]interface{}{
		{"Id": "sha256:img-bob-1"},
		{"Id": "sha256:img-bob-2"},
		{"Id": "sha256:img-alice-1"},
		{"Id": "sha256:img-public"},
		{"Id": "sha256:img-orphan"},
	}

	// docker image ls 路径：FilterImageListResponse
	imageListBody := mustMarshalFilter(t, allImages) // 重用 filter_test.go 的辅助函数
	filteredImageList, err := FilterImageListResponse(imageListBody, bob.RealUID, false, db)
	if err != nil {
		t.Fatalf("FilterImageListResponse 失败: %v", err)
	}
	var imageListResult []json.RawMessage
	if err := json.Unmarshal(filteredImageList, &imageListResult); err != nil {
		t.Fatalf("解析 image list 结果失败: %v", err)
	}
	imageListCount := len(imageListResult)

	// docker system df 路径：FilterSystemDFResponse（镜像字段）
	systemDFBody := buildSystemDFBody(t, allImages, nil, nil)
	filteredDF, err := FilterSystemDFResponse(systemDFBody, bob.RealUID, false, db)
	if err != nil {
		t.Fatalf("FilterSystemDFResponse 失败: %v", err)
	}
	dfCounts := parseSystemDFCounts(t, filteredDF)

	// 两条路径必须返回相同的镜像数量
	if dfCounts.Images != imageListCount {
		t.Errorf(
			"镜像数量不一致：docker system df 显示 %d 个镜像，docker image ls 显示 %d 个镜像。\n"+
				"两者均调用 CanSeeImage，相同 DB 状态下结果必须一致。\n"+
				"请检查 filter.go:388-413 中是否存在影响计数的逻辑分歧。",
			dfCounts.Images, imageListCount,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG-3: docker system df -v 显示全空（verbose 模式）
// ══════════════════════════════════════════════════════════════════════════════

// ── 1. 复现测试（Red Test）─────────────────────────────────────────────────────
//
// TestFilterSystemDFResponse_BUG_VerboseMode_ItemsFromUsageField
//
// 复现 Bug：Docker 29.x daemon 在 ?verbose=1 时只返回 *Usage.Items，不含顶层 Images[]。
// FilterSystemDFResponse 旧代码只从顶层 Images[] 过滤，verbose 格式下该数组为空，
// 导致重建后的 ImageUsage.Items=[] → CLI 29.x verbose 读 ImageUsage.Items → 显示空行。
//
// 未修复前（old behavior）：
//
//	ImageUsage.Items = []（顶层 Images[] 为空，过滤结果为空）
//	TotalCount = 0 → CLI 显示 0 行 / 空表格
//
// 修复后：
//
//	从 ImageUsage.Items 提取条目 → 过滤 → 重建 ImageUsage.Items=[bob 的镜像]
//	TotalCount = 1 → CLI 正确显示 bob 的镜像
func TestFilterSystemDFResponse_BUG_VerboseMode_ItemsFromUsageField(t *testing.T) {
	db := newFilterTestDB(t)
	bob := makeFilterIdentity("bob", 1002, 1002)
	root := makeFilterIdentity("root", 0, 0)

	_ = db.SetContainerOwner("ctr-bob-001", bob, "")
	_ = db.SetImageOwner("sha256:bob-img-001", bob, false, "pull")
	_ = db.SetImageOwner("sha256:public-base", root, true, "pull")

	// 模拟 Docker 29.x daemon ?verbose=1 的原始响应：
	// 关键前提——只有 *Usage.Items 字段，无顶层 Images[]/Containers[] 数组
	verboseBody := buildSystemDFVerboseBody(t,
		[]map[string]interface{}{
			{"Id": "sha256:bob-img-001", "RepoTags": []string{"myapp:v1"}, "Containers": 1},
			{"Id": "sha256:public-base", "RepoTags": []string{"alpine:latest"}, "Containers": 0},
			{"Id": "sha256:alice-private", "RepoTags": []string{"alice:v1"}, "Containers": 0},
		},
		[]map[string]interface{}{
			{"Id": "ctr-bob-001", "Image": "sha256:bob-img-001"},
			{"Id": "ctr-alice-001", "Image": "sha256:alice-private"},
		},
		nil,
	)

	filtered, err := FilterSystemDFResponse(verboseBody, bob.RealUID, false, db)
	if err != nil {
		t.Fatalf("FilterSystemDFResponse: %v", err)
	}

	// ── 核心断言：过滤后 ImageUsage.Items 应包含 bob 的镜像 ──────────────────
	counts := parseSystemDFVerboseCounts(t, filtered)
	if counts.Images != 2 {
		t.Errorf(
			"[BUG-3] verbose 模式 ImageUsage.Items = %d 条，期望 2（bob 自有 1 + 公共 1）。\n"+
				"根因：FilterSystemDFResponse 从顶层 Images[]（verbose 下为空）过滤，\n"+
				"导致 ImageUsage.Items=[] → CLI 29.x verbose 显示空表格。\n"+
				"修复方案：检测 verbose 格式并从 *Usage.Items 提取条目再过滤。",
			counts.Images,
		)
	}
	if counts.Containers != 1 {
		t.Errorf(
			"[BUG-3] verbose 模式 ContainerUsage.Items = %d 条，期望 1（仅 bob 自己的容器）",
			counts.Containers,
		)
	}

	// ── 辅助断言：alice 的私有镜像不应出现 ────────────────────────────────────
	var result struct {
		ImageUsage struct {
			Items []struct {
				Id string `json:"Id"`
			} `json:"Items"`
		} `json:"ImageUsage"`
	}
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatalf("解析 ImageUsage.Items 失败: %v", err)
	}
	for _, img := range result.ImageUsage.Items {
		if img.Id == "sha256:alice-private" {
			t.Errorf("alice 的私有镜像 sha256:alice-private 不应出现在 bob 的 verbose 结果中")
		}
	}
}

// ── 2. 回归测试矩阵（Regression Suite）───────────────────────────────────────

// TestFilterSystemDFResponse_Regression_NonVerbose_UsageFieldsRebuilt
// 非 verbose 模式（daemon 返回 *Usage 字段）时，代理必须正确重建 *Usage 字段，
// 保证 Docker CLI 29.x 非 verbose 下的 TotalCount 显示正确。
func TestFilterSystemDFResponse_Regression_NonVerbose_UsageFieldsRebuilt(t *testing.T) {
	db := newFilterTestDB(t)
	bob := makeFilterIdentity("bob", 1002, 1002)

	_ = db.SetContainerOwner("ctr-bob-001", bob, "")
	_ = db.SetImageOwner("sha256:bob-img-001", bob, false, "pull")

	// 非 verbose 模式：daemon 包含 *Usage 字段（Docker 29.x 标准响应）
	body, err := json.Marshal(map[string]interface{}{
		"LayersSize": int64(0),
		"Images":     []map[string]interface{}{{"Id": "sha256:bob-img-001"}, {"Id": "sha256:alice-img"}},
		"Containers": []map[string]interface{}{{"Id": "ctr-bob-001"}, {"Id": "ctr-alice-001"}},
		"Volumes":    []map[string]interface{}{},
		"BuildCache": []interface{}{},
		// daemon 包含 *Usage 汇总字段
		"ImageUsage": map[string]interface{}{
			"Items":       []map[string]interface{}{{"Id": "sha256:bob-img-001"}, {"Id": "sha256:alice-img"}},
			"TotalCount":  2,
			"ActiveCount": 1,
			"TotalSize":   int64(50_000_000),
		},
		"ContainerUsage": map[string]interface{}{
			"Items":       []map[string]interface{}{{"Id": "ctr-bob-001"}, {"Id": "ctr-alice-001"}},
			"TotalCount":  2,
			"Reclaimable": int64(1024),
			"TotalSize":   int64(2048),
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	filtered, err := FilterSystemDFResponse(body, bob.RealUID, false, db)
	if err != nil {
		t.Fatalf("FilterSystemDFResponse: %v", err)
	}

	var result struct {
		ImageUsage struct {
			TotalCount int `json:"TotalCount"`
		} `json:"ImageUsage"`
		ContainerUsage struct {
			TotalCount int `json:"TotalCount"`
		} `json:"ContainerUsage"`
	}
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatalf("解析 filtered 失败: %v\nbody=%s", err, filtered)
	}

	// 非 verbose 模式：*Usage 必须被重建（daemon 原本有这些字段）
	if result.ImageUsage.TotalCount != 1 {
		t.Errorf("非 verbose 模式 ImageUsage.TotalCount = %d，期望 1（bob 仅有 1 个镜像）",
			result.ImageUsage.TotalCount)
	}
	if result.ContainerUsage.TotalCount != 1 {
		t.Errorf("非 verbose 模式 ContainerUsage.TotalCount = %d，期望 1（bob 仅有 1 个容器）",
			result.ContainerUsage.TotalCount)
	}

	// 补充：验证 ImageUsage.Items 内容正确，防止 TotalCount 正确但 Items 为空的静默回归
	var detailed struct {
		ImageUsage struct {
			Items []struct {
				Id string `json:"Id"`
			} `json:"Items"`
		} `json:"ImageUsage"`
	}
	if err := json.Unmarshal(filtered, &detailed); err != nil {
		t.Fatalf("解析 ImageUsage.Items 失败: %v", err)
	}
	if len(detailed.ImageUsage.Items) != 1 || detailed.ImageUsage.Items[0].Id != "sha256:bob-img-001" {
		t.Errorf("ImageUsage.Items 内容错误，期望 [{Id:sha256:bob-img-001}]，实际 %+v",
			detailed.ImageUsage.Items)
	}

	// 补充：验证 "ImageUsage": null 不会触发 nil map panic
	// （回归防护：orig 非空但 json.Unmarshal 后 m=nil 的极端情形）
	nullUsageBody, _ := json.Marshal(map[string]interface{}{
		"LayersSize":     int64(0),
		"Images":         []interface{}{},
		"Containers":     []interface{}{},
		"Volumes":        []interface{}{},
		"BuildCache":     []interface{}{},
		"ImageUsage":     nil, // JSON null → orig=[]byte("null"), len=4>0, Unmarshal→m=nil
		"ContainerUsage": nil,
		"VolumeUsage":    nil,
	})
	if _, err := FilterSystemDFResponse(nullUsageBody, bob.RealUID, false, db); err != nil {
		t.Errorf(`"field":null 输入不应返回 error，实际: %v`, err)
	}
	// 若 nil map panic，Go test 框架会以 FAIL 捕获（不会 crash 进程）
}

// TestFilterSystemDFResponse_Regression_VerboseMode_EmptyUser
// 边界条件：verbose 模式下，用户拥有零个可见资源时，
// 过滤结果应在 *Usage.Items 中返回空数组。
func TestFilterSystemDFResponse_Regression_VerboseMode_EmptyUser(t *testing.T) {
	db := newFilterTestDB(t)
	// carol 在 DB 中无任何资源

	// daemon verbose=1 响应（包含 alice 的资源）
	verboseBody := buildSystemDFVerboseBody(t,
		[]map[string]interface{}{
			{"Id": "sha256:alice-img", "RepoTags": []string{"alice:v1"}},
		},
		[]map[string]interface{}{
			{"Id": "ctr-alice-001"},
		},
		nil,
	)

	filtered, err := FilterSystemDFResponse(verboseBody, 1003 /*carol uid*/, false, db)
	if err != nil {
		t.Fatalf("FilterSystemDFResponse: %v", err)
	}

	// verbose 模式：carol 无资源，*Usage.Items 应为空
	counts := parseSystemDFVerboseCounts(t, filtered)
	if counts.Images != 0 || counts.Containers != 0 || counts.Volumes != 0 {
		t.Errorf("carol 无资源，期望 verbose Images/Containers/Volumes 全为 0，实际 (%d/%d/%d)",
			counts.Images, counts.Containers, counts.Volumes)
	}
}

// TestFilterSystemDFResponse_Regression_VerboseMode_PrivilegedUserPassthrough
// 特权用户（root/sudo）在 verbose 模式下应原样透传 daemon 响应，
// 不做任何过滤，也不添加任何额外字段。
func TestFilterSystemDFResponse_Regression_VerboseMode_PrivilegedUserPassthrough(t *testing.T) {
	db := newFilterTestDB(t)

	verboseBody := buildSystemDFVerboseBody(t,
		[]map[string]interface{}{
			{"Id": "sha256:img-aaa"},
			{"Id": "sha256:img-bbb"},
		},
		[]map[string]interface{}{
			{"Id": "ctr-001"},
			{"Id": "ctr-002"},
		},
		[]map[string]interface{}{
			{"Name": "vol-001"},
		},
	)

	filtered, err := FilterSystemDFResponse(verboseBody, 0 /*root*/, true /*privileged*/, db)
	if err != nil {
		t.Fatalf("特权用户 verbose FilterSystemDFResponse 失败: %v", err)
	}

	// 特权用户：原样透传，内容与输入完全一致
	if string(filtered) != string(verboseBody) {
		t.Errorf("特权用户应原样透传 verbose 响应，实际输出与输入不一致\n输入: %s\n输出: %s",
			verboseBody, filtered)
	}
}

// TestFilterSystemDFResponse_Regression_VerboseMode_MultiUserIsolation
// 回归验证：verbose 模式下，不同用户的资源严格隔离。
// bob 的镜像/容器不应出现在 alice 的过滤结果中，反之亦然。
func TestFilterSystemDFResponse_Regression_VerboseMode_MultiUserIsolation(t *testing.T) {
	db := newFilterTestDB(t)
	alice := makeFilterIdentity("alice", 1001, 1001)
	bob := makeFilterIdentity("bob", 1002, 1002)

	_ = db.SetContainerOwner("ctr-alice-001", alice, "")
	_ = db.SetContainerOwner("ctr-bob-001", bob, "")
	_ = db.SetImageOwner("sha256:alice-img", alice, false, "pull")
	_ = db.SetImageOwner("sha256:bob-img", bob, false, "pull")

	verboseBody := buildSystemDFVerboseBody(t,
		[]map[string]interface{}{
			{"Id": "sha256:alice-img", "RepoTags": []string{"alice-app:latest"}},
			{"Id": "sha256:bob-img", "RepoTags": []string{"bob-app:latest"}},
		},
		[]map[string]interface{}{
			{"Id": "ctr-alice-001"},
			{"Id": "ctr-bob-001"},
		},
		nil,
	)

	// ── alice 视角 ────────────────────────────────────────────────────────────
	filteredAlice, err := FilterSystemDFResponse(verboseBody, alice.RealUID, false, db)
	if err != nil {
		t.Fatalf("alice FilterSystemDFResponse: %v", err)
	}
	aliceCounts := parseSystemDFVerboseCounts(t, filteredAlice)
	if aliceCounts.Images != 1 {
		t.Errorf("alice verbose Images = %d，期望 1（仅自己的镜像）", aliceCounts.Images)
	}
	if aliceCounts.Containers != 1 {
		t.Errorf("alice verbose Containers = %d，期望 1（仅自己的容器）", aliceCounts.Containers)
	}

	// ── bob 视角 ──────────────────────────────────────────────────────────────
	filteredBob, err := FilterSystemDFResponse(verboseBody, bob.RealUID, false, db)
	if err != nil {
		t.Fatalf("bob FilterSystemDFResponse: %v", err)
	}
	bobCounts := parseSystemDFVerboseCounts(t, filteredBob)
	if bobCounts.Images != 1 {
		t.Errorf("bob verbose Images = %d，期望 1（仅自己的镜像）", bobCounts.Images)
	}
	if bobCounts.Containers != 1 {
		t.Errorf("bob verbose Containers = %d，期望 1（仅自己的容器）", bobCounts.Containers)
	}
}
