package isolation

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// CountJSONArray 统计 JSON 数组中的元素数量，解析失败返回 0
func CountJSONArray(data []byte) int {
	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err != nil {
		return 0
	}
	return len(arr)
}

// CountVolumeList 统计 Docker volumes 响应中的 Volume 数量
func CountVolumeList(data []byte) int {
	var resp struct {
		Volumes []json.RawMessage `json:"Volumes"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return 0
	}
	return len(resp.Volumes)
}

// emptyJSONArray 空容器/镜像列表（fail-secure 时返回）
var emptyJSONArray = []byte("[]")

// FilterContainerListResponse 过滤容器列表响应，只返回用户自己的容器。
// 归属判定顺序：① 归属数据库 → ② system.authz.owner.uid 标签 → ③ owner 标签（用户名）。
func FilterContainerListResponse(body []byte, realUID int, realUsername string, privileged bool, db OwnershipReader) ([]byte, error) {
	if privileged {
		return body, nil
	}

	var containers []json.RawMessage
	if err := json.Unmarshal(body, &containers); err != nil {
		// 上游返回非 JSON（如错误信息），原样透传，不截断
		return body, nil
	}

	ownedIDs, err := db.GetContainerIDsByOwner(realUID)
	if err != nil {
		return emptyJSONArray, err
	}
	owned := make(map[string]bool, len(ownedIDs)*2)
	for _, id := range ownedIDs {
		owned[id] = true
		if len(id) >= 12 {
			owned[id[:12]] = true
		}
	}

	var filtered []json.RawMessage
	for _, raw := range containers {
		var item struct {
			ID     string            `json:"Id"`
			Labels map[string]string `json:"Labels"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}

		// ① 数据库归属
		if owned[item.ID] || (len(item.ID) >= 12 && owned[item.ID[:12]]) {
			filtered = append(filtered, raw)
			continue
		}

		if item.Labels == nil {
			continue
		}

		// sudo 上下文容器（LabelCallerType = "sudo"）不得对非特权用户可见，
		// 即使 UID/用户名匹配也必须跳过——与 path① 的 DB pc=0 过滤语义对齐。
		if GetLastLabelValue(item.Labels[LabelCallerType]) == "sudo" {
			continue
		}

		// ② system.authz.owner.uid 标签（防篡改，取末位值）
		if uidStr := GetLastLabelValue(item.Labels[LabelOwnerUID]); uidStr != "" {
			uid := parseUID(uidStr)
			if uid >= 0 && uid == realUID {
				filtered = append(filtered, raw)
				continue
			}
		}

		// ③ owner 标签（用户可见，取末位值）
		if ownerName := GetLastLabelValue(item.Labels[LabelOwner]); ownerName != "" && ownerName == realUsername {
			filtered = append(filtered, raw)
		}
	}

	if filtered == nil {
		return emptyJSONArray, nil
	}

	// 剥除容器名称前缀（user-{uid}-），让用户看到原始名称
	containerPrefix := UserContainerPrefix(realUID)
	for i, raw := range filtered {
		var item map[string]json.RawMessage
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}
		namesRaw, ok := item["Names"]
		if !ok {
			continue
		}
		var names []string
		if err := json.Unmarshal(namesRaw, &names); err != nil {
			continue
		}
		modified := false
		for j, name := range names {
			// Docker 容器名带前导斜杠："/user-1001-test_container"
			if strings.HasPrefix(name, "/"+containerPrefix) {
				names[j] = "/" + name[1+len(containerPrefix):]
				modified = true
			}
		}
		if modified {
			newNames, _ := json.Marshal(names)
			item["Names"] = newNames
			newRaw, _ := json.Marshal(item)
			filtered[i] = newRaw
		}
	}

	return json.Marshal(filtered)
}

// parseUID 将字符串解析为非负整数 UID，失败返回 -1
func parseUID(s string) int {
	uid := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		uid = uid*10 + int(c-'0')
	}
	return uid
}

// FilterImageListResponse 过滤镜像列表响应，只返回用户可见的镜像。
// 对于用户自有镜像（owner_uid = realUID）：保留全部条目（含多 Tag）。
// 对于仅通过 is_public=1 可见的镜像：按 ImageId 去重，每个 ID 只保留一条，
// 防止其他用户推送到同一 ImageId 的私有 Tag 名称泄露给当前用户。
func FilterImageListResponse(body []byte, realUID int, privileged bool, db OwnershipReader) ([]byte, error) {
	if privileged {
		return body, nil
	}

	var images []json.RawMessage
	if err := json.Unmarshal(body, &images); err != nil {
		return emptyJSONArray, err
	}

	// 获取用户自有镜像 ID，区分"自有"与"仅公共可见"
	ownedIDs, err := db.GetImageIDsByOwner(realUID)
	if err != nil {
		ownedIDs = nil // DB 故障降级：等同原有 CanSeeImage 行为
	}
	ownedSet := make(map[string]bool, len(ownedIDs))
	for _, id := range ownedIDs {
		ownedSet[id] = true
	}

	var filtered []json.RawMessage
	publicSeen := make(map[string]bool)
	for _, raw := range images {
		var item struct {
			ID string `json:"Id"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}
		if !db.CanSeeImage(realUID, item.ID) {
			continue
		}
		// DB 存储时通过 normalizeImageID 去掉了 "sha256:" 前缀，
		// 但响应体中的 Id 字段可能带 "sha256:" 前缀，需要两端对齐后再查 ownedSet。
		normID := strings.TrimPrefix(item.ID, "sha256:")
		if ownedSet[normID] {
			// 自有镜像：不去重，保留全部条目
			filtered = append(filtered, raw)
			continue
		}
		// 公共镜像：按 ImageId 去重，防止私有 Tag 名称跨用户泄露
		if !publicSeen[item.ID] {
			publicSeen[item.ID] = true
			filtered = append(filtered, raw)
		}
	}

	if filtered == nil {
		return emptyJSONArray, nil
	}
	return json.Marshal(filtered)
}

// FilterServiceListResponse 过滤 Swarm service 列表，只返回用户自己的 service
func FilterServiceListResponse(body []byte, uid int, privileged bool, db OwnershipReader) ([]byte, error) {
	if privileged {
		return body, nil
	}

	var services []json.RawMessage
	if err := json.Unmarshal(body, &services); err != nil {
		return emptyJSONArray, err
	}

	ownedIDs, err := db.GetServiceIDsByOwner(uid)
	if err != nil {
		return emptyJSONArray, err
	}
	owned := make(map[string]bool, len(ownedIDs))
	for _, id := range ownedIDs {
		owned[id] = true
	}

	var filtered []json.RawMessage
	for _, raw := range services {
		var item struct {
			ID string `json:"ID"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}
		if owned[item.ID] {
			filtered = append(filtered, raw)
		}
	}
	if filtered == nil {
		return emptyJSONArray, nil
	}
	return json.Marshal(filtered)
}

// FilterSecretListResponse 过滤 Swarm secret 列表，只返回用户自己的 secret
func FilterSecretListResponse(body []byte, uid int, privileged bool, db OwnershipReader) ([]byte, error) {
	if privileged {
		return body, nil
	}

	var secrets []json.RawMessage
	if err := json.Unmarshal(body, &secrets); err != nil {
		return emptyJSONArray, err
	}

	ownedIDs, err := db.GetSecretIDsByOwner(uid)
	if err != nil {
		return emptyJSONArray, err
	}
	owned := make(map[string]bool, len(ownedIDs))
	for _, id := range ownedIDs {
		owned[id] = true
	}

	var filtered []json.RawMessage
	for _, raw := range secrets {
		var item struct {
			ID string `json:"ID"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}
		if owned[item.ID] {
			filtered = append(filtered, raw)
		}
	}
	if filtered == nil {
		return emptyJSONArray, nil
	}
	return json.Marshal(filtered)
}

// FilterConfigListResponse 过滤 Swarm config 列表，只返回用户自己的 config
func FilterConfigListResponse(body []byte, uid int, privileged bool, db OwnershipReader) ([]byte, error) {
	if privileged {
		return body, nil
	}

	var configs []json.RawMessage
	if err := json.Unmarshal(body, &configs); err != nil {
		return emptyJSONArray, err
	}

	ownedIDs, err := db.GetConfigIDsByOwner(uid)
	if err != nil {
		return emptyJSONArray, err
	}
	owned := make(map[string]bool, len(ownedIDs))
	for _, id := range ownedIDs {
		owned[id] = true
	}

	var filtered []json.RawMessage
	for _, raw := range configs {
		var item struct {
			ID string `json:"ID"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}
		if owned[item.ID] {
			filtered = append(filtered, raw)
		}
	}
	if filtered == nil {
		return emptyJSONArray, nil
	}
	return json.Marshal(filtered)
}

// ReadFullBody 读取 HTTP 响应体并关闭
func ReadFullBody(body io.ReadCloser) ([]byte, error) {
	defer body.Close()
	return io.ReadAll(body)
}

// CopyHeaders 复制响应头到 ResponseWriter
func CopyHeaders(dst http.ResponseWriter, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Header().Add(k, v)
		}
	}
}

// IsJSONContentType 判断响应是否为 JSON
func IsJSONContentType(header http.Header) bool {
	ct := header.Get("Content-Type")
	return strings.Contains(ct, "application/json")
}

// IsStreamResponse 判断响应是否为流式
func IsStreamResponse(header http.Header) bool {
	ct := header.Get("Content-Type")
	return strings.Contains(ct, "application/x-ndjson") ||
		strings.Contains(ct, "text/plain") ||
		header.Get("Transfer-Encoding") == "chunked"
}

// RebuildBody 重新构建响应体
func RebuildBody(data []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(data))
}

// NewResponseScanner 创建响应行扫描器（用于流式响应）
func NewResponseScanner(r io.Reader) *bufio.Scanner {
	return bufio.NewScanner(r)
}

// FilterSystemDFResponse 对 GET /system/df 响应做用户级过滤。
// 特权用户直接返回原始响应体；普通用户只保留自己的容器、镜像（含公共镜像）、卷。
// LayersSize 置为 0（无法精确计算用户级别的 layer 共享大小）。
//
// Docker system df 有两种响应格式：
//
//	非 verbose（旧版 / Docker 29.x 默认）：
//	  顶层同时含 Images[]/Containers[]/Volumes[]/BuildCache[] 和 *Usage{} 汇总字段。
//	  CLI 读 *Usage.TotalCount 显示条数，读顶层数组渲染详情。
//
//	verbose（Docker 29.x -v）：
//	  顶层仅含 *Usage{Items:[...]} 字段（无 Images[]/Containers[]/Volumes[]）。
//	  CLI 直接读 *Usage.Items 渲染详情表格。
//	  旧版 Docker 的 BuildCache[] → verbose 时变为 BuildCacheUsage{Items:[...]}。
func FilterSystemDFResponse(body []byte, realUID int, privileged bool, db OwnershipReader) ([]byte, error) {
	if privileged {
		return body, nil
	}

	// 用 map 解析以精确检测哪些顶层字段实际存在（nil = key 缺失，与空数组不同）
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(body, &rawMap); err != nil {
		return body, nil
	}

	// extractItems 从 *Usage JSON 字段中提取 Items 数组
	extractItems := func(usageRaw json.RawMessage) []json.RawMessage {
		if len(usageRaw) == 0 {
			return nil
		}
		var u struct {
			Items []json.RawMessage `json:"Items"`
		}
		_ = json.Unmarshal(usageRaw, &u)
		return u.Items
	}

	// 解析各字段的原始值
	var imagesArr, containersArr, volumesArr, buildCacheArr []json.RawMessage
	_ = json.Unmarshal(rawMap["Images"], &imagesArr)
	_ = json.Unmarshal(rawMap["Containers"], &containersArr)
	_ = json.Unmarshal(rawMap["Volumes"], &volumesArr)
	_ = json.Unmarshal(rawMap["BuildCache"], &buildCacheArr)

	imageUsageRaw := rawMap["ImageUsage"]
	containerUsageRaw := rawMap["ContainerUsage"]
	volumeUsageRaw := rawMap["VolumeUsage"]
	buildCacheUsageRaw := rawMap["BuildCacheUsage"]

	// Docker 29.x verbose 格式：顶层无 Images 字段，数据在 *Usage.Items 中
	isVerboseFormat := rawMap["Images"] == nil && imageUsageRaw != nil

	// 待过滤的条目：优先用顶层数组，缺失时降级到 *Usage.Items（verbose 格式）
	imageItems := imagesArr
	if len(imageItems) == 0 && len(imageUsageRaw) > 0 {
		imageItems = extractItems(imageUsageRaw)
	}
	containerItems := containersArr
	if len(containerItems) == 0 && len(containerUsageRaw) > 0 {
		containerItems = extractItems(containerUsageRaw)
	}
	volumeItems := volumesArr
	if len(volumeItems) == 0 && len(volumeUsageRaw) > 0 {
		volumeItems = extractItems(volumeUsageRaw)
	}

	// ── 过滤容器 ────────────────────────────────────────────────────────────
	ownedContainerIDs, err := db.GetContainerIDsByOwner(realUID)
	if err != nil {
		return EmptySystemDFBody(), err
	}
	ownedCIDs := make(map[string]bool, len(ownedContainerIDs)*2)
	for _, cid := range ownedContainerIDs {
		ownedCIDs[cid] = true
		if len(cid) >= 12 {
			ownedCIDs[cid[:12]] = true
		}
	}
	var filteredContainers []json.RawMessage
	for _, rawItem := range containerItems {
		var c struct {
			ID string `json:"Id"`
		}
		if json.Unmarshal(rawItem, &c) != nil {
			continue
		}
		if ownedCIDs[c.ID] || (len(c.ID) >= 12 && ownedCIDs[c.ID[:12]]) {
			filteredContainers = append(filteredContainers, rawItem)
		}
	}
	if filteredContainers == nil {
		filteredContainers = []json.RawMessage{}
	}

	// ── 过滤镜像（用户自己的 + 公共镜像） ───────────────────────────────────
	var filteredImages []json.RawMessage
	for _, rawItem := range imageItems {
		var img struct {
			ID string `json:"Id"`
		}
		if json.Unmarshal(rawItem, &img) != nil {
			continue
		}
		if db.CanSeeImage(realUID, img.ID) {
			filteredImages = append(filteredImages, rawItem)
		}
	}
	if filteredImages == nil {
		filteredImages = []json.RawMessage{}
	}

	// ── 过滤卷 ──────────────────────────────────────────────────────────────
	ownedVolNames, err := db.GetVolumeNamesByOwner(realUID)
	if err != nil {
		return EmptySystemDFBody(), err
	}
	ownedVols := make(map[string]bool, len(ownedVolNames))
	for _, name := range ownedVolNames {
		ownedVols[name] = true
	}
	// 前缀兜底：与 FilterVolumeListResponse 保持一致。
	// 当 volume 带有用户前缀但未入 DB（如 DB 重置/历史遗留）时，
	// docker volume ls 通过前缀仍可见该卷；此处同步该逻辑以保证计数一致。
	volPrefix := UserVolumePrefix(realUID)
	var filteredVolumes []json.RawMessage
	for _, rawItem := range volumeItems {
		var v struct {
			Name string `json:"Name"`
		}
		if json.Unmarshal(rawItem, &v) != nil {
			continue
		}
		if ownedVols[v.Name] || strings.HasPrefix(v.Name, volPrefix) {
			// 向用户展示时剥离内部前缀，与 docker volume ls 的显示保持一致
			if strings.HasPrefix(v.Name, volPrefix) {
				var item map[string]json.RawMessage
				if json.Unmarshal(rawItem, &item) == nil {
					item["Name"], _ = json.Marshal(strings.TrimPrefix(v.Name, volPrefix))
					if rewritten, err := json.Marshal(item); err == nil {
						rawItem = rewritten
					}
				}
			}
			filteredVolumes = append(filteredVolumes, rawItem)
		}
	}
	if filteredVolumes == nil {
		filteredVolumes = []json.RawMessage{}
	}

	// ── 重建 *Usage 汇总字段 ─────────────────────────────────────────────────
	// rebuildUsageField 在 orig==nil 时返回 nil（omitempty 省略），
	// 在 orig 非空时用过滤结果重建 TotalCount/Items 等字段。
	imageUsage, _ := rebuildUsageField(imageUsageRaw, filteredImages, "image")
	containerUsage, _ := rebuildUsageField(containerUsageRaw, filteredContainers, "container")
	volumeUsage, _ := rebuildUsageField(volumeUsageRaw, filteredVolumes, "volume")

	// ── 输出：按照 daemon 使用的格式回写 ────────────────────────────────────
	if isVerboseFormat {
		// Docker 29.x verbose：只输出 *Usage 字段，BuildCacheUsage 原样透传
		out := map[string]json.RawMessage{}
		if imageUsage != nil {
			out["ImageUsage"] = imageUsage
		}
		if containerUsage != nil {
			out["ContainerUsage"] = containerUsage
		}
		if volumeUsage != nil {
			out["VolumeUsage"] = volumeUsage
		}
		if buildCacheUsageRaw != nil {
			out["BuildCacheUsage"] = buildCacheUsageRaw
		}
		return json.Marshal(out)
	}

	// 非 verbose / 旧版 Docker：输出顶层数组 + *Usage 字段
	buildCache := buildCacheArr
	if buildCache == nil {
		buildCache = []json.RawMessage{}
	}
	out := struct {
		LayersSize     int64             `json:"LayersSize"`
		Images         []json.RawMessage `json:"Images"`
		Containers     []json.RawMessage `json:"Containers"`
		Volumes        []json.RawMessage `json:"Volumes"`
		BuildCache     []json.RawMessage `json:"BuildCache"`
		ImageUsage     json.RawMessage   `json:"ImageUsage,omitempty"`
		ContainerUsage json.RawMessage   `json:"ContainerUsage,omitempty"`
		VolumeUsage    json.RawMessage   `json:"VolumeUsage,omitempty"`
	}{
		LayersSize:     0, // 用户级别无法精确计算共享层大小
		Images:         filteredImages,
		Containers:     filteredContainers,
		Volumes:        filteredVolumes,
		BuildCache:     buildCache,
		ImageUsage:     imageUsage,
		ContainerUsage: containerUsage,
		VolumeUsage:    volumeUsage,
	}
	return json.Marshal(out)
}

// FilterSwarmInspectResponse 对 GET /swarm 响应隐藏非特权用户的 JoinTokens。
// 特权用户原样返回；非特权用户的 Worker/Manager token 替换为 "*"，并附加提示信息。
func FilterSwarmInspectResponse(body []byte, privileged bool) ([]byte, error) {
	if privileged {
		return body, nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, nil
	}

	masked, _ := json.Marshal(struct {
		Worker  string `json:"Worker"`
		Manager string `json:"Manager"`
		Hint    string `json:"_hint"`
	}{
		Worker:  "****************************************",
		Manager: "****************************************",
		Hint:    "如需加入集群，请联系管理员",
	})
	raw["JoinTokens"] = masked

	return json.Marshal(raw)
}

// rebuildUsageField 根据过滤后的 items 重建 Docker 29.x *Usage 汇总字段。
//
// orig 为空（absent/nil）的情形：旧版 Docker（< 29.x）或 ?verbose=1 请求时，
// daemon 不返回 *Usage 字段。若代理此时主动创建该字段，Docker CLI verbose
// 渲染路径会切换到 *Usage.Items，导致详情表格全空。
// 因此 orig 为空时直接返回 nil（omitempty 省略该字段）。
//
// 注意：若 daemon 返回 "ImageUsage": null（JSON null），orig = []byte("null")，
// len > 0 会通过早期返回检查，Unmarshal 后 m 可能为 nil，
// 需在写入前显式初始化，防止 nil map panic。
// kind 仅用于区分不同资源的字段名差异（"image"/"container"/"volume"）。
func rebuildUsageField(orig json.RawMessage, items []json.RawMessage, kind string) (json.RawMessage, error) {
	// orig 为空：daemon 未返回该字段（旧版 Docker 或 verbose=1）→ 不创建新字段
	if len(orig) == 0 {
		return nil, nil
	}

	// 解析原始字段为通用 map，保留所有原始数值字段。
	// 若 orig 为 JSON null，Unmarshal 不报错但 m 仍为 nil，需显式初始化防止 nil map panic。
	var m map[string]json.RawMessage
	if err := json.Unmarshal(orig, &m); err != nil || m == nil {
		m = make(map[string]json.RawMessage)
	}

	// 用过滤后的条目数覆盖 TotalCount（CLI 用此字段显示数量）
	totalCount, _ := json.Marshal(len(items))
	m["TotalCount"] = totalCount

	// Items 同步替换为过滤后的条目
	if items == nil {
		items = []json.RawMessage{}
	}
	itemsRaw, _ := json.Marshal(items)
	m["Items"] = itemsRaw

	// ActiveCount（镜像/卷使用）：不超过 TotalCount
	if _, ok := m["ActiveCount"]; ok {
		m["ActiveCount"] = totalCount
	}

	// zero 用于置空无法精确计算的用户级数值字段
	zero, _ := json.Marshal(int64(0))

	// TotalSize 置 0（用户级别无法精确计算共享层大小）
	m["TotalSize"] = zero

	// container 特有：Reclaimable 置 0（无法精确计算用户级别）
	if kind == "container" {
		m["Reclaimable"] = zero
	}

	return json.Marshal(m)
}

// EmptySystemDFBody 返回空的 system df 响应（DB 故障时 fail-secure，供外部包使用）
func EmptySystemDFBody() []byte {
	b, _ := json.Marshal(struct {
		LayersSize int64             `json:"LayersSize"`
		Images     []json.RawMessage `json:"Images"`
		Containers []json.RawMessage `json:"Containers"`
		Volumes    []json.RawMessage `json:"Volumes"`
		BuildCache []json.RawMessage `json:"BuildCache"`
	}{
		Images: []json.RawMessage{}, Containers: []json.RawMessage{},
		Volumes: []json.RawMessage{}, BuildCache: []json.RawMessage{},
	})
	return b
}
