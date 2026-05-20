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

// FilterImageListResponse 过滤镜像列表响应，只返回用户可见的镜像
func FilterImageListResponse(body []byte, realUID int, privileged bool, db OwnershipReader) ([]byte, error) {
	if privileged {
		return body, nil
	}

	var images []json.RawMessage
	if err := json.Unmarshal(body, &images); err != nil {
		return emptyJSONArray, err
	}

	var filtered []json.RawMessage
	for _, raw := range images {
		var item struct {
			ID string `json:"Id"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}
		if db.CanSeeImage(realUID, item.ID) {
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
// Docker system df 响应结构：
//
//	{
//	  "LayersSize": int64,
//	  "Images":     [{"Id","ParentId","RepoTags","RepoDigests","Created","SharedSize","UniqueSize","Containers",...}],
//	  "Containers": [{"Id","Names","Image","ImageID","SizeRootFs","SizeRw",...}],
//	  "Volumes":    [{"Name","Driver","Mountpoint","UsageData":{"Size","RefCount"}}],
//	  "BuildCache": [...]
//	}
func FilterSystemDFResponse(body []byte, realUID int, privileged bool, db OwnershipReader) ([]byte, error) {
	if privileged {
		return body, nil
	}

	// 解析原始响应
	var raw struct {
		LayersSize int64               `json:"LayersSize"`
		Images     []json.RawMessage   `json:"Images"`
		Containers []json.RawMessage   `json:"Containers"`
		Volumes    []json.RawMessage   `json:"Volumes"`
		BuildCache []json.RawMessage   `json:"BuildCache"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		// 解析失败原样透传
		return body, nil
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
	for _, rawItem := range raw.Containers {
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
	for _, rawItem := range raw.Images {
		var img struct {
			ID string `json:"Id"`
		}
		if json.Unmarshal(rawItem, &img) != nil {
			continue
		}
		if db.CanSeeImage(realUID, img.ID) {
			// filteredImages 已在循环体内收集，提到外层
		}
	}
	var filteredImages []json.RawMessage
	for _, rawItem := range raw.Images {
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
	var filteredVolumes []json.RawMessage
	for _, rawItem := range raw.Volumes {
		var v struct {
			Name string `json:"Name"`
		}
		if json.Unmarshal(rawItem, &v) != nil {
			continue
		}
		if ownedVols[v.Name] {
			filteredVolumes = append(filteredVolumes, rawItem)
		}
	}
	if filteredVolumes == nil {
		filteredVolumes = []json.RawMessage{}
	}

	// BuildCache 不做用户级过滤（纯构建缓存层，无法准确归属）
	buildCache := raw.BuildCache
	if buildCache == nil {
		buildCache = []json.RawMessage{}
	}

	out := struct {
		LayersSize int64             `json:"LayersSize"`
		Images     []json.RawMessage `json:"Images"`
		Containers []json.RawMessage `json:"Containers"`
		Volumes    []json.RawMessage `json:"Volumes"`
		BuildCache []json.RawMessage `json:"BuildCache"`
	}{
		LayersSize: 0, // 用户级别无法精确计算共享层大小
		Images:     filteredImages,
		Containers: filteredContainers,
		Volumes:    filteredVolumes,
		BuildCache: buildCache,
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
