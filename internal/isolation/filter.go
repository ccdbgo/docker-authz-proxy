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
