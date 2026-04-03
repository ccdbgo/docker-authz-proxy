package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// emptyJSONArray 空容器/镜像列表（fail-secure 时返回）
var emptyJSONArray = []byte("[]")

// filterContainerListResponse 过滤容器列表响应，只返回用户自己的容器
// 安全原则：任何错误均 fail-secure（返回空列表），不暴露其他用户的容器
func filterContainerListResponse(body []byte, realUID int, db *OwnershipDB) ([]byte, error) {
	// root 可见所有容器（系统管理需要），直接透传
	if realUID == 0 {
		return body, nil
	}

	var containers []json.RawMessage
	if err := json.Unmarshal(body, &containers); err != nil {
		// 解析失败：fail-secure，返回空列表
		return emptyJSONArray, err
	}

	// 获取该用户拥有的所有容器 ID
	ownedIDs, err := db.GetContainerIDsByOwner(realUID)
	if err != nil {
		// DB 错误：fail-secure，返回空列表（而非全量暴露）
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
			// 单条解析失败：跳过（fail-secure，不展示不可信数据）
			continue
		}

		// 优先用 DB 判断归属
		if owned[item.ID] || (len(item.ID) >= 12 && owned[item.ID[:12]]) {
			filtered = append(filtered, raw)
			continue
		}

		// 兜底：读取容器 Labels 中的系统归属标签（DB 写入失败时的保底）
		if item.Labels != nil {
			uidStr := item.Labels[labelOwnerUID]
			if uidStr == "" {
				continue
			}
			lastUID := getLastLabelValue(uidStr)
			if lastUID == "" {
				continue
			}
			uid := 0
			for _, c := range lastUID {
				if c < '0' || c > '9' {
					uid = -1
					break
				}
				uid = uid*10 + int(c-'0')
			}
			if uid >= 0 && uid == realUID {
				filtered = append(filtered, raw)
			}
		}
	}

	if filtered == nil {
		filtered = []json.RawMessage{}
	}
	return json.Marshal(filtered)
}

// filterImageListResponse 过滤镜像列表响应，只返回用户自己的镜像和公共镜像
// 安全原则：任何错误均 fail-secure（返回空列表），不暴露其他用户的镜像
func filterImageListResponse(body []byte, realUID int, db *OwnershipDB) ([]byte, error) {
	// root 可见所有镜像（系统管理需要），直接透传
	if realUID == 0 {
		return body, nil
	}

	var images []json.RawMessage
	if err := json.Unmarshal(body, &images); err != nil {
		// 解析失败：fail-secure，返回空列表
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
		// 去掉 "sha256:" 前缀后查询 DB
		imageID := strings.TrimPrefix(item.ID, "sha256:")
		// CanSeeImage：严格可见性检查，未追踪镜像不显示
		if db.CanSeeImage(realUID, item.ID) || db.CanSeeImage(realUID, imageID) {
			filtered = append(filtered, raw)
		}
	}

	if filtered == nil {
		filtered = []json.RawMessage{}
	}
	return json.Marshal(filtered)
}

// streamAndCaptureLoadedImageIDs 流式转发 docker load 响应，捕获加载的镜像 ID
// docker load 输出行格式：{"stream":"Loaded image ID: sha256:..."}
// 或：{"stream":"Loaded image: nginx:latest\n"}（有 tag 时）
func streamAndCaptureLoadedImageIDs(w http.ResponseWriter, resp *http.Response) []string {
	flusher, canFlush := w.(http.Flusher)
	var imageIDs []string

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		_, _ = w.Write([]byte(line + "\n"))
		if canFlush {
			flusher.Flush()
		}
		var msg struct {
			Stream string `json:"stream"`
		}
		if err := json.Unmarshal([]byte(line), &msg); err == nil {
			// "Loaded image ID: sha256:abc123..."
			if strings.HasPrefix(msg.Stream, "Loaded image ID: ") {
				id := strings.TrimSpace(strings.TrimPrefix(msg.Stream, "Loaded image ID: "))
				if id != "" {
					imageIDs = append(imageIDs, id)
				}
			}
		}
	}
	return imageIDs
}


func extractContainerIDFromCreateResponse(body []byte) string {
	var resp struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}
	return resp.ID
}

// streamAndCaptureImageID 流式转发 build/pull 响应，同时从末尾提取镜像 ID
// 返回最终镜像 ID（可能为空）
func streamAndCaptureImageID(w http.ResponseWriter, resp *http.Response, source string) string {
	flusher, canFlush := w.(http.Flusher)

	// 保留最后 N 行用于提取镜像 ID
	const keepLines = 20
	var lastLines []string

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		// 转发给客户端
		_, _ = w.Write([]byte(line + "\n"))
		if canFlush {
			flusher.Flush()
		}
		// 滚动保留最后 N 行
		lastLines = append(lastLines, line)
		if len(lastLines) > keepLines {
			lastLines = lastLines[1:]
		}
	}

	return extractImageIDFromStreamLines(lastLines, source)
}

// extractImageIDFromStreamLines 从 build/pull 的末尾流行中提取镜像 ID
func extractImageIDFromStreamLines(lines []string, source string) string {
	// 反向扫描，找包含镜像 ID 的行
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]

		// docker build 最终输出：{"aux":{"ID":"sha256:..."}}
		if source == "build" {
			var msg struct {
				Aux *struct {
					ID string `json:"ID"`
				} `json:"aux"`
			}
			if err := json.Unmarshal([]byte(line), &msg); err == nil && msg.Aux != nil && msg.Aux.ID != "" {
				return msg.Aux.ID
			}
			// 旧格式：Successfully built <short-id>
			if strings.HasPrefix(line, "Successfully built ") {
				return strings.TrimPrefix(line, "Successfully built ")
			}
		}

		// docker pull 最终输出包含 digest 或 status: "Status: Downloaded newer image"
		// 镜像 ID 可能在：{"status":"...","id":"sha256:..."}
		if source == "pull" {
			var msg struct {
				ID     string `json:"id"`
				Status string `json:"status"`
				Aux    *struct {
					Tag    string `json:"Tag"`
					Digest string `json:"Digest"`
					Size   int64  `json:"Size"`
				} `json:"aux"`
			}
			if err := json.Unmarshal([]byte(line), &msg); err == nil {
				if msg.Aux != nil && msg.Aux.Digest != "" {
					return msg.Aux.Digest
				}
			}
		}
	}
	return ""
}

// readFullBody 读取 HTTP 响应体并关闭
func readFullBody(body io.ReadCloser) ([]byte, error) {
	defer body.Close()
	return io.ReadAll(body)
}

// copyHeaders 复制响应头到 ResponseWriter
func copyHeaders(dst http.ResponseWriter, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Header().Add(k, v)
		}
	}
}

// isJSONContentType 判断响应是否为 JSON
func isJSONContentType(header http.Header) bool {
	ct := header.Get("Content-Type")
	return strings.Contains(ct, "application/json")
}

// isStreamResponse 判断响应是否为流式
func isStreamResponse(header http.Header) bool {
	ct := header.Get("Content-Type")
	return strings.Contains(ct, "application/x-ndjson") ||
		strings.Contains(ct, "text/plain") ||
		header.Get("Transfer-Encoding") == "chunked"
}

// rebuildBody 重新构建响应体（用于修改后的响应）
func rebuildBody(data []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(data))
}
