package isolation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// NamedVolumeViolation 描述容器创建请求中引用了不属于用户的 named volume
type NamedVolumeViolation struct {
	VolumeName string
}

func (e *NamedVolumeViolation) Error() string {
	return fmt.Sprintf("get %s: no such volume", e.VolumeName)
}

// ValidateAndRewriteNamedVolumes 校验并重写容器创建请求体中 HostConfig.Binds 和
// HostConfig.Mounts 里的 named volume 引用。
//
// 对每个 named volume（无 / 前缀的 bind 源，或 Type=volume 的 Mount）：
//   - 若已带用户前缀，保持不变
//   - 若 db.GetVolumeNamesByOwner 返回的列表中包含带前缀的名称，则重写为带前缀名称
//   - 否则返回 *NamedVolumeViolation（volume 不存在或不属于该用户）
//
// root 用户（uid==0）直接返回原始 body。
func ValidateAndRewriteNamedVolumes(body []byte, uid int, db OwnershipReader) ([]byte, *NamedVolumeViolation) {
	if uid == 0 {
		return body, nil
	}

	prefix := UserVolumePrefix(uid)

	// 获取用户拥有的所有 volume 内部名称（带前缀）
	ownedNames, err := db.GetVolumeNamesByOwner(uid)
	if err != nil {
		return body, nil // DB 故障时放行，由后续检查兜底
	}
	ownedSet := make(map[string]bool, len(ownedNames))
	for _, n := range ownedNames {
		ownedSet[n] = true
	}

	var req struct {
		HostConfig struct {
			Binds  []string `json:"Binds"`
			Mounts []struct {
				Type   string `json:"Type"`
				Source string `json:"Source"`
				Target string `json:"Target"`
			} `json:"Mounts"`
		} `json:"HostConfig"`
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, nil
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return body, nil
	}

	// 重写 Binds
	newBinds := make([]string, 0, len(req.HostConfig.Binds))
	for _, b := range req.HostConfig.Binds {
		src, rest := splitBindSrc(b)
		if strings.HasPrefix(src, "/") {
			// bind mount 路径，不处理
			newBinds = append(newBinds, b)
			continue
		}
		if strings.HasPrefix(src, prefix) {
			// 已带前缀
			newBinds = append(newBinds, b)
			continue
		}
		// named volume：检查是否属于用户
		fullName := prefix + src
		if !ownedSet[fullName] {
			return body, &NamedVolumeViolation{VolumeName: src}
		}
		newBinds = append(newBinds, fullName+rest)
	}

	// 将重写结果写回 raw map
	var hcRaw map[string]json.RawMessage
	if err := json.Unmarshal(raw["HostConfig"], &hcRaw); err != nil {
		return body, nil
	}

	if len(req.HostConfig.Binds) > 0 {
		hcRaw["Binds"], _ = json.Marshal(newBinds)
	}

	// 重写 Mounts（Type=volume）中的 Source
	if len(req.HostConfig.Mounts) > 0 {
		var mountsRaw []json.RawMessage
		if err := json.Unmarshal(hcRaw["Mounts"], &mountsRaw); err == nil {
			for i, m := range req.HostConfig.Mounts {
				if !strings.EqualFold(m.Type, "volume") || m.Source == "" {
					continue
				}
				if strings.HasPrefix(m.Source, prefix) {
					continue
				}
				fullName := prefix + m.Source
				if !ownedSet[fullName] {
					return body, &NamedVolumeViolation{VolumeName: m.Source}
				}
				if i >= len(mountsRaw) {
					continue
				}
				var item map[string]json.RawMessage
				if err := json.Unmarshal(mountsRaw[i], &item); err != nil {
					continue
				}
				item["Source"], _ = json.Marshal(fullName)
				mountsRaw[i], _ = json.Marshal(item)
			}
			hcRaw["Mounts"], _ = json.Marshal(mountsRaw)
		}
	}

	raw["HostConfig"], _ = json.Marshal(hcRaw)
	result, err := json.Marshal(raw)
	if err != nil {
		return body, nil
	}
	return result, nil
}

// splitBindSrc 将 "src:dst[:opts]" 拆分为 (src, ":dst[:opts]")
func splitBindSrc(b string) (src, rest string) {
	idx := strings.Index(b, ":")
	if idx < 0 {
		return b, ""
	}
	return b[:idx], b[idx:]
}

// InjectVolumeNamePrefix 向 Volume 创建请求体注入用户前缀（user-{uid}-volume-）
func InjectVolumeNamePrefix(body []byte, identity *auth.CallerIdentity) ([]byte, error) {
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		return body, nil
	}

	prefix := UserVolumePrefix(identity.RealUID)
	var name string
	if raw, ok := req["Name"]; ok {
		_ = json.Unmarshal(raw, &name)
	}
	if !strings.HasPrefix(name, prefix) {
		raw, _ := json.Marshal(prefix + name)
		req["Name"] = raw
	}

	result, err := json.Marshal(req)
	if err != nil {
		return body, nil
	}
	return result, nil
}

// FilterVolumeListResponse 过滤 Volume 列表，只返回用户自己的 Volume，
// 并去除名称中的用户前缀（还原为用户创建时的原始名称）
func FilterVolumeListResponse(body []byte, realUID int, privileged bool, db OwnershipReader) ([]byte, error) {
	emptyResp := func() ([]byte, error) {
		return json.Marshal(struct {
			Volumes  []json.RawMessage `json:"Volumes"`
			Warnings []string          `json:"Warnings"`
		}{Volumes: []json.RawMessage{}, Warnings: nil})
	}

	if privileged {
		return body, nil
	}

	var resp struct {
		Volumes  []json.RawMessage `json:"Volumes"`
		Warnings []string          `json:"Warnings"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return emptyResp()
	}

	ownedNames, err := db.GetVolumeNamesByOwner(realUID)
	if err != nil {
		return emptyResp()
	}
	owned := make(map[string]bool, len(ownedNames))
	for _, n := range ownedNames {
		owned[n] = true
	}

	prefix := UserVolumePrefix(realUID)

	var filtered []json.RawMessage
	for _, raw := range resp.Volumes {
		var item map[string]json.RawMessage
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}
		var name string
		_ = json.Unmarshal(item["Name"], &name)

		if !owned[name] && !strings.HasPrefix(name, prefix) {
			continue
		}

		// 向用户展示时去掉前缀，还原原始名称
		if strings.HasPrefix(name, prefix) {
			stripped, _ := json.Marshal(strings.TrimPrefix(name, prefix))
			item["Name"] = stripped
		}

		out, err := json.Marshal(item)
		if err != nil {
			continue
		}
		filtered = append(filtered, out)
	}
	if filtered == nil {
		filtered = []json.RawMessage{}
	}

	return json.Marshal(struct {
		Volumes  []json.RawMessage `json:"Volumes"`
		Warnings []string          `json:"Warnings"`
	}{Volumes: filtered, Warnings: resp.Warnings})
}

// RewriteVolumeURL 将请求 URL 中的卷名补全用户前缀（未带前缀时）
func RewriteVolumeURL(r *http.Request, uid int) *http.Request {
	volName := ExtractVolumeName(r.URL.Path)
	if volName == "" || volName == "create" || volName == "prune" {
		return r
	}
	prefix := UserVolumePrefix(uid)
	if strings.HasPrefix(volName, prefix) {
		return r
	}
	newPath := strings.Replace(r.URL.Path, "/volumes/"+volName, "/volumes/"+prefix+volName, 1)
	newURL := *r.URL
	newURL.Path = newPath
	newReq := r.Clone(r.Context())
	newReq.URL = &newURL
	return newReq
}

// ExtractVolumeName 从路径中提取 Volume 名称
func ExtractVolumeName(path string) string {
	p := authz.StripAPIVersion(path)
	const prefix = "/volumes/"
	if !strings.HasPrefix(p, prefix) {
		return ""
	}
	rest := p[len(prefix):]
	if idx := strings.Index(rest, "/"); idx >= 0 {
		return rest[:idx]
	}
	return rest
}

// StripVolumeInspectPrefix 将 Volume inspect 响应体中的内部名称还原为用户原始名称。
// 处理 Name 字段和 Mountpoint 路径中的用户前缀。出错时返回原始 body。
func StripVolumeInspectPrefix(body []byte, uid int) []byte {
	prefix := UserVolumePrefix(uid)
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(body, &resp); err != nil {
		return body
	}

	var name string
	if raw, ok := resp["Name"]; ok {
		_ = json.Unmarshal(raw, &name)
	}
	if !strings.HasPrefix(name, prefix) {
		return body
	}
	stripped := strings.TrimPrefix(name, prefix)

	// 还原 Name 字段
	resp["Name"], _ = json.Marshal(stripped)

	// 还原 Mountpoint 中的路径段（将内部名替换为原始名）
	if raw, ok := resp["Mountpoint"]; ok {
		var mp string
		if json.Unmarshal(raw, &mp) == nil && strings.Contains(mp, name) {
			resp["Mountpoint"], _ = json.Marshal(strings.Replace(mp, name, stripped, 1))
		}
	}

	result, err := json.Marshal(resp)
	if err != nil {
		return body
	}
	return result
}

// 仅修改 JSON 中的 Name 字段，其余字段保持不变。出错时返回原始 body。
func StripVolumeNamePrefix(body []byte, uid int) []byte {
	prefix := UserVolumePrefix(uid)
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(body, &resp); err != nil {
		return body
	}
	var name string
	if raw, ok := resp["Name"]; ok {
		_ = json.Unmarshal(raw, &name)
	}
	if !strings.HasPrefix(name, prefix) {
		return body
	}
	stripped := strings.TrimPrefix(name, prefix)
	resp["Name"], _ = json.Marshal(stripped)
	result, err := json.Marshal(resp)
	if err != nil {
		return body
	}
	return result
}
