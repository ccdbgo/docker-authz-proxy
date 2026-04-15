package isolation

import (
	"encoding/json"
	"strings"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

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
func FilterVolumeListResponse(body []byte, realUID int, db OwnershipReader) ([]byte, error) {
	emptyResp := func() ([]byte, error) {
		return json.Marshal(struct {
			Volumes  []json.RawMessage `json:"Volumes"`
			Warnings []string          `json:"Warnings"`
		}{Volumes: []json.RawMessage{}, Warnings: nil})
	}

	if realUID == 0 {
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
