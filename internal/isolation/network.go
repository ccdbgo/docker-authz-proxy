package isolation

import (
	"encoding/json"
	"fmt"
	"strings"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
)

// UserResourcePrefix 返回用户网络/Volume 名称前缀
// 格式：<username>_u<uid>_
func UserResourcePrefix(identity *auth.CallerIdentity) string {
	return fmt.Sprintf("%s_u%d_", identity.RealUsername, identity.RealUID)
}

// UserContainerPrefix 返回用户容器名称前缀
// 格式：user-{uid}-
func UserContainerPrefix(uid int) string {
	return fmt.Sprintf("user-%d-", uid)
}

// InjectContainerNamePrefix 向容器创建请求体注入用户前缀（user-{uid}-）
// 若 Name 字段为空或已有前缀则跳过
func InjectContainerNamePrefix(body []byte, identity *auth.CallerIdentity) ([]byte, string, error) {
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		return body, "", nil
	}

	prefix := UserContainerPrefix(identity.RealUID)
	var name string
	if raw, ok := req["Name"]; ok {
		_ = json.Unmarshal(raw, &name)
	}
	if name == "" || strings.HasPrefix(name, prefix) {
		return body, name, nil
	}

	rewritten := prefix + name
	raw, _ := json.Marshal(rewritten)
	req["Name"] = raw

	result, err := json.Marshal(req)
	if err != nil {
		return body, name, nil
	}
	return result, rewritten, nil
}

// InjectNetworkNamePrefix 向网络创建请求体注入用户前缀
func InjectNetworkNamePrefix(body []byte, identity *auth.CallerIdentity) ([]byte, error) {
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		return body, nil
	}

	prefix := UserResourcePrefix(identity)
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

// FilterNetworkListResponse 过滤网络列表，只返回用户可访问的网络
func FilterNetworkListResponse(body []byte, realUID int, db OwnershipReader) ([]byte, error) {
	if realUID == 0 {
		return body, nil
	}

	var networks []json.RawMessage
	if err := json.Unmarshal(body, &networks); err != nil {
		return emptyJSONArray, err
	}

	accessibleIDs, err := db.GetAccessibleNetworkIDs(realUID)
	if err != nil {
		return emptyJSONArray, err
	}
	accessible := make(map[string]bool, len(accessibleIDs))
	for _, id := range accessibleIDs {
		accessible[id] = true
		if len(id) >= 12 {
			accessible[id[:12]] = true
		}
	}

	username := auth.LookupUsername(realUID)
	prefix := fmt.Sprintf("%s_u%d_", username, realUID)

	var filtered []json.RawMessage
	for _, raw := range networks {
		var item map[string]json.RawMessage
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}
		var id, name string
		_ = json.Unmarshal(item["Id"], &id)
		_ = json.Unmarshal(item["Name"], &name)

		match := accessible[id] || (len(id) >= 12 && accessible[id[:12]]) || strings.HasPrefix(name, prefix)
		if !match {
			continue
		}

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
		return emptyJSONArray, nil
	}
	return json.Marshal(filtered)
}

// ExtractNetworkID 从路径中提取网络 ID
func ExtractNetworkID(path string) string {
	p := authz.StripAPIVersion(path)
	const prefix = "/networks/"
	if !strings.HasPrefix(p, prefix) {
		return ""
	}
	rest := p[len(prefix):]
	if idx := strings.Index(rest, "/"); idx >= 0 {
		return rest[:idx]
	}
	return rest
}
