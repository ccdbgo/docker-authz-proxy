package isolation

import (
	"encoding/json"
	"fmt"
	"net/http"
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
	result, _, err := InjectNetworkNamePrefixWithName(body, identity)
	return result, err
}

// InjectNetworkNamePrefixWithName 向网络创建请求体注入用户前缀，同时返回注入后的实际网络名。
func InjectNetworkNamePrefixWithName(body []byte, identity *auth.CallerIdentity) ([]byte, string, error) {
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		return body, "", nil
	}

	prefix := UserResourcePrefix(identity)
	var name string
	if raw, ok := req["Name"]; ok {
		_ = json.Unmarshal(raw, &name)
	}
	actualName := name
	if !strings.HasPrefix(name, prefix) {
		actualName = prefix + name
		raw, _ := json.Marshal(actualName)
		req["Name"] = raw
	}

	// 重写 ConfigFrom.Network（--config-from 引用的配置源网络名）
	// docker network create --config-from <src> <dst> 将源网络名放在 ConfigFrom.Network 中，
	// 需同样注入用户前缀，否则 Docker 找不到内部名称（如 bob_u1002_xxx）
	if cfRaw, ok := req["ConfigFrom"]; ok {
		var configFrom map[string]json.RawMessage
		if err := json.Unmarshal(cfRaw, &configFrom); err == nil {
			var cfNetwork string
			if nRaw, ok := configFrom["Network"]; ok {
				_ = json.Unmarshal(nRaw, &cfNetwork)
			}
			if cfNetwork != "" && !strings.HasPrefix(cfNetwork, prefix) {
				newName, _ := json.Marshal(prefix + cfNetwork)
				configFrom["Network"] = newName
				newCFRaw, _ := json.Marshal(configFrom)
				req["ConfigFrom"] = newCFRaw
			}
		}
	}

	result, err := json.Marshal(req)
	if err != nil {
		return body, actualName, nil
	}
	return result, actualName, nil
}

// RewriteNetworkURL 将请求 URL 中的网络名补全用户前缀（未带前缀时）
func RewriteNetworkURL(r *http.Request, identity *auth.CallerIdentity) *http.Request {
	netName := ExtractNetworkID(r.URL.Path)
	if netName == "" || netName == "create" || netName == "prune" {
		return r
	}
	// hex ID（12位或64位纯十六进制）直接透传，不加前缀
	if isHexID(netName) {
		return r
	}
	prefix := UserResourcePrefix(identity)
	if strings.HasPrefix(netName, prefix) {
		return r
	}
	newName := prefix + netName
	newPath := strings.Replace(r.URL.Path, "/networks/"+netName, "/networks/"+newName, 1)
	newURL := *r.URL
	newURL.Path = newPath
	newReq := r.Clone(r.Context())
	newReq.URL = &newURL
	return newReq
}

// FilterNetworkListResponse 过滤网络列表，只返回用户可访问的网络
func FilterNetworkListResponse(body []byte, realUID int, privileged bool, db OwnershipReader) ([]byte, error) {
	if privileged {
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

// isHexID 判断字符串是否为纯十六进制 ID（只含 0-9 a-f A-F，长度 12 或 64）
func isHexID(s string) bool {
	if len(s) != 12 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// containerSpecialIDs 是 /containers/{id} 中不是真实容器名的保留路径片段
var containerSpecialIDs = map[string]bool{
	"json": true, "create": true, "prune": true,
}

// RewriteContainerURL 将请求 URL 中的容器名补全用户前缀（未带前缀时）
// 只对看起来是名称的部分补前缀（跳过十六进制 ID 和保留路径片段）
func RewriteContainerURL(r *http.Request, uid int) *http.Request {
	p := authz.StripAPIVersion(r.URL.Path)
	prefix := UserContainerPrefix(uid)

	// POST /commit?container={name}：docker commit 通过 query 参数传递容器名，不在路径中
	if p == "/commit" {
		containerParam := r.URL.Query().Get("container")
		if containerParam != "" &&
			!strings.HasPrefix(containerParam, prefix) &&
			!isHexID(containerParam) {
			newURL := *r.URL
			q := newURL.Query()
			q.Set("container", prefix+containerParam)
			newURL.RawQuery = q.Encode()
			newReq := r.Clone(r.Context())
			newReq.URL = &newURL
			return newReq
		}
		return r
	}

	const containersPrefix = "/containers/"
	if !strings.HasPrefix(p, containersPrefix) {
		return r
	}
	rest := p[len(containersPrefix):]
	var containerID string
	if idx := strings.Index(rest, "/"); idx >= 0 {
		containerID = rest[:idx]
	} else {
		containerID = rest
	}
	if containerID == "" || containerSpecialIDs[containerID] || isHexID(containerID) {
		return r // 保留路径或已是 hex ID，不需要重写
	}
	// 包含 ':' 或 '/' 的标识符是镜像引用，不是容器名（如 busybox:latest, library/nginx）
	if strings.ContainsAny(containerID, ":/") {
		return r
	}
	if strings.HasPrefix(containerID, prefix) {
		return r // 已有前缀
	}
	newName := prefix + containerID
	newPath := strings.Replace(r.URL.Path, containersPrefix+containerID, containersPrefix+newName, 1)
	newURL := *r.URL
	newURL.Path = newPath
	newReq := r.Clone(r.Context())
	newReq.URL = &newURL
	return newReq
}
// RewriteContainerInNetworkBody 重写网络 connect/disconnect 请求体中的容器名，补全用户前缀
func RewriteContainerInNetworkBody(body []byte, uid int) []byte {
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		return body
	}
	raw, ok := req["Container"]
	if !ok {
		return body
	}
	var containerName string
	if err := json.Unmarshal(raw, &containerName); err != nil || containerName == "" {
		return body
	}
	prefix := UserContainerPrefix(uid)
	if strings.HasPrefix(containerName, prefix) || isHexID(containerName) {
		return body
	}
	newName, _ := json.Marshal(prefix + containerName)
	req["Container"] = newName
	result, err := json.Marshal(req)
	if err != nil {
		return body
	}
	return result
}

// ExtractRequestedNetworks 从容器创建请求体中提取用户显式指定的网络名列表。
// Docker CLI 28+ 将 --network 放在 HostConfig.NetworkMode，旧版本放在 NetworkingConfig.EndpointsConfig。
// 两处都检查，去重后返回。
func ExtractRequestedNetworks(body []byte) []string {
	var req struct {
		HostConfig struct {
			NetworkMode string `json:"NetworkMode"`
		} `json:"HostConfig"`
		NetworkingConfig struct {
			EndpointsConfig map[string]json.RawMessage `json:"EndpointsConfig"`
		} `json:"NetworkingConfig"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var names []string
	if req.HostConfig.NetworkMode != "" {
		seen[req.HostConfig.NetworkMode] = true
		names = append(names, req.HostConfig.NetworkMode)
	}
	for name := range req.NetworkingConfig.EndpointsConfig {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
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

// StripContainerInspectNetworkPrefix 剥除容器 inspect 响应中
// NetworkSettings.Networks 键名及各网络条目 DNSNames 里的用户网络前缀。
// 格式："{username}_u{uid}_"。出错时原样返回 body，保证安全透传。
func StripContainerInspectNetworkPrefix(body []byte, netPrefix string) []byte {
	if len(body) == 0 || netPrefix == "" {
		return body
	}

	var resp map[string]json.RawMessage
	if err := json.Unmarshal(body, &resp); err != nil {
		return body
	}

	nsRaw, ok := resp["NetworkSettings"]
	if !ok {
		return body // 镜像 inspect，无 NetworkSettings，直接跳过
	}

	var ns map[string]json.RawMessage
	if err := json.Unmarshal(nsRaw, &ns); err != nil {
		return body
	}

	networksRaw, ok := ns["Networks"]
	if !ok {
		return body
	}

	var networks map[string]json.RawMessage
	if err := json.Unmarshal(networksRaw, &networks); err != nil {
		return body
	}

	if len(networks) == 0 {
		return body
	}

	// 重建 Networks map：剥除键名前缀，并处理各条目内的 DNSNames
	newNetworks := make(map[string]json.RawMessage, len(networks))
	for key, entry := range networks {
		newKey := strings.TrimPrefix(key, netPrefix)
		newNetworks[newKey] = stripNetworkEntryDNSPrefix(entry, netPrefix)
	}

	newNetworksRaw, err := json.Marshal(newNetworks)
	if err != nil {
		return body
	}
	ns["Networks"] = newNetworksRaw

	newNSRaw, err := json.Marshal(ns)
	if err != nil {
		return body
	}
	resp["NetworkSettings"] = newNSRaw

	result, err := json.Marshal(resp)
	if err != nil {
		return body
	}
	return result
}

// stripNetworkEntryDNSPrefix 剥除单个网络条目 JSON 中 DNSNames 数组里的用户前缀。
// 出错或无变化时返回原始 entry。
func stripNetworkEntryDNSPrefix(entry json.RawMessage, prefix string) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(entry, &obj); err != nil {
		return entry
	}

	dnsRaw, ok := obj["DNSNames"]
	if !ok || string(dnsRaw) == "null" {
		return entry
	}

	var dnsNames []string
	if err := json.Unmarshal(dnsRaw, &dnsNames); err != nil {
		return entry
	}

	modified := false
	for i, dns := range dnsNames {
		if strings.HasPrefix(dns, prefix) {
			dnsNames[i] = strings.TrimPrefix(dns, prefix)
			modified = true
		}
	}
	if !modified {
		return entry
	}

	newDNSRaw, err := json.Marshal(dnsNames)
	if err != nil {
		return entry
	}
	obj["DNSNames"] = newDNSRaw

	result, err := json.Marshal(obj)
	if err != nil {
		return entry
	}
	return result
}
