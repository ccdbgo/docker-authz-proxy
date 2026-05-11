//go:build linux

package isolation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

// ── 用户桥接网络 ──────────────────────────────────────────────

// UserBridgeName 返回用户专属桥接网络名称，格式：user-{uid}-bridge
func UserBridgeName(uid int) string {
	return fmt.Sprintf("user-%d-bridge", uid)
}

// PeerNetworkName 返回两个用户共享辅助网络名称，格式：peer-{uidA}-{uidB}（小 uid 在前）
func PeerNetworkName(uidA, uidB int) string {
	if uidA > uidB {
		uidA, uidB = uidB, uidA
	}
	return fmt.Sprintf("peer-%d-%d", uidA, uidB)
}

// BridgeManager 管理用户专属桥接网络、iptables 隔离规则和用户间互通
type BridgeManager struct {
	client *dockerClient
}

func NewBridgeManager(upstreamSock string) *BridgeManager {
	return &BridgeManager{client: newDockerClient(upstreamSock)}
}

// EnsureUserBridge 确保用户专属桥接网络存在，不存在则创建
// 返回网络 ID（已存在或新建）
func (m *BridgeManager) EnsureUserBridge(uid int, username string) (string, error) {
	name := UserBridgeName(uid)

	if id, err := m.client.findNetworkByName(name); err == nil && id != "" {
		return id, nil
	}

	body := map[string]any{
		"Name":   name,
		"Driver": "bridge",
		"Options": map[string]string{
			"com.docker.network.bridge.enable_icc":           "true",
			"com.docker.network.bridge.enable_ip_masquerade": "true",
		},
		"Labels": map[string]string{
			"docker-authz-proxy.owner_uid":      fmt.Sprintf("%d", uid),
			"docker-authz-proxy.owner_username": username,
			"docker-authz-proxy.managed":        "true",
		},
	}

	networkID, err := m.client.createNetwork(body)
	if err != nil {
		return "", fmt.Errorf("create bridge for uid=%d: %w", uid, err)
	}

	// 获取桥接接口名，添加 iptables 隔离规则
	if brIface, err := m.client.getBridgeInterface(networkID); err == nil && brIface != "" {
		_ = addIsolationRules(brIface)
	}

	return networkID, nil
}

// DeleteUserBridge 删除用户专属桥接网络（用户注销时调用）
func (m *BridgeManager) DeleteUserBridge(uid int) error {
	name := UserBridgeName(uid)
	id, err := m.client.findNetworkByName(name)
	if err != nil || id == "" {
		return nil
	}
	if brIface, err := m.client.getBridgeInterface(id); err == nil && brIface != "" {
		removeIsolationRules(brIface)
	}
	return m.client.deleteNetwork(id)
}

// GetUserBridgeID 查询用户桥接网络 ID，不存在返回 ""
func (m *BridgeManager) GetUserBridgeID(uid int) string {
	id, _ := m.client.findNetworkByName(UserBridgeName(uid))
	return id
}

// GetBridgeInterface 查询 Docker 网络对应的 Linux 网桥接口名
func (m *BridgeManager) GetBridgeInterface(networkID string) (string, error) {
	return m.client.getBridgeInterface(networkID)
}

// ── 用户网络互通（共享辅助网络方案）─────────────────────────
//
// 实现方式：
//   1. 创建一个共享辅助网络 peer-{uidA}-{uidB}
//   2. 将双方已有容器连接到该辅助网络（可选，新容器创建时自动加入）
//   3. 在 DOCKER-USER 链添加 ACCEPT 规则，允许辅助网络网桥的流量通过
//
// 这样双方容器可以通过辅助网络互相通信，同时各自的专属网络仍然隔离。
// 新容器创建时，代理检查是否有互通配置，若有则同时加入辅助网络。

// CreatePeerNetwork 创建两个用户之间的共享辅助网络
// 返回辅助网络 ID
func (m *BridgeManager) CreatePeerNetwork(uidA, uidB int) (string, error) {
	return m.createPeerNetworkWithName(PeerNetworkName(uidA, uidB), uidA, uidB)
}

// CreateContainerPeerNetwork 创建容器级互通专用网络，名称含容器 ID 短串，与用户级 peer 网络严格隔离
func (m *BridgeManager) CreateContainerPeerNetwork(uidA, uidB int, shortContA, shortContB string) (string, error) {
	name := fmt.Sprintf("cpeer-%d-%d-%s-%s", uidA, uidB, shortContA, shortContB)
	return m.createPeerNetworkWithName(name, uidA, uidB)
}

func (m *BridgeManager) createPeerNetworkWithName(name string, uidA, uidB int) (string, error) {
	// 幂等：已存在则直接返回
	if id, err := m.client.findNetworkByName(name); err == nil && id != "" {
		return id, nil
	}

	body := map[string]any{
		"Name":   name,
		"Driver": "bridge",
		"Options": map[string]string{
			"com.docker.network.bridge.enable_icc":           "true",
			"com.docker.network.bridge.enable_ip_masquerade": "true",
		},
		"Labels": map[string]string{
			"docker-authz-proxy.peer_uid_a": fmt.Sprintf("%d", uidA),
			"docker-authz-proxy.peer_uid_b": fmt.Sprintf("%d", uidB),
			"docker-authz-proxy.managed":    "true",
			"docker-authz-proxy.type":       "peer",
		},
	}

	networkID, err := m.client.createNetwork(body)
	if err != nil {
		return "", fmt.Errorf("create peer network %s: %w", name, err)
	}
	return networkID, nil
}

// DeletePeerNetwork 先断开所有容器再删除共享辅助网络，
// 避免容器重启时因网络已删除而启动失败。
func (m *BridgeManager) DeletePeerNetwork(peerNetworkID string) error {
	// 查出网络里的所有容器并逐一 disconnect
	containerIDs, _ := m.client.listNetworkContainers(peerNetworkID)
	for _, cid := range containerIDs {
		_ = m.client.disconnectContainerFromNetwork(cid, peerNetworkID)
	}
	return m.client.deleteNetwork(peerNetworkID)
}

// ConnectContainerToPeerNetwork 将容器连接到共享辅助网络
func (m *BridgeManager) ConnectContainerToPeerNetwork(containerID, peerNetworkID string) error {
	return m.client.connectContainerToNetwork(containerID, peerNetworkID)
}

// DisconnectContainerFromPeerNetwork 将容器从共享辅助网络断开
func (m *BridgeManager) DisconnectContainerFromPeerNetwork(containerID, peerNetworkID string) error {
	return m.client.disconnectContainerFromNetwork(containerID, peerNetworkID)
}

// GetContainersByOwner 查询用户的所有运行中容器 ID
func (m *BridgeManager) GetContainersByOwner(uid int) ([]string, error) {
	return m.client.listContainersByLabel(
		fmt.Sprintf("%s=%d", LabelOwnerUID, uid),
	)
}

// ── iptables 隔离规则 ─────────────────────────────────────────
//
// 在 DOCKER-USER 链中添加规则（Docker 重启不会清除该链）：
//   -I DOCKER-USER -o <br-xxxx> ! -i <br-xxxx> -j DROP  阻断其他网桥→本网桥
//   -I DOCKER-USER -i <br-xxxx> ! -o <br-xxxx> -j DROP  阻断本网桥→其他网桥
//
// 注意：辅助网络（peer-*）的网桥不添加 DROP 规则，允许双方容器通过辅助网络通信。

const iptablesChain = "DOCKER-USER"

func addIsolationRules(brIface string) error {
	if err := iptables("-I", iptablesChain, "-o", brIface, "!", "-i", brIface, "-j", "DROP"); err != nil {
		return fmt.Errorf("add inbound drop for %s: %w", brIface, err)
	}
	if err := iptables("-I", iptablesChain, "-i", brIface, "!", "-o", brIface, "-j", "DROP"); err != nil {
		_ = iptables("-D", iptablesChain, "-o", brIface, "!", "-i", brIface, "-j", "DROP")
		return fmt.Errorf("add outbound drop for %s: %w", brIface, err)
	}
	return nil
}

func removeIsolationRules(brIface string) {
	_ = iptables("-D", iptablesChain, "-o", brIface, "!", "-i", brIface, "-j", "DROP")
	_ = iptables("-D", iptablesChain, "-i", brIface, "!", "-o", brIface, "-j", "DROP")
}

func iptables(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %v: %w (output: %s)", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ── 端口映射解析 ──────────────────────────────────────────────

// PortMapping 容器端口映射（从请求体解析）
type PortMapping struct {
	HostPort      int
	ContainerPort int
	Protocol      string // "tcp" | "udp"
}

// ExtractPortMappings 从容器创建请求体中提取端口映射
func ExtractPortMappings(body []byte) []PortMapping {
	var req struct {
		HostConfig struct {
			PortBindings map[string][]struct {
				HostPort string `json:"HostPort"`
			} `json:"PortBindings"`
		} `json:"HostConfig"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}

	var mappings []PortMapping
	for portProto, bindings := range req.HostConfig.PortBindings {
		parts := strings.SplitN(portProto, "/", 2)
		if len(parts) != 2 {
			continue
		}
		var containerPort int
		fmt.Sscanf(parts[0], "%d", &containerPort)
		proto := parts[1]

		for _, b := range bindings {
			if b.HostPort == "" {
				continue // 动态分配，跳过冲突检测
			}
			var hostPort int
			fmt.Sscanf(b.HostPort, "%d", &hostPort)
			if hostPort > 0 {
				mappings = append(mappings, PortMapping{
					HostPort:      hostPort,
					ContainerPort: containerPort,
					Protocol:      proto,
				})
			}
		}
	}
	return mappings
}

// ── 网络注入 ──────────────────────────────────────────────────

// InjectUserNetwork 向容器创建请求体注入用户专属网络及所有用户级 peer 网络。
// userRequestedNetworks 为用户显式指定的、已通过权限检查的网络名列表（带用户前缀的真实名称）。
// 若用户指定了自己的网络，NetworkMode 保留为该网络；否则强制设为用户专属 bridge。
// peerNetworkIDs 为该用户已配置的用户级互通网络 ID 列表，可为空。
func InjectUserNetwork(body []byte, uid int, peerNetworkIDs []string, userRequestedNetworks []string) ([]byte, error) {
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		return body, nil
	}

	hostConfig := make(map[string]json.RawMessage)
	if hc, ok := req["HostConfig"]; ok && len(hc) > 0 && string(hc) != "null" {
		_ = json.Unmarshal(hc, &hostConfig)
	}

	bridgeName := UserBridgeName(uid)

	// 确定 NetworkMode：用户显式指定了自己的网络时保留，否则强制用专属 bridge
	primaryNet := bridgeName
	if len(userRequestedNetworks) > 0 && userRequestedNetworks[0] != "" {
		primaryNet = userRequestedNetworks[0]
	}
	b, _ := json.Marshal(primaryNet)
	hostConfig["NetworkMode"] = b

	// 读取原始 EndpointsConfig，保留 alias 等用户配置
	origEndpoints := make(map[string]json.RawMessage)
	if nc, ok := req["NetworkingConfig"]; ok && len(nc) > 0 && string(nc) != "null" {
		var ncMap struct {
			EndpointsConfig map[string]json.RawMessage `json:"EndpointsConfig"`
		}
		if json.Unmarshal(nc, &ncMap) == nil {
			origEndpoints = ncMap.EndpointsConfig
		}
	}

	// EndpointsConfig：始终包含专属 bridge + 用户指定的所有网络（保留原始配置）+ peer 网络
	endpoints := map[string]json.RawMessage{}
	emptyObj, _ := json.Marshal(map[string]any{})
	endpoints[bridgeName] = emptyObj
	for i, netName := range userRequestedNetworks {
		if netName == "" || netName == bridgeName {
			continue
		}
		// 尝试从原始 EndpointsConfig 中找到对应的配置（原始名或带前缀名）
		origName := netName
		if i < len(userRequestedNetworks) {
			// 原始请求里的网络名（不带前缀）
			rawNames := ExtractRequestedNetworks(body)
			if i < len(rawNames) {
				origName = rawNames[i]
			}
		}
		if cfg, ok := origEndpoints[origName]; ok {
			endpoints[netName] = cfg
		} else if cfg, ok := origEndpoints[netName]; ok {
			endpoints[netName] = cfg
		} else {
			endpoints[netName] = emptyObj
		}
	}
	for _, netID := range peerNetworkIDs {
		if netID != "" {
			if _, exists := endpoints[netID]; !exists {
				endpoints[netID] = emptyObj
			}
		}
	}
	networkingConfig := map[string]any{"EndpointsConfig": endpoints}
	if raw, err := json.Marshal(networkingConfig); err == nil {
		req["NetworkingConfig"] = raw
	}

	hcRaw, err := json.Marshal(hostConfig)
	if err != nil {
		return body, nil
	}
	req["HostConfig"] = hcRaw

	out, err := json.Marshal(req)
	if err != nil {
		return body, nil
	}
	return out, nil
}

// ── Docker API 客户端（内部使用）─────────────────────────────

type dockerClient struct {
	http *http.Client
}

func newDockerClient(sockPath string) *dockerClient {
	return &dockerClient{
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", sockPath)
				},
			},
			Timeout: 15 * time.Second,
		},
	}
}

func (c *dockerClient) findNetworkByName(name string) (string, error) {
	resp, err := c.http.Get(fmt.Sprintf("http://docker/networks/%s", name))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("inspect network %q: status %d", name, resp.StatusCode)
	}
	var result struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.ID, nil
}

func (c *dockerClient) createNetwork(body any) (string, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Post("http://docker/networks/create",
		"application/json", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("create network: status %d: %s", resp.StatusCode, string(b))
	}
	var result struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.ID, nil
}

func (c *dockerClient) deleteNetwork(id string) error {
	req, err := http.NewRequest(http.MethodDelete,
		fmt.Sprintf("http://docker/networks/%s", id), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete network %s: status %d: %s", id, resp.StatusCode, string(b))
	}
	return nil
}

func (c *dockerClient) getBridgeInterface(networkID string) (string, error) {
	resp, err := c.http.Get(fmt.Sprintf("http://docker/networks/%s", networkID))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("inspect network %s: status %d", networkID, resp.StatusCode)
	}
	var result struct {
		Options map[string]string `json:"Options"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if iface, ok := result.Options["com.docker.network.bridge.name"]; ok && iface != "" {
		return iface, nil
	}
	if len(networkID) >= 12 {
		return "br-" + networkID[:12], nil
	}
	return "", fmt.Errorf("cannot determine bridge interface for network %s", networkID)
}

func (c *dockerClient) connectContainerToNetwork(containerID, networkID string) error {
	body := map[string]string{"Container": containerID}
	data, _ := json.Marshal(body)
	resp, err := c.http.Post(
		fmt.Sprintf("http://docker/networks/%s/connect", networkID),
		"application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("connect container %s to network %s: status %d: %s",
			containerID, networkID, resp.StatusCode, string(b))
	}
	return nil
}

func (c *dockerClient) disconnectContainerFromNetwork(containerID, networkID string) error {
	body := map[string]any{"Container": containerID, "Force": false}
	data, _ := json.Marshal(body)
	resp, err := c.http.Post(
		fmt.Sprintf("http://docker/networks/%s/disconnect", networkID),
		"application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("disconnect container %s from network %s: status %d: %s",
			containerID, networkID, resp.StatusCode, string(b))
	}
	return nil
}

func (c *dockerClient) listContainersByLabel(labelFilter string) ([]string, error) {
	filterJSON, _ := json.Marshal(map[string][]string{
		"label": {labelFilter},
	})
	resp, err := c.http.Get(
		fmt.Sprintf("http://docker/containers/json?all=true&filters=%s",
			url.QueryEscape(string(filterJSON))))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var containers []struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(containers))
	for _, c := range containers {
		ids = append(ids, c.ID)
	}
	return ids, nil
}

func (c *dockerClient) listNetworkContainers(networkID string) ([]string, error) {
	resp, err := c.http.Get(fmt.Sprintf("http://docker/networks/%s", networkID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	var result struct {
		Containers map[string]struct{} `json:"Containers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(result.Containers))
	for id := range result.Containers {
		ids = append(ids, id)
	}
	return ids, nil
}

// DockerEventListener Docker 事件监听器，用于监听容器删除事件
type DockerEventListener struct {
	client *dockerClient
}

func NewDockerEventListener(upstreamSock string) *DockerEventListener {
	// /events 是长连接流式接口，不能使用带 Timeout 的 http.Client
	// 否则 15s 后触发 context deadline exceeded 导致反复重连
	streamClient := &dockerClient{
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", upstreamSock)
				},
			},
			// 不设置 Timeout，由调用方通过 ctx 控制生命周期
		},
	}
	return &DockerEventListener{client: streamClient}
}

// DockerEvent Docker 事件结构
type DockerEvent struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
}

// Listen 监听 Docker 事件流，将容器删除事件发送到 ch
// 调用方应在 goroutine 中运行，ctx 取消时退出
func (l *DockerEventListener) Listen(ctx context.Context, ch chan<- DockerEvent) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://docker/events?filters=%7B%22type%22%3A%5B%22container%22%5D%7D", nil)
	if err != nil {
		return err
	}
	resp, err := l.client.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	for {
		var event DockerEvent
		if err := dec.Decode(&event); err != nil {
			if ctx.Err() != nil {
				return nil // 正常退出
			}
			// EOF / ErrUnexpectedEOF 是 Docker daemon 断开长连接的正常现象
			// （daemon 重启、空闲超时等），返回 nil 让调用方静默重连
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return err
		}
		select {
		case ch <- event:
		case <-ctx.Done():
			return nil
		}
	}
}
