//go:build !linux

package isolation

import (
	"context"
	"fmt"
)

func UserBridgeName(uid int) string        { return fmt.Sprintf("user-%d-bridge", uid) }
func PeerNetworkName(uidA, uidB int) string {
	if uidA > uidB {
		uidA, uidB = uidB, uidA
	}
	return fmt.Sprintf("peer-%d-%d", uidA, uidB)
}

type BridgeManager struct{}

func NewBridgeManager(_ string) *BridgeManager { return &BridgeManager{} }

func (m *BridgeManager) EnsureUserBridge(uid int, username string) (string, error) {
	return "", fmt.Errorf("not supported on this platform")
}
func (m *BridgeManager) DeleteUserBridge(_ int) error          { return nil }
func (m *BridgeManager) GetUserBridgeID(_ int) string          { return "" }
func (m *BridgeManager) GetBridgeInterface(_ string) (string, error) {
	return "", fmt.Errorf("not supported")
}
func (m *BridgeManager) CreatePeerNetwork(_, _ int) (string, error) {
	return "", fmt.Errorf("not supported")
}
func (m *BridgeManager) DeletePeerNetwork(_ string) error { return nil }
func (m *BridgeManager) ConnectContainerToPeerNetwork(_, _ string) error { return nil }
func (m *BridgeManager) DisconnectContainerFromPeerNetwork(_, _ string) error { return nil }
func (m *BridgeManager) GetContainersByOwner(_ int) ([]string, error) { return nil, nil }

func ExtractPortMappings(_ []byte) []PortMapping { return nil }
func InjectUserNetwork(body []byte, _ int) ([]byte, error) { return body, nil }

type PortMapping struct {
	HostPort      int
	ContainerPort int
	Protocol      string
}

type DockerEventListener struct{}

func NewDockerEventListener(_ string) *DockerEventListener { return &DockerEventListener{} }

type DockerEvent struct {
	Type   string
	Action string
	Actor  struct {
		ID         string
		Attributes map[string]string
	}
}

func (l *DockerEventListener) Listen(_ context.Context, _ chan<- DockerEvent) error {
	return fmt.Errorf("not supported")
}
