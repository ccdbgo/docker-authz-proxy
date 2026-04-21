package forward

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"docker-authz-proxy/internal/auth"
)

// ── 场景测试：跨用户网络互通 ──────────────────────────────────────────────────
//
// 测试前提：
//   - alice uid=1001，bob uid=1002
//   - 互通通过 db.AddNetworkPeer 直接预置（绕过 BridgeManager，单元测试不依赖 Docker）
//   - 共享辅助网络 ID 用常量 "peer-net-id-001" 代替

const (
	aliceUID = 1001
	bobUID   = 1002
	peerNetID = "peer-net-id-001"
)

// setupPeer 在 DB 中预置 alice<->bob 用户级互通记录，并注册辅助网络归属
func setupPeer(t *testing.T, p *ProxyServer) {
	t.Helper()
	if err := p.db.AddNetworkPeer(aliceUID, bobUID, peerNetID, "", ""); err != nil {
		t.Fatalf("AddNetworkPeer: %v", err)
	}
	// 将辅助网络注册为双方均可访问的共享网络
	if err := p.db.SetManagedNetworkOwner(peerNetID, "peer-1001-1002", aliceUID, "alice"); err != nil {
		t.Fatalf("SetManagedNetworkOwner: %v", err)
	}
	if err := p.db.SetNetworkShared(peerNetID, []int{aliceUID, bobUID}); err != nil {
		t.Fatalf("SetNetworkShared: %v", err)
	}
}

// ── 1. 互通前：bob 无法访问 alice 的网络 ─────────────────────────────────────

func TestNetworkPeer_BeforeAllow_BobCannotInspectAliceNetwork(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 注册 alice 的私有网络，bob 未被授权
	aliceID := &auth.CallerIdentity{RealUID: aliceUID, RealUsername: "alice"}
	_ = p.db.SetNetworkOwner("alice-net-id", "alice_u1001_mynet", aliceID)

	req := httptest.NewRequest("GET", "/networks/alice-net-id/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (bob cannot access alice's network before peer)", rw.Code)
	}
}

// ── 2. 互通后：bob 可以访问共享辅助网络 ──────────────────────────────────────

func TestNetworkPeer_AfterAllow_BobCanInspectPeerNetwork(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Id":"peer-net-id-001","Name":"peer-1001-1002"}`))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	setupPeer(t, p)

	req := httptest.NewRequest("GET", "/networks/"+peerNetID+"/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (bob can inspect peer network after allow)", rw.Code)
	}
}

// ── 3. 互通后：alice 也可以访问共享辅助网络 ───────────────────────────────────

func TestNetworkPeer_AfterAllow_AliceCanInspectPeerNetwork(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	setupPeer(t, p)

	req := httptest.NewRequest("GET", "/networks/"+peerNetID+"/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", aliceUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (alice can inspect peer network after allow)", rw.Code)
	}
}

// ── 4. 互通后：新容器创建时 connectContainerToPeerNetworks 能找到 peer 记录 ──
// 直接测试 DB 层逻辑：peer 记录存在时，GetAllNetworkPeers 能返回正确数据

func TestNetworkPeer_AfterAllow_PeerRecordVisibleForNewContainer(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	setupPeer(t, p)

	peers, err := p.db.GetAllNetworkPeers()
	if err != nil {
		t.Fatalf("GetAllNetworkPeers: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer record, got %d", len(peers))
	}
	peer := peers[0]
	if peer.PeerNetworkID != peerNetID {
		t.Errorf("PeerNetworkID = %q, want %q", peer.PeerNetworkID, peerNetID)
	}
	// bob 的 uid 应在 peer 记录中
	if peer.UidA != aliceUID && peer.UidB != aliceUID {
		t.Errorf("alice uid %d not in peer record (uid_a=%d, uid_b=%d)", aliceUID, peer.UidA, peer.UidB)
	}
	if peer.UidA != bobUID && peer.UidB != bobUID {
		t.Errorf("bob uid %d not in peer record (uid_a=%d, uid_b=%d)", bobUID, peer.UidA, peer.UidB)
	}
}

// ── 5. 撤销互通后：bob 无法再访问辅助网络 ────────────────────────────────────

func TestNetworkPeer_AfterDeny_BobCannotAccessPeerNetwork(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	setupPeer(t, p)

	// 模拟 DenyNetworkPeer：删除 peer 记录 + 删除辅助网络的 DB 记录（移除所有访问权）
	if _, err := p.db.RemoveNetworkPeer(aliceUID, bobUID, "", ""); err != nil {
		t.Fatalf("RemoveNetworkPeer: %v", err)
	}
	if err := p.db.DeleteNetwork(peerNetID); err != nil {
		t.Fatalf("DeleteNetwork: %v", err)
	}

	req := httptest.NewRequest("GET", "/networks/"+peerNetID+"/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (bob cannot access peer network after deny)", rw.Code)
	}
}

// ── 6. 互通幂等：重复 AddNetworkPeer 不报错 ───────────────────────────────────

func TestNetworkPeer_AddPeer_Idempotent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	if err := p.db.AddNetworkPeer(aliceUID, bobUID, peerNetID, "", ""); err != nil {
		t.Fatalf("first AddNetworkPeer: %v", err)
	}
	// 第二次应幂等（不报 unique constraint 错误）
	if err := p.db.AddNetworkPeer(aliceUID, bobUID, peerNetID, "", ""); err != nil {
		t.Errorf("second AddNetworkPeer should be idempotent, got: %v", err)
	}

	_, exists := p.db.GetNetworkPeer(aliceUID, bobUID)
	if !exists {
		t.Error("peer record should exist after AddNetworkPeer")
	}
}

// ── 7. 第三方用户 charlie 不受 alice<->bob 互通影响 ──────────────────────────

func TestNetworkPeer_ThirdUser_CannotAccessPeerNetwork(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	setupPeer(t, p)

	req := httptest.NewRequest("GET", "/networks/"+peerNetID+"/json", nil)
	req = injectIdentity(req, makeTestIdentityProxy("charlie", 1003))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (charlie not in alice<->bob peer)", rw.Code)
	}
}

// ── 8. bob connect 容器到辅助网络：互通后允许，互通前拒绝 ─────────────────────

func TestNetworkPeer_NetworkConnect_AllowedAfterPeer(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	setupPeer(t, p)

	// bob 将自己的容器连接到辅助网络
	bobID := &auth.CallerIdentity{RealUID: bobUID, RealUsername: "bob"}
	_ = p.db.SetContainerOwner("bob-cont-x", bobID, "")

	body, _ := json.Marshal(map[string]string{"Container": "bob-cont-x"})
	req := httptest.NewRequest("POST", "/networks/"+peerNetID+"/connect", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (bob can connect to peer network after allow)", rw.Code)
	}
}

func TestNetworkPeer_NetworkConnect_DeniedBeforePeer(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	// 不调用 setupPeer，互通未配置

	body, _ := json.Marshal(map[string]string{"Container": "bob-cont-y"})
	req := httptest.NewRequest("POST", "/networks/"+peerNetID+"/connect", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req = injectIdentity(req, makeTestIdentityProxy("bob", bobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (bob cannot connect to unknown peer network)", rw.Code)
	}
}
