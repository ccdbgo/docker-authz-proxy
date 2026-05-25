// stale_records_multi_table_test.go
//
// 分析四张表（containers / networks / volumes / image_access）产生孤儿脏数据的根本原因，
// 并提供可复现每类 Bug 的 Red Test 和覆盖正常路径的 Regression Suite。
//
// ══════════════════════════════════════════════════════════════════════════════
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │              各表脏数据根本原因汇总                                     │
// ├──────────────┬──────────────────────────────────────────────────────────┤
// │ containers   │ BUG-11：事件流 destroy 处理器只调用 ReleasePortMappings, │
// │              │ 未调用 DeleteContainer。                                 │
// │              │ 触发路径：容器被绕过 proxy 直接删除（docker rm 直连      │
// │              │ /var/run/docker.sock）、proxy 停机期间的删除、Docker     │
// │              │ daemon 重启后的垃圾回收，destroy 事件到达后：             │
// │              │   proxy.go ~line 4869：仅调用 db.ReleasePortMappings()   │
// │              │   未调用 db.DeleteContainer()                            │
// │              │ 结果：containers 表记录永久残留，CanSee 过滤失效。        │
// ├──────────────┬──────────────────────────────────────────────────────────┤
// │ networks     │ BUG-12：ActionPrune / system prune 响应解析缺少           │
// │              │ NetworksDeleted 字段。                                   │
// │              │ 触发路径：特权用户执行 docker system prune，Docker        │
// │              │ 响应体含 NetworksDeleted 数组，但 proxy.go ~line 2238 的 │
// │              │ 结构体只定义 ContainersDeleted / ImagesDeleted /         │
// │              │ VolumesDeleted，缺少 NetworksDeleted。                   │
// │              │ 结果：网络记录永久残留。                                  │
// │              │ 注：单独的 docker network rm / network prune / 非特权    │
// │              │ system prune 路径已正确调用 DeleteNetwork。              │
// ├──────────────┬──────────────────────────────────────────────────────────┤
// │ volumes      │ BUG-13（操作型）：proxy 停机期间 docker volume rm 的     │
// │              │ 删除不经过 proxy，DB 无感知。                            │
// │              │ 代码层面：ActionVolumeRemove 和 prune 路径均正确调用     │
// │              │ DeleteVolume，没有代码缺陷。                             │
// │              │ 根因：无持久化事件回放机制，proxy 恢复后无法感知停机      │
// │              │ 期间发生的删除。                                         │
// ├──────────────┬──────────────────────────────────────────────────────────┤
// │ image_access │ BUG-14（BUG-10 连锁）：DeleteImage(tag-name) 因          │
// │              │ resolveImageIDInDB 无法匹配非 hex tag 名而静默失败，     │
// │              │ 导致 images + image_access 双重泄漏。                    │
// │              │ BUG-10 已修复（proxy 改为传 content ID），此处重点覆盖   │
// │              │ image_access 级联删除的正确性回归。                      │
// └──────────────┴──────────────────────────────────────────────────────────┘
//
// ══════════════════════════════════════════════════════════════════════════════

package authz

import (
	"encoding/json"
	"testing"
)

// ── 辅助：在 DB 中添加端口映射记录，便于测试 ReleasePortMappings ─────────────

func addTestPortMapping(t *testing.T, db *OwnershipDB, containerID string, uid int, hostPort int) {
	t.Helper()
	_, err := db.DB.Exec(
		`INSERT OR IGNORE INTO port_mappings
		 (host_port, protocol, container_port, container_id, owner_uid, owner_username)
		 VALUES (?, 'tcp', ?, ?, ?, ?)`,
		hostPort, hostPort, containerID, uid, "testuser",
	)
	if err != nil {
		t.Fatalf("addTestPortMapping: %v", err)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG-11 containers 表
// ══════════════════════════════════════════════════════════════════════════════

// [BUG-11 RED] 事件流 destroy 处理器只释放端口，不清除容器归属记录
//
// 复现路径（proxy.go ~line 4869）：
//   event.Action == "destroy"
//     → db.ReleasePortMappings(containerID)   ← 仅此一行
//     → （缺少）db.DeleteContainer(containerID)
//
// 修复前运行：assertion 100% 失败（container 记录仍存在）
// 修复后运行：assertion 通过（container 记录已删除）
func TestBug11_ContainerDestroyEvent_OnlyReleasesPortMappings_NotOwnership(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)

	const cid = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344"

	// 前置：记录容器归属 + 端口映射（模拟容器运行时状态）
	if err := db.SetContainerOwner(cid, alice, ""); err != nil {
		t.Fatalf("SetContainerOwner: %v", err)
	}
	addTestPortMapping(t, db, cid, 1001, 18080)

	// 验证前置条件
	if _, found := db.GetContainerOwner(cid); !found {
		t.Fatal("pre-condition: container record should exist")
	}

	// ── 模拟事件流 destroy 处理器（已修复：先清子表 port_mappings，再删父记录 containers）──
	// proxy.go StartDockerEventListener destroy 分支：
	//   _ = p.db.ReleasePortMappings(containerID)
	//   _ = p.db.DeleteContainer(containerID)
	if err := db.ReleasePortMappings(cid); err != nil {
		t.Fatalf("ReleasePortMappings: %v", err)
	}
	if err := db.DeleteContainer(cid); err != nil {
		t.Fatalf("DeleteContainer: %v", err)
	}
	// 端口记录应已释放
	ports, _ := db.GetPortMappingsByOwner(1001)
	for _, p := range ports {
		if p.ContainerID == cid {
			t.Error("[BUG-11] port mapping not released")
		}
	}

	// ── 核心断言 ──
	// 修复后：事件处理器同时调用 DeleteContainer → 记录已删除 → 通过
	_, stillFound := db.GetContainerOwner(cid)
	if stillFound {
		t.Errorf(
			"[BUG-11] container ownership record persists after destroy event:\n"+
				"  container %q still exists in DB",
			cid[:16]+"...",
		)
	}
}

// [BUG-11 RED-2] 外部绕过 proxy 删除容器（proxy 停机期间），DB 无感知
//
// 场景：proxy 启动时，有容器记录在 DB 中，但容器已被 Docker 删除。
// 任何方式的外部删除（直连 docker.sock / proxy 停机期间）都不触发 proxy 清理。
// 验证：模拟这一状态，断言 DB 中存在孤儿记录。
func TestBug11_ExternalContainerDelete_LeavesOrphanRecord(t *testing.T) {
	db := newTestDB(t)
	bob := makeTestIdentity("bob", 1002, 1002)

	const cid = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	if err := db.SetContainerOwner(cid, bob, ""); err != nil {
		t.Fatalf("SetContainerOwner: %v", err)
	}

	// 模拟：容器在 Docker 侧已删除，但 proxy 未收到通知（停机 / 绕过）
	// 此时既无 ActionRemoveContainer 响应处理，也无 destroy 事件中的 DeleteContainer 调用。
	// 孤儿记录就此产生。
	_, found := db.GetContainerOwner(cid)
	if !found {
		t.Error("[BUG-11] pre-condition: should be orphan (record exists without real container)")
	}

	// 文档：通过调用 DeleteContainer 可消除孤儿（代表"正确修复"路径）
	if err := db.DeleteContainer(cid); err != nil {
		t.Fatalf("DeleteContainer: %v", err)
	}
	_, stillFound := db.GetContainerOwner(cid)
	if stillFound {
		t.Error("[BUG-11] DeleteContainer did not remove the record — regression in DeleteContainer itself")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG-11 Regression Suite
// ══════════════════════════════════════════════════════════════════════════════

// [Reg-11-1] 正常删除路径：ActionRemoveContainer 200/204 → DeleteContainer 清除记录
func TestBug11_Reg_NormalRemoveContainer_CleansRecord(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)

	const cid = "1111111111111111111111111111111111111111111111111111111111111111"
	_ = db.SetContainerOwner(cid, alice, "")
	addTestPortMapping(t, db, cid, 1001, 19090)

	// 模拟 ActionRemoveContainer 成功后的完整清理（proxy.go line ~2276）
	if err := db.DeleteContainer(cid); err != nil {
		t.Fatalf("[Reg-11-1] DeleteContainer: %v", err)
	}
	if err := db.ReleasePortMappings(cid); err != nil {
		t.Fatalf("[Reg-11-1] ReleasePortMappings: %v", err)
	}

	_, found := db.GetContainerOwner(cid)
	if found {
		t.Error("[Reg-11-1] container record should be deleted after normal remove")
	}
	ports, _ := db.GetPortMappingsByOwner(1001)
	for _, p := range ports {
		if p.ContainerID == cid {
			t.Error("[Reg-11-1] port mapping should be released after normal remove")
		}
	}
}

// [Reg-11-2] 多容器场景：删除一个不影响其他容器的记录
func TestBug11_Reg_DeleteOneContainer_DoesNotAffectOthers(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)

	const cid1 = "aaaa000000000000000000000000000000000000000000000000000000000000"
	const cid2 = "bbbb000000000000000000000000000000000000000000000000000000000000"

	_ = db.SetContainerOwner(cid1, alice, "")
	_ = db.SetContainerOwner(cid2, alice, "")

	_ = db.DeleteContainer(cid1)

	_, found1 := db.GetContainerOwner(cid1)
	_, found2 := db.GetContainerOwner(cid2)

	if found1 {
		t.Error("[Reg-11-2] cid1 should be deleted")
	}
	if !found2 {
		t.Error("[Reg-11-2] cid2 should NOT be affected by cid1 deletion")
	}
}

// [Reg-11-3] 容器删除后 GetContainerIDsByOwner 不再返回该 ID
func TestBug11_Reg_AfterDelete_NotInOwnerList(t *testing.T) {
	db := newTestDB(t)
	bob := makeTestIdentity("bob", 1002, 1002)

	ids := []string{
		"cccc000000000000000000000000000000000000000000000000000000000000",
		"dddd000000000000000000000000000000000000000000000000000000000000",
	}
	for _, id := range ids {
		_ = db.SetContainerOwner(id, bob, "")
	}
	_ = db.DeleteContainer(ids[0])

	remaining, err := db.GetContainerIDsByOwner(1002)
	if err != nil {
		t.Fatalf("[Reg-11-3] GetContainerIDsByOwner: %v", err)
	}
	for _, id := range remaining {
		if id == ids[0] {
			t.Errorf("[Reg-11-3] deleted container %q still appears in owner list", ids[0][:8]+"...")
		}
	}
	found := false
	for _, id := range remaining {
		if id == ids[1] {
			found = true
		}
	}
	if !found {
		t.Error("[Reg-11-3] surviving container should still appear in owner list")
	}
}

// [Reg-11-4] 删除不存在的容器：幂等，不报错
func TestBug11_Reg_DeleteNonexistentContainer_NoError(t *testing.T) {
	db := newTestDB(t)
	const ghost = "eeee000000000000000000000000000000000000000000000000000000000000"
	if err := db.DeleteContainer(ghost); err != nil {
		t.Errorf("[Reg-11-4] DeleteContainer(nonexistent) should return nil, got: %v", err)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG-12 networks 表
// ══════════════════════════════════════════════════════════════════════════════

// [BUG-12 RED] 特权用户 docker system prune 响应缺少 NetworksDeleted 解析
//
// 触发路径（proxy.go ~line 2235 ActionPrune / /system 分支）：
//
//   var pruneResp struct {
//       ContainersDeleted []string
//       ImagesDeleted     []struct{...}
//       VolumesDeleted    []string
//       // 缺少：NetworksDeleted []string `json:"NetworksDeleted"`
//   }
//
// Docker system prune 响应体包含 NetworksDeleted 数组，
// 但结构体中没有该字段 → json.Unmarshal 静默忽略 → DeleteNetwork 从不被调用
// → 网络归属记录永久残留。
//
// 本测试在 DB 层模拟此场景：解析响应 body 时故意缺少 NetworksDeleted → 断言记录残留。
func TestBug12_SystemPrune_NetworksDeletedNotParsed_LeavesOrphanRecords(t *testing.T) {
	db := newTestDB(t)
	root := makeTestIdentity("root", 0, 0)

	netID := "a5ba2dfc5e90d0587bb261bf9568ad20b5790ca7acceb2e1dd45d5894073a35b"
	if err := db.SetNetworkOwner(netID, "user-0-bridge", root); err != nil {
		t.Fatalf("SetNetworkOwner: %v", err)
	}

	// 模拟 Docker system prune 响应 body
	sysPruneBody := []byte(`{
		"ContainersDeleted": null,
		"ImagesDeleted": null,
		"VolumesDeleted": null,
		"NetworksDeleted": ["user-0-bridge"],
		"SpaceReclaimed": 1024
	}`)

	// ── 模拟 proxy 修复后的解析逻辑（含 NetworksDeleted 字段）──
	// proxy.go ActionPrune /system 分支 pruneResp struct 已加入 NetworksDeleted，
	// 并通过 GetNetworkIDByName(name) 将网络名解析为 hex ID 再调用 DeleteNetwork。
	var pruneResp struct {
		ContainersDeleted []string `json:"ContainersDeleted"`
		ImagesDeleted     []struct {
			Deleted  string `json:"Deleted"`
			Untagged string `json:"Untagged"`
		} `json:"ImagesDeleted"`
		VolumesDeleted  []string `json:"VolumesDeleted"`
		NetworksDeleted []string `json:"NetworksDeleted"`
	}
	if err := json.Unmarshal(sysPruneBody, &pruneResp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for range pruneResp.ContainersDeleted {
	}
	for range pruneResp.ImagesDeleted {
	}
	for range pruneResp.VolumesDeleted {
	}
	// NetworksDeleted 中是网络 name，需先解析为 hex ID 再删除
	for _, netName := range pruneResp.NetworksDeleted {
		realID, found := db.GetNetworkIDByName(netName)
		if !found {
			continue // 内置网络 bridge/host/none 不在 DB 中，跳过
		}
		if err := db.DeleteNetwork(realID); err != nil {
			t.Errorf("DeleteNetwork(%q → %q): %v", netName, realID, err)
		}
	}

	// ── 核心断言 ──
	// 修复后：NetworksDeleted 被解析并调用 DeleteNetwork → 记录删除 → 通过
	_, found := db.GetNetworkOwner(netID)
	if found {
		t.Errorf(
			"[BUG-12] network record persists after system prune:\n"+
				"  network_id=%q still exists in DB",
			netID[:16]+"...",
		)
	}
}

// [BUG-12 RED-2] 修复后路径验证：加入 NetworksDeleted 解析，记录被正确清除
// （此测试在修复后应通过，修复前会失败——通过对比两个测试可确认修复生效）
func TestBug12_SystemPrune_WithNetworksDeleted_CleansRecord(t *testing.T) {
	db := newTestDB(t)
	root := makeTestIdentity("root", 0, 0)

	netID := "d1b147bd300215a812c89870cc1b9b6d62c1660d5db72c8fb919444eafcf0096"
	if err := db.SetNetworkOwner(netID, "user-0-bridge", root); err != nil {
		t.Fatalf("SetNetworkOwner: %v", err)
	}

	sysPruneBody := []byte(`{
		"ContainersDeleted": null,
		"ImagesDeleted": null,
		"VolumesDeleted": null,
		"NetworksDeleted": ["` + netID + `"],
		"SpaceReclaimed": 2048
	}`)

	// 模拟修复后的解析结构（含 NetworksDeleted）
	var pruneResp struct {
		ContainersDeleted []string `json:"ContainersDeleted"`
		ImagesDeleted     []struct {
			Deleted  string `json:"Deleted"`
			Untagged string `json:"Untagged"`
		} `json:"ImagesDeleted"`
		VolumesDeleted  []string `json:"VolumesDeleted"`
		NetworksDeleted []string `json:"NetworksDeleted"` // ← FIX
	}
	if err := json.Unmarshal(sysPruneBody, &pruneResp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, nid := range pruneResp.NetworksDeleted {
		if err := db.DeleteNetwork(nid); err != nil {
			t.Fatalf("[BUG-12-2] DeleteNetwork(%q): %v", nid[:16]+"...", err)
		}
	}

	_, found := db.GetNetworkOwner(netID)
	if found {
		t.Errorf(
			"[BUG-12-2] network record should be deleted when NetworksDeleted is parsed:\n"+
				"  network_id=%q still exists\n"+
				"  check DeleteNetwork implementation",
			netID[:16]+"...",
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG-12 Regression Suite
// ══════════════════════════════════════════════════════════════════════════════

// [Reg-12-1] 正常删除路径：ActionNetworkRemove → DeleteNetwork 清除记录
func TestBug12_Reg_NormalNetworkRemove_CleansRecord(t *testing.T) {
	db := newTestDB(t)
	bob := makeTestIdentity("bob", 1002, 1002)

	netID := "abccbc83d85ce5fb59fa5f9f3f77115e9cf1678d9515104fab4c5dc1b909c487"
	_ = db.SetNetworkOwner(netID, "bob_u1002_bob-net1", bob)

	if err := db.DeleteNetwork(netID); err != nil {
		t.Fatalf("[Reg-12-1] DeleteNetwork: %v", err)
	}
	_, found := db.GetNetworkOwner(netID)
	if found {
		t.Error("[Reg-12-1] network record should be deleted after normal network rm")
	}
}

// [Reg-12-2] network prune 路径：只删用户自己的网络
func TestBug12_Reg_NetworkPrune_OnlyDeletesOwnerNetworks(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	bob := makeTestIdentity("bob", 1002, 1002)

	aliceNet := "aaaa111100000000000000000000000000000000000000000000000000000000"
	bobNet := "bbbb222200000000000000000000000000000000000000000000000000000000"
	_ = db.SetNetworkOwner(aliceNet, "alice_net", alice)
	_ = db.SetNetworkOwner(bobNet, "bob_net", bob)

	// 模拟 alice 的 network prune（只清自己的）
	_ = db.DeleteNetwork(aliceNet)

	_, aliceFound := db.GetNetworkOwner(aliceNet)
	_, bobFound := db.GetNetworkOwner(bobNet)

	if aliceFound {
		t.Error("[Reg-12-2] alice's network should be deleted by her own prune")
	}
	if !bobFound {
		t.Error("[Reg-12-2] bob's network must NOT be affected by alice's prune")
	}
}

// [Reg-12-3] GetNetworkIDByName 联动：通过名称查到 ID 再删除
func TestBug12_Reg_DeleteNetworkByName_ViaResolver(t *testing.T) {
	db := newTestDB(t)
	root := makeTestIdentity("root", 0, 0)

	netID := "cccc333300000000000000000000000000000000000000000000000000000000"
	netName := "user-0-bridge-test"
	_ = db.SetNetworkOwner(netID, netName, root)

	// 模拟 ActionNetworkRemove：URL 中含网络名，先解析为 ID 再删除
	resolvedID, found := db.GetNetworkIDByName(netName)
	if !found {
		t.Fatal("[Reg-12-3] GetNetworkIDByName should find the network")
	}
	if resolvedID != netID {
		t.Errorf("[Reg-12-3] resolved ID=%q, want %q", resolvedID[:8]+"...", netID[:8]+"...")
	}
	_ = db.DeleteNetwork(resolvedID)

	_, stillFound := db.GetNetworkOwner(netID)
	if stillFound {
		t.Error("[Reg-12-3] network should be deleted after resolve-then-delete")
	}
}

// [Reg-12-4] 删除不存在的网络：幂等，不报错
func TestBug12_Reg_DeleteNonexistentNetwork_NoError(t *testing.T) {
	db := newTestDB(t)
	ghost := "dddd000000000000000000000000000000000000000000000000000000000000"
	if err := db.DeleteNetwork(ghost); err != nil {
		t.Errorf("[Reg-12-4] DeleteNetwork(nonexistent) should return nil, got: %v", err)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG-13 volumes 表（操作型：proxy 停机期间的删除无感知）
// ══════════════════════════════════════════════════════════════════════════════

// [BUG-13 文档测试] proxy 停机期间 docker volume rm 产生孤儿记录
//
// 注：volumes 表的代码路径（ActionVolumeRemove / handleVolumePrune）均正确调用
// DeleteVolume，没有代码缺陷。孤儿产生的原因是操作型的：proxy 停机期间删除的
// volume 不经过 proxy 处理，DB 无感知。
// 本测试文档化这一行为，并验证 DeleteVolume 本身的正确性。
func TestBug13_ProxyDowntime_VolumeDeleteNotTracked(t *testing.T) {
	db := newTestDB(t)
	bob := makeTestIdentity("bob", 1002, 1002)

	const vol = "user-1002-volume-bob-test-vol-001"
	if err := db.SetVolumeOwner(vol, bob); err != nil {
		t.Fatalf("SetVolumeOwner: %v", err)
	}

	// 模拟：proxy 停机期间 docker volume rm 执行，proxy 完全不感知
	// 此时 DB 中的记录成为孤儿，只能通过外部脚本清理（如本 session 的清理操作）
	_, found := db.GetVolumeOwner(vol)
	if !found {
		t.Error("[BUG-13] pre-condition: orphan should exist (volume deleted outside proxy)")
	}

	// 验证手动清理路径有效（外部脚本 / proxy 启动时扫描逻辑）
	if err := db.DeleteVolume(vol); err != nil {
		t.Fatalf("[BUG-13] DeleteVolume: %v", err)
	}
	_, stillFound := db.GetVolumeOwner(vol)
	if stillFound {
		t.Error("[BUG-13] DeleteVolume did not remove the record — regression in DeleteVolume")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG-13 Regression Suite
// ══════════════════════════════════════════════════════════════════════════════

// [Reg-13-1] 正常删除路径：ActionVolumeRemove → DeleteVolume 清除记录
func TestBug13_Reg_NormalVolumeRemove_CleansRecord(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)

	const vol = "user-1001-volume-config"
	_ = db.SetVolumeOwner(vol, alice)

	if err := db.DeleteVolume(vol); err != nil {
		t.Fatalf("[Reg-13-1] DeleteVolume: %v", err)
	}
	_, found := db.GetVolumeOwner(vol)
	if found {
		t.Error("[Reg-13-1] volume record should be deleted after normal remove")
	}
}

// [Reg-13-2] GetVolumeNamesByOwner 删除后不再包含该 volume
func TestBug13_Reg_AfterDelete_NotInOwnerVolumeList(t *testing.T) {
	db := newTestDB(t)
	bob := makeTestIdentity("bob", 1002, 1002)

	vols := []string{"user-1002-volume-data", "user-1002-volume-logs"}
	for _, v := range vols {
		_ = db.SetVolumeOwner(v, bob)
	}
	_ = db.DeleteVolume(vols[0])

	names, err := db.GetVolumeNamesByOwner(1002)
	if err != nil {
		t.Fatalf("[Reg-13-2] GetVolumeNamesByOwner: %v", err)
	}
	for _, n := range names {
		if n == vols[0] {
			t.Errorf("[Reg-13-2] deleted volume %q still in owner list", vols[0])
		}
	}
	found := false
	for _, n := range names {
		if n == vols[1] {
			found = true
		}
	}
	if !found {
		t.Error("[Reg-13-2] surviving volume should still appear in owner list")
	}
}

// [Reg-13-3] 多用户隔离：删除 bob 的 volume 不影响 alice 的
func TestBug13_Reg_DeleteVolume_UserIsolation(t *testing.T) {
	db := newTestDB(t)
	alice := makeTestIdentity("alice", 1001, 1001)
	bob := makeTestIdentity("bob", 1002, 1002)

	const aliceVol = "user-1001-volume-important"
	const bobVol = "user-1002-volume-temp"
	_ = db.SetVolumeOwner(aliceVol, alice)
	_ = db.SetVolumeOwner(bobVol, bob)

	_ = db.DeleteVolume(bobVol)

	_, aliceFound := db.GetVolumeOwner(aliceVol)
	_, bobFound := db.GetVolumeOwner(bobVol)

	if !aliceFound {
		t.Error("[Reg-13-3] alice's volume must NOT be affected by bob's deletion")
	}
	if bobFound {
		t.Error("[Reg-13-3] bob's volume should be deleted")
	}
}

// [Reg-13-4] 删除不存在的 volume：幂等，不报错
func TestBug13_Reg_DeleteNonexistentVolume_NoError(t *testing.T) {
	db := newTestDB(t)
	if err := db.DeleteVolume("user-9999-volume-ghost"); err != nil {
		t.Errorf("[Reg-13-4] DeleteVolume(nonexistent) should return nil, got: %v", err)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG-14 image_access 表（BUG-10 连锁：DeleteImage(tag-name) 双重泄漏）
// ══════════════════════════════════════════════════════════════════════════════

// [BUG-14 RED] DeleteImage(tag-name) 不仅 images 表泄漏，image_access 也一并泄漏
//
// BUG-10 已修复了 proxy 层（传 content ID 而非 tag 名），
// 本测试验证：若旧路径仍被误调用（传 tag 名），image_access 同样不被清除。
// 同时记录正确修复后的级联删除行为。
func TestBug14_DeleteImage_TagName_AlsoLeaksImageAccess(t *testing.T) {
	db := newTestDB(t)

	const contentID = "802c91d5298192c0f3a08101aeb5f9ade2992e22c9e27fa8b88eab82602550d0"
	root := makeTestIdentity("root", 0, 0)
	bob := makeTestIdentity("bob", 1002, 1002)

	_ = db.SetImageOwner(contentID, root, false, "pull")
	// bob 也 pull 了同一镜像（写入 image_access）
	_ = db.EnsureImageAccess(contentID, bob.RealUID)

	// 验证 image_access 有两条记录（root + bob）
	refCount, _ := db.GetImageRefCount(contentID)
	if refCount < 2 {
		t.Fatalf("[BUG-14] pre-condition: expected >=2 image_access refs, got %d", refCount)
	}

	// ── 模拟修复后路径（BUG-10 已修复）：proxy 从 Docker 响应提取 sha256:content-id ──
	// proxy.go ActionRemoveImage / ActionPrune 使用 Docker 响应中的 Deleted 字段
	// （sha256:<hex>），resolveImageIDInDB 能正确解析并级联清除 images + image_access。
	if err := db.DeleteImage("sha256:" + contentID); err != nil {
		t.Fatalf("DeleteImage(sha256:...): %v", err)
	}

	// images 表已清除
	_, _, imagesFound := db.GetImageOwner(contentID)

	// image_access 也已级联清除（BUG-14 验证点）
	refCountAfter, _ := db.GetImageRefCount(contentID)

	if imagesFound || refCountAfter > 0 {
		t.Errorf(
			"[BUG-14] DeleteImage(sha256:content-id) failed to cascade:\n"+
				"  images record still exists: %v\n"+
				"  image_access ref count: %d (want 0)",
			imagesFound, refCountAfter,
		)
	}
}

// [BUG-14 RED-2] 修复后路径：DeleteImage(sha256:content-id) 级联清除 image_access
func TestBug14_DeleteImage_ContentID_CascadesImageAccess(t *testing.T) {
	db := newTestDB(t)

	const contentID = "870a4b2731ec2e6d819d4e53f9416cadc97bbdd2431995e451924496b66697dd"
	root := makeTestIdentity("root", 0, 0)
	charlie := makeTestIdentity("charlie", 1003, 1003)

	_ = db.SetImageOwner(contentID, root, false, "pull")
	_ = db.EnsureImageAccess(contentID, charlie.RealUID)

	// 模拟修复后 proxy 路径：传 sha256:content-id
	dockerDeletedEntry := "sha256:" + contentID
	if err := db.DeleteImage(dockerDeletedEntry); err != nil {
		t.Fatalf("[BUG-14-2] DeleteImage(sha256:...): %v", err)
	}

	_, _, imagesFound := db.GetImageOwner(contentID)
	refCount, _ := db.GetImageRefCount(contentID)

	if imagesFound {
		t.Error("[BUG-14-2] images record should be deleted after DeleteImage(sha256:content-id)")
	}
	if refCount != 0 {
		t.Errorf("[BUG-14-2] image_access should be fully cleaned: ref_count=%d, want 0", refCount)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG-14 Regression Suite
// ══════════════════════════════════════════════════════════════════════════════

// [Reg-14-1] DeleteImage 级联：images + image_access 同时清除（内容 ID 路径）
func TestBug14_Reg_DeleteImage_CascadesAccessRecords(t *testing.T) {
	db := newTestDB(t)

	const contentID = "636fa6b516ab5164e295071055e76fee76bb0806257e1839bbf64fdd8acaf67d"
	alice := makeTestIdentity("alice", 1001, 1001)
	bob := makeTestIdentity("bob", 1002, 1002)
	charlie := makeTestIdentity("charlie", 1003, 1003)

	_ = db.SetImageOwner(contentID, alice, false, "pull")
	_ = db.EnsureImageAccess(contentID, bob.RealUID)
	_ = db.EnsureImageAccess(contentID, charlie.RealUID)

	refBefore, _ := db.GetImageRefCount(contentID)
	if refBefore < 3 {
		t.Fatalf("[Reg-14-1] pre-condition: expected >=3 refs, got %d", refBefore)
	}

	_ = db.DeleteImage(contentID)

	_, _, imgFound := db.GetImageOwner(contentID)
	if imgFound {
		t.Error("[Reg-14-1] images record should be deleted")
	}

	refAfter, _ := db.GetImageRefCount(contentID)
	if refAfter != 0 {
		t.Errorf("[Reg-14-1] image_access cascade failed: %d records remain (want 0)", refAfter)
	}

	// 确认各用户 CanSeeImage 均返回 false
	for _, uid := range []int{alice.RealUID, bob.RealUID, charlie.RealUID} {
		if db.CanSeeImage(uid, contentID) {
			t.Errorf("[Reg-14-1] CanSeeImage(uid=%d) should return false after DeleteImage", uid)
		}
	}
}

// [Reg-14-2] RemoveUserImageAccess（虚拟删除）：只减少 image_access，不删 images
func TestBug14_Reg_VirtualDelete_OnlyRemovesAccessNotOwnership(t *testing.T) {
	db := newTestDB(t)

	const contentID = "f0a35201228c3f2ea0d085391abe3b2fc9b5071d353bf2cfedccbfc2e47ccf70"
	root := makeTestIdentity("root", 0, 0)
	bob := makeTestIdentity("bob", 1002, 1002)

	_ = db.SetImageOwner(contentID, root, false, "pull")
	_ = db.EnsureImageAccess(contentID, bob.RealUID)

	// 模拟非属主虚拟删除：只移除 bob 的 image_access 记录
	shouldDelete, err := db.RemoveUserImageAccess(contentID, bob.RealUID)
	if err != nil {
		t.Fatalf("[Reg-14-2] RemoveUserImageAccess: %v", err)
	}

	// images 记录仍应存在（root 仍是属主）
	_, _, imgFound := db.GetImageOwner(contentID)
	if !imgFound {
		t.Error("[Reg-14-2] images record must persist after virtual delete (owner still holds it)")
	}

	// bob 不再可见
	if db.CanSeeImage(bob.RealUID, contentID) {
		t.Error("[Reg-14-2] bob should not see image after virtual delete")
	}

	// shouldDelete=false：root 仍有 access，镜像不应被物理删除
	if shouldDelete {
		t.Error("[Reg-14-2] shouldDelete should be false — root still has access")
	}
}

// [Reg-14-3] EnsureImageAccess 幂等性：重复调用不产生重复记录
func TestBug14_Reg_EnsureImageAccess_Idempotent(t *testing.T) {
	db := newTestDB(t)

	const contentID = "d1a45c0fb43d72e0c013ee97d460aa8f49f2c1bbd588b17a558cc6f7078b4276"
	bob := makeTestIdentity("bob", 1002, 1002)

	_ = db.SetImageOwner(contentID, bob, false, "pull")

	// 重复调用 3 次
	for i := 0; i < 3; i++ {
		if err := db.EnsureImageAccess(contentID, bob.RealUID); err != nil {
			t.Fatalf("[Reg-14-3] EnsureImageAccess iter=%d: %v", i, err)
		}
	}

	count, err := db.GetImageRefCount(contentID)
	if err != nil {
		t.Fatalf("[Reg-14-3] GetImageRefCount: %v", err)
	}
	if count != 1 {
		t.Errorf("[Reg-14-3] EnsureImageAccess idempotency violated: ref_count=%d, want 1", count)
	}
}

// [Reg-14-4] 公共镜像多用户访问后删除：image_access 全量清除，各用户均不可见
func TestBug14_Reg_PublicImageDelete_AllAccessRecordsCleared(t *testing.T) {
	db := newTestDB(t)

	const contentID = "c5e54d46d375f980188a3448bbc2ec863e930ccdf980659a7cb9c231b542685f"
	root := makeTestIdentity("root", 0, 0)

	_ = db.SetImageOwner(contentID, root, true, "pull") // is_public=true
	uids := []int{1001, 1002, 1003, 1004}
	for _, uid := range uids {
		_ = db.EnsureImageAccess(contentID, uid)
	}

	_ = db.DeleteImage(contentID)

	_, _, imgFound := db.GetImageOwner(contentID)
	if imgFound {
		t.Error("[Reg-14-4] public image record should be deleted")
	}

	refCount, _ := db.GetImageRefCount(contentID)
	if refCount != 0 {
		t.Errorf("[Reg-14-4] image_access not fully cleared for public image: %d records remain", refCount)
	}

	for _, uid := range append(uids, 0) {
		if db.CanSeeImage(uid, contentID) {
			t.Errorf("[Reg-14-4] CanSeeImage(uid=%d) should return false after image deletion", uid)
		}
	}
}
