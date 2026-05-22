// shared_network_filter_test.go
//
// 针对 [BUG-5] 共享网络 net_base 可见性的单元测试。
//
// FilterNetworkListResponse 通过 network_access 表的 ID 匹配支持共享网络，
// 这部分逻辑目前是正确的，测试用于确认此行为并防止后续回归。
//
// Bug 的实际根因在 RewriteNetworkURL（见 shared_network_access_test.go），
// 此文件专注于 List 过滤层的回归覆盖。

package isolation

import (
	"encoding/json"
	"strings"
	"testing"
)

// ── 共享网络场景：FilterNetworkListResponse ──────────────────────────────────

// [BUG-5 单元] Red Test：共享网络 net_base 应出现在 bob 的网络列表中
//
// 根本原因背景：
//   FilterNetworkListResponse 通过 DB 的 network_access 表匹配 ID。
//   若该部分正确（bob 能看到 net_base），则证明 List 层无 bug。
//   真正的 bug 在 RewriteNetworkURL，导致 Inspect/Connect 失败。
//
// 此测试验证 FilterNetworkListResponse 对共享网络的可见性已正确实现。
// 若此测试失败，说明 List 过滤层也有问题需要同步修复。
func TestSharedNetwork_FilterNetworkList_BobSeesSharedNetBase(t *testing.T) {
	db := newFilterTestDB(t)

	const sharedNetID = "ccdd112233445566aabb000000000000000000000000000000000000000000ff"
	rootID := makeFilterIdentity("root", 0, 0)
	if err := db.SetNetworkOwner(sharedNetID, "net_base", rootID); err != nil {
		t.Fatalf("SetNetworkOwner: %v", err)
	}
	// 授权 bob 访问
	if err := db.SetNetworkShared(sharedNetID, []int{1002}); err != nil {
		t.Fatalf("SetNetworkShared: %v", err)
	}

	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": sharedNetID, "Name": "net_base"},
	})

	filtered, err := FilterNetworkListResponse(body, 1002 /*bobUID*/, false, db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	_ = json.Unmarshal(filtered, &result)

	if len(result) != 1 {
		t.Errorf("[BUG-5 过滤层] bob 应看到共享网络 net_base，got %d 个网络（want 1）\n"+
			"若此测试失败，FilterNetworkListResponse 的 network_access 匹配逻辑有问题", len(result))
	}
	if len(result) == 1 {
		name, _ := result[0]["Name"].(string)
		if name != "net_base" {
			t.Errorf("[BUG-5 过滤层] 共享网络名称 = %q, want \"net_base\"", name)
		}
	}
}

// [回归-A] 共享网络 net_base 对 bob 可见，但 alice 的私有网络不可见
func TestSharedNetwork_FilterNetworkList_BobSeesSharedOnly(t *testing.T) {
	db := newFilterTestDB(t)

	const sharedNetID = "ccdd112233445566aabb000000000000000000000000000000000000000011"
	const alicePrivNetID = "aaaa000000000000000000000000000000000000000000000000000000000001"

	rootID := makeFilterIdentity("root", 0, 0)
	aliceID := makeFilterIdentity("alice", 1001, 1001)

	_ = db.SetNetworkOwner(sharedNetID, "net_base", rootID)
	_ = db.SetNetworkShared(sharedNetID, []int{1002}) // bob 可访问
	_ = db.SetNetworkOwner(alicePrivNetID, "alice_u1001_private", aliceID)
	// alice 私有网络：不调用 SetNetworkShared，bob 不在授权列表

	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": sharedNetID, "Name": "net_base"},
		{"Id": alicePrivNetID, "Name": "alice_u1001_private"},
	})

	filtered, err := FilterNetworkListResponse(body, 1002 /*bobUID*/, false, db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	_ = json.Unmarshal(filtered, &result)

	if len(result) != 1 {
		t.Errorf("[回归-A] bob 应只看到 net_base（1 个），got %d 个", len(result))
	}
	for _, net := range result {
		name, _ := net["Name"].(string)
		if strings.Contains(name, "alice") {
			t.Errorf("[回归-A] bob 看到了 alice 的私有网络 %q，应被过滤掉", name)
		}
	}
}

// [回归-B] 共享网络对多个用户可见，各自不可见对方私有网络
func TestSharedNetwork_FilterNetworkList_MultipleUsersShareSameNetwork(t *testing.T) {
	db := newFilterTestDB(t)

	const sharedNetID = "ccdd112233445566aabb000000000000000000000000000000000000000022"
	rootID := makeFilterIdentity("root", 0, 0)
	_ = db.SetNetworkOwner(sharedNetID, "net_base", rootID)
	_ = db.SetNetworkShared(sharedNetID, []int{1001, 1002}) // alice 和 bob 都可访问

	bobPrivNetID := "bbbb000000000000000000000000000000000000000000000000000000000001"
	bobID := makeFilterIdentity("bob", 1002, 1002)
	_ = db.SetNetworkOwner(bobPrivNetID, "bob_u1002_mynet", bobID)

	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": sharedNetID, "Name": "net_base"},
		{"Id": bobPrivNetID, "Name": "bob_u1002_mynet"},
	})

	// alice 只能看到 net_base（不能看到 bob 的私有网络）
	filteredAlice, _ := FilterNetworkListResponse(body, 1001, false, db)
	var aliceNets []map[string]interface{}
	_ = json.Unmarshal(filteredAlice, &aliceNets)
	if len(aliceNets) != 1 {
		t.Errorf("[回归-B] alice 应看到 1 个网络（net_base），got %d", len(aliceNets))
	}

	// bob 能看到 net_base 和自己的 mynet（共 2 个）
	filteredBob, _ := FilterNetworkListResponse(body, 1002, false, db)
	var bobNets []map[string]interface{}
	_ = json.Unmarshal(filteredBob, &bobNets)
	if len(bobNets) != 2 {
		t.Errorf("[回归-B] bob 应看到 2 个网络（net_base + mynet），got %d", len(bobNets))
	}
}

// [回归-C] root 特权用户看到所有网络（包括共享和私有）
func TestSharedNetwork_FilterNetworkList_RootSeesAllIncludingShared(t *testing.T) {
	db := newFilterTestDB(t)

	const sharedNetID = "ccdd112233445566aabb000000000000000000000000000000000000000033"
	const alicePrivNetID = "aaaa000000000000000000000000000000000000000000000000000000000002"

	rootID := makeFilterIdentity("root", 0, 0)
	aliceID := makeFilterIdentity("alice", 1001, 1001)
	_ = db.SetNetworkOwner(sharedNetID, "net_base", rootID)
	_ = db.SetNetworkShared(sharedNetID, []int{1002})
	_ = db.SetNetworkOwner(alicePrivNetID, "alice_u1001_mynet", aliceID)

	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": sharedNetID, "Name": "net_base"},
		{"Id": alicePrivNetID, "Name": "alice_u1001_mynet"},
	})

	// privileged=true → root 看到全部
	filtered, err := FilterNetworkListResponse(body, 0, true, db)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	_ = json.Unmarshal(filtered, &result)
	if len(result) != 2 {
		t.Errorf("[回归-C] root 应看到所有 2 个网络，got %d", len(result))
	}
}

// [回归-D] 共享网络被 SetNetworkShared 授权后可访问，撤销授权（DeleteNetwork）后不可访问
func TestSharedNetwork_FilterNetworkList_AfterRevoke_BobCannotSeeIt(t *testing.T) {
	db := newFilterTestDB(t)

	const sharedNetID = "ccdd112233445566aabb000000000000000000000000000000000000000044"
	rootID := makeFilterIdentity("root", 0, 0)
	_ = db.SetNetworkOwner(sharedNetID, "net_base", rootID)
	_ = db.SetNetworkShared(sharedNetID, []int{1002}) // 初始授权

	body := mustMarshalFilter(t, []map[string]interface{}{
		{"Id": sharedNetID, "Name": "net_base"},
	})

	// 授权后 bob 可见
	before, _ := FilterNetworkListResponse(body, 1002, false, db)
	var beforeNets []map[string]interface{}
	_ = json.Unmarshal(before, &beforeNets)
	if len(beforeNets) != 1 {
		t.Errorf("[回归-D] 授权后 bob 应看到 net_base，got %d", len(beforeNets))
	}

	// 删除网络归属记录（模拟网络被销毁或权限撤销）
	if err := db.DeleteNetwork(sharedNetID); err != nil {
		t.Fatalf("DeleteNetwork: %v", err)
	}

	// 撤销后 bob 不可见
	after, _ := FilterNetworkListResponse(body, 1002, false, db)
	var afterNets []map[string]interface{}
	_ = json.Unmarshal(after, &afterNets)
	if len(afterNets) != 0 {
		t.Errorf("[回归-D] 撤销授权后 bob 不应看到 net_base，got %d", len(afterNets))
	}
}

// [回归-E] 空网络列表 → 返回空数组，不报错
func TestSharedNetwork_FilterNetworkList_EmptyList_ReturnsEmpty(t *testing.T) {
	db := newFilterTestDB(t)
	_ = db.SetNetworkShared("nonexistent", []int{1002})

	body := mustMarshalFilter(t, []map[string]interface{}{})
	filtered, err := FilterNetworkListResponse(body, 1002, false, db)
	if err != nil {
		t.Fatalf("[回归-E] 空列表不应报错：%v", err)
	}
	var result []map[string]interface{}
	_ = json.Unmarshal(filtered, &result)
	if len(result) != 0 {
		t.Errorf("[回归-E] 空列表过滤结果应为空，got %d", len(result))
	}
}

// mustMarshalFilter 和 newFilterTestDB 已在同包的 filter_test.go 中定义，此处直接复用。
