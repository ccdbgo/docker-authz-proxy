package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-33b：sudo docker rmi 删除未追踪镜像时 sha256 格式事件泄漏给其他用户
//
// ──── Bug 场景 ─────────────────────────────────────────────────────────────
//
//   sudo_test(uid=1005) 执行 sudo docker rmi c6348fa86ba0（镜像未在 DB 中追踪）
//   bob(uid=1002) 执行 docker system events
//
//   期望：bob 不应收到 sudo_test 的 image untag / image delete 事件
//   实际（修复前）：bob 收到了：
//     image untag sha256:c6348fa86ba0...
//     image delete sha256:c6348fa86ba0...
//
// ──── 根本原因 ─────────────────────────────────────────────────────────────
//
//   时序竞态：Docker daemon 在执行 DELETE /images 期间先广播事件（约早 7ms），
//   再返回 HTTP 响应。postprocessResponse ActionRemoveImage case 在收到 HTTP
//   响应后才写入 completedPruneOwner。对于未追踪镜像（imgFound=false），
//   事件到达 eventBelongsToUser 时 completedPruneOwner 尚未写入，路径3 miss，
//   return true 透传泄漏。
//
//   注：已追踪镜像（imgFound=true）由 BUG-32/33 覆盖（postprocessResponse 写入
//   足够早，因为 DB 查询可命中），此处仅针对 imgFound=false 的边界情况。
//
// ──── 修复方案 ─────────────────────────────────────────────────────────────
//
//   在 forward() 之前（pre-forward 块，约 line 800）为未追踪特权镜像预注册
//   completedPruneOwner，覆盖从 DELETE 请求发出到 HTTP 响应返回之间的窗口。
//   与 BUG-19（pull）、BUG-29（volume create）、BUG-29b（network create）模式对称。
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	rmiRaceUID     = 1005 // sudo_test Real UID
	rmiRaceBobUID  = 1002 // bob Real UID
)

var (
	// 未追踪镜像（DB 中无记录，如通过 docker load / 系统预装的镜像）
	rmiRaceUntrackedImageID = "sha256:c6348fa86ba04e8d63a40daa3b44b5e434ae34cd7893fccd4f45b51afaa4c69a"
)

// makeRmiDeleteEvent 构造 image delete 事件（Actor.ID = sha256:...，name 也是 sha256:...）
func makeRmiDeleteEvent(imageID string) []byte {
	return []byte(fmt.Sprintf(
		`{"Type":"image","Action":"delete","Actor":{"ID":%q,"Attributes":{"name":%q}}}`,
		imageID, imageID,
	))
}

// makeRmiUntagEvent 构造 image untag 事件
func makeRmiUntagEvent(imageID, name string) []byte {
	return []byte(fmt.Sprintf(
		`{"Type":"image","Action":"untag","Actor":{"ID":%q,"Attributes":{"name":%q}}}`,
		imageID, name,
	))
}

// ══════════════════════════════════════════════════════════════════════════════
// RED TEST：Bug 复现
// ══════════════════════════════════════════════════════════════════════════════

// TestBug33b_UntrackedRmi_DeleteEvent_LeaksToOtherUsers
//
// 直接单元测试 eventBelongsToUser：验证 completedPruneOwner 预注册后
// bob 不再收到 sudo_test 删除未追踪镜像的 image delete 事件。
func TestBug33b_UntrackedRmi_DeleteEvent_LeaksToOtherUsers(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// 模拟 pre-forward 预注册：DB 无记录但特权用户发起 rmi
	// （proxy.go pre-forward 块在 forward() 前写入此条目）
	rmiEntry := pruneOwnerInfo{ownerUID: rmiRaceUID, privCtx: 1} // sudo context
	rmiKey := "image:" + rmiRaceUntrackedImageID
	p.completedPruneOwner.Store(rmiKey, rmiEntry)

	// image delete 事件不应泄漏给 bob
	deleteEvent := makeRmiDeleteEvent(rmiRaceUntrackedImageID)
	if p.eventBelongsToUser(deleteEvent, rmiRaceBobUID, false) {
		t.Errorf(
			"BUG-33b [image delete 泄漏]:\n"+
				"\tbob(uid=%d) 收到了 sudo_test(uid=%d) 的 image delete 事件\n"+
				"\t镜像 ID: %q\n"+
				"\t根因: 未追踪镜像 completedPruneOwner 未预注册 → return true（泄漏）\n"+
				"\t修复: forward() 前预注册 completedPruneOwner",
			rmiRaceBobUID, rmiRaceUID, rmiRaceUntrackedImageID,
		)
	}

	// image untag 事件不应泄漏给 bob（name = sha256 格式）
	untagEvent := makeRmiUntagEvent(rmiRaceUntrackedImageID, rmiRaceUntrackedImageID)
	if p.eventBelongsToUser(untagEvent, rmiRaceBobUID, false) {
		t.Errorf(
			"BUG-33b [image untag(sha256) 泄漏]:\n"+
				"\tbob(uid=%d) 收到了 sudo_test(uid=%d) 的 image untag(sha256) 事件\n"+
				"\t镜像 ID: %q",
			rmiRaceBobUID, rmiRaceUID, rmiRaceUntrackedImageID,
		)
	}

	// 正向：sudo_test 自己在 sudo 模式下能看到自己的 delete 事件
	if !p.eventBelongsToUser(deleteEvent, rmiRaceUID, true) {
		t.Errorf(
			"回归: sudo_test(uid=%d) 不应被过滤掉自己的 image delete 事件（sudo 模式）\n"+
				"\t镜像 ID: %q",
			rmiRaceUID, rmiRaceUntrackedImageID,
		)
	}

	// privCtx=1 隔离：sudo_test 以非 sudo 模式监听时，也不应看到自己 sudo 删除的镜像事件
	if p.eventBelongsToUser(deleteEvent, rmiRaceUID, false) {
		t.Errorf(
			"回归: sudo_test(uid=%d) 在非 sudo 模式下不应看到 privCtx=1 的 image delete 事件\n"+
				"\t镜像 ID: %q",
			rmiRaceUID, rmiRaceUntrackedImageID,
		)
	}
}

// TestBug33b_Reg1_NoEntry_Passthrough
//
// 回归-1：completedPruneOwner 无条目时（非特权用户删除、或 30s 已过期），
// 未追踪镜像事件对所有用户透传（基础镜像/中间层不应被隐藏）。
func TestBug33b_Reg1_NoEntry_Passthrough(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	// completedPruneOwner 为空（无预注册）

	unknownID := "sha256:deadbeef11223344556677889900aabbccddeeff1122334455667788990011ab"
	event := makeRmiDeleteEvent(unknownID)

	for _, uid := range []int{rmiRaceBobUID, rmiRaceUID, 1001} {
		if !p.eventBelongsToUser(event, uid, false) {
			t.Errorf(
				"回归-1: completedPruneOwner 无条目时事件应对 uid=%d 透传\n"+
					"\t镜像 ID: %q\n"+
					"\t未追踪的基础镜像/中间层不应被误过滤",
				uid, unknownID,
			)
		}
	}
}

// TestBug33b_Reg2_TrackedImage_UsesDB
//
// 回归-2：已追踪镜像（DB 中有记录）走 DB 路径，与 BUG-32/33 行为一致，
// 不受 completedPruneOwner 预注册影响。
func TestBug33b_Reg2_TrackedImage_UsesDB(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	trackedID := "sha256:aabb1122334455667788990011223344556677889900112233445566778899ccdd"
	sudoID := regularIdentity("sudo_test", rmiRaceUID)
	if err := p.db.SetImageOwner(trackedID, sudoID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	event := makeRmiDeleteEvent(trackedID)

	// bob 不应收到 sudo_test 的已追踪镜像事件
	if p.eventBelongsToUser(event, rmiRaceBobUID, false) {
		t.Errorf(
			"回归-2: 已追踪镜像事件不应泄漏给 bob(uid=%d)\n"+
				"\t镜像 ID: %q",
			rmiRaceBobUID, trackedID,
		)
	}

	// sudo_test 自己能看到
	if !p.eventBelongsToUser(event, rmiRaceUID, false) {
		t.Errorf(
			"回归-2: sudo_test(uid=%d) 不应被过滤掉自己的已追踪镜像事件\n"+
				"\t镜像 ID: %q",
			rmiRaceUID, trackedID,
		)
	}
}

// TestBug33b_Reg3_Integration_HTTP
//
// 回归-3：HTTP 集成测试（通过 proxy ServeHTTP），验证完整事件流过滤：
// fake Docker 返回混合事件流（sudo_test 未追踪 + bob 已追踪），bob 只收到自己的事件。
func TestBug33b_Reg3_Integration_HTTP(t *testing.T) {
	bobTrackedID := "sha256:bbbb1122334455667788990011223344556677889900112233445566778899ccdd"

	events := []string{
		// sudo_test 删除未追踪镜像的事件（sha256 格式，无 tag name）
		fmt.Sprintf(`{"Type":"image","Action":"delete","Actor":{"ID":%q,"Attributes":{"name":%q}}}`,
			rmiRaceUntrackedImageID, rmiRaceUntrackedImageID),
		fmt.Sprintf(`{"Type":"image","Action":"untag","Actor":{"ID":%q,"Attributes":{"name":%q}}}`,
			rmiRaceUntrackedImageID, rmiRaceUntrackedImageID),
		// bob 自己追踪镜像的事件
		fmt.Sprintf(`{"Type":"image","Action":"delete","Actor":{"ID":%q,"Attributes":{"name":%q}}}`,
			bobTrackedID, bobTrackedID),
	}
	upstream := fakeDockerEventsServer(events)
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 预置：bob 的已追踪镜像
	bobID := regularIdentity("bob", rmiRaceBobUID)
	if err := p.db.SetImageOwner(bobTrackedID, bobID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner(bob): %v", err)
	}

	// 模拟 pre-forward 预注册（proxy ActionRemoveImage pre-forward 块效果）
	rmiEntry := pruneOwnerInfo{ownerUID: rmiRaceUID, privCtx: 1}
	p.completedPruneOwner.Store("image:"+rmiRaceUntrackedImageID, rmiEntry)

	// bob 订阅 image 事件
	req := httptest.NewRequest("GET", "/events?type=image", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", rmiRaceBobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)
	body := rw.Body.String()

	// sudo_test 未追踪镜像事件不应到达 bob
	if strings.Contains(body, rmiRaceUntrackedImageID) {
		t.Errorf(
			"回归-3 [HTTP集成]: bob(uid=%d) 收到了 sudo_test(uid=%d) 的未追踪镜像事件\n"+
				"\t镜像 ID: %q\n"+
				"\t响应体: %s",
			rmiRaceBobUID, rmiRaceUID, rmiRaceUntrackedImageID, body,
		)
	}

	// bob 自己的镜像事件必须到达
	if !strings.Contains(body, bobTrackedID) {
		t.Errorf(
			"回归-3: bob(uid=%d) 应收到自己的已追踪镜像事件\n"+
				"\t镜像 ID: %q\n"+
				"\t响应体: %s",
			rmiRaceBobUID, bobTrackedID, body,
		)
	}
}
