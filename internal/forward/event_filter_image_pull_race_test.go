package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-19：image pull 事件竞态泄漏
//
// ──── 复现场景 ──────────────────────────────────────────────────────────────
//
//   alice(uid=1001) 执行 docker run --rm busybox echo hello
//   → 触发 POST /images/create?fromImage=busybox&tag=latest
//   bob(uid=1002)  执行 docker system events
//
//   期望：bob 不应收到 alice 的 image pull 事件
//   实际：bob 收到：
//     2026-05-25T13:36:21... image pull busybox:latest (name=busybox)
//
// ──── 根因 ─────────────────────────────────────────────────────────────────
//
//   ActionPull case 中，SetImageOwner 在 streamAndCaptureImageID 读完全部
//   响应流之后才执行。Docker 在 pull 完成瞬间就发出 image pull 事件，该事件
//   到达 bob 的 eventBelongsToUser 时 DB 为空：
//     GetImageOwner("sha256:...") → found=false → 路径3 return true → 泄漏
//
//   与 BUG-18 的区别：
//     BUG-18 是 build tag 事件（image tag），BUG-19 是 pull 事件（image pull）。
//     pendingBuildTags 只检查 build tag，不覆盖 pull 场景。
//
// ──── 修复 ─────────────────────────────────────────────────────────────────
//
//   ProxyServer 增加 pendingPullRefs sync.Map（imageRef → ownerUID）：
//     ActionPull case 开头（响应头到达，早于 pull 完成和事件发出）：
//       if imageRef != "" { Store(imageRef, uid); defer CompareAndDelete }
//     eventBelongsToUser image 分支路径 0b（紧接路径 0a 之后）：
//       若 name 非 sha256 前缀 → 查 pendingPullRefs → 按 uid 过滤
//
//   imageRef 由 parseImageRefFromURI 从请求 URI 中提取：
//     ?fromImage=busybox&tag=latest → "busybox"（省略 :latest，与事件 name 一致）
//     ?fromImage=nginx&tag=1.25.3  → "nginx:1.25.3"（保留非 latest tag）
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// pullRaceImageRef 是 alice pull 的镜像引用，与以下两者保持一致：
//   - parseImageRefFromURI("/images/create?fromImage=busybox&tag=latest") 返回值
//   - Docker image pull 事件中 Attributes["name"] 的值
const pullRaceImageRef = "busybox"

// pullRaceImageID 是 busybox 的 sha256 content ID（任意有效格式即可）。
const pullRaceImageID = "sha256:3fbc632167424a6d997e74f52b878d7cc478225cffac6bc977eedfe51c7f4e79"

// pullRaceAliceUID / pullRaceBobUID 用于本套件，与其他文件区分。
const (
	pullRaceAliceUID = 1001
	pullRaceBobUID   = 1002
)

// makeRawImagePullEvent 构造 image pull 事件字符串（用于 fakeDockerEventsServer）。
func makeRawImagePullEvent(imageID, name string) string {
	return makeRawImageEvent("pull", imageID, name)
}

// ══════════════════════════════════════════════════════════════════════════════
// RED TEST：竞态复现（DB 为空时 image pull 事件泄漏）
// ══════════════════════════════════════════════════════════════════════════════

// TestBug19_ImagePullRace_PullEventLeaksWhenDBEmpty
//
// RED TEST：修复前必须 100% 失败。
//
// 精确复现竞态窗口：
//   DB 为空（SetImageOwner 尚未被调用），
//   pendingPullRefs 已注册（模拟 ActionPull 开头的 Store），
//   Docker 已发出 "image pull sha256:3fbc... name=busybox"，
//   bob 不应收到该事件。
//
// 失败路径（修复前）：
//   ev.Type=="image" → pendingBuildTags miss → GetImageOwner("sha256:...") → found=false
//   → 路径3 return true → bob 收到 alice 的 pull 事件
//
// 通过路径（修复后）：
//   路径0b：pendingPullRefs["busybox"] = 1001
//           ownerUID(1001) ≠ bob(1002) → return false
func TestBug19_ImagePullRace_PullEventLeaksWhenDBEmpty(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	// 模拟 ActionPull case 开头已注册（响应头到达时）
	p.pendingPullRefs.Store(pullRaceImageRef, pullRaceAliceUID)
	defer p.pendingPullRefs.CompareAndDelete(pullRaceImageRef, pullRaceAliceUID)
	// DB 完全为空——模拟竞态窗口：SetImageOwner 尚未执行

	pullEvent := makeImageEvent("pull", pullRaceImageID, pullRaceImageRef)

	// ── RED ASSERTION A：image pull 事件不应泄漏给 bob ──────────────────
	if p.eventBelongsToUser(pullEvent, pullRaceBobUID, false) {
		t.Errorf(
			"BUG-19 [image pull 竞态泄漏]:\n"+
				"\tbob(uid=%d) 收到了 alice(uid=%d) 的 image pull 事件\n"+
				"\tDB 为空（竞态窗口），pendingPullRefs 已注册但未生效\n"+
				"\tAction=%q  imageID=%q  name=%q\n"+
				"\t根因：路径0b（pendingPullRefs）未实现，pull 事件走路径3放行",
			pullRaceBobUID, pullRaceAliceUID, "pull", pullRaceImageID, pullRaceImageRef,
		)
	}

	// ── RED ASSERTION B：charlie 同样不应收到 ────────────────────────────
	if p.eventBelongsToUser(pullEvent, 1003, false) {
		t.Errorf(
			"BUG-19 [竞态泄漏]: charlie(uid=1003) 收到了 alice 的 image pull 事件\n"+
				"\t隔离失效对任意非拉取者均成立",
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归矩阵
// ══════════════════════════════════════════════════════════════════════════════

// TestBug19_Reg1_Puller_ReceivesOwnPullEvent
//
// 回归-1：pendingPullRefs 已注册时，拉取者（alice）应能看到自己的 image pull 事件。
func TestBug19_Reg1_Puller_ReceivesOwnPullEvent(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.pendingPullRefs.Store(pullRaceImageRef, pullRaceAliceUID)
	defer p.pendingPullRefs.CompareAndDelete(pullRaceImageRef, pullRaceAliceUID)

	pullEvent := makeImageEvent("pull", pullRaceImageID, pullRaceImageRef)

	if !p.eventBelongsToUser(pullEvent, pullRaceAliceUID, false) {
		t.Errorf(
			"回归-1: alice(uid=%d) 应能看到自己的 image pull 事件\n"+
				"\tpendingPullRefs[%q]=%d → uid 匹配 → return true",
			pullRaceAliceUID, pullRaceImageRef, pullRaceAliceUID,
		)
	}
}

// TestBug19_Reg2_AfterPullComplete_DBFiltersCorrectly
//
// 回归-2：pull 完成后 SetImageOwner 已调用（DB 有记录，pending map 已清理），
// 后续同一 image pull 事件仍通过 DB 路径正确过滤（BUG-16 路径不受影响）。
func TestBug19_Reg2_AfterPullComplete_DBFiltersCorrectly(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	// 模拟 pull 完成后：pending map 已清理，DB 已更新
	aliceID := regularIdentity("alice", pullRaceAliceUID)
	if err := p.db.SetImageOwner(pullRaceImageID, aliceID, false, "pull"); err != nil {
		t.Fatalf("SetImageOwner: %v", err)
	}

	pullEvent := makeImageEvent("pull", pullRaceImageID, pullRaceImageRef)

	if p.eventBelongsToUser(pullEvent, pullRaceBobUID, false) {
		t.Errorf(
			"回归-2: bob(uid=%d) 不应收到 DB 已注册的 alice(uid=%d) image pull 事件\n"+
				"\tBUG-16 的 DB 过滤路径应继续正确工作",
			pullRaceBobUID, pullRaceAliceUID,
		)
	}
	if !p.eventBelongsToUser(pullEvent, pullRaceAliceUID, false) {
		t.Errorf(
			"回归-2: alice(uid=%d) 应收到自己的 image pull 事件（DB 路径）",
			pullRaceAliceUID,
		)
	}
}

// TestBug19_Reg3_NonLatestTag_MatchesCorrectly
//
// 回归-3：非 latest tag（如 nginx:1.25.3）时，
// parseImageRefFromURI 返回 "nginx:1.25.3"，Docker 事件 name 也为 "nginx:1.25.3"。
// 两者匹配，pendingPullRefs 路径0b 应正确过滤。
func TestBug19_Reg3_NonLatestTag_MatchesCorrectly(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	nginxRef := "nginx:1.25.3"
	nginxID := "sha256:aabbcc001122334455667788990011223344556677889900aabbccddeeff0011"

	p.pendingPullRefs.Store(nginxRef, pullRaceAliceUID)
	defer p.pendingPullRefs.CompareAndDelete(nginxRef, pullRaceAliceUID)

	event := makeImageEvent("pull", nginxID, nginxRef)

	if p.eventBelongsToUser(event, pullRaceBobUID, false) {
		t.Errorf(
			"回归-3 [非 latest tag]: bob(uid=%d) 收到了 alice 的 nginx:1.25.3 pull 事件\n"+
				"\tpendingPullRefs[%q] 应保护该事件",
			pullRaceBobUID, nginxRef,
		)
	}
	if !p.eventBelongsToUser(event, pullRaceAliceUID, false) {
		t.Errorf(
			"回归-3: alice(uid=%d) 应能看到自己的 nginx:1.25.3 pull 事件",
			pullRaceAliceUID,
		)
	}
}

// TestBug19_Reg4_Sha256ImageCreate_StillPassthrough
//
// 回归-4：image create 事件（name 为 sha256 格式，pull 中间层）在 DB 为空时
// 仍应对所有用户放行（路径3）。pendingPullRefs 修复不得将中间层 create 事件错误隔离。
func TestBug19_Reg4_Sha256ImageCreate_StillPassthrough(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)
	// pendingPullRefs 已注册（模拟正在进行的 pull）
	p.pendingPullRefs.Store(pullRaceImageRef, pullRaceAliceUID)
	defer p.pendingPullRefs.CompareAndDelete(pullRaceImageRef, pullRaceAliceUID)

	// image create：name 为 sha256（中间层格式，非命名 tag）
	createEvent := makeImageEvent("create", pullRaceImageID, pullRaceImageID)

	for _, uid := range []int{pullRaceBobUID, pullRaceAliceUID, 1003} {
		if !p.eventBelongsToUser(createEvent, uid, false) {
			t.Errorf(
				"回归-4: uid=%d 不应被过滤 image create sha256 事件（路径0 不生效）\n"+
					"\timageID=%q  name=%q（sha256 前缀，路径0 跳过 → 路径3 放行）\n"+
					"\t修复不得破坏 pull 中间层事件的透传行为",
				uid, pullRaceImageID, pullRaceImageID,
			)
		}
	}
}

// TestBug19_Reg5_Integration_PendingBlocksOtherUsers
//
// 回归-5：HTTP 集成测试（通过 ServeHTTP）。
// pendingPullRefs 已注册 alice 的 imageRef → bob 响应体不含该 pull 事件；
// bob 自己的 image 事件（DB 已注册）必须到达。
func TestBug19_Reg5_Integration_PendingBlocksOtherUsers(t *testing.T) {
	events := []string{
		makeRawImagePullEvent(pullRaceImageID, pullRaceImageRef), // alice 的 pull，bob 不应收到
		makeRawImageEvent("tag", bobImageID, "bob-app:latest"),   // bob 自己的镜像
	}
	upstream := fakeDockerEventsServer(events)
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	// 模拟 ActionPull 开头已注册（alice 正在 pull busybox）
	p.pendingPullRefs.Store(pullRaceImageRef, pullRaceAliceUID)
	defer p.pendingPullRefs.CompareAndDelete(pullRaceImageRef, pullRaceAliceUID)

	// bob 的镜像已在 DB 中（pull 已完成）
	bobID := regularIdentity("bob", pullRaceBobUID)
	if err := p.db.SetImageOwner(bobImageID, bobID, false, "build"); err != nil {
		t.Fatalf("SetImageOwner(bob): %v", err)
	}

	req := httptest.NewRequest("GET", "/events?type=image", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", pullRaceBobUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)
	body := rw.Body.String()

	if strings.Contains(body, pullRaceImageRef) {
		t.Errorf(
			"回归-5 [HTTP集成]: bob(uid=%d) 收到了 alice(uid=%d) 的 image pull 事件\n"+
				"\t包含: %q\n"+
				"\t响应体: %s",
			pullRaceBobUID, pullRaceAliceUID, pullRaceImageRef, body,
		)
	}
	if !strings.Contains(body, bobImageID) {
		t.Errorf(
			"回归-5: bob(uid=%d) 应收到自己的 image 事件\n"+
				"\t镜像 ID: %q\n"+
				"\t响应体: %s",
			pullRaceBobUID, bobImageID, body,
		)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// BUG 修复：pull 事件 Actor.ID 含完整 tag，attrs["name"] 仅含仓库名
//
// 复现场景：alice 执行 docker pull alpine:3.18，bob 执行 docker system events
//   Docker 发出事件：{"Type":"image","Action":"pull",
//                     "Actor":{"ID":"alpine:3.18","Attributes":{"name":"alpine"}}}
//   pendingPullRefs key = "alpine:3.18"（来自 parseImageRefFromURI）
//   路径0b 用 attrs["name"]="alpine" 查询 → miss
//   路径3（DB 无记录）→ return true → bob 错误地收到 alice 的 pull 事件
//
// 修复：路径0b.2 用 Actor.ID="alpine:3.18" 补充查询 pendingPullRefs → hit → 隔离
// ══════════════════════════════════════════════════════════════════════════════

// TestBug_PullEvent_ActorIDHasTag_NameHasNoTag
//
// 精确复现 alice pull alpine:3.18 导致 bob 收到事件的场景：
//   - pendingPullRefs["alpine:3.18"] = aliceUID（parseImageRefFromURI 的结果）
//   - 事件：Actor.ID="alpine:3.18", attrs["name"]="alpine"（真实 Docker 格式）
//   - 路径0b 用 "alpine" 查询 → miss；路径0b.2 用 "alpine:3.18" 查询 → hit → 隔离
func TestBug_PullEvent_ActorIDHasTag_NameHasNoTag(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	const fullRef = "alpine:3.18" // parseImageRefFromURI("?fromImage=alpine&tag=3.18")
	p.pendingPullRefs.Store(fullRef, pullRaceAliceUID)
	defer p.pendingPullRefs.CompareAndDelete(fullRef, pullRaceAliceUID)

	// 真实 Docker 事件格式：Actor.ID=完整 ref，attrs["name"]=仓库名（无 tag）
	event := makeImageEvent("pull", fullRef, "alpine")

	if p.eventBelongsToUser(event, pullRaceBobUID, false) {
		t.Errorf(
			"[pull tag 泄漏]: bob(uid=%d) 收到了 alice(uid=%d) 的 image pull 事件\n"+
				"\tActor.ID=%q  attrs[\"name\"]=%q  pendingPullRefs key=%q\n"+
				"\t路径0b 用 attrs[\"name\"] 查询未命中，路径0b.2（Actor.ID 查询）应命中",
			pullRaceBobUID, pullRaceAliceUID, fullRef, "alpine", fullRef,
		)
	}
	if !p.eventBelongsToUser(event, pullRaceAliceUID, false) {
		t.Errorf(
			"alice(uid=%d) 应能看到自己的 alpine:3.18 pull 事件（路径0b.2 命中）",
			pullRaceAliceUID,
		)
	}
}

// TestBug_PullEvent_ActorIDHasTag_Reg_Latest
//
// 回归：latest tag 场景（docker pull busybox）。
//   parseImageRefFromURI 省略 :latest → key="busybox"
//   Actor.ID="busybox:latest", attrs["name"]="busybox"
//   路径0b 用 "busybox" 查询 → hit（key="busybox"）→ 仍然正确隔离
func TestBug_PullEvent_ActorIDHasTag_Reg_Latest(t *testing.T) {
	p := newTestProxy(t, httptest.NewServer(nil), nil)

	// latest tag：parseImageRefFromURI 省略 :latest，存储 key="busybox"
	p.pendingPullRefs.Store("busybox", pullRaceAliceUID)
	defer p.pendingPullRefs.CompareAndDelete("busybox", pullRaceAliceUID)

	// 真实 Docker 事件：Actor.ID="busybox:latest", attrs["name"]="busybox"
	event := makeImageEvent("pull", "busybox:latest", "busybox")

	if p.eventBelongsToUser(event, pullRaceBobUID, false) {
		t.Errorf(
			"回归 [latest tag]: bob(uid=%d) 不应收到 alice 的 busybox pull 事件",
			pullRaceBobUID,
		)
	}
	if !p.eventBelongsToUser(event, pullRaceAliceUID, false) {
		t.Errorf(
			"回归 [latest tag]: alice(uid=%d) 应收到自己的 busybox pull 事件",
			pullRaceAliceUID,
		)
	}
}
