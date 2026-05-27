package forward

// ══════════════════════════════════════════════════════════════════════════════
// BUG-29b：docker build -t myapp:test 产生的 tag 事件泄漏给其他用户
//
// ──── 根因 ─────────────────────────────────────────────────────────────────
//
//   真实 Docker image tag 事件格式：
//     Actor.ID          = "myapp:test"  （完整 ref，含 tag）
//     Attributes["name"] = "myapp"      （仅仓库名，不含 tag）
//
//   pendingBuildTags / completedBuildOwner 以完整 ref（"myapp:test"）为 key，
//   而 eventBelongsToUser 原路径 0a/0a.2 只用 attrs["name"]（"myapp"）查询：
//     pendingBuildTags.Load("myapp")   → MISS
//     completedBuildOwner.Load("myapp") → MISS
//   竞态窗口内 DB 也无记录 → 路径3 return true → alice / sudo_test 非 sudo 视图泄漏。
//
// ──── 修复 ─────────────────────────────────────────────────────────────────
//
//   新增路径 0a.3：当 ev.Action != "pull" 时，用 Actor.ID（完整 ref）查询
//   pendingBuildTags 和 completedBuildOwner，与 pull 路径的 0b.2 对称。
//   Action 类型过滤避免 pull 事件与同名 build tag 在 pendingBuildTags 中碰撞。
//
// ══════════════════════════════════════════════════════════════════════════════

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// makeRealBuildTagEvent 构造与真实 Docker daemon 一致的 image tag 事件。
//
// 真实格式（已在服务器验证）：
//
//	Action            = "tag"
//	Actor.ID          = 完整 ref（如 "myapp:test"）
//	Attributes["name"] = 仅仓库名（如 "myapp"，不含 tag）
func makeRealBuildTagEvent(actorRef, repoName string) []byte {
	return []byte(fmt.Sprintf(
		`{"Type":"image","Action":"tag","Actor":{"ID":%q,"Attributes":{"name":%q}}}`,
		actorRef, repoName,
	))
}

// makeRealPullEvent 构造与真实 Docker daemon 一致的 image pull 事件。
//
//	Actor.ID          = 完整 ref（如 "nginx:latest"）
//	Attributes["name"] = 仅仓库名（如 "nginx"）
func makeRealPullEvent(actorRef, repoName string) []byte {
	return []byte(fmt.Sprintf(
		`{"Type":"image","Action":"pull","Actor":{"ID":%q,"Attributes":{"name":%q}}}`,
		actorRef, repoName,
	))
}

// ══════════════════════════════════════════════════════════════════════════════
// RED TEST（修复前必须失败）
// ══════════════════════════════════════════════════════════════════════════════

// TestBug29b_BuildTagEvent_ActorIDLookup
//
// RED TEST：精确复现真实格式下 pendingBuildTags 查找失效导致的泄漏。
//
//	pendingBuildTags["myapp:test"] = {ownerUID:bob}
//	tag 事件：Actor.ID="myapp:test"，attrs["name"]="myapp"（真实格式）
//	alice / sudo_test 非 sudo 视图不应收到此事件。
func TestBug29b_BuildTagEvent_ActorIDLookup(t *testing.T) {
	const (
		bobUID   = 1002
		aliceUID = 1001
		sudoUID  = 1005
		buildTag = "myapp:test"
		repoName = "myapp"
	)

	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.pendingBuildTags.Store(buildTag, pruneOwnerInfo{ownerUID: bobUID})
	defer p.pendingBuildTags.CompareAndDelete(buildTag, pruneOwnerInfo{ownerUID: bobUID})

	ev := makeRealBuildTagEvent(buildTag, repoName)

	if p.eventBelongsToUser(ev, aliceUID, false) {
		t.Errorf(
			"BUG-29b [pendingBuildTags 竞态]: alice(uid=%d) 收到了 bob(uid=%d) 的 build tag 事件\n"+
				"\tActor.ID=%q Attributes.name=%q\n"+
				"\tpendingBuildTags[%q]=%d 应拦截此事件",
			aliceUID, bobUID, buildTag, repoName, buildTag, bobUID,
		)
	}
	if p.eventBelongsToUser(ev, sudoUID, false) {
		t.Errorf(
			"BUG-29b [sudo 非 sudo 视图]: sudo_test(uid=%d) 收到了 bob(uid=%d) 的 build tag 事件",
			sudoUID, bobUID,
		)
	}
	// bob 自己必须能收到
	if !p.eventBelongsToUser(ev, bobUID, false) {
		t.Errorf("BUG-29b: bob(uid=%d) 应收到自己的 build tag 事件", bobUID)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 回归矩阵
// ══════════════════════════════════════════════════════════════════════════════

// TestBug29b_Reg1_CompletedBuildOwner_ActorIDLookup
//
// 回归-1：build 完成后（pendingBuildTags 已清，completedBuildOwner 已写），
// 延迟到达的 tag 事件仍被正确过滤。
func TestBug29b_Reg1_CompletedBuildOwner_ActorIDLookup(t *testing.T) {
	const (
		bobUID   = 1002
		aliceUID = 1001
		buildTag = "myapp:test"
		repoName = "myapp"
	)

	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.completedBuildOwner.Store(buildTag, pruneOwnerInfo{ownerUID: bobUID})
	defer p.completedBuildOwner.CompareAndDelete(buildTag, pruneOwnerInfo{ownerUID: bobUID})

	ev := makeRealBuildTagEvent(buildTag, repoName)

	if p.eventBelongsToUser(ev, aliceUID, false) {
		t.Errorf(
			"回归-1 [completedBuildOwner]: alice(uid=%d) 收到了 bob(uid=%d) 的 build tag 事件（投递延迟窗口）",
			aliceUID, bobUID,
		)
	}
	if !p.eventBelongsToUser(ev, bobUID, false) {
		t.Errorf("回归-1: bob(uid=%d) 应收到自己的 build tag 事件", bobUID)
	}
}

// TestBug29b_Reg2_SudoBuild_PrivCtx_HiddenInNonSudoView
//
// 回归-2：sudo docker build（privCtx=1）的 tag 事件，
// 同用户的非 sudo events 视图不应看到（与 BUG-27 对齐）。
func TestBug29b_Reg2_SudoBuild_PrivCtx_HiddenInNonSudoView(t *testing.T) {
	const (
		sudoUID  = 1005
		buildTag = "myapp:test"
		repoName = "myapp"
	)

	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.pendingBuildTags.Store(buildTag, pruneOwnerInfo{ownerUID: sudoUID, privCtx: 1})
	defer p.pendingBuildTags.CompareAndDelete(buildTag, pruneOwnerInfo{ownerUID: sudoUID, privCtx: 1})

	ev := makeRealBuildTagEvent(buildTag, repoName)

	// 非 sudo 视图（sudoCtx=false）不可见
	if p.eventBelongsToUser(ev, sudoUID, false) {
		t.Errorf(
			"回归-2 [sudo privCtx]: sudo_test(uid=%d) 非 sudo events 收到了 sudo build tag 事件\n"+
				"\tpendingBuildTags[%q]={privCtx:1}，应被过滤",
			sudoUID, buildTag,
		)
	}
	// sudo 视图（sudoCtx=true）可见
	if !p.eventBelongsToUser(ev, sudoUID, true) {
		t.Errorf(
			"回归-2: sudo_test(uid=%d) 以 sudo 视图应能看到自己的 sudo build tag 事件",
			sudoUID,
		)
	}
}

// TestBug29b_Reg3_PullEvent_NotAffectedByBuildTags
//
// 回归-3（关键边界）：用户 A 正在 build "nginx:latest"，同时用户 B pull "nginx:latest"。
// B 的 pull 事件的 Actor.ID = "nginx:latest" 与 A 的 pendingBuildTags key 碰撞，
// 但因 ev.Action == "pull" 跳过路径 0a.3，不应误判 A 收到 B 的 pull 事件。
func TestBug29b_Reg3_PullEvent_NotAffectedByBuildTags(t *testing.T) {
	const (
		builderUID = 1002 // A：正在 build nginx:latest
		pullerUID  = 1001 // B：正在 pull nginx:latest
		watcherUID = 1003 // C：监听 events 的无关用户
		tag        = "nginx:latest"
		repoName   = "nginx"
	)

	p := newTestProxy(t, httptest.NewServer(nil), nil)
	// A 正在 build nginx:latest
	p.pendingBuildTags.Store(tag, pruneOwnerInfo{ownerUID: builderUID})
	defer p.pendingBuildTags.CompareAndDelete(tag, pruneOwnerInfo{ownerUID: builderUID})
	// B 正在 pull nginx:latest
	p.pendingPullRefs.Store(tag, pruneOwnerInfo{ownerUID: pullerUID})
	defer p.pendingPullRefs.CompareAndDelete(tag, pruneOwnerInfo{ownerUID: pullerUID})

	// B 的 pull 事件（Action="pull"，应走路径 0b.2 而非 0a.3）
	pullEv := makeRealPullEvent(tag, repoName)

	// A（构建者）不应收到 B 的 pull 事件（路径 0a.3 排除 pull，不碰撞 pendingBuildTags）
	if p.eventBelongsToUser(pullEv, builderUID, false) {
		t.Errorf(
			"回归-3 [pull/build 碰撞]: builderUID(%d) 收到了 pullerUID(%d) 的 pull 事件\n"+
				"\tpendingBuildTags[%q]=%d 不应影响 pull 事件过滤\n"+
				"\t根因：路径 0a.3 未排除 pull Action",
			builderUID, pullerUID, tag, builderUID,
		)
	}
	// B（pull 者）应收到自己的 pull 事件（路径 0b.2）
	if !p.eventBelongsToUser(pullEv, pullerUID, false) {
		t.Errorf(
			"回归-3: pullerUID(%d) 应收到自己的 pull 事件（路径 0b.2 via pendingPullRefs）",
			pullerUID,
		)
	}
	// C（无关用户）不应收到（路径 0b.2 命中 B，return B==C → false）
	if p.eventBelongsToUser(pullEv, watcherUID, false) {
		t.Errorf(
			"回归-3: watcherUID(%d) 不应收到 pullerUID(%d) 的 pull 事件",
			watcherUID, pullerUID,
		)
	}
}

// TestBug29b_Reg4_SHA256ActorID_Unaffected
//
// 回归-4：sha256 格式 Actor.ID 的事件（中间层 create）不进入路径 0a.3，
// 行为与修复前完全一致（路径3放行，设计行为）。
func TestBug29b_Reg4_SHA256ActorID_Unaffected(t *testing.T) {
	const (
		bobUID   = 1002
		aliceUID = 1001
		buildTag = "myapp:test"
		sha256ID = "sha256:9da033d6be322ed2efdba84a9c973bb046793fadbc71108e48914091546d5c93"
	)

	p := newTestProxy(t, httptest.NewServer(nil), nil)
	p.pendingBuildTags.Store(buildTag, pruneOwnerInfo{ownerUID: bobUID})
	defer p.pendingBuildTags.CompareAndDelete(buildTag, pruneOwnerInfo{ownerUID: bobUID})

	createEv := []byte(fmt.Sprintf(
		`{"Type":"image","Action":"create","Actor":{"ID":%q,"Attributes":{"name":%q}}}`,
		sha256ID, sha256ID,
	))

	// sha256 Actor.ID 跳过路径 0a.3，走路径3放行
	if !p.eventBelongsToUser(createEv, aliceUID, false) {
		t.Errorf(
			"回归-4: sha256 create 事件应对所有用户放行（路径3），alice 被错误过滤",
		)
	}
}

// TestBug29b_Reg5_HTTP_Integration
//
// 回归-5：HTTP 集成测试（通过 ServeHTTP）。
// pendingBuildTags 注册 bob 的 tag，alice 响应体不含该 tag；
// bob 自己收到；
func TestBug29b_Reg5_HTTP_Integration(t *testing.T) {
	const (
		bobUID   = 1002
		aliceUID = 1001
		buildTag = "myapp:test"
		repoName = "myapp"
	)

	// 真实格式事件：Actor.ID=完整 ref，attrs["name"]=仓库名
	events := []string{
		fmt.Sprintf(`{"Type":"image","Action":"tag","Actor":{"ID":%q,"Attributes":{"name":%q}}}`,
			buildTag, repoName),
	}
	upstream := fakeDockerEventsServer(events)
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	p.pendingBuildTags.Store(buildTag, pruneOwnerInfo{ownerUID: bobUID})
	defer p.pendingBuildTags.CompareAndDelete(buildTag, pruneOwnerInfo{ownerUID: bobUID})

	// alice 监听
	req := httptest.NewRequest("GET", "/events?type=image", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", aliceUID))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if strings.Contains(rw.Body.String(), buildTag) {
		t.Errorf(
			"回归-5 [HTTP集成]: alice(uid=%d) 收到了 bob(uid=%d) 的 build tag 事件\n"+
				"\t响应体: %s",
			aliceUID, bobUID, rw.Body.String(),
		)
	}
}
