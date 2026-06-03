// container_rm_prefix_leak_test.go
//
// BUG-34: docker rm 错误响应泄漏内部容器名前缀
//
// 表现：bob 执行 `docker rm registry`，看到 "No such container: user-1000-registry"
// 期望：普通用户看到 "No such container: registry"（前缀已剥离）
//       root/sudo 用户可看到完整内部名称
//
// 根本原因（proxy.go, ActionRemoveContainer case）：
//   Docker daemon 返回的错误响应体（404/409/500）通过 io.Copy(w, resp.Body) 直接透传，
//   未调用 stripInternalPrefixFromErrorMessage() 剥离 "user-{uid}-" 前缀。
//   同类问题也存在于 ActionStop/Kill/Pause/Unpause 的错误响应路径。
//
// 对比已修复的 ActionCreateContainer (line ~2676-2678)：
//   if resp.StatusCode >= 400 && !id.IsPrivileged() {
//       body = stripInternalPrefixFromErrorMessage(p, body, id)
//   }
//
// 修复方向：
//   ActionRemoveContainer 及 ActionStop/Kill/Pause/Unpause 在错误响应路径上，
//   对非特权用户调用 stripInternalPrefixFromErrorMessage 剥离内部前缀。
//
// 测试结构：
//   Part A: Red Tests — 未修复前必定失败（验证 Bug 存在）
//   Part B: Regression Suite — 正常路径 + 边界条件 + 关联操作（防止修复引入新回归）

package forward

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/isolation"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Part A: Red Tests — 复现 BUG-34
// ═══════════════════════════════════════════════════════════════════════════════

// [BUG-34 Red Test 1] docker rm 404 错误响应泄漏容器名前缀
// 场景：bob (uid=1000) 执行 docker rm registry，容器不存在，Docker 返回 404
// 期望：bob 看到 "No such container: registry"（剥离 "user-1000-"）
// 实际（Bug）：bob 看到 "No such container: user-1000-registry"
func TestBug34_ContainerRm_404_LeaksPrefix(t *testing.T) {
	const uid = 1000
	const containerName = "registry"
	prefix := isolation.UserContainerPrefix(uid)
	internalName := prefix + containerName // "user-1000-registry"

	// fake upstream：模拟 Docker daemon 对 DELETE /containers/user-1000-registry 返回 404
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && strings.Contains(r.URL.Path, "/containers/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			// Docker 返回的错误信息包含内部前缀名
			_, _ = fmt.Fprintf(w, `{"message":"No such container: %s"}`, internalName)
			return
		}
		// inspect 请求也返回 404（容器不存在）
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// bob 执行 docker rm registry → URL 被重写为 /containers/user-1000-registry
	req := httptest.NewRequest("DELETE", "/v1.45/containers/"+containerName, nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()

	// 核心断言：响应体不应包含内部前缀名
	if strings.Contains(body, internalName) {
		t.Errorf("[BUG-34 RED] docker rm 404 响应泄漏了内部容器名前缀\n"+
			"  got body:  %s\n"+
			"  leaked:    %q\n"+
			"  expected:  响应中不应包含 %q，应显示 %q\n"+
			"  根本原因:  ActionRemoveContainer case 用 io.Copy 直接透传 Docker 响应，"+
			"未调用 stripInternalPrefixFromErrorMessage 剥离前缀",
			body, internalName, prefix, containerName)
	}
}

// [BUG-34 Red Test 2] docker rm 409 错误响应（容器正在运行）泄漏前缀
// 场景：bob (uid=1000) 执行 docker rm registry，容器正在运行，Docker 返回 409 Conflict
// 期望：bob 看到 "You cannot remove a running container registry..."
// 实际（Bug）：bob 看到 "You cannot remove a running container user-1000-registry..."
func TestBug34_ContainerRm_409_Conflict_LeaksPrefix(t *testing.T) {
	const uid = 1000
	const containerName = "registry"
	prefix := isolation.UserContainerPrefix(uid)
	internalName := prefix + containerName

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/json") {
			// inspect 返回容器信息（包含 owner label 以通过归属检查）
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{
				"Id": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
				"Name": "/%s",
				"Config": {
					"Labels": {
						"%s": "%d",
						"%s": "bob"
					}
				}
			}`, internalName,
				isolation.LabelOwnerUID, uid,
				isolation.LabelOwner)
			return
		}
		if r.Method == "DELETE" && strings.Contains(r.URL.Path, "/containers/") {
			// 容器正在运行，返回 409 Conflict
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = fmt.Fprintf(w,
				`{"message":"You cannot remove a running container %s. Stop the container before removing or force remove"}`,
				internalName)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	req := httptest.NewRequest("DELETE", "/v1.45/containers/"+containerName, nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()

	if strings.Contains(body, internalName) {
		t.Errorf("[BUG-34 RED] docker rm 409 响应泄漏了内部容器名前缀\n"+
			"  got body:  %s\n"+
			"  leaked:    %q\n"+
			"  expected:  响应中应显示 %q 而非 %q\n"+
			"  根本原因:  ActionRemoveContainer case 中 io.Copy 透传 Docker 409 响应",
			body, internalName, containerName, internalName)
	}
}

// [BUG-34 Red Test 3] docker stop 错误响应同样泄漏前缀
// 场景：bob (uid=1000) 执行 docker stop registry，容器不存在，Docker 返回 404
// 同一 io.Copy 透传 Bug 也影响 ActionStop
func TestBug34_ContainerStop_404_LeaksPrefix(t *testing.T) {
	const uid = 1000
	const containerName = "myapp"
	prefix := isolation.UserContainerPrefix(uid)
	internalName := prefix + containerName

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/stop") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, `{"message":"No such container: %s"}`, internalName)
			return
		}
		// inspect → 404（容器不存在，幂等放行）
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	req := httptest.NewRequest("POST", "/v1.45/containers/"+containerName+"/stop", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()

	if strings.Contains(body, internalName) {
		t.Errorf("[BUG-34 RED] docker stop 404 响应泄漏了内部容器名前缀\n"+
			"  got body:  %s\n"+
			"  leaked:    %q\n"+
			"  根本原因:  ActionStop case 也用 io.Copy 透传 Docker 错误响应",
			body, internalName)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Part B: Regression Suite — 正常路径 + 边界条件 + 关联操作
// ═══════════════════════════════════════════════════════════════════════════════

// ── B1: 正常路径回归 ────────────────────────────────────────────────────────────

// [Reg-1] docker rm 成功（204）不受影响
// 成功删除时 Docker 返回 204 No Content（空 body），不需要剥离前缀
func TestBug34_Reg1_ContainerRm_Success204_EmptyBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/json") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{
				"Id": "aabb000000000000000000000000000000000000000000000000000000000001",
				"Name": "/user-1000-web",
				"Config": {"Labels": {"%s": "1000", "%s": "bob"}}
			}`, isolation.LabelOwnerUID, isolation.LabelOwner)
			return
		}
		w.WriteHeader(http.StatusNoContent) // DELETE 成功
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest("DELETE", "/v1.45/containers/web", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", 1000))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusNoContent {
		t.Errorf("[Reg-1] docker rm 成功应返回 204, got %d", rw.Code)
	}
	body := rw.Body.String()
	if body != "" {
		t.Errorf("[Reg-1] docker rm 204 响应 body 应为空, got %q", body)
	}
}

// [Reg-2] root 用户 docker rm 错误响应保留完整内部名称
// root 是特权用户，不做前缀剥离
func TestBug34_Reg2_RootUser_ContainerRm_404_KeepsFullName(t *testing.T) {
	const internalName = "user-1000-registry"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `{"message":"No such container: %s"}`, internalName)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	root := makeTestIdentityProxy("root", 0)
	root.UserType = auth.UserTypeRoot

	// root 直接访问内部名（IsPrivileged → 不做 URL 重写）
	req := httptest.NewRequest("DELETE", "/v1.45/containers/"+internalName, nil)
	req = injectIdentity(req, root)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()
	if !strings.Contains(body, internalName) {
		t.Errorf("[Reg-2] root 用户应能看到完整内部名 %q\n  got body: %s",
			internalName, body)
	}
}

// [Reg-3] sudo 用户 docker rm 错误响应保留完整内部名称
func TestBug34_Reg3_SudoUser_ContainerRm_404_KeepsFullName(t *testing.T) {
	const internalName = "user-1001-registry"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `{"message":"No such container: %s"}`, internalName)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	sudo := makeTestIdentityProxy("alice", 1001)
	sudo.UserType = auth.UserTypeSudo // sudo 用户 → IsPrivileged() = true

	req := httptest.NewRequest("DELETE", "/v1.45/containers/"+internalName, nil)
	req = injectIdentity(req, sudo)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()
	if !strings.Contains(body, internalName) {
		t.Errorf("[Reg-3] sudo 用户应能看到完整内部名 %q\n  got body: %s",
			internalName, body)
	}
}

// ── B2: 边界条件 ────────────────────────────────────────────────────────────────

// [Reg-4] 使用 hex ID 的 docker rm 不触发 URL 重写（hex ID 原样透传）
func TestBug34_Reg4_HexID_NoRewrite_ErrorPassthrough(t *testing.T) {
	hexID := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	errMsg := fmt.Sprintf("No such container: %s", hexID)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证 URL 中容器 ID 未被重写（hex ID 应原样保留）
		if !strings.Contains(r.URL.Path, hexID) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"test infra error: hex ID was rewritten"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `{"message":"%s"}`, errMsg)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest("DELETE", "/v1.45/containers/"+hexID, nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", 1000))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()
	// hex ID 不含 "user-1000-" 前缀，所以不需要剥离
	if !strings.Contains(body, hexID) {
		t.Errorf("[Reg-4] hex ID 的错误响应应包含原始 ID\n  got body: %s", body)
	}
}

// [Reg-5] Docker daemon 返回 500 Internal Server Error，错误信息也应剥离前缀
func TestBug34_Reg5_ContainerRm_500_InternalError_StripsPrefix(t *testing.T) {
	const uid = 1000
	const containerName = "db-server"
	prefix := isolation.UserContainerPrefix(uid)
	internalName := prefix + containerName

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/json") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{
				"Id": "ddbb000000000000000000000000000000000000000000000000000000000001",
				"Name": "/%s",
				"Config": {"Labels": {"%s": "%d", "%s": "bob"}}
			}`, internalName, isolation.LabelOwnerUID, uid, isolation.LabelOwner)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w,
			`{"message":"driver %s: device busy"}`, internalName)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest("DELETE", "/v1.45/containers/"+containerName, nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()
	if strings.Contains(body, internalName) {
		t.Errorf("[Reg-5] docker rm 500 响应也应剥离前缀\n"+
			"  got body:  %s\n"+
			"  leaked:    %q",
			body, internalName)
	}
}

// [Reg-6] 容器名包含特殊字符（连字符），确保前缀剥离不会误伤
func TestBug34_Reg6_ContainerName_WithHyphens_CorrectStrip(t *testing.T) {
	const uid = 1002
	const containerName = "my-web-app-v2"
	prefix := isolation.UserContainerPrefix(uid)
	internalName := prefix + containerName // "user-1002-my-web-app-v2"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `{"message":"No such container: %s"}`, internalName)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest("DELETE", "/v1.45/containers/"+containerName, nil)
	req = injectIdentity(req, makeTestIdentityProxy("charlie", uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()

	// 断言1：不应包含内部前缀名
	if strings.Contains(body, internalName) {
		t.Errorf("[Reg-6] 带连字符的容器名前缀未剥离\n  got body: %s\n  leaked: %q",
			body, internalName)
	}

	// 断言2：剥离后应保留原始容器名（若 message 仍在响应中）
	if strings.Contains(body, "No such container") && !strings.Contains(body, containerName) {
		t.Errorf("[Reg-6] 剥离过度：原始容器名 %q 也被移除了\n  got body: %s",
			containerName, body)
	}
}

// [Reg-7] JSON 解析失败时保持原样（非 JSON 错误响应）
// Docker daemon 极少数情况下返回非 JSON 响应，剥离函数应安全降级
func TestBug34_Reg7_NonJSON_ErrorResponse_SafeFallback(t *testing.T) {
	const uid = 1000
	const containerName = "test"
	prefix := isolation.UserContainerPrefix(uid)
	internalName := prefix + containerName
	// 非 JSON 格式的错误响应
	plainTextError := "Error: container " + internalName + " not found"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(plainTextError))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest("DELETE", "/v1.45/containers/"+containerName, nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	// 非 JSON 响应：前缀剥离可能无法生效（降级为字节替换也可），
	// 但至少不应 panic 或返回 5xx
	if rw.Code == http.StatusInternalServerError && !strings.Contains(rw.Body.String(), internalName) {
		t.Errorf("[Reg-7] 非 JSON 错误响应不应导致代理自身返回 500")
	}
}

// ── B3: 关联操作回归 ────────────────────────────────────────────────────────────

// [Reg-8] docker kill 错误响应应剥离前缀（同一 io.Copy 代码路径）
func TestBug34_Reg8_ContainerKill_404_StripsPrefix(t *testing.T) {
	const uid = 1000
	const containerName = "worker"
	prefix := isolation.UserContainerPrefix(uid)
	internalName := prefix + containerName

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/kill") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, `{"message":"No such container: %s"}`, internalName)
			return
		}
		w.WriteHeader(http.StatusNotFound) // inspect 404
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest("POST", "/v1.45/containers/"+containerName+"/kill", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()
	if strings.Contains(body, internalName) {
		t.Errorf("[Reg-8] docker kill 404 响应泄漏了前缀\n  got body: %s\n  leaked: %q",
			body, internalName)
	}
}

// [Reg-9] docker pause 错误响应应剥离前缀
func TestBug34_Reg9_ContainerPause_Error_StripsPrefix(t *testing.T) {
	const uid = 1001
	const containerName = "nginx"
	prefix := isolation.UserContainerPrefix(uid)
	internalName := prefix + containerName

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/pause") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = fmt.Fprintf(w,
				`{"message":"Container %s is not running"}`, internalName)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest("POST", "/v1.45/containers/"+containerName+"/pause", nil)
	req = injectIdentity(req, makeTestIdentityProxy("alice", uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()
	if strings.Contains(body, internalName) {
		t.Errorf("[Reg-9] docker pause 错误响应泄漏了前缀\n  got body: %s\n  leaked: %q",
			body, internalName)
	}
}

// [Reg-10] docker restart 错误响应应剥离前缀
func TestBug34_Reg10_ContainerRestart_Error_StripsPrefix(t *testing.T) {
	const uid = 1000
	const containerName = "api-server"
	prefix := isolation.UserContainerPrefix(uid)
	internalName := prefix + containerName

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/restart") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, `{"message":"No such container: %s"}`, internalName)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest("POST", "/v1.45/containers/"+containerName+"/restart", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()
	if strings.Contains(body, internalName) {
		t.Errorf("[Reg-10] docker restart 404 响应泄漏了前缀\n  got body: %s\n  leaked: %q",
			body, internalName)
	}
}

// [Reg-11] docker start 错误响应应剥离前缀
func TestBug34_Reg11_ContainerStart_Error_StripsPrefix(t *testing.T) {
	const uid = 1000
	const containerName = "cache"
	prefix := isolation.UserContainerPrefix(uid)
	internalName := prefix + containerName

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/start") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, `{"message":"No such container: %s"}`, internalName)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest("POST", "/v1.45/containers/"+containerName+"/start", nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()
	if strings.Contains(body, internalName) {
		t.Errorf("[Reg-11] docker start 404 响应泄漏了前缀\n  got body: %s\n  leaked: %q",
			body, internalName)
	}
}

// ── B4: Content-Length 一致性 ────────────────────────────────────────────────────

// [Reg-12] 剥离前缀后 Content-Length 应与 body 长度一致
// 修复时需要用 ReadFullBody 替代 io.Copy，并重新计算 Content-Length
func TestBug34_Reg12_ContentLength_MatchesBody_AfterStrip(t *testing.T) {
	const uid = 1000
	const containerName = "web"
	prefix := isolation.UserContainerPrefix(uid)
	internalName := prefix + containerName

	errMsg := fmt.Sprintf(`{"message":"No such container: %s"}`, internalName)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(errMsg))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest("DELETE", "/v1.45/containers/"+containerName, nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	resp := rw.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// 如果有 Content-Length，验证它与 body 长度一致
	cl := resp.Header.Get("Content-Length")
	if cl != "" {
		var clInt int
		fmt.Sscanf(cl, "%d", &clInt)
		if clInt != len(body) {
			t.Errorf("[Reg-12] Content-Length (%d) 与实际 body 长度 (%d) 不一致\n"+
				"  可能原因：剥离前缀后未重新设置 Content-Length",
				clInt, len(body))
		}
	}
}

// ── B5: 错误消息语义完整性 ──────────────────────────────────────────────────────

// [Reg-13] 剥离前缀后，错误消息仍然是有效 JSON
func TestBug34_Reg13_StrippedResponse_ValidJSON(t *testing.T) {
	const uid = 1000
	const containerName = "test-svc"
	prefix := isolation.UserContainerPrefix(uid)
	internalName := prefix + containerName

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `{"message":"No such container: %s"}`, internalName)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest("DELETE", "/v1.45/containers/"+containerName, nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.Bytes()
	if len(body) == 0 {
		return // 空 body 可以接受（某些 404 路径由 writeDockerNotFound 处理）
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Errorf("[Reg-13] 剥离前缀后的响应不是有效 JSON\n  body: %s\n  err:  %v",
			string(body), err)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Part C: 同类 Bug — ActionNetworkRemove / ActionVolumeRemove
// ═══════════════════════════════════════════════════════════════════════════════

// ── C1: NetworkRemove ───────────────────────────────────────────────────────────

// [Reg-14] docker network rm 404 错误响应应剥离网络前缀
func TestBug34_Reg14_NetworkRm_404_StripsPrefix(t *testing.T) {
	const uid = 1001
	const username = "alice"
	const networkName = "mynet"
	netPrefix := fmt.Sprintf("%s_u%d_", username, uid)
	internalName := netPrefix + networkName // "alice_u1001_mynet"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `{"message":"network %s not found"}`, internalName)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest("DELETE", "/v1.45/networks/"+networkName, nil)
	id := makeTestIdentityProxy(username, uid)
	req = injectIdentity(req, id)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()
	if strings.Contains(body, internalName) {
		t.Errorf("[Reg-14] docker network rm 404 响应泄漏了网络前缀\n"+
			"  got body: %s\n  leaked: %q", body, internalName)
	}
}

// [Reg-15] root 用户 docker network rm 错误应保留完整内部名
func TestBug34_Reg15_RootUser_NetworkRm_404_KeepsFullName(t *testing.T) {
	const internalName = "alice_u1001_mynet"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `{"message":"network %s not found"}`, internalName)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	root := makeTestIdentityProxy("root", 0)
	root.UserType = auth.UserTypeRoot

	req := httptest.NewRequest("DELETE", "/v1.45/networks/"+internalName, nil)
	req = injectIdentity(req, root)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()
	if !strings.Contains(body, internalName) {
		t.Errorf("[Reg-15] root 用户应能看到完整内部网络名 %q\n  got body: %s",
			internalName, body)
	}
}

// [Reg-16] docker network rm 成功 (204) 不受影响
func TestBug34_Reg16_NetworkRm_Success204(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 预注册网络到 DB，使归属检查通过
	const uid = 1001
	const username = "alice"
	netPrefix := fmt.Sprintf("%s_u%d_", username, uid)
	internalNetName := netPrefix + "mynet"
	fakeNetDockerID := "aabb000000000000000000000000000000000000000000000000000000000001"
	id := makeTestIdentityProxy(username, uid)
	_ = p.db.SetNetworkOwner(fakeNetDockerID, internalNetName, id)

	req := httptest.NewRequest("DELETE", "/v1.45/networks/mynet", nil)
	req = injectIdentity(req, id)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusNoContent {
		t.Errorf("[Reg-16] docker network rm 成功应返回 204, got %d\n  body: %s",
			rw.Code, rw.Body.String())
	}
}

// ── C2: VolumeRemove ────────────────────────────────────────────────────────────

// [Reg-17] docker volume rm 404 错误响应应剥离完整卷前缀（user-{uid}-volume-）
// 关键测试：验证不会残留 "volume-" 前缀
func TestBug34_Reg17_VolumeRm_404_StripsFullVolumePrefix(t *testing.T) {
	const uid = 1000
	const volumeName = "data"
	volPrefix := isolation.UserVolumePrefix(uid) // "user-1000-volume-"
	internalName := volPrefix + volumeName       // "user-1000-volume-data"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `{"message":"get %s: no such volume"}`, internalName)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest("DELETE", "/v1.45/volumes/"+volumeName, nil)
	req = injectIdentity(req, makeTestIdentityProxy("bob", uid))
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()

	// 断言1：完整内部名不应出现
	if strings.Contains(body, internalName) {
		t.Errorf("[Reg-17] docker volume rm 404 响应泄漏了卷前缀\n"+
			"  got body: %s\n  leaked: %q", body, internalName)
	}

	// 断言2：不应残留 "volume-" 前缀（这是 QA 发现的关键边界）
	if strings.Contains(body, "volume-"+volumeName) {
		t.Errorf("[Reg-17] docker volume rm 404 前缀剥离不完整，残留 'volume-'\n"+
			"  got body: %s\n  期望包含 %q 而非 %q",
			body, volumeName, "volume-"+volumeName)
	}
}

// [Reg-18] docker volume rm 409（卷正在使用）应剥离完整卷前缀
// 此测试覆盖 post-response 路径（卷在 DB 中，归属检查通过，Docker 返回 409）
func TestBug34_Reg18_VolumeRm_409_InUse_StripsPrefix(t *testing.T) {
	const uid = 1002
	const volumeName = "pgdata"
	volPrefix := isolation.UserVolumePrefix(uid)
	internalName := volPrefix + volumeName

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = fmt.Fprintf(w,
			`{"message":"remove %s: volume is in use"}`, internalName)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 预注册卷到 DB，使归属检查通过，请求转发到 upstream
	id := makeTestIdentityProxy("charlie", uid)
	_ = p.db.SetVolumeOwner(internalName, id)

	req := httptest.NewRequest("DELETE", "/v1.45/volumes/"+volumeName, nil)
	req = injectIdentity(req, id)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()
	if strings.Contains(body, internalName) {
		t.Errorf("[Reg-18] docker volume rm 409 响应泄漏了卷前缀\n"+
			"  got body: %s\n  leaked: %q", body, internalName)
	}
	// 确认原始卷名保留
	if !strings.Contains(body, volumeName) {
		t.Errorf("[Reg-18] 剥离后原始卷名 %q 也丢失了\n  got body: %s",
			volumeName, body)
	}
}

// [Reg-19] root 用户 docker volume rm 错误应保留完整内部名
func TestBug34_Reg19_RootUser_VolumeRm_404_KeepsFullName(t *testing.T) {
	internalName := isolation.UserVolumePrefix(1000) + "data"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `{"message":"get %s: no such volume"}`, internalName)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	root := makeTestIdentityProxy("root", 0)
	root.UserType = auth.UserTypeRoot

	req := httptest.NewRequest("DELETE", "/v1.45/volumes/"+internalName, nil)
	req = injectIdentity(req, root)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	body := rw.Body.String()
	if !strings.Contains(body, internalName) {
		t.Errorf("[Reg-19] root 用户应能看到完整内部卷名 %q\n  got body: %s",
			internalName, body)
	}
}

// [Reg-20] docker volume rm 成功 (204) 不受影响
func TestBug34_Reg20_VolumeRm_Success204(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)

	// 预注册卷到 DB，使归属检查通过
	const uid = 1000
	volPrefix := isolation.UserVolumePrefix(uid)
	internalVolName := volPrefix + "mydata" // "user-1000-volume-mydata"
	id := makeTestIdentityProxy("bob", uid)
	_ = p.db.SetVolumeOwner(internalVolName, id)

	req := httptest.NewRequest("DELETE", "/v1.45/volumes/mydata", nil)
	req = injectIdentity(req, id)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusNoContent {
		t.Errorf("[Reg-20] docker volume rm 成功应返回 204, got %d\n  body: %s",
			rw.Code, rw.Body.String())
	}
}
