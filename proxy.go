package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// contextKey 用于在 request context 中传递 CallerIdentity
type contextKey string

const identityContextKey contextKey = "caller_identity"

// ProxyServer 每用户 Unix socket 代理，内置授权逻辑
type ProxyServer struct {
	socketDir    string
	upstreamSock string
	policy       *Policy
	db           *OwnershipDB
	logger       *zap.Logger

	mu        sync.Mutex
	listeners map[string]net.Listener // username -> listener
	servers   []*http.Server

	transport http.RoundTripper
}

func newProxyServer(socketDir, upstreamSock string, policy *Policy, db *OwnershipDB, logger *zap.Logger) *ProxyServer {
	// 上游 transport：每次请求新建 Unix socket 连接
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// 使用带超时的 Dial，防止 Unix socket 连接无限期阻塞
			d := &net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "unix", upstreamSock)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second, // 防止上游无响应导致挂起
		DisableCompression:    true,             // 避免压缩干扰响应体解析
	}

	return &ProxyServer{
		socketDir:    socketDir,
		upstreamSock: upstreamSock,
		policy:       policy,
		db:           db,
		logger:       logger,
		listeners:    make(map[string]net.Listener),
		transport:    transport,
	}
}

// Start 为所有系统用户创建 per-user 监听 socket 并启动 HTTP 服务
func (p *ProxyServer) Start() error {
	if err := os.MkdirAll(p.socketDir, 0755); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}

	users := listSystemUsers()
	if len(users) == 0 {
		return fmt.Errorf("no system users found")
	}

	for _, u := range users {
		if err := p.startUserListener(u); err != nil {
			p.logger.Error("failed to start listener",
				zap.String("username", u.Username),
				zap.Int("uid", u.UID),
				zap.Error(err))
		} else {
			setUserDockerHost(u, p.socketDir, p.logger)
		}
	}

	// 启动定期扫描，为新用户创建 socket
	go p.watchNewUsers()

	return nil
}

// watchNewUsers 定期扫描系统用户，为新用户创建 socket
func (p *ProxyServer) watchNewUsers() {
	ticker := time.NewTicker(10 * time.Second) // 每 10 秒扫描一次
	defer ticker.Stop()

	for range ticker.C {
		users := listSystemUsers()
		for _, u := range users {
			p.mu.Lock()
			_, exists := p.listeners[u.Username]
			p.mu.Unlock()

			if !exists {
				// 为新用户创建 socket
				if err := p.startUserListener(u); err != nil {
					p.logger.Error("failed to start listener for new user",
						zap.String("username", u.Username),
						zap.Int("uid", u.UID),
						zap.Error(err))
				} else {
					p.logger.Info("created socket for new user",
						zap.String("username", u.Username),
						zap.Int("uid", u.UID))
					setUserDockerHost(u, p.socketDir, p.logger)
				}
			}
		}
	}
}

// startUserListener 为单个用户创建 Unix socket 并启动 HTTP 服务
func (p *ProxyServer) startUserListener(u systemUser) error {
	sockPath := filepath.Join(p.socketDir, u.Username+".sock")

	// 清理旧 socket 文件
	_ = os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	// 只允许该用户访问自己的 socket
	if err := os.Chown(sockPath, u.UID, u.GID); err != nil {
		ln.Close()
		return fmt.Errorf("chown socket: %w", err)
	}
	if err := os.Chmod(sockPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	p.logger.Info("user socket created",
		zap.String("username", u.Username),
		zap.Int("uid", u.UID),
		zap.Int("gid", u.GID),
		zap.String("socket", sockPath))

	p.mu.Lock()
	p.listeners[u.Username] = ln
	p.mu.Unlock()

	srv := &http.Server{
		Handler: p,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			// DEBUG: 记录每个新连接
			p.logger.Debug("new_connection",
				zap.String("socket", sockPath),
				zap.String("remote", c.RemoteAddr().String()),
			)
			// 在连接建立时解析调用方身份并注入 context
			identity, err := resolveCallerIdentity(c)
			if err != nil {
				p.logger.Error("identity resolution failed",
					zap.String("socket", sockPath),
					zap.Error(err))
				// 使用匿名身份（会在后续检查中被拒绝）
				identity = &CallerIdentity{
					RealUsername:      "unknown",
					RealUID:           -1,
					UserType:          UserTypeRegular,
					EffectiveUsername: "unknown",
				}
			} else {
				p.logger.Debug("identity_resolved",
					zap.String("user", identity.RealUsername),
					zap.Int("uid", identity.RealUID),
					zap.String("cmdline", identity.CmdLine),
				)
			}
			return context.WithValue(ctx, identityContextKey, identity)
		},
	}

	p.mu.Lock()
	p.servers = append(p.servers, srv)
	p.mu.Unlock()

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			p.logger.Error("server error",
				zap.String("username", u.Username),
				zap.Error(err))
		}
	}()

	return nil
}

// UpdatePolicy 动态更新策略配置（热重载）
func (p *ProxyServer) UpdatePolicy(newPolicy *Policy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policy = newPolicy
}

// getPolicy 线程安全地获取当前策略
func (p *ProxyServer) getPolicy() *Policy {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.policy
}

// Stop 关闭所有监听器和服务
func (p *ProxyServer) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, srv := range p.servers {
		_ = srv.Shutdown(ctx)
	}
	for path, ln := range p.listeners {
		ln.Close()
		sockPath := filepath.Join(p.socketDir, path+".sock")
		_ = os.Remove(sockPath)
	}
}

// ServeHTTP 是每个请求的入口：授权 + 代理
func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// DEBUG: 记录每个 HTTP 请求（最早阶段，用于排查请求是否到达）
	p.logger.Debug("http_request_received",
		zap.String("method", r.Method),
		zap.String("uri", r.URL.RequestURI()),
		zap.String("proto", r.Proto),
		zap.String("upgrade", r.Header.Get("Upgrade")),
		zap.String("connection", r.Header.Get("Connection")),
	)

	// 从 context 中获取调用方身份
	identity, _ := r.Context().Value(identityContextKey).(*CallerIdentity)
	if identity == nil || identity.RealUID < 0 {
		p.logger.Error("identity_missing_or_invalid")
		http.Error(w, "identity resolution failed", http.StatusInternalServerError)
		return
	}

	// docker run -it / docker attach / docker exec -it 等需要双向流式连接（HTTP hijack）
	// 检测到 Upgrade: tcp 请求头或 attach/exec 路径时，走专用隧道处理
	if isHijackRequest(r) {
		p.logger.Debug("hijack_detected",
			zap.String("user", fmt.Sprintf("%s(uid=%d)", identity.RealUsername, identity.RealUID)),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("upgrade", r.Header.Get("Upgrade")),
			zap.String("connection", r.Header.Get("Connection")),
		)
		p.handleHijack(w, r, identity)
		return
	}
	// DEBUG: 记录所有未被 hijack 检测到的请求（帮助排查 attach 是否漏检）
	p.logger.Debug("non_hijack_request",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("upgrade", r.Header.Get("Upgrade")),
		zap.String("connection", r.Header.Get("Connection")),
	)

	action := classifyAction(r.Method, r.URL.Path)

	// 获取当前策略（线程安全）
	policy := p.getPolicy()

	// ── 识别 Docker CLI 内部辅助调用 ────────────────────────────
	//
	// Docker CLI 在执行用户命令的过程中会自动调用 /info、/version、/_ping 等
	// 辅助端点，这些是 CLI 的实现细节，不是用户主动执行的操作。
	//
	// 判断依据：将 CmdLine 解析出的 DockerCommand（用户实际执行的子命令）
	// 与当前 API action 对比：
	//   - 二者匹配        → 用户主动执行的目标操作，走策略检查
	//   - 二者不匹配      → CLI 执行目标操作过程中的内部辅助调用，直接放行
	//
	// 示例：
	//   docker run nginx
	//     GET /info     → DockerCommand="run", action="info" → 不匹配 → 辅助调用，放行
	//     GET /version  → DockerCommand="run", action="info" → 不匹配 → 辅助调用，放行
	//     POST /containers/create → DockerCommand="run", action="run" → 匹配 → 策略检查
	//
	//   docker info（用户主动执行）
	//     GET /info     → DockerCommand="info", action="info" → 匹配 → 策略检查
	//
	// 特殊情况：/_ping 始终放行（纯健康检查，不对应任何子命令）
	isAuxiliary := isAuxiliaryCall(identity.DockerCommand, action, r.Method, r.URL.Path)

	// DEBUG：每个请求都记录，方便排查问题（生产环境用 --log-level=info 关闭）
	p.logger.Debug("authz_trace",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", identity.RealUsername, identity.RealUID)),
		zap.String("docker_cmd", identity.DockerCommand),
		zap.String("action", action),
		zap.String("method", r.Method),
		zap.String("uri", r.URL.RequestURI()),
		zap.Bool("is_auxiliary", isAuxiliary),
	)

	// 只记录用户实际执行的目标操作，过滤掉 CLI 内部辅助调用
	if !isAuxiliary {
		logAuthzRequest(p.logger, identity, action, r.Method, r.URL.RequestURI())
	}

	// ── 层次一：命令授权检查 ──────────────────────────────────
	// 辅助调用直接放行，不受策略控制
	if !isAuxiliary && policy.IsDenied(identity, action) {
		// docker_cmd 和 is_auxiliary 帮助排查"为何某命令意外被拦截"
		p.logger.Warn("AUTHZ_DENY",
			append(logIdentityFields(identity),
				zap.String("reason", "command_not_permitted"),
				zap.String("action", action),
				zap.String("docker_cmd", identity.DockerCommand),
				zap.Bool("is_auxiliary", isAuxiliary),
				zap.String("uri", r.URL.RequestURI()),
			)...)
		http.Error(w,
			fmt.Sprintf("user '%s'(uid=%d) not permitted to perform: %s",
				identity.RealUsername, identity.RealUID, action),
			http.StatusForbidden)
		return
	}

	// ── 层次二：资源归属检查（请求前）────────────────────────
	if !p.checkOwnershipPreRequest(w, r, identity, action) {
		return // checkOwnershipPreRequest 已写入错误响应
	}

	// ── 请求预处理（标签注入等）──────────────────────────────
	p.logger.Debug("preprocess_request_start",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", identity.RealUsername, identity.RealUID)),
		zap.String("action", action),
		zap.String("uri", r.URL.RequestURI()),
	)
	modifiedReq, err := p.preprocessRequest(r, identity, action)
	if err != nil {
		p.logger.Error("preprocess_request_failed",
			zap.Error(err),
			zap.String("real_username", identity.RealUsername),
			zap.Int("real_uid", identity.RealUID),
		)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	p.logger.Debug("preprocess_request_done",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", identity.RealUsername, identity.RealUID)),
		zap.String("action", action),
	)

	// ── 虚拟镜像删除：在转发前处理 ──────────────────────────────
	if action == ActionRemoveImage {
		imageID := extractImageID(r.URL.Path)
		if imageID != "" {
			shouldDelete, err := p.db.RemoveUserImageAccess(imageID, identity.RealUID)
			if err != nil {
				p.logger.Error("remove_image_access_failed",
					zap.Error(err),
					zap.String("real_username", identity.RealUsername),
					zap.Int("real_uid", identity.RealUID),
					zap.String("image_id", imageID),
				)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			if !shouldDelete {
				// 其他用户仍在使用该镜像，虚拟删除成功（不转发到 Docker）
				p.logger.Info("AUTHZ_ALLOW",
					append(logIdentityShort(identity),
						zap.String("action", "rmi"),
						zap.String("image_id", imageID),
						zap.String("note", "virtual_delete_only"),
					)...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			// shouldDelete=true：没有其他用户使用，继续转发到 Docker 真正删除
		}
	}

	// ── 转发到上游 dockerd ───────────────────────────────────
	p.logger.Debug("forward_request_start",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", identity.RealUsername, identity.RealUID)),
		zap.String("action", action),
		zap.String("uri", r.URL.RequestURI()),
	)
	resp, err := p.forward(modifiedReq)
	if err != nil {
		p.logger.Error("upstream_error",
			zap.String("real_username", identity.RealUsername),
			zap.Int("real_uid", identity.RealUID),
			zap.String("action", action),
			zap.Error(err))
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	p.logger.Debug("forward_request_done",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", identity.RealUsername, identity.RealUID)),
		zap.String("action", action),
		zap.Int("status_code", resp.StatusCode),
	)

	// ── 响应后处理（过滤列表、记录归属）─────────────────────
	p.logger.Debug("postprocess_response_start",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", identity.RealUsername, identity.RealUID)),
		zap.String("action", action),
	)
	p.postprocessResponse(w, resp, identity, action, r.URL.RequestURI())
	p.logger.Debug("postprocess_response_done",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", identity.RealUsername, identity.RealUID)),
		zap.String("action", action),
	)

	// INFO 日志：只记录用户实际执行的命令
	if !isAuxiliary {
		logAuthzAllowed(p.logger, identity, action, r.URL.RequestURI())
	}
}

// checkOwnershipPreRequest 请求前的资源归属检查
// 返回 false 表示已拒绝并写入响应
func (p *ProxyServer) checkOwnershipPreRequest(w http.ResponseWriter, r *http.Request,
	id *CallerIdentity, action string) bool {

	// ── 通用容器归属检查（覆盖所有 /containers/{id}/... 操作）────────────
	// 只要路径中有容器 ID（且不是列表/创建/清理等非 ID 路径段），就验证归属
	containerID := extractContainerID(r.URL.Path)
	nonContainerIDs := map[string]bool{"json": true, "create": true, "prune": true}
	if containerID != "" && !nonContainerIDs[containerID] {
		owner, found := p.db.GetContainerOwner(containerID)
		if !found {
			// 容器未在代理中注册（部署前已存在或 DB 写入失败）
			// root 可管理所有容器，普通用户只能操作自己创建的容器
			if id.RealUID != 0 {
				logAuthzDeniedNotTracked(p.logger, id, "container", truncID(containerID), action)
				http.Error(w,
					fmt.Sprintf("container '%s' not tracked by proxy (only root can manage untracked containers)",
						truncID(containerID)),
					http.StatusForbidden)
				return false
			}
		} else if owner.UID != id.RealUID {
			// 容器已注册但归属不匹配
			logAuthzDeniedOwnership(p.logger, id, owner, "container", truncID(containerID), action)
			http.Error(w,
				fmt.Sprintf("container '%s' belongs to '%s'(uid=%d), not '%s'(uid=%d)",
					truncID(containerID), owner.Username, owner.UID,
					id.RealUsername, id.RealUID),
				http.StatusForbidden)
			return false
		}
	}

	// ── docker commit：容器 ID 在 query 参数中 ───────────────────────────
	if action == ActionCommit {
		qContainerID := r.URL.Query().Get("container")
		if qContainerID != "" {
			owner, found := p.db.GetContainerOwner(qContainerID)
			if !found {
				// 容器未追踪，只允许 root 操作
				if id.RealUID != 0 {
					logAuthzDeniedNotTracked(p.logger, id, "container", truncID(qContainerID), action)
					http.Error(w,
						fmt.Sprintf("container '%s' not tracked by proxy (only root can manage untracked containers)",
							truncID(qContainerID)),
						http.StatusForbidden)
					return false
				}
			} else if owner.UID != id.RealUID {
				logAuthzDeniedOwnership(p.logger, id, owner, "container", truncID(qContainerID), action)
				http.Error(w,
					fmt.Sprintf("container '%s' belongs to '%s'(uid=%d), not '%s'(uid=%d)",
						truncID(qContainerID), owner.Username, owner.UID,
						id.RealUsername, id.RealUID),
					http.StatusForbidden)
				return false
			}
		}
	}

	// ── 创建容器：验证镜像使用权限 ──────────────────────────────────────
	// 注意：不在此处解析镜像 ID（会导致同步调用上游 Docker，可能死锁）
	// 镜像权限检查推迟到响应后处理阶段（postprocessResponse）
	// 此处仅做基本的镜像引用提取，实际权限验证在容器创建成功后进行
	if action == ActionCreateContainer {
		imageRef := extractImageRefFromBody(r)
		if imageRef != "" {
			// 先用镜像名称直接查 DB（可能是 tag 或 sha256）
			// CanUseImage 内部已处理未追踪镜像（返回 true，兼容存量）
			// 所以这里只能拦截明确在 DB 中且无权限的镜像
			if !p.db.CanUseImage(id.RealUID, imageRef) {
				// 尝试加 sha256: 前缀再查一次
				if !p.db.CanUseImage(id.RealUID, "sha256:"+imageRef) {
					logAuthzDeniedImageAccess(p.logger, id, imageRef, action, "image_not_permitted")
					http.Error(w,
						fmt.Sprintf("user '%s'(uid=%d) not permitted to use image '%s'",
							id.RealUsername, id.RealUID, imageRef),
						http.StatusForbidden)
					return false
				}
			}
		}
	}

	// ── 镜像 inspect / save：验证查看/导出权限 ──────────────────────────
	// 注意：不在此处解析镜像 ID（避免同步调用上游导致死锁）
	// 直接用 URL 中的镜像引用查 DB，未追踪镜像会被 CanUseImage 放行
	if action == ActionInspect || action == ActionSave {
		if imageRef := extractImageID(r.URL.Path); imageRef != "" {
			// 尝试原始引用和加 sha256: 前缀两种方式
			if !p.db.CanUseImage(id.RealUID, imageRef) && !p.db.CanUseImage(id.RealUID, "sha256:"+imageRef) {
				logAuthzDeniedImageAccess(p.logger, id, truncID(imageRef), action, "image_not_permitted")
				http.Error(w,
					fmt.Sprintf("user '%s'(uid=%d) not permitted to access image '%s'",
						id.RealUsername, id.RealUID, truncID(imageRef)),
					http.StatusForbidden)
				return false
			}
		}
	}

	// ── 镜像删除：虚拟隔离（允许多用户共享同一镜像）────────────────────
	if action == ActionRemoveImage {
		imageID := extractImageID(r.URL.Path)
		if imageID != "" {
			owner, isPublic, found := p.db.GetImageOwner(imageID)
			if found {
				if isPublic && id.RealUID != 0 {
					logAuthzDeniedImageAccess(p.logger, id, truncID(imageID), action, "public_image_delete_denied")
					http.Error(w, "public images can only be removed by root", http.StatusForbidden)
					return false
				}
				if !p.db.CanUseImage(id.RealUID, imageID) {
					logAuthzDeniedOwnership(p.logger, id, owner, "image", truncID(imageID), action)
					http.Error(w,
						fmt.Sprintf("image '%s' not accessible by '%s'(uid=%d)",
							truncID(imageID), id.RealUsername, id.RealUID),
						http.StatusForbidden)
					return false
				}
			}
		}
	}

	// ── 镜像推送/标记：检查访问权限（不要求必须是 owner）────────────────
	// 注意：不在此处解析镜像 ID（避免同步调用上游导致死锁）
	switch action {
	case ActionPush, ActionTag:
		imageRef := extractImageID(r.URL.Path)
		if imageRef == "" {
			break
		}
		// 尝试原始引用和加 sha256: 前缀两种方式
		if !p.db.CanUseImage(id.RealUID, imageRef) && !p.db.CanUseImage(id.RealUID, "sha256:"+imageRef) {
			logAuthzDeniedImageAccess(p.logger, id, truncID(imageRef), action, "image_not_permitted")
			http.Error(w,
				fmt.Sprintf("user '%s'(uid=%d) not permitted to %s image '%s'",
					id.RealUsername, id.RealUID, action, truncID(imageRef)),
				http.StatusForbidden)
			return false
		}
	}
	return true
}

// preprocessRequest 修改请求（注入标签等）
func (p *ProxyServer) preprocessRequest(r *http.Request, id *CallerIdentity, action string) (*http.Request, error) {
	if action != ActionCreateContainer {
		return r, nil
	}

	// 读取请求体
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return r, fmt.Errorf("read body: %w", err)
	}

	// 注入系统标签
	modified, err := injectSystemLabels(body, id)
	if err != nil {
		modified = body // 注入失败原样使用
	}

	// 重建请求
	newReq := r.Clone(r.Context())
	newReq.Body = io.NopCloser(bytes.NewReader(modified))
	newReq.ContentLength = int64(len(modified))
	return newReq, nil
}

// forward 将请求转发到上游 dockerd
func (p *ProxyServer) forward(r *http.Request) (*http.Response, error) {
	// 构建上游 URL（http://docker/ 作为虚拟主机，实际通过 Unix socket 连接）
	upstreamURL := &url.URL{
		Scheme:   "http",
		Host:     "docker",
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), r.Body)
	if err != nil {
		return nil, err
	}

	// 复制原始请求头
	for k, vals := range r.Header {
		for _, v := range vals {
			outReq.Header.Add(k, v)
		}
	}
	outReq.ContentLength = r.ContentLength

	return p.transport.RoundTrip(outReq)
}

// postprocessResponse 处理上游响应：过滤列表、记录归属
func (p *ProxyServer) postprocessResponse(w http.ResponseWriter, resp *http.Response,
	id *CallerIdentity, action, requestURI string) {

	switch action {
	case ActionPS:
		// 过滤容器列表
		p.logger.Debug("filter_containers_start",
			zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
		)
		body, err := readFullBody(resp.Body)
		if err != nil {
			p.logger.Error("read_response_body_failed",
				zap.String("action", "ps"),
				zap.Error(err))
			http.Error(w, "read upstream response failed", http.StatusBadGateway)
			return
		}
		p.logger.Debug("filter_containers_before",
			zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
			zap.Int("body_size", len(body)),
		)
		filtered, err := filterContainerListResponse(body, id.RealUID, p.db)
		if err != nil {
			p.logger.Error("filter_containers_failed",
				zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
				zap.Error(err))
			filtered = emptyJSONArray // fail-secure：过滤失败返回空列表
		}
		p.logger.Debug("filter_containers_done",
			zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
			zap.Int("original_size", len(body)),
			zap.Int("filtered_size", len(filtered)),
		)
		copyHeaders(w, resp.Header)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(filtered)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(filtered)

	case ActionImages:
		// 过滤镜像列表
		body, err := readFullBody(resp.Body)
		if err != nil {
			http.Error(w, "read upstream response failed", http.StatusBadGateway)
			return
		}
		filtered, err := filterImageListResponse(body, id.RealUID, p.db)
		if err != nil {
			p.logger.Error("filter_images_failed",
				zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
				zap.Error(err))
			filtered = emptyJSONArray // fail-secure：过滤失败返回空列表
		}
		copyHeaders(w, resp.Header)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(filtered)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(filtered)

	case ActionCreateContainer:
		// 从响应中提取容器 ID 并记录归属
		p.logger.Debug("create_container_response",
			zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
			zap.Int("status_code", resp.StatusCode),
		)
		body, err := readFullBody(resp.Body)
		if err != nil {
			p.logger.Error("read_response_body_failed",
				zap.String("action", "create"),
				zap.Error(err))
			http.Error(w, "read upstream response failed", http.StatusBadGateway)
			return
		}
		if resp.StatusCode == http.StatusCreated {
			containerID := extractContainerIDFromCreateResponse(body)
			p.logger.Debug("extract_container_id",
				zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
				zap.String("container_id", containerID),
			)
			if containerID != "" {
				p.logger.Debug("set_container_owner_start",
					zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
					zap.String("container_id", truncID(containerID)),
				)
				if err := p.db.SetContainerOwner(containerID, id); err != nil {
					p.logger.Error("save_container_owner_failed",
						zap.String("container_id", containerID),
						zap.String("real_username", id.RealUsername),
						zap.Int("real_uid", id.RealUID),
						zap.Error(err))
				} else {
					p.logger.Debug("set_container_owner_done",
						zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
						zap.String("container_id", truncID(containerID)),
					)
					p.logger.Info("container_created",
						append(logIdentityFields(id),
							zap.String("container_id", truncID(containerID)),
						)...)
				}
			}
		}
		// 关键修复：确保 Content-Length 正确
		copyHeaders(w, resp.Header)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)

	case ActionLoad:
		// 流式转发 load 输出，捕获加载的镜像 ID 并记录归属
		copyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		if resp.StatusCode == http.StatusOK {
			imageIDs := streamAndCaptureLoadedImageIDs(w, resp)
			for _, imageID := range imageIDs {
				if err := p.db.SetImageOwner(imageID, id, false, "load"); err != nil {
					p.logger.Error("save_image_owner_failed",
						zap.String("image_id", imageID),
						zap.String("real_username", id.RealUsername),
						zap.Int("real_uid", id.RealUID),
						zap.Error(err))
				} else {
					p.logger.Info("image_loaded",
						append(logIdentityFields(id),
							zap.String("image_id", truncID(imageID)),
						)...)
				}
			}
		} else {
			_, _ = io.Copy(w, resp.Body)
		}

	case ActionPrune:
		// 清理成功时从 DB 中删除归属记录
		body, err := readFullBody(resp.Body)
		if err != nil {
			http.Error(w, "read upstream response failed", http.StatusBadGateway)
			return
		}
		if resp.StatusCode == http.StatusOK {
			if strings.HasPrefix(requestURI, "/containers") || strings.Contains(requestURI, "/containers/") {
				// docker container prune：{"ContainersDeleted": ["id1", "id2", ...]}
				var pruneResp struct {
					ContainersDeleted []string `json:"ContainersDeleted"`
				}
				if json.Unmarshal(body, &pruneResp) == nil {
					for _, cid := range pruneResp.ContainersDeleted {
						_ = p.db.DeleteContainer(cid)
					}
				}
			} else if strings.HasPrefix(requestURI, "/images") || strings.Contains(requestURI, "/images/") ||
				strings.HasPrefix(requestURI, "/build") {
				// docker image prune / builder prune：{"ImagesDeleted": [{"Deleted":"sha256:..."}]}
				var pruneResp struct {
					ImagesDeleted []struct {
						Deleted  string `json:"Deleted"`
						Untagged string `json:"Untagged"`
					} `json:"ImagesDeleted"`
				}
				if json.Unmarshal(body, &pruneResp) == nil {
					for _, img := range pruneResp.ImagesDeleted {
						if img.Deleted != "" {
							_ = p.db.DeleteImage(img.Deleted)
						}
					}
				}
			}
		}
		copyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)

	case ActionStartContainer, ActionRestart, ActionStop:
		// 容器启动/重启/停止：透明转发
		copyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)

	case ActionRemoveContainer:
		// 删除成功时清除归属记录
		if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
			containerID := extractContainerID(requestURI)
			if containerID != "" {
				_ = p.db.DeleteContainer(containerID)
			}
		}
		copyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)

	case ActionPull:
		// 流式转发 pull 输出；manifest digest ≠ 本地镜像 ID，不能直接用
		copyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		streamAndCaptureImageID(w, resp, "pull")
		if resp.StatusCode == http.StatusOK {
			// pull 完成后通过 GET /images/{ref}/json 查询真实镜像内容 ID
			imageRef := parseImageRefFromURI(requestURI)
			if imageRef != "" {
				if imageID := p.resolveImageIDByRef(imageRef); imageID != "" {
					// 先尝试设置 owner（如果是新镜像，第一个拉取的用户成为 owner）
					if err := p.db.SetImageOwner(imageID, id, false, "pull"); err != nil {
						p.logger.Error("save_image_owner_failed",
							zap.String("image_id", imageID),
							zap.String("real_username", id.RealUsername),
							zap.Int("real_uid", id.RealUID),
							zap.Error(err))
					}
					// 确保当前用户有访问权限（即使镜像已存在，也要添加到 image_access）
					if err := p.db.EnsureImageAccess(imageID, id.RealUID); err != nil {
						p.logger.Error("ensure_image_access_failed",
							zap.String("image_id", imageID),
							zap.String("real_username", id.RealUsername),
							zap.Int("real_uid", id.RealUID),
							zap.Error(err))
					} else {
						p.logger.Info("image_pulled",
							append(logIdentityFields(id),
								zap.String("image_id", truncID(imageID)),
								zap.String("image_ref", imageRef),
							)...)
					}
				}
			}
		}

	case ActionBuild:
		// 流式转发 build 输出，结束后提取镜像 ID
		copyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		imageID := streamAndCaptureImageID(w, resp, "build")
		if imageID != "" && resp.StatusCode == http.StatusOK {
			// 先尝试设置 owner（如果是新镜像，构建者成为 owner）
			if err := p.db.SetImageOwner(imageID, id, false, "build"); err != nil {
				p.logger.Error("save_image_owner_failed",
					zap.String("image_id", imageID),
					zap.String("real_username", id.RealUsername),
					zap.Int("real_uid", id.RealUID),
					zap.Error(err))
			}
			// 确保构建者有访问权限（即使 image ID 已存在，也要添加到 image_access）
			// 这处理了极少见的情况：构建结果的 image ID 恰好和已存在的镜像相同
			if err := p.db.EnsureImageAccess(imageID, id.RealUID); err != nil {
				p.logger.Error("ensure_image_access_failed",
					zap.String("image_id", imageID),
					zap.String("real_username", id.RealUsername),
					zap.Int("real_uid", id.RealUID),
					zap.Error(err))
			} else {
				p.logger.Info("image_built",
					append(logIdentityFields(id),
						zap.String("image_id", truncID(imageID)),
					)...)
			}
		}

	case ActionRemoveImage:
		// 镜像删除成功后，从数据库中删除记录
		// 注意：虚拟删除已在 ServeHTTP 中处理，这里只处理真正删除的情况
		if resp.StatusCode == http.StatusOK {
			imageID := extractImageID(requestURI)
			if imageID != "" {
				_ = p.db.DeleteImage(imageID)
				p.logger.Info("image_deleted",
					append(logIdentityFields(id),
						zap.String("image_id", truncID(imageID)),
					)...)
			}
		}
		copyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)

	default:
		// 其他请求：透明转发（含流式响应、exec 等）
		copyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		// 立即 flush 响应头，避免长轮询（如 /wait）阻塞客户端发后续请求
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.Copy(w, resp.Body)
	}

}

// ── 辅助函数 ─────────────────────────────────────────────────

// isAuxiliaryCall 判断当前 API 请求是否为 Docker CLI 的内部辅助调用
//
// 原理：将用户实际执行的 docker 子命令（dockerCmd）与当前 API 对应的 action 对比。
//   - dockerCmd == ""     → 无法解析子命令，保守放行（避免误拦）
//   - /_ping              → 纯健康检查，始终放行
//   - action 与 dockerCmd 对应的 action 匹配 → 用户目标操作，走策略检查
//   - action 与 dockerCmd 不匹配           → CLI 内部辅助调用，直接放行
//
// 例：docker run nginx 执行时调用 GET /info
//   dockerCmd="run", action="info" → 不匹配 → 辅助调用 → 放行
//
// 例：用户主动执行 docker info
//   dockerCmd="info", action="info" → 匹配 → 走策略检查
func isAuxiliaryCall(dockerCmd, action, method, path string) bool {
	// /_ping 始终放行
	if (method == "GET" || method == "HEAD") &&
		(path == "/_ping" || strings.HasSuffix(path, "/_ping")) {
		return true
	}

	// 无法解析子命令（readProcCmdline 失败或进程非 docker）：
	// /info 和 /version 始终是辅助调用，无论是否能解析出子命令都放行。
	// 这样即使 cmdline 读取失败，docker run 等命令也不会因 /info 被意外拦截。
	if dockerCmd == "" {
		if action == ActionSystemInfo {
			return true // info/version 始终是辅助调用
		}
		return false // 其他 action：无法判断，走策略检查
	}

	// dockerCmd → 该子命令执行过程中属于"目标操作"的 action 集合
	// 集合内的 action 走策略检查；不在集合内的是辅助调用，直接放行
	// 注：policy.go 中 ActionStop 覆盖 kill/pause/unpause，ActionLogs 覆盖 stats/top，
	//     ActionExec 覆盖 attach
	cmdTargetActions := map[string][]string{
		"run":     {ActionPull, ActionCreateContainer, ActionStartContainer, ActionRemoveContainer},
		"create":  {ActionCreateContainer},
		"start":   {ActionStartContainer},
		"stop":    {ActionStop},
		"restart": {ActionRestart},
		"kill":    {ActionStop},
		"rm":      {ActionRemoveContainer},
		"exec":    {ActionExec},
		"attach":  {ActionExec},
		"logs":    {ActionLogs},
		"stats":   {ActionLogs},
		"top":     {ActionLogs},
		"cp":      {ActionCp},
		"commit":  {ActionCommit},
		"ps":      {ActionPS},
		"inspect": {ActionInspect},
		"pause":   {ActionStop},
		"unpause": {ActionStop},
		"pull":    {ActionPull},
		"push":    {ActionPush},
		"build":   {ActionBuild},
		"images":  {ActionImages},
		"rmi":     {ActionRemoveImage},
		"tag":     {ActionTag},
		"save":    {ActionSave},
		"load":    {ActionLoad},
		"search":  {ActionSearch},
		"info":    {ActionSystemInfo},
		"version": {ActionSystemInfo},
		"events":  {ActionSystemEvents},
		"login":   {ActionSystemLogin},
		"logout":  {ActionSystemLogin},
		"df":      {ActionSystemDF},
		"prune":   {ActionPrune},
	}

	// info/version 只在用户主动执行 docker info/docker version 时才受策略控制；
	// 其他任何子命令执行过程中调用的 /info、/version 都是辅助调用，无条件放行。
	if action == ActionSystemInfo && dockerCmd != "info" && dockerCmd != "version" {
		return true
	}

	targetActions, known := cmdTargetActions[dockerCmd]
	if !known {
		// 未知子命令，放行（保守策略，避免误拦）
		return false
	}

	// 当前 action 在目标集合内 → 用户目标操作，不是辅助调用
	for _, t := range targetActions {
		if action == t {
			return false // 不是辅助调用
		}
	}
	return true // 不在目标集合内 → 辅助调用，放行
}

// systemUser 从 /etc/passwd 读取的用户信息
type systemUser struct {
	Username string
	UID      int
	GID      int
	HomeDir  string
}

// listSystemUsers 返回 UID >= 0 的所有系统用户（含 root）
func listSystemUsers() []systemUser {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	var users []systemUser
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		uid := 0
		gid := 0
		fmt.Sscanf(fields[2], "%d", &uid)
		fmt.Sscanf(fields[3], "%d", &gid)
		// 只为有 shell 的用户创建 socket（排除 nologin 等系统服务账户）
		shell := ""
		if len(fields) >= 7 {
			shell = strings.TrimSpace(fields[6])
		}
		if shell == "" || strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "false") {
			continue
		}
		homeDir := ""
		if len(fields) >= 6 {
			homeDir = strings.TrimSpace(fields[5])
		}
		users = append(users, systemUser{Username: fields[0], UID: uid, GID: gid, HomeDir: homeDir})
	}
	return users
}

// setUserDockerHost 将 DOCKER_HOST 环境变量写入用户的 ~/.bashrc
func setUserDockerHost(u systemUser, socketDir string, logger *zap.Logger) {
	if u.HomeDir == "" {
		return
	}
	bashrc := filepath.Join(u.HomeDir, ".bashrc")
	sockPath := "unix://" + filepath.Join(socketDir, u.Username+".sock")
	exportLine := fmt.Sprintf("export DOCKER_HOST=%s", sockPath)
	marker := "# docker-authz-proxy: DOCKER_HOST"

	// 读取现有内容，检查是否已设置
	existing, err := os.ReadFile(bashrc)
	if err == nil && strings.Contains(string(existing), marker) {
		return // 已存在，跳过
	}

	f, err := os.OpenFile(bashrc, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logger.Warn("failed to write DOCKER_HOST to bashrc",
			zap.String("username", u.Username),
			zap.String("bashrc", bashrc),
			zap.Error(err))
		return
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "\n%s\n%s\n", marker, exportLine)
	if err != nil {
		logger.Warn("failed to write DOCKER_HOST to bashrc",
			zap.String("username", u.Username),
			zap.Error(err))
		return
	}

	// 设置文件归属为该用户
	_ = os.Chown(bashrc, u.UID, u.GID)

	logger.Info("set DOCKER_HOST in bashrc",
		zap.String("username", u.Username),
		zap.String("bashrc", bashrc),
		zap.String("docker_host", sockPath))
}

// extractImageRefFromBody 从请求体中提取 Image 字段
func extractImageRefFromBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return ""
	}
	// 重新设置 Body 供后续读取
	r.Body = io.NopCloser(bytes.NewReader(body))

	var req struct {
		Image string `json:"Image"`
	}
	_ = json.Unmarshal(body, &req)
	return req.Image
}

// truncID 截取容器/镜像 ID 前 12 位用于日志显示
func truncID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// parseImageRefFromURI 从 docker pull 的请求 URI 中提取镜像引用
// docker pull 对应 POST /images/create?fromImage=nginx&tag=latest
func parseImageRefFromURI(requestURI string) string {
	idx := strings.Index(requestURI, "?")
	if idx < 0 {
		return ""
	}
	params, err := url.ParseQuery(requestURI[idx+1:])
	if err != nil {
		return ""
	}
	fromImage := params.Get("fromImage")
	if fromImage == "" {
		return ""
	}
	if tag := params.Get("tag"); tag != "" && tag != "latest" {
		return fromImage + ":" + tag
	}
	return fromImage
}

// resolveImageIDByRef 查询 dockerd 获取镜像的真实内容 ID（sha256:...）
// pull 流中返回的 manifest digest ≠ 本地镜像 ID，需要额外查询
func (p *ProxyServer) resolveImageIDByRef(imageRef string) string {
	upstreamURL := &url.URL{
		Scheme: "http",
		Host:   "docker",
		Path:   "/images/" + imageRef + "/json",
	}
	req, err := http.NewRequest("GET", upstreamURL.String(), nil)
	if err != nil {
		return ""
	}
	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var img struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&img); err != nil {
		return ""
	}
	return img.ID
}

// ── Hijack（双向流）处理 ─────────────────────────────────────
//
// docker run -it / docker attach / docker exec -it 使用 HTTP Hijack：
// 客户端发送带 Upgrade: tcp 的请求，服务端返回 101 Switching Protocols，
// 之后连接退化为原始 TCP 双向管道（stdin↔stdout/stderr）。
//
// 标准 http.Transport 不支持这种协议升级，必须直接操作底层连接。

// isHijackRequest 判断请求是否需要 HTTP hijack（双向流）
//
// Docker CLI 在以下两种情况下需要 hijack：
//  1. attach：POST /containers/{id}/attach?stream=1&stdin=1
//     请求头：Connection: Upgrade, Upgrade: tcp
//  2. exec-start：POST /exec/{id}/start（body 中 Detach=false）
//     请求头同上
//
// 检测方式：优先看 Upgrade 头，再看路径（兜底，防止头部格式不一致）
func isHijackRequest(r *http.Request) bool {
	// 检查 Upgrade: tcp（最可靠）
	if strings.EqualFold(r.Header.Get("Upgrade"), "tcp") {
		return true
	}
	// Connection 头可能是多值逗号分隔，需逐一检查
	for _, v := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}
	// 路径兜底：attach 和 exec/start 路径一定需要 hijack（当 stdin=true 时）
	path := stripAPIVersion(r.URL.Path)
	if r.Method == "POST" {
		if strings.HasSuffix(path, "/attach") {
			return true
		}
		if strings.Contains(path, "/exec/") && strings.HasSuffix(path, "/start") {
			return true
		}
	}
	return false
}

// handleHijack 处理需要双向流的请求（attach/exec-start 等）
// 流程：
//  1. 执行授权检查（命令策略 + 容器归属）
//  2. 劫持客户端连接（获得底层 TCP）
//  3. 直接 dial 上游 dockerd Unix socket
//  4. 手工写入 HTTP 请求
//  5. 双向 io.Copy（goroutine）
func (p *ProxyServer) handleHijack(w http.ResponseWriter, r *http.Request, id *CallerIdentity) {
	action := classifyAction(r.Method, r.URL.Path)
	p.logger.Debug("hijack_request",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
		zap.String("action", action),
		zap.String("uri", r.URL.RequestURI()),
	)

	// 授权检查（与普通请求相同的策略 + 归属逻辑）
	policy := p.getPolicy()
	isAuxiliary := isAuxiliaryCall(id.DockerCommand, action, r.Method, r.URL.Path)
	if !isAuxiliary && policy.IsDenied(id, action) {
		p.logger.Warn("AUTHZ_DENY",
			append(logIdentityFields(id),
				zap.String("reason", "command_not_permitted"),
				zap.String("action", action),
				zap.String("uri", r.URL.RequestURI()),
			)...)
		http.Error(w, fmt.Sprintf("user '%s'(uid=%d) not permitted to perform: %s",
			id.RealUsername, id.RealUID, action), http.StatusForbidden)
		return
	}
	if !p.checkOwnershipPreRequest(w, r, id, action) {
		return
	}

	// 1. 劫持客户端连接
	p.logger.Debug("hijack_step1_start", zap.String("step", "hijack_client"))
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.logger.Error("hijack_not_supported")
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		p.logger.Error("hijack_failed", zap.Error(err))
		http.Error(w, "hijack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()
	p.logger.Debug("hijack_step1_done", zap.String("step", "client_hijacked"))

	// 2. 直接连接上游 dockerd
	p.logger.Debug("hijack_step2_start", zap.String("step", "dial_upstream"))
	upstreamConn, err := net.DialTimeout("unix", p.upstreamSock, 5*time.Second)
	if err != nil {
		p.logger.Error("upstream_dial_failed", zap.Error(err))
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\nupstream dial failed: %s", err.Error())
		return
	}
	defer upstreamConn.Close()
	p.logger.Debug("hijack_step2_done", zap.String("step", "upstream_connected"))

	// 3. 手工重建 HTTP 请求并发给上游（直接写入，不使用缓冲）
	p.logger.Debug("hijack_step3_start", zap.String("step", "forward_request"))
	var reqBuilder strings.Builder
	fmt.Fprintf(&reqBuilder, "%s %s HTTP/1.1\r\n", r.Method, r.URL.RequestURI())
	fmt.Fprintf(&reqBuilder, "Host: docker\r\n")
	for k, vals := range r.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&reqBuilder, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&reqBuilder, "\r\n")

	if _, err := upstreamConn.Write([]byte(reqBuilder.String())); err != nil {
		p.logger.Error("write_request_failed", zap.Error(err))
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\nwrite request failed: %s", err.Error())
		return
	}

	if clientBuf.Reader.Buffered() > 0 {
		n := clientBuf.Reader.Buffered()
		buffered := make([]byte, n)
		io.ReadFull(clientBuf.Reader, buffered)
		upstreamConn.Write(buffered)
	}
	p.logger.Debug("hijack_step3_done", zap.String("step", "request_forwarded"))

	// 3.5. 读取并立即转发上游的 101 响应（确保客户端收到后才启动双向复制）
	p.logger.Debug("hijack_step3_5_start", zap.String("step", "forward_101_response"))
	// 读取上游响应的第一行（HTTP/1.1 101 Switching Protocols）
	upstreamReader := bufio.NewReader(upstreamConn)
	statusLine, err := upstreamReader.ReadString('\n')
	if err != nil {
		p.logger.Error("read_upstream_status_failed", zap.Error(err))
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\nread upstream status failed: %s", err.Error())
		return
	}
	// 立即写给客户端
	if _, err := clientConn.Write([]byte(statusLine)); err != nil {
		p.logger.Error("write_status_to_client_failed", zap.Error(err))
		return
	}
	p.logger.Debug("hijack_status_line_forwarded", zap.String("status", strings.TrimSpace(statusLine)))

	// 读取并转发响应头（直到空行）
	for {
		line, err := upstreamReader.ReadString('\n')
		if err != nil {
			p.logger.Error("read_upstream_header_failed", zap.Error(err))
			return
		}
		if _, err := clientConn.Write([]byte(line)); err != nil {
			p.logger.Error("write_header_to_client_failed", zap.Error(err))
			return
		}
		if line == "\r\n" || line == "\n" {
			break // 空行表示响应头结束
		}
	}
	p.logger.Debug("hijack_step3_5_done", zap.String("step", "101_response_forwarded"))

	// 4. 双向 io.Copy（上游↔客户端）
	p.logger.Debug("hijack_step4_start", zap.String("step", "start_bidirectional_copy"))
	done := make(chan struct{}, 2)
	go func() {
		n, err := io.Copy(upstreamConn, clientConn)
		p.logger.Debug("hijack_copy_client_to_upstream_done", zap.Int64("bytes", n), zap.Error(err))
		upstreamConn.Close() // 通知另一方向退出
		done <- struct{}{}
	}()
	go func() {
		// 使用 upstreamReader 而非 upstreamConn，避免丢失响应头后的缓冲数据
		n, err := io.Copy(clientConn, upstreamReader)
		p.logger.Debug("hijack_copy_upstream_to_client_done", zap.Int64("bytes", n), zap.Error(err))
		clientConn.Close() // 通知另一方向退出
		done <- struct{}{}
	}()
	<-done
	<-done // 等待两个方向都完成

	p.logger.Debug("hijack_done",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
		zap.String("action", action),
	)
}

