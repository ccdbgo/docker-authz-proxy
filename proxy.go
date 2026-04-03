package main

import (
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
			return net.Dial("unix", upstreamSock)
		},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true, // 避免压缩干扰响应体解析
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
	// 从 context 中获取调用方身份
	identity, _ := r.Context().Value(identityContextKey).(*CallerIdentity)
	if identity == nil || identity.RealUID < 0 {
		http.Error(w, "identity resolution failed", http.StatusInternalServerError)
		return
	}

	action := classifyAction(r.Method, r.URL.Path)

	// INFO 日志：记录每次请求（所有操作均记录）
	p.logger.Info("authz_request",
		append(logIdentityFields(identity),
			zap.String("action", action),
			zap.String("http_method", r.Method),
			zap.String("http_uri", r.URL.RequestURI()),
		)...)

	// 获取当前策略（线程安全）
	policy := p.getPolicy()

	// ── 层次一：命令授权检查 ──────────────────────────────────
	if policy.IsDenied(identity, action) {
		p.logger.Warn("authz_denied_command",
			append(logIdentityFields(identity),
				zap.String("reason", "command_not_permitted"),
				zap.String("action", action),
				zap.String("http_method", r.Method),
				zap.String("http_uri", r.URL.RequestURI()),
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

	// ── 转发到上游 dockerd ───────────────────────────────────
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

	// ── 响应后处理（过滤列表、记录归属）─────────────────────
	p.postprocessResponse(w, resp, identity, action, r.URL.RequestURI())

	// INFO 日志：所有授权通过的操作均记录
	p.logger.Info("authz_allowed",
		append(logIdentityFields(identity),
			zap.String("action", action),
			zap.String("http_uri", r.URL.RequestURI()),
		)...)
}

// checkOwnershipPreRequest 请求前的资源归属检查
// 返回 false 表示已拒绝并写入响应
func (p *ProxyServer) checkOwnershipPreRequest(w http.ResponseWriter, r *http.Request,
	id *CallerIdentity, action string) bool {

	// ── 通用容器归属检查（覆盖所有 /containers/{id}/... 操作）────────────
	// 只要路径中有容器 ID（且不是 /containers/json 列表接口），就验证归属
	containerID := extractContainerID(r.URL.Path)
	if containerID != "" && containerID != "json" {
		owner, found := p.db.GetContainerOwner(containerID)
		if found && owner.UID != id.RealUID {
			p.logger.Warn("authz_denied_ownership",
				append(logIdentityFields(id),
					append(logOwnerFields("owner", owner),
						zap.String("reason", "not_your_container"),
						zap.String("container_id", containerID),
						zap.String("action", action),
					)...)...)
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
			if found && owner.UID != id.RealUID {
				p.logger.Warn("authz_denied_ownership",
					append(logIdentityFields(id),
						append(logOwnerFields("owner", owner),
							zap.String("reason", "not_your_container"),
							zap.String("container_id", qContainerID),
							zap.String("action", action),
						)...)...)
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
	if action == ActionCreateContainer {
		imageRef := extractImageRefFromBody(r)
		if imageRef != "" {
			if !p.db.CanUseImage(id.RealUID, imageRef) {
				p.logger.Warn("authz_denied_image_access",
					append(logIdentityFields(id),
						zap.String("reason", "image_not_permitted"),
						zap.String("image_ref", imageRef),
					)...)
				http.Error(w,
					fmt.Sprintf("user '%s'(uid=%d) not permitted to use image '%s'",
						id.RealUsername, id.RealUID, imageRef),
					http.StatusForbidden)
				return false
			}
		}
	}

	// ── 镜像 inspect：验证查看权限 ──────────────────────────────────────
	if action == ActionInspect {
		if imageID := extractImageID(r.URL.Path); imageID != "" {
			if !p.db.CanUseImage(id.RealUID, imageID) {
				p.logger.Warn("authz_denied_image_access",
					append(logIdentityFields(id),
						zap.String("reason", "image_not_permitted"),
						zap.String("image_id", imageID),
						zap.String("action", action),
					)...)
				http.Error(w,
					fmt.Sprintf("user '%s'(uid=%d) not permitted to inspect image '%s'",
						id.RealUsername, id.RealUID, truncID(imageID)),
					http.StatusForbidden)
				return false
			}
		}
	}

	// ── 镜像删除/推送/标记：验证归属 ────────────────────────────────────
	switch action {
	case ActionRemoveImage, ActionPush, ActionTag:
		imageID := extractImageID(r.URL.Path)
		if imageID == "" {
			break
		}
		owner, isPublic, found := p.db.GetImageOwner(imageID)
		if !found {
			break // 不在 DB 中，放行
		}
		if isPublic {
			// 公共镜像只有 root 可以删除
			if action == ActionRemoveImage && id.RealUID != 0 {
				http.Error(w, "public images can only be removed by root", http.StatusForbidden)
				return false
			}
			break
		}
		if owner.UID != id.RealUID {
			p.logger.Warn("authz_denied_ownership",
				append(logIdentityFields(id),
					append(logOwnerFields("owner", owner),
						zap.String("reason", "not_your_image"),
						zap.String("image_id", imageID),
						zap.String("action", action),
					)...)...)
			http.Error(w,
				fmt.Sprintf("image '%s' belongs to '%s'(uid=%d)",
					truncID(imageID), owner.Username, owner.UID),
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
		body, err := readFullBody(resp.Body)
		if err != nil {
			http.Error(w, "read upstream response failed", http.StatusBadGateway)
			return
		}
		filtered, err := filterContainerListResponse(body, id.RealUID, p.db)
		if err != nil {
			filtered = body
		}
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
			filtered = body
		}
		copyHeaders(w, resp.Header)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(filtered)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(filtered)

	case ActionCreateContainer:
		// 从响应中提取容器 ID 并记录归属
		body, err := readFullBody(resp.Body)
		if err != nil {
			http.Error(w, "read upstream response failed", http.StatusBadGateway)
			return
		}
		if resp.StatusCode == http.StatusCreated {
			if containerID := extractContainerIDFromCreateResponse(body); containerID != "" {
				if err := p.db.SetContainerOwner(containerID, id); err != nil {
					p.logger.Error("save_container_owner_failed",
						zap.String("container_id", containerID),
						zap.String("real_username", id.RealUsername),
						zap.Int("real_uid", id.RealUID),
						zap.Error(err))
				} else {
					p.logger.Info("container_created",
						append(logIdentityFields(id),
							zap.String("container_id", truncID(containerID)),
						)...)
				}
			}
		}
		copyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)

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
					if err := p.db.SetImageOwner(imageID, id, false, "pull"); err != nil {
						p.logger.Error("save_image_owner_failed",
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
			if err := p.db.SetImageOwner(imageID, id, false, "build"); err != nil {
				p.logger.Error("save_image_owner_failed",
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
		// 删除成功时清除归属记录
		if resp.StatusCode == http.StatusOK {
			imageID := extractImageID(requestURI)
			if imageID != "" {
				_ = p.db.DeleteImage(imageID)
			}
		}
		copyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)

	default:
		// 其他请求：透明转发（含流式响应、exec 等）
		copyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}

}

// ── 辅助函数 ─────────────────────────────────────────────────

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

