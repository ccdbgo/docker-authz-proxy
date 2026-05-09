package forward

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
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

	"docker-authz-proxy/internal/audit"
	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
	"docker-authz-proxy/internal/isolation"

	"go.uber.org/zap"
)

// ErrPeerNotFound 表示撤销互通时指定的用户对不存在互通记录。
var ErrPeerNotFound = fmt.Errorf("peer record not found")

// contextKey 用于在 request context 中传递 CallerIdentity
type contextKey string

const (
	identityContextKey  contextKey = "caller_identity"
	resourceUsageCtxKey contextKey = "resource_usage"
	portMappingsCtxKey  contextKey = "port_mappings" // []isolation.PortMapping，容器创建时传递
	rewrittenNameCtxKey contextKey = "rewritten_name" // 容器名称改写后的值，供审计使用
)

// ProxyServer 每用户 Unix socket 代理，内置授权逻辑
type ProxyServer struct {
	socketDir      string
	upstreamSock   string
	policy         *authz.Policy
	db             *authz.OwnershipDB
	logger         *zap.Logger
	quota          *isolation.QuotaManager
	auditLog       *audit.AuditLogger
	authenticators []auth.Authenticator
	bridge         *isolation.BridgeManager  // 用户桥接网络管理
	storage        *isolation.StorageManager // 用户存储资源管理
	storageBase    string                    // 用户存储根目录

	// requestTimeout 单请求超时（含上游响应），0 表示不限制
	requestTimeout time.Duration
	// semaphore 并发信号量，nil 表示不限制
	semaphore chan struct{}

	mu        sync.Mutex
	listeners map[string]net.Listener
	servers   []*http.Server

	transport http.RoundTripper
}

// ProxyOptions 可选配置参数
type ProxyOptions struct {
	// RequestTimeout 单个请求的最大处理时间（含等待上游响应），0 表示不限制，建议 30s
	RequestTimeout time.Duration
	// MaxConcurrent 全局最大并发请求数，0 表示不限制，建议 100
	MaxConcurrent int
	// StorageBase 用户存储根目录，默认 /var/docker/user-storage
	StorageBase string
	// StorageCleanupInterval 定期清理孤立 Volume 的间隔，0 表示不启用清理，建议 5m
	StorageCleanupInterval time.Duration
}

func NewProxyServer(socketDir, upstreamSock string, policy *authz.Policy, db *authz.OwnershipDB,
	logger *zap.Logger, quota *isolation.QuotaManager, auditLog *audit.AuditLogger,
	authenticators []auth.Authenticator, opts ProxyOptions) *ProxyServer {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "unix", upstreamSock)
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableCompression:    true,
	}

	var sem chan struct{}
	if opts.MaxConcurrent > 0 {
		sem = make(chan struct{}, opts.MaxConcurrent)
	}

	storageBase := opts.StorageBase
	if storageBase == "" {
		storageBase = isolation.DefaultStorageBase
	}

	return &ProxyServer{
		socketDir:      socketDir,
		upstreamSock:   upstreamSock,
		policy:         policy,
		db:             db,
		logger:         logger,
		quota:          quota,
		auditLog:       auditLog,
		authenticators: authenticators,
		bridge:         isolation.NewBridgeManager(upstreamSock),
		storageBase:    storageBase,
		storage:        isolation.NewStorageManager(storageBase, upstreamSock),
		requestTimeout: opts.RequestTimeout,
		semaphore:      sem,
		listeners:      make(map[string]net.Listener),
		transport:      transport,
	}
}

// Start 为所有系统用户创建 per-user 监听 socket 并启动 HTTP 服务
func (p *ProxyServer) Start() error {
	if err := os.MkdirAll(p.socketDir, 0711); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	// 顶层目录 root 拥有，711：用户可进入子目录但无法列举
	if err := os.Chmod(p.socketDir, 0711); err != nil {
		return fmt.Errorf("chmod socket dir: %w", err)
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
			p.ensureUserBridge(u)
			p.ensureUserStorageDir(u)
		}
	}

	go p.watchNewUsers()
	return nil
}

func (p *ProxyServer) watchNewUsers() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		users := listSystemUsers()
		for _, u := range users {
			p.mu.Lock()
			_, exists := p.listeners[u.Username]
			p.mu.Unlock()

			if !exists {
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
					p.ensureUserBridge(u)
					p.ensureUserStorageDir(u)
				}
			}
		}
	}
}

// userSockPath 返回用户专属 socket 路径（子目录隔离）
// 路径格式：<socketDir>/<username>/docker.sock
// 子目录权限 700 且属主为该用户，其他用户无法进入
func (p *ProxyServer) userSockPath(u systemUser) string {
	return filepath.Join(p.socketDir, u.Username, "docker.sock")
}

func (p *ProxyServer) startUserListener(u systemUser) error {
	// 为每个用户创建独立子目录，权限 700，属主为该用户
	userDir := filepath.Join(p.socketDir, u.Username)
	if err := os.MkdirAll(userDir, 0700); err != nil {
		return fmt.Errorf("create user socket dir: %w", err)
	}
	if err := os.Chown(userDir, u.UID, u.GID); err != nil {
		return fmt.Errorf("chown user socket dir: %w", err)
	}
	if err := os.Chmod(userDir, 0700); err != nil {
		return fmt.Errorf("chmod user socket dir: %w", err)
	}

	sockPath := p.userSockPath(u)
	_ = os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

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
		Handler:      p,
		ReadTimeout:  p.requestTimeout,
		WriteTimeout: p.requestTimeout,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			clientAddr := c.RemoteAddr().String()
			p.logger.Debug("new_connection",
				zap.String("socket", sockPath),
				zap.String("remote", clientAddr),
			)
			identity, err := auth.ResolveCallerIdentity(c)
			if err != nil {
				isForgery := auth.IsIdentityForgery(err)
				event := "auth_failure"
				if isForgery {
					event = "auth_forgery"
					p.logger.Warn("identity_forgery_at_connect",
						zap.String("socket", sockPath),
						zap.Error(err))
				} else {
					p.logger.Error("identity resolution failed",
						zap.String("socket", sockPath),
						zap.Error(err))
				}
				p.auditLog.LogAuth(audit.AuthAuditEntry{
					Event:          event,
					ClientAddr:     clientAddr,
					EffectiveUID:   -1,
					LoginUID:       -1,
					RealUID:        -1,
					PasswdVerified: false,
					FailureReason:  err.Error(),
					ForgeryDetail:  func() string {
						if isForgery {
							return err.Error()
						}
						return ""
					}(),
				})
				// RealUID=-1 causes ServeHTTP to reject with 401/403
				identity = &auth.CallerIdentity{
					RealUsername:      "unknown",
					RealUID:           -1,
					UserType:          auth.UserTypeRegular,
					EffectiveUsername: "unknown",
					LoginUID:          -1,
				}
			} else {
				switchType := ""
				if identity.SwitchedIdentity {
					if identity.EffectiveUID == 0 {
						switchType = "sudo"
					} else {
						switchType = "su"
					}
				}
				p.logger.Debug("identity_resolved",
					zap.String("user", identity.RealUsername),
					zap.Int("uid", identity.RealUID),
					zap.Int("login_uid", identity.LoginUID),
					zap.Bool("switched", identity.SwitchedIdentity),
					zap.String("cmdline", identity.CmdLine),
				)
				p.auditLog.LogAuth(audit.AuthAuditEntry{
					Event:             "auth_success",
					PID:               identity.PID,
					ClientAddr:        clientAddr,
					EffectiveUID:      identity.EffectiveUID,
					EffectiveUsername: identity.EffectiveUsername,
					LoginUID:          identity.LoginUID,
					LoginUsername:     identity.LoginUsername,
					RealUID:           identity.RealUID,
					RealUsername:      identity.RealUsername,
					SwitchedIdentity:  identity.SwitchedIdentity,
					SwitchType:        switchType,
					PasswdVerified:    true,
				})
			}
			identity.ClientAddr = clientAddr
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
func (p *ProxyServer) UpdatePolicy(newPolicy *authz.Policy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policy = newPolicy
}

func (p *ProxyServer) getPolicy() *authz.Policy {
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
	for path := range p.listeners {
		sockPath := filepath.Join(p.socketDir, path, "docker.sock")
		_ = os.Remove(sockPath)
	}
	if p.auditLog != nil {
		p.auditLog.Close()
	}
}

// StartTCPListener 启动 TCP 监听器（用于 JWT/mTLS 认证）
func (p *ProxyServer) StartTCPListener(addr string, tlsCfg *tls.Config) error {
	var ln net.Listener
	var err error
	if tlsCfg != nil {
		ln, err = tls.Listen("tcp", addr, tlsCfg)
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("tcp listen %s: %w", addr, err)
	}

	srv := &http.Server{
		Handler:      p,
		ReadTimeout:  p.requestTimeout,
		WriteTimeout: p.requestTimeout,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, identityContextKey, &auth.CallerIdentity{
				RealUID:    -1,
				UserType:   auth.UserTypeRegular,
				ClientAddr: c.RemoteAddr().String(),
			})
		},
	}

	p.mu.Lock()
	p.servers = append(p.servers, srv)
	p.mu.Unlock()

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			p.logger.Error("tcp server error", zap.String("addr", addr), zap.Error(err))
		}
	}()

	p.logger.Info("tcp listener started", zap.String("addr", addr), zap.Bool("tls", tlsCfg != nil))
	return nil
}

// ServeHTTP 是每个请求的入口：并发控制 + 授权 + 代理
func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 并发限制：信号量满时直接返回 503，避免请求堆积
	if p.semaphore != nil {
		select {
		case p.semaphore <- struct{}{}:
			defer func() { <-p.semaphore }()
		default:
			p.logger.Warn("concurrency_limit_reached",
				zap.Int("limit", cap(p.semaphore)),
				zap.String("uri", r.URL.RequestURI()),
			)
			writeDockerError(w, http.StatusServiceUnavailable, "server busy, please retry later")
			return
		}
	}

	p.logger.Debug("http_request_received",
		zap.String("method", r.Method),
		zap.String("uri", r.URL.RequestURI()),
		zap.String("proto", r.Proto),
		zap.String("upgrade", r.Header.Get("Upgrade")),
		zap.String("connection", r.Header.Get("Connection")),
	)

	identity, _ := r.Context().Value(identityContextKey).(*auth.CallerIdentity)

	if identity == nil || identity.RealUID < 0 {
		for _, authenticator := range p.authenticators {
			id, err := authenticator.Authenticate(r)
			if err != nil {
				p.logger.Warn("authenticator error", zap.Error(err))
				continue
			}
			if id != nil {
				identity = id
				break
			}
		}
	}

	if identity == nil || identity.RealUID < 0 {
		clientIP := ""
		if identity != nil {
			clientIP = identity.ClientAddr
		}
		p.logger.Warn("authentication_required",
			zap.String("remote", r.RemoteAddr),
			zap.String("uri", r.URL.RequestURI()))
		p.auditLog.WriteEntry(audit.AuditEntry{
			User:       "unknown",
			UID:        -1,
			ClientIP:   clientIP,
			Method:     r.Method,
			Action:     "unknown",
			URI:        r.URL.RequestURI(),
			Result:     "deny",
			DenyReason: "authentication_required",
			StatusCode: http.StatusUnauthorized,
		})
		writeDockerError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// 每次请求重新验证进程 UID，防止连接建立后通过 setuid 提权
	if err := auth.VerifyIdentityAtRequest(identity); err != nil {
		p.logger.Warn("identity_mutation_detected",
			zap.String("user", identity.RealUsername),
			zap.Int("uid", identity.RealUID),
			zap.Int("pid", identity.PID),
			zap.Error(err))
		e := makeAuditEntry(identity, r, "unknown", "deny", "identity_mutation", err.Error(), http.StatusForbidden)
		p.auditLog.WriteEntry(e)
		writeDockerError(w, http.StatusForbidden, "identity verification failed")
		return
	}

	if isHijackRequest(r) {
		p.logger.Debug("hijack_detected",
			zap.String("user", fmt.Sprintf("%s(uid=%d)", identity.RealUsername, identity.RealUID)),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("upgrade", r.Header.Get("Upgrade")),
			zap.String("connection", r.Header.Get("Connection")),
		)
		// 在进入 hijack 之前先做策略检查：此时连接尚未升级，ResponseWriter 仍可
		// 写普通 HTTP 响应，Docker CLI 能正确解析并显示 "Error response from daemon: ..."
		hijackAction := authz.ClassifyAction(r.Method, r.URL.RequestURI())
		hijackPolicy := p.getPolicy()
		if !isAuxiliaryCall(identity.DockerCommand, hijackAction, r.Method, r.URL.Path) &&
			hijackPolicy.IsDenied(identity, hijackAction) {
			auditID := toAuditIdentity(identity)
			audit.LogAuthzDeniedCommand(p.logger, auditID, hijackAction, r.URL.RequestURI())
			p.auditLog.WriteEntry(makeAuditEntry(identity, r, hijackAction, "deny", "command_not_permitted", hijackAction, http.StatusForbidden))
			writeDockerError(w, http.StatusForbidden, fmt.Sprintf("user '%s'(uid=%d) not permitted to perform: %s",
				identity.RealUsername, identity.RealUID, hijackAction))
			return
		}
		p.handleHijack(w, r, identity)
		return
	}
	p.logger.Debug("non_hijack_request",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("upgrade", r.Header.Get("Upgrade")),
		zap.String("connection", r.Header.Get("Connection")),
	)

	action := authz.ClassifyAction(r.Method, r.URL.RequestURI())
	policy := p.getPolicy()

	isAuxiliary := isAuxiliaryCall(identity.DockerCommand, action, r.Method, r.URL.Path)

	p.logger.Debug("authz_trace",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", identity.RealUsername, identity.RealUID)),
		zap.String("docker_cmd", identity.DockerCommand),
		zap.String("action", action),
		zap.String("method", r.Method),
		zap.String("uri", r.URL.RequestURI()),
		zap.Bool("is_auxiliary", isAuxiliary),
	)

	if !isAuxiliary {
		auditID := toAuditIdentity(identity)
		audit.LogAuthzRequest(p.logger, auditID, action, r.Method, r.URL.RequestURI())
	}

	if !isAuxiliary && policy.IsDenied(identity, action) {
		auditID := toAuditIdentity(identity)
		audit.LogAuthzDeniedCommand(p.logger, auditID, action, r.URL.RequestURI())
		p.auditLog.WriteEntry(makeAuditEntry(identity, r, action, "deny", "command_not_permitted", "", http.StatusForbidden))
		writeDockerError(w, http.StatusForbidden,
			fmt.Sprintf("user '%s'(uid=%d) not permitted to perform: %s",
				identity.RealUsername, identity.RealUID, action))
		return
	}

	// 提前重写网络/卷 URL（容器名不加前缀，通过 Docker hex ID + label 追踪归属）
	// 不对容器 URL 做前缀重写，保持原始容器名直接转发给 Docker daemon

	r, ok := p.checkOwnershipPreRequest(w, r, identity, action)
	if !ok {
		return
	}

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
		writeDockerError(w, http.StatusInternalServerError, "internal error")
		return
	}
	p.logger.Debug("preprocess_request_done",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", identity.RealUsername, identity.RealUID)),
		zap.String("action", action),
	)

	p.logger.Debug("forward_request_start",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", identity.RealUsername, identity.RealUID)),
		zap.String("action", action),
		zap.String("uri", r.URL.RequestURI()),
	)
	forwardStart := time.Now()
	resp, err := p.forward(modifiedReq)
	latencyMs := time.Since(forwardStart).Milliseconds()
	if err != nil {
		statusCode := http.StatusBadGateway
		if ue, ok := err.(*upstreamError); ok {
			statusCode = ue.code
		}
		p.logger.Error("upstream_error",
			zap.String("real_username", identity.RealUsername),
			zap.Int("real_uid", identity.RealUID),
			zap.String("action", action),
			zap.Int("status_code", statusCode),
			zap.Error(err))
		writeDockerError(w, statusCode, "upstream error: "+err.Error())
		return
	}
	defer resp.Body.Close()
	p.logger.Debug("forward_request_done",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", identity.RealUsername, identity.RealUID)),
		zap.String("action", action),
		zap.Int("status_code", resp.StatusCode),
	)

	p.logger.Debug("postprocess_response_start",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", identity.RealUsername, identity.RealUID)),
		zap.String("action", action),
	)
	totalCount, filteredCount := p.postprocessResponse(w, resp, identity, action, modifiedReq.URL.RequestURI(), modifiedReq)
	p.logger.Debug("postprocess_response_done",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", identity.RealUsername, identity.RealUID)),
		zap.String("action", action),
	)

	// 获取容器名称改写信息（如有）
	rewrittenName, _ := r.Context().Value(rewrittenNameCtxKey).(string)

	if !isAuxiliary {
		auditID := toAuditIdentity(identity)
		audit.LogAuthzAllowed(p.logger, auditID, action, r.URL.RequestURI())
		// 步骤8：非容器创建操作的通用 allow 审计（容器创建在 postprocessResponse 里单独记录）
		if action != authz.ActionCreateContainer {
			p.auditLog.LogFull(identity.RealUsername, identity.RealUID, string(identity.AuthSource),
				action, r.URL.RequestURI(), rewrittenName, "allow", "", "", resp.StatusCode,
				latencyMs, totalCount, filteredCount, nil)
		}
	}
}

// checkOwnershipPreRequest 请求前的资源归属检查
func (p *ProxyServer) checkOwnershipPreRequest(w http.ResponseWriter, r *http.Request,
	id *auth.CallerIdentity, action string) (*http.Request, bool) {

	containerID := authz.ExtractContainerID(r.URL.Path)
	nonContainerIDs := map[string]bool{"json": true, "create": true, "prune": true}
	if containerID != "" && !nonContainerIDs[containerID] {
		owner, found := p.db.GetContainerOwner(containerID)
		if !found {
			if id.RealUID != 0 {
				// 数据库中未找到 → 通过 Docker API 读取容器标签，进行标签归属核验
				if !p.checkContainerOwnershipByLabel(w, id, containerID, action) {
					return r, false
				}
			}
		} else if owner.UID != id.RealUID && id.RealUID != 0 {
			// root (uid=0) 可访问所有容器，普通用户只能访问自己的容器
			auditID := toAuditIdentity(id)
			auditOwner := &audit.OwnerInfo{Username: owner.Username, UID: owner.UID, GID: owner.GID}
			audit.LogAuthzDeniedOwnership(p.logger, auditID, auditOwner, "container", truncID(containerID), action)
			p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "container_not_owned",
				fmt.Sprintf("owner=%s(uid=%d)", owner.Username, owner.UID), http.StatusNotFound))
			writeDockerNotFound(w, "container", containerID)
			return r, false
		}
	}

	if action == authz.ActionCommit {
		qContainerID := r.URL.Query().Get("container")
		if qContainerID != "" {
			// docker commit 传的是容器名（原始名），DB 中存的是 Docker 容器 ID。
			// 通过 Docker API 将容器名解析为真实 Docker ID（直接用原始名，不加前缀）
			dockerID := p.resolveContainerDockerID(qContainerID)
			if dockerID == "" {
				dockerID = qContainerID // fallback：直接用名称查（兼容短 ID 场景）
			}
			owner, found := p.db.GetContainerOwner(dockerID)
			if !found {
				if id.RealUID != 0 {
					// DB 中未找到 → 回退到标签归属核验（容器可能在代理重启前创建）
					if !p.checkContainerOwnershipByLabel(w, id, qContainerID, action) {
						return r, false
					}
				}
			} else if owner.UID != id.RealUID && id.RealUID != 0 {
				auditID := toAuditIdentity(id)
				auditOwner := &audit.OwnerInfo{Username: owner.Username, UID: owner.UID, GID: owner.GID}
				audit.LogAuthzDeniedOwnership(p.logger, auditID, auditOwner, "container", truncID(qContainerID), action)
				writeDockerNotFound(w, "container", qContainerID)
				return r, false
			}
		}
	}

	if action == authz.ActionCreateContainer {
		imageRef := extractImageRefFromBody(r)
		if imageRef != "" {
			resolvedID := p.resolveImageIDByRef(imageRef)
			if resolvedID == "" {
				// 本地不存在，让 docker 自动 pull
			} else {
				_, isPublic, found := p.db.GetImageOwner(resolvedID)
				if !found {
					if id.RealUID != 0 {
						auditID := toAuditIdentity(id)
						p.logger.Info("image_not_tracked_trigger_pull",
							append(audit.LogIdentityFields(auditID),
								zap.String("image_ref", imageRef),
							)...)
						writeDockerError(w, http.StatusNotFound, fmt.Sprintf("No such image: %s", imageRef))
						return r, false
					}
				} else if isPublic {
					_ = p.db.EnsureImageAccess(resolvedID, id.RealUID)
				} else {
					if !p.db.CanUseImage(id.RealUID, resolvedID) {
						auditID := toAuditIdentity(id)
						p.logger.Info("image_not_accessible_trigger_pull",
							append(audit.LogIdentityFields(auditID),
								zap.String("image_ref", imageRef),
								zap.String("image_id", truncID(resolvedID)),
							)...)
						writeDockerError(w, http.StatusNotFound, fmt.Sprintf("No such image: %s", imageRef))
						return r, false
					}
				}
			}
		}

		// 检查容器创建请求中显式指定的网络权限（非 root 用户）
		// 防止 docker run --network alice-net 或 docker network connect alice-net $(docker run -d ...)
		// 在容器创建阶段就拒绝，避免先 pull 镜像/创建容器再失败
		if id.RealUID != 0 {
			if err := p.checkCreateContainerNetworks(w, r, id, action); err != nil {
				return r, false
			}
		}

		// 步骤3+4：查询配额，校验请求参数，记录详细审计日志
		if p.quota != nil && id.RealUID != 0 {
			quota := p.quota.GetQuota(id)
			auditID := toAuditIdentity(id)
			p.logger.Info("quota_resolved",
				append(audit.LogIdentityShortFields(auditID),
					zap.Float64("cpu_cores", quota.CPUCores),
					zap.Int("mem_mb", quota.MemMB),
					zap.Int("storage_gb", quota.StorageGB),
					zap.Int("max_containers", quota.MaxContainers),
				)...)

			body, _ := io.ReadAll(r.Body)
			r.Body.Close()

			newBody, qr, qErr := isolation.CheckAndInjectQuota(body, quota, id.RealUID, p.db)

			// 记录详细配额审计日志
			logQuotaCheck(p.logger, auditID, qr)

			if qErr != nil {
				p.logger.Warn("quota_exceeded",
					append(audit.LogIdentityFields(auditID),
						zap.String("resource", qr.DeniedResource),
						zap.String("requested", qr.DeniedRequested),
						zap.String("limit", qr.DeniedLimit),
						zap.String("excess", qr.DeniedExcess),
					)...)
				p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "quota_exceeded", qErr.Error(), http.StatusForbidden))
				writeDockerError(w, http.StatusForbidden, qErr.Error())
				return r, false
			}

			// 用注入后的请求体替换原始 body，后续 preprocessRequest 直接使用
			r.Body = io.NopCloser(bytes.NewReader(newBody))
		}

		// 网络注入：强制容器接入用户专属桥接网络（root 用户跳过）
		if id.RealUID != 0 {
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()

			// 挂载路径校验：bind mount 源路径必须在用户专属存储目录下
			if mountErr := isolation.ValidateBindMounts(body, p.storageBase, id.RealUID); mountErr != nil {
				auditID := toAuditIdentity(id)
				p.logger.Warn("bind_mount_violation",
					append(audit.LogIdentityFields(auditID),
						zap.String("detail", mountErr.Error()),
					)...)
				p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "bind_mount_not_allowed", mountErr.Error(), http.StatusForbidden))
				writeDockerError(w, http.StatusForbidden, mountErr.Error())
				return r, false
			}

			// named volume 校验与重写：确保用户只能挂载自己的 volume，并补全前缀
			var volViolation *isolation.NamedVolumeViolation
			body, volViolation = isolation.ValidateAndRewriteNamedVolumes(body, id.RealUID, p.db)
			if volViolation != nil {
				auditID := toAuditIdentity(id)
				p.logger.Warn("AUTHZ_DENY",
					append(audit.LogIdentityFields(auditID),
						zap.String("reason", "volume_not_accessible"),
						zap.String("volume", volViolation.VolumeName),
						zap.String("action", action),
					)...)
				p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "volume_not_accessible", volViolation.VolumeName, http.StatusInternalServerError))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = fmt.Fprintf(w, `{"message":%q}`, volViolation.Error())
				return r, false
			}

			// 端口冲突检测（在注入网络前，使用原始请求体）
			if !p.checkPortConflict(w, r, id, body) {
				return r, false
			}

			// 将端口映射存入 context，供 postprocessResponse 在容器创建成功后写入 DB
			portMappings := isolation.ExtractPortMappings(body)
			if len(portMappings) > 0 {
				ctx := context.WithValue(r.Context(), portMappingsCtxKey, portMappings)
				r = r.WithContext(ctx)
			}

			// 确保用户专属网桥存在（新用户首次 run 时按需创建）
			if networkID, bridgeErr := p.bridge.EnsureUserBridge(id.RealUID, id.RealUsername); bridgeErr != nil {
				auditID := toAuditIdentity(id)
				p.logger.Error("ensure_user_bridge_failed_on_run",
					append(audit.LogIdentityFields(auditID),
						zap.Error(bridgeErr),
					)...)
				writeDockerError(w, http.StatusInternalServerError, "failed to initialize user network: "+bridgeErr.Error())
				return r, false
			} else if networkID != "" {
				bridgeName := isolation.UserBridgeName(id.RealUID)
				_ = p.db.SetManagedNetworkOwner(networkID, bridgeName, id.RealUID, id.RealUsername)
			}

			// 查出该用户的用户级 peer 网络 ID，在创建时一并注入，避免异步 connect 的竞态
			var peerNetIDs []string
			if peers, err := p.db.GetNetworkPeersByUID(id.RealUID); err == nil {
				for _, peer := range peers {
					if peer.IsUserLevel() {
						peerNetIDs = append(peerNetIDs, peer.PeerNetworkID)
					}
				}
			}

			// 收集用户显式指定的网络名（加前缀后的真实名称），传给 InjectUserNetwork 保留
			var userRequestedNets []string
			prefix := isolation.UserResourcePrefix(id)
			bridgeName := isolation.UserBridgeName(id.RealUID)
			for _, netName := range isolation.ExtractRequestedNetworks(body) {
				if netName == "default" || netName == "bridge" || netName == "host" || netName == "none" || netName == bridgeName {
					continue
				}
				if strings.HasPrefix(netName, prefix) {
					userRequestedNets = append(userRequestedNets, netName)
				} else {
					userRequestedNets = append(userRequestedNets, prefix+netName)
				}
			}

			injected, err := isolation.InjectUserNetwork(body, id.RealUID, peerNetIDs, userRequestedNets)
			if err == nil {
				r.Body = io.NopCloser(bytes.NewReader(injected))
			} else {
				r.Body = io.NopCloser(bytes.NewReader(body))
			}
		}
	}

	// ── 镜像权限校验 ──────────────────────────────────────────────────────────
	switch action {
	case authz.ActionInspect, authz.ActionSave:
		// docker save 使用 GET /images/get?names=... 格式，需从 query 参数提取镜像名
		imageRef := authz.ExtractImageID(r.URL.Path)
		if action == authz.ActionSave && (imageRef == "" || imageRef == "get") {
			imageRef = r.URL.Query().Get("names")
		}
		if imageRef != "" {
			// 先将 tag 解析为 sha256 ID（DB 中以 sha256 为主键存储）
			resolvedRef := p.resolveImageIDByRef(imageRef)
			if resolvedRef == "" {
				// 镜像在 Docker 中不存在，直接放行让 Docker 返回 404
				break
			}
			if !p.db.CanUseImage(id.RealUID, resolvedRef) &&
				!p.db.CanUseImage(id.RealUID, imageRef) &&
				!p.db.CanUseImage(id.RealUID, "sha256:"+imageRef) {
				auditID := toAuditIdentity(id)
				audit.LogAuthzDeniedImageAccess(p.logger, auditID, truncID(imageRef), action, "image_not_permitted")
				writeDockerError(w, http.StatusForbidden,
					fmt.Sprintf("user '%s'(uid=%d) not permitted to access image '%s'",
						id.RealUsername, id.RealUID, truncID(imageRef)))
				return r, false
			}
		}

	case authz.ActionRemoveImage:
		if !p.checkImageRemovePermission(w, r, id) {
			return r, false
		}

	case authz.ActionPull:
		if !p.checkImagePullPermission(w, r, id) {
			return r, false
		}

	case authz.ActionTag:
		if !p.checkImageTagPermission(w, r, id) {
			return r, false
		}

	case authz.ActionPush:
		if !p.checkImagePushPermission(w, r, id) {
			return r, false
		}
	}

	switch action {
	case authz.ActionNetworkInspect, authz.ActionNetworkConnect, authz.ActionNetworkDisconnect, authz.ActionNetworkRemove:
		networkName := isolation.ExtractNetworkID(r.URL.Path)
		if networkName != "" && id.RealUID != 0 {
			// 尝试按用户前缀名查找真实 Docker 网络 ID
			prefix := isolation.UserResourcePrefix(id)
			lookupName := networkName
			if !strings.HasPrefix(networkName, prefix) {
				lookupName = prefix + networkName
			}
			lookupID := networkName
			if docID, found := p.db.GetNetworkIDByName(lookupName); found {
				lookupID = docID
			}
			ok, err := p.db.CanUserAccessNetwork(lookupID, id.RealUID)
			if err != nil || !ok {
				auditID := toAuditIdentity(id)
				p.logger.Warn("AUTHZ_DENY",
					append(audit.LogIdentityFields(auditID),
						zap.String("reason", "network_not_accessible"),
						zap.String("network_id", truncID(lookupID)),
						zap.String("action", action),
					)...)
				p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "network_not_accessible", "", http.StatusNotFound))
				writeDockerNotFound(w, "network", networkName)
				return r, false
			}
		}
	}

	if action == authz.ActionVolumeRemove {
		volName := isolation.ExtractVolumeName(r.URL.Path)
		if volName != "" && id.RealUID != 0 {
			// 补全用户前缀以匹配 DB 中存储的卷名
			prefix := isolation.UserVolumePrefix(id.RealUID)
			if !strings.HasPrefix(volName, prefix) {
				volName = prefix + volName
			}
			owner, found := p.db.GetVolumeOwner(volName)
			if !found {
				auditID := toAuditIdentity(id)
				p.logger.Warn("AUTHZ_DENY",
					append(audit.LogIdentityFields(auditID),
						zap.String("reason", "volume_not_tracked"),
						zap.String("volume_name", volName),
						zap.String("action", action),
					)...)
				p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "volume_not_tracked", "", http.StatusNotFound))
				writeDockerNotFound(w, "volume", volName)
				return r, false
			} else if owner.UID != id.RealUID {
				auditID := toAuditIdentity(id)
				p.logger.Warn("AUTHZ_DENY",
					append(audit.LogIdentityFields(auditID),
						zap.String("reason", "not_your_volume"),
						zap.String("volume_name", volName),
						zap.String("action", action),
					)...)
				p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "not_your_volume", "", http.StatusNotFound))
				writeDockerNotFound(w, "volume", volName)
				return r, false
			}
		}
	}

	return r, true
}

// checkImageRemovePermission 校验 docker rmi 权限：
// - 用户有该镜像的引用记录（image_access）：允许，解除引用由 ServeHTTP virtual-delete 路径处理
// - 用户无引用记录但为属主或 root：允许（物理删除）
// - 用户无引用记录且非属主：拒绝
// - 镜像还有其他用户引用且当前用户是最后物理删除者（属主/root）：阻止物理删除
func (p *ProxyServer) checkImageRemovePermission(w http.ResponseWriter, r *http.Request, id *auth.CallerIdentity) bool {
	imageRef := authz.ExtractImageID(r.URL.Path)
	if imageRef == "" {
		return true
	}
	resolvedID := p.resolveImageIDByRef(imageRef)
	if resolvedID == "" {
		// 镜像在 Docker 中不存在，直接放行让 Docker 返回 404
		return true
	}
	owner, isPublic, found := p.db.GetImageOwner(resolvedID)
	if !found {
		if id.RealUID != 0 {
			auditID := toAuditIdentity(id)
			audit.LogAuthzDeniedNotTracked(p.logger, auditID, "image", truncID(resolvedID), authz.ActionRemoveImage)
			writeDockerNotFound(w, "image", resolvedID)
			return false
		}
		return true
	}

	auditID := toAuditIdentity(id)

	// 非 root：只有属主才能 rmi
	if id.RealUID != 0 {
		isImageOwner := owner.UID == id.RealUID
		if !isImageOwner {
			auditOwner := &audit.OwnerInfo{Username: owner.Username, UID: owner.UID, GID: owner.GID}
			audit.LogAuthzDeniedOwnership(p.logger, auditID, auditOwner, "image", truncID(resolvedID), authz.ActionRemoveImage)
			msg := fmt.Sprintf("image '%s' belongs to user '%s', only the owner can remove it", truncID(resolvedID), owner.Username)
			if isPublic {
				msg = fmt.Sprintf("image '%s' is public and belongs to user '%s', only the owner can remove it", truncID(resolvedID), owner.Username)
			}
			writeDockerError(w, http.StatusForbidden, msg)
			return false
		}
	}

	// 检查该用户是否有容器仍在使用该镜像
	inUse, err := p.db.HasContainerUsingImage(id.RealUID, resolvedID)
	if err != nil || inUse {
		audit.LogAuthzDeniedImageAccess(p.logger, auditID, truncID(resolvedID), authz.ActionRemoveImage, "image_in_use_by_user_containers")
		writeDockerError(w, http.StatusConflict,
			fmt.Sprintf("image '%s' is still used by your containers, remove them first", truncID(resolvedID)))
		return false
	}

	// 属主或 root 尝试物理删除时，若其他用户还有引用则阻止
	isOwner := id.RealUID == 0 || owner.UID == id.RealUID
	if isOwner && isPublic {
		refCount, err := p.db.GetImageRefCount(resolvedID)
		if err != nil {
			writeDockerError(w, http.StatusInternalServerError, "internal error")
			return false
		}
		if refCount > 1 {
			refUsers, _ := p.db.GetImageRefUsers(resolvedID)
			p.logger.Info("image_rmi_blocked_by_refs",
				append(audit.LogIdentityShortFields(auditID),
					zap.String("image_id", truncID(resolvedID)),
					zap.Int("ref_count", refCount),
					zap.Ints("ref_uids", refUsers),
				)...)
			writeDockerError(w, http.StatusConflict,
				fmt.Sprintf("image '%s' is still referenced by %d other user(s); cannot delete until all references are removed",
					truncID(resolvedID), refCount-1))
			return false
		}
	}

	return true
}

// checkImagePullPermission 校验 docker pull 权限：
// - 公共镜像：所有用户可拉取；覆盖公共镜像只有属主或 root 可操作
// - 私有镜像：只有属主或 root 可拉取
func (p *ProxyServer) checkImagePullPermission(w http.ResponseWriter, r *http.Request, id *auth.CallerIdentity) bool {
	if id.RealUID == 0 {
		return true
	}
	if r.URL.Query().Get("authz.public") == "true" {
		writeDockerError(w, http.StatusForbidden, "only root can mark images as public")
		return false
	}

	imageRef := parseImageRefFromURI(r.URL.RequestURI())
	if imageRef == "" {
		return true
	}

	resolvedID := p.resolveImageIDByRef(imageRef)
	if resolvedID == "" {
		return true // 本地无此镜像，允许从仓库拉取
	}

	owner, isPublic, found := p.db.GetImageOwner(resolvedID)
	if !found {
		return true
	}

	auditID := toAuditIdentity(id)
	if isPublic {
		// 公共镜像：非属主 pull 视为增加引用计数，模拟 pull 成功
		if owner.UID != id.RealUID {
			if err := p.db.EnsureImageAccess(resolvedID, id.RealUID); err != nil {
				p.logger.Error("ensure_image_access_failed",
					zap.String("image_id", resolvedID),
					zap.String("real_username", id.RealUsername),
					zap.Int("real_uid", id.RealUID),
					zap.Error(err))
				writeDockerError(w, http.StatusInternalServerError, "internal error")
				return false
			}
			p.logger.Info("image_pull_virtual",
				append(audit.LogIdentityShortFields(auditID),
					zap.String("image_ref", imageRef),
					zap.String("image_id", truncID(resolvedID)),
					zap.String("owner", owner.Username),
					zap.Bool("public", true),
				)...)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "{\"status\":\"Pull complete\",\"id\":\"%s\"}\r\n", truncID(resolvedID))
			return false
		}
		return true
	}

	// 私有镜像且非属主：镜像已在本地，模拟 pull 成功并记录引用计数
	// 不需要从仓库重新下载，直接给当前用户添加访问权限
	if owner.UID != id.RealUID {
		if err := p.db.EnsureImageAccess(resolvedID, id.RealUID); err != nil {
			p.logger.Error("ensure_image_access_failed",
				zap.String("image_id", resolvedID),
				zap.String("real_username", id.RealUsername),
				zap.Int("real_uid", id.RealUID),
				zap.Error(err))
			writeDockerError(w, http.StatusInternalServerError, "internal error")
			return false
		}
		p.logger.Info("image_pull_virtual",
			append(audit.LogIdentityShortFields(auditID),
				zap.String("image_ref", imageRef),
				zap.String("image_id", truncID(resolvedID)),
				zap.String("owner", owner.Username),
			)...)
		// 模拟 Docker pull 的流式输出格式
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "{\"status\":\"Pull complete\",\"id\":\"%s\"}\r\n", truncID(resolvedID))
		return false
	}
	return true
}

// checkImageTagPermission 校验 docker tag 权限：属主、有访问权限的用户或 root 可打标签
func (p *ProxyServer) checkImageTagPermission(w http.ResponseWriter, r *http.Request, id *auth.CallerIdentity) bool {
	if id.RealUID == 0 {
		return true
	}
	imageRef := authz.ExtractImageID(r.URL.Path)
	if imageRef == "" {
		return true
	}
	resolvedID := p.resolveImageIDByRef(imageRef)
	if resolvedID == "" {
		resolvedID = imageRef
	}
	owner, _, found := p.db.GetImageOwner(resolvedID)
	if !found {
		// 镜像未被代理追踪（可能是 docker build 产生的中间层），允许通过
		return true
	}
	if owner.UID != id.RealUID {
		// 非属主但有访问权限（如 docker build 中间层复用场景），允许打标签
		if p.db.CanUseImage(id.RealUID, resolvedID) {
			return true
		}
		auditID := toAuditIdentity(id)
		auditOwner := &audit.OwnerInfo{Username: owner.Username, UID: owner.UID, GID: owner.GID}
		audit.LogAuthzDeniedOwnership(p.logger, auditID, auditOwner, "image", truncID(resolvedID), authz.ActionTag)
		writeDockerNotFound(w, "image", resolvedID)
		return false
	}
	return true
}

// checkImagePushPermission 校验 docker push 权限：只有属主或 root 可推送
func (p *ProxyServer) checkImagePushPermission(w http.ResponseWriter, r *http.Request, id *auth.CallerIdentity) bool {
	if id.RealUID == 0 {
		return true
	}
	imageRef := authz.ExtractImageID(r.URL.Path)
	if imageRef == "" {
		return true
	}
	resolvedID := p.resolveImageIDByRef(imageRef)
	if resolvedID == "" {
		resolvedID = imageRef
	}
	owner, _, found := p.db.GetImageOwner(resolvedID)
	if !found {
		auditID := toAuditIdentity(id)
		audit.LogAuthzDeniedNotTracked(p.logger, auditID, "image", truncID(resolvedID), authz.ActionPush)
		writeDockerError(w, http.StatusForbidden,
			fmt.Sprintf("image '%s' not tracked by proxy (only root can push untracked images)", truncID(resolvedID)))
		return false
	}
	if owner.UID != id.RealUID {
		auditID := toAuditIdentity(id)
		auditOwner := &audit.OwnerInfo{Username: owner.Username, UID: owner.UID, GID: owner.GID}
		audit.LogAuthzDeniedOwnership(p.logger, auditID, auditOwner, "image", truncID(resolvedID), authz.ActionPush)
		writeDockerNotFound(w, "image", resolvedID)
		return false
	}
	return true
}

// preprocessRequest 修改请求（注入标签、配额、资源名称前缀等）
func (p *ProxyServer) preprocessRequest(r *http.Request, id *auth.CallerIdentity, action string) (*http.Request, error) {
	// 先处理不需要读取 body 的 URL 重写
	switch action {
	case authz.ActionNetworkInspect, authz.ActionNetworkConnect,
		authz.ActionNetworkDisconnect, authz.ActionNetworkRemove:
		if id.RealUID != 0 {
			r = isolation.RewriteNetworkURL(r, id)
		}
	case authz.ActionVolumeInspect, authz.ActionVolumeRemove:
		if id.RealUID != 0 {
			r = isolation.RewriteVolumeURL(r, id.RealUID)
		}
	}

	switch action {
	case authz.ActionCreateContainer, authz.ActionNetworkCreate, authz.ActionVolumeCreate:
		// 需要读取并修改请求体
	default:
		return r, nil
	}

	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return r, fmt.Errorf("read body: %w", err)
	}

	switch action {
	case authz.ActionCreateContainer:
		// 注入容器名称前缀（user-{uid}-），并将改写后名称存入 context 供审计使用
		if id.RealUID != 0 {
			rewritten, rewrittenName, _ := isolation.InjectContainerNamePrefix(body, id)
			if rewrittenName != "" {
				body = rewritten
				newCtx := context.WithValue(r.Context(), rewrittenNameCtxKey, rewrittenName)
				r = r.WithContext(newCtx)
			}
		}
		body, _ = isolation.InjectSystemLabels(body, id)
		// 配额注入已在 checkOwnershipPreRequest 中通过 CheckAndInjectQuota 完成
		// 此处仅注入系统标签，并提取最终资源参数存入 context 供审计使用
		if resUsage := isolation.ExtractRequestedResources(body); len(resUsage) > 0 {
			newCtx := context.WithValue(r.Context(), resourceUsageCtxKey, resUsage)
			r = r.WithContext(newCtx)
		}

	case authz.ActionNetworkCreate:
		if id.RealUID != 0 {
			modified, actualName, _ := isolation.InjectNetworkNamePrefixWithName(body, id)
			body = modified
			if actualName != "" {
				newCtx := context.WithValue(r.Context(), rewrittenNameCtxKey, actualName)
				r = r.WithContext(newCtx)
			}
		}

	case authz.ActionVolumeCreate:
		if id.RealUID != 0 {
			body, _ = isolation.InjectVolumeNamePrefix(body, id)
		}
	}

	newReq := r.Clone(r.Context())
	newReq.Body = io.NopCloser(bytes.NewReader(body))
	newReq.ContentLength = int64(len(body))
	return newReq, nil
}

// forward 将请求转发到上游 dockerd，支持超时重试（最多2次，指数退避）
func (p *ProxyServer) forward(r *http.Request) (*http.Response, error) {
	upstreamURL := &url.URL{
		Scheme:   "http",
		Host:     "docker",
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	// 判断是否可重试：幂等方法（GET/HEAD）或无请求体的请求
	canRetry := r.Method == http.MethodGet || r.Method == http.MethodHead

	// 读取请求体以支持重试（非幂等请求也可能需要重试502/503）
	var bodyBytes []byte
	if r.Body != nil && r.Body != http.NoBody {
		var err error
		bodyBytes, err = io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		// 有请求体的非幂等请求，仅在502/503时重试
		canRetry = true
	}

	const maxRetries = 2
	retryDelays := []time.Duration{500 * time.Millisecond, time.Second}

	var (
		resp *http.Response
		err  error
	)

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(retryDelays[attempt-1])
		}

		var body io.Reader
		if len(bodyBytes) > 0 {
			body = bytes.NewReader(bodyBytes)
		}

		outReq, reqErr := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), body)
		if reqErr != nil {
			return nil, reqErr
		}
		for k, vals := range r.Header {
			for _, v := range vals {
				outReq.Header.Add(k, v)
			}
		}
		outReq.ContentLength = r.ContentLength
		if len(bodyBytes) > 0 {
			outReq.ContentLength = int64(len(bodyBytes))
		} else if body == nil && outReq.ContentLength < 0 {
			// body 为 nil 时 ContentLength 不能为 -1，否则 http.Transport 会报错
			// （docker import <url> 场景：fromSrc 作为 query 参数，body 为空）
			outReq.ContentLength = 0
		}

		resp, err = p.transport.RoundTrip(outReq)
		if err != nil {
			// 连接拒绝/Dockerd未启动 → 503；网络中断 → 500（重试后仍失败）
			if attempt < maxRetries && canRetry {
				p.logger.Warn("upstream_error_retrying",
					zap.Int("attempt", attempt+1),
					zap.Error(err))
				continue
			}
			// 判断是否为连接拒绝（Dockerd未启动）
			if isConnectionRefused(err) {
				return nil, &upstreamError{code: http.StatusServiceUnavailable, cause: err}
			}
			return nil, &upstreamError{code: http.StatusInternalServerError, cause: err}
		}

		// 502/503 时重试（幂等或有请求体的请求）
		if canRetry && attempt < maxRetries &&
			(resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable) {
			resp.Body.Close()
			p.logger.Warn("upstream_bad_status_retrying",
				zap.Int("attempt", attempt+1),
				zap.Int("status", resp.StatusCode))
			continue
		}
		break
	}

	return resp, err
}

// upstreamError 携带建议 HTTP 状态码的上游错误
type upstreamError struct {
	code  int
	cause error
}

func (e *upstreamError) Error() string { return e.cause.Error() }
func (e *upstreamError) Unwrap() error { return e.cause }

// isConnectionRefused 判断错误是否为连接拒绝（Dockerd未启动）
func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "connect: no such file")
}

// postprocessResponse 处理上游响应：过滤列表、记录归属
// 返回 (totalCount, filteredCount)：列表类请求过滤前后的资源数量，非列表请求均为 0
func (p *ProxyServer) postprocessResponse(w http.ResponseWriter, resp *http.Response,
	id *auth.CallerIdentity, action, requestURI string, r *http.Request) (totalCount, filteredCount int) {

	auditID := toAuditIdentity(id)
	emptyJSONArray := []byte("[]")

	switch action {
	case authz.ActionPS:
		p.logger.Debug("filter_containers_start",
			zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
		)
		body, err := isolation.ReadFullBody(resp.Body)
		if err != nil {
			p.logger.Error("read_response_body_failed", zap.String("action", "ps"), zap.Error(err))
			writeDockerError(w, http.StatusBadGateway, "read upstream response failed")
			return
		}
		totalCount = isolation.CountJSONArray(body)
		filtered, err := isolation.FilterContainerListResponse(body, id.RealUID, id.RealUsername, p.db)
		if err != nil {
			p.logger.Error("filter_containers_failed",
				zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
				zap.Error(err))
			filtered = emptyJSONArray
		}
		filteredCount = isolation.CountJSONArray(filtered)
		isolation.CopyHeaders(w, resp.Header)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(filtered)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(filtered)

	case authz.ActionImages:
		body, err := isolation.ReadFullBody(resp.Body)
		if err != nil {
			writeDockerError(w, http.StatusBadGateway, "read upstream response failed")
			return
		}
		totalCount = isolation.CountJSONArray(body)
		filtered, err := isolation.FilterImageListResponse(body, id.RealUID, p.db)
		if err != nil {
			p.logger.Error("filter_images_failed",
				zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
				zap.Error(err))
			filtered = emptyJSONArray
		}
		filteredCount = isolation.CountJSONArray(filtered)
		isolation.CopyHeaders(w, resp.Header)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(filtered)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(filtered)

	case authz.ActionCreateContainer:
		body, err := isolation.ReadFullBody(resp.Body)
		if err != nil {
			p.logger.Error("read_response_body_failed", zap.String("action", "create"), zap.Error(err))
			writeDockerError(w, http.StatusBadGateway, "read upstream response failed")
			return
		}
		if resp.StatusCode == http.StatusCreated {
			containerID := extractContainerIDFromCreateResponse(body)
			if containerID != "" {
				imageRef := extractImageRefFromBody(r)
				resolvedImageID := ""
				if imageRef != "" {
					resolvedImageID = p.resolveImageIDByRef(imageRef)
					if resolvedImageID == "" {
						resolvedImageID = imageRef
					}
				}
				if err := p.db.SetContainerOwner(containerID, id, resolvedImageID); err != nil {
					p.logger.Error("save_container_owner_failed",
						zap.String("container_id", containerID),
						zap.String("real_username", id.RealUsername),
						zap.Int("real_uid", id.RealUID),
						zap.Error(err))
				} else {
					p.logger.Info("container_created",
						append(audit.LogIdentityFields(auditID),
							zap.String("container_id", truncID(containerID)),
						)...)
				}
				// 写入端口映射记录（容器创建成功后才写入，避免失败时留下脏数据）
				if id.RealUID != 0 {
					if portMappings, ok := r.Context().Value(portMappingsCtxKey).([]isolation.PortMapping); ok && len(portMappings) > 0 {
						dbMappings := make([]authz.PortMappingInfo, 0, len(portMappings))
						for _, m := range portMappings {
							dbMappings = append(dbMappings, authz.PortMappingInfo{
								HostPort:      m.HostPort,
								Protocol:      m.Protocol,
								ContainerPort: m.ContainerPort,
								ContainerID:   containerID,
								OwnerUID:      id.RealUID,
								OwnerUsername: id.RealUsername,
							})
						}
						if err := p.db.AddPortMappings(dbMappings); err != nil {
							p.logger.Error("save_port_mappings_failed",
								zap.String("container_id", truncID(containerID)),
								zap.Error(err))
						} else {
							p.logger.Info("port_mappings_recorded",
								zap.String("container_id", truncID(containerID)),
								zap.Int("count", len(dbMappings)),
							)
						}
					}
					// 若该用户有互通配置，将新容器连接到所有辅助网络（异步，避免阻塞 handler）
					go p.connectContainerToPeerNetworks(containerID, id.RealUID)
				}
				// 步骤8：记录资源使用情况到审计日志
				resUsage, _ := r.Context().Value(resourceUsageCtxKey).(map[string]string)
				p.auditLog.LogWithResources(id.RealUsername, id.RealUID, string(id.AuthSource),
					action, r.URL.RequestURI(), "allow", "", containerID, resp.StatusCode, resUsage)
			}
		}
		isolation.CopyHeaders(w, resp.Header)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)

	case authz.ActionLoad:
		isolation.CopyHeaders(w, resp.Header)
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
						append(audit.LogIdentityFields(auditID),
							zap.String("image_id", truncID(imageID)),
						)...)
				}
			}
		} else {
			_, _ = io.Copy(w, resp.Body)
		}

	case authz.ActionCommit:
		body, err := isolation.ReadFullBody(resp.Body)
		if err != nil {
			writeDockerError(w, http.StatusBadGateway, "read upstream response failed")
			return
		}
		if resp.StatusCode == http.StatusCreated {
			var commitResp struct {
				ID string `json:"Id"`
			}
			if json.Unmarshal(body, &commitResp) == nil && commitResp.ID != "" {
				imageID := strings.TrimPrefix(commitResp.ID, "sha256:")
				if err := p.db.SetImageOwner(imageID, id, false, "commit"); err != nil {
					p.logger.Error("save_committed_image_owner_failed",
						zap.String("image_id", truncID(imageID)),
						zap.String("real_username", id.RealUsername),
						zap.Int("real_uid", id.RealUID),
						zap.Error(err))
				} else {
					_ = p.db.EnsureImageAccess(imageID, id.RealUID)
					p.logger.Info("image_committed",
						append(audit.LogIdentityFields(auditID),
							zap.String("image_id", truncID(imageID)),
						)...)
				}
			}
		}
		isolation.CopyHeaders(w, resp.Header)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)

	case authz.ActionPrune:
		body, err := isolation.ReadFullBody(resp.Body)
		if err != nil {
			writeDockerError(w, http.StatusBadGateway, "read upstream response failed")
			return
		}
		if resp.StatusCode == http.StatusOK {
			if strings.HasPrefix(requestURI, "/containers") || strings.Contains(requestURI, "/containers/") {
				var pruneResp struct {
					ContainersDeleted []string `json:"ContainersDeleted"`
				}
				if json.Unmarshal(body, &pruneResp) == nil {
					for _, cid := range pruneResp.ContainersDeleted {
						_ = p.db.DeleteContainer(cid)
						_ = p.db.ReleasePortMappings(cid)
					}
				}
			} else if strings.HasPrefix(requestURI, "/images") || strings.Contains(requestURI, "/images/") ||
				strings.HasPrefix(requestURI, "/build") {
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
		isolation.CopyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)

	case authz.ActionStartContainer, authz.ActionRestart, authz.ActionStop:
		isolation.CopyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)

	case authz.ActionRemoveContainer:
		if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
			containerID := authz.ExtractContainerID(requestURI)
			if containerID != "" {
				_ = p.db.DeleteContainer(containerID)
				// 释放端口映射记录
				_ = p.db.ReleasePortMappings(containerID)
			}
		}
		isolation.CopyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)

	case authz.ActionImport:
		isolation.CopyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		_, _ = w.Write(body)
		if resp.StatusCode == http.StatusOK {
			// 响应格式：{"status":"sha256:..."} 或纯文本 "sha256:..."
			var statusMsg struct {
				Status string `json:"status"`
			}
			imageID := ""
			if json.Unmarshal(body, &statusMsg) == nil && statusMsg.Status != "" {
				imageID = strings.TrimPrefix(strings.TrimSpace(statusMsg.Status), "sha256:")
			} else {
				imageID = strings.TrimPrefix(strings.TrimSpace(string(body)), "sha256:")
				imageID = strings.TrimRight(imageID, "\r\n")
			}
			if imageID != "" {
				if err := p.db.SetImageOwner(imageID, id, false, "import"); err != nil {
					p.logger.Error("save_image_owner_failed",
						zap.String("image_id", truncID(imageID)),
						zap.String("real_username", id.RealUsername),
						zap.Int("real_uid", id.RealUID),
						zap.Error(err))
				}
				if err := p.db.EnsureImageAccess(imageID, id.RealUID); err != nil {
					p.logger.Error("ensure_image_access_failed",
						zap.String("image_id", truncID(imageID)),
						zap.String("real_username", id.RealUsername),
						zap.Int("real_uid", id.RealUID),
						zap.Error(err))
				} else {
					p.logger.Info("image_imported",
						append(audit.LogIdentityFields(auditID),
							zap.String("image_id", truncID(imageID)),
						)...)
				}
			}
		}

	case authz.ActionPull:
		isolation.CopyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(w, resp.Body)
			break
		}
		streamAndCaptureImageID(w, resp, "pull")
		imageRef := parseImageRefFromURI(requestURI)
		if imageRef != "" {
			if imageID := p.resolveImageIDByRef(imageRef); imageID != "" {
				if err := p.db.SetImageOwner(imageID, id, false, "pull"); err != nil {
					p.logger.Error("save_image_owner_failed",
						zap.String("image_id", imageID),
						zap.String("real_username", id.RealUsername),
						zap.Int("real_uid", id.RealUID),
						zap.Error(err))
				}
				if err := p.db.EnsureImageAccess(imageID, id.RealUID); err != nil {
					p.logger.Error("ensure_image_access_failed",
						zap.String("image_id", imageID),
						zap.String("real_username", id.RealUsername),
						zap.Int("real_uid", id.RealUID),
						zap.Error(err))
				} else {
					p.logger.Info("image_pulled",
						append(audit.LogIdentityFields(auditID),
							zap.String("image_id", truncID(imageID)),
							zap.String("image_ref", imageRef),
						)...)
				}
				if id.RealUID == 0 {
					if strings.Contains(requestURI, "authz.public=true") {
						if err := p.db.SetImagePublic(imageID, true); err != nil {
							p.logger.Error("set_image_public_failed", zap.Error(err))
						} else {
							p.logger.Info("image_marked_public",
								append(audit.LogIdentityFields(auditID),
									zap.String("image_id", truncID(imageID)),
								)...)
						}
					}
				}
			}
		}

	case authz.ActionBuild:
		isolation.CopyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		imageID := streamAndCaptureImageID(w, resp, "build")
		if imageID != "" && resp.StatusCode == http.StatusOK {
			// 将短 ID（12-char）或 BuildKit ID 解析为完整 sha256（规范化存储）
			if fullID := p.resolveImageIDByRef(imageID); fullID != "" {
				imageID = fullID // "sha256:ba6dc382fcdc..."（SetImageOwner 会自动去掉 sha256: 前缀）
			}
			if err := p.db.SetImageOwner(imageID, id, false, "build"); err != nil {
				p.logger.Error("save_image_owner_failed",
					zap.String("image_id", truncID(imageID)),
					zap.String("real_username", id.RealUsername),
					zap.Int("real_uid", id.RealUID),
					zap.Error(err))
			}
			if err := p.db.EnsureImageAccess(imageID, id.RealUID); err != nil {
				p.logger.Error("ensure_image_access_failed",
					zap.String("image_id", truncID(imageID)),
					zap.String("real_username", id.RealUsername),
					zap.Int("real_uid", id.RealUID),
					zap.Error(err))
			} else {
				p.logger.Info("image_built",
					append(audit.LogIdentityFields(auditID),
						zap.String("image_id", truncID(imageID)),
					)...)
			}
		}

	case authz.ActionRemoveImage:
		if resp.StatusCode == http.StatusOK {
			imageRef := authz.ExtractImageID(requestURI)
			if imageRef != "" {
				// 解析真实 content ID，与 pre-request 阶段保持一致
				resolvedID := p.resolveImageIDByRef(imageRef)
				if resolvedID == "" {
					resolvedID = imageRef
				}
				// 到达此处说明 pre-request 阶段已确认引用计数降为 0，可物理删除
				_ = p.db.DeleteImage(resolvedID)
				p.logger.Info("image_deleted",
					append(audit.LogIdentityFields(auditID),
						zap.String("image_id", truncID(resolvedID)),
					)...)
				p.auditLog.WriteEntry(func() audit.AuditEntry {
					e := makeAuditEntry(id, r, action, "allow", "physical_delete", resolvedID, resp.StatusCode)
					e.URI = requestURI
					return e
				}())
			}
		}
		isolation.CopyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)

	case authz.ActionNetworkCreate:
		body, err := isolation.ReadFullBody(resp.Body)
		if err != nil {
			writeDockerError(w, http.StatusBadGateway, "read upstream response failed")
			return
		}
		if resp.StatusCode == http.StatusCreated {
			var createResp struct {
				ID string `json:"Id"`
			}
			if json.Unmarshal(body, &createResp) == nil && createResp.ID != "" {
				// 从 context 取注入前缀后的实际网络名，fallback 为 Docker ID
				actualName, _ := r.Context().Value(rewrittenNameCtxKey).(string)
				if actualName == "" {
					actualName = createResp.ID
				}
				if err := p.db.SetNetworkOwner(createResp.ID, actualName, id); err != nil {
					p.logger.Error("save_network_owner_failed", zap.Error(err))
				} else {
					p.logger.Info("network_created",
						append(audit.LogIdentityShortFields(auditID), zap.String("network_id", truncID(createResp.ID)))...)
				}
			}
		}
		isolation.CopyHeaders(w, resp.Header)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)

	case authz.ActionNetworkList:
		body, err := isolation.ReadFullBody(resp.Body)
		if err != nil {
			writeDockerError(w, http.StatusBadGateway, "read upstream response failed")
			return
		}
		totalCount = isolation.CountJSONArray(body)
		filtered, err := isolation.FilterNetworkListResponse(body, id.RealUID, p.db)
		if err != nil {
			p.logger.Error("filter_networks_failed", zap.Error(err))
			filtered = emptyJSONArray
		}
		filteredCount = isolation.CountJSONArray(filtered)
		isolation.CopyHeaders(w, resp.Header)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(filtered)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(filtered)

	case authz.ActionNetworkRemove:
		if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
			networkID := isolation.ExtractNetworkID(requestURI)
			if networkID != "" {
				// requestURI 可能含有前缀名（如 alice_u1001_testnet），需解析为 Docker 网络 ID
				if realID, found := p.db.GetNetworkIDByName(networkID); found {
					networkID = realID
				}
				_ = p.db.DeleteNetwork(networkID)
			}
		}
		isolation.CopyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)

	case authz.ActionVolumeCreate:
		body, err := isolation.ReadFullBody(resp.Body)
		if err != nil {
			writeDockerError(w, http.StatusBadGateway, "read upstream response failed")
			return
		}
		if resp.StatusCode == http.StatusCreated {
			var createResp struct {
				Name string `json:"Name"`
			}
			if json.Unmarshal(body, &createResp) == nil && createResp.Name != "" {
				if err := p.db.SetVolumeOwner(createResp.Name, id); err != nil {
					p.logger.Error("save_volume_owner_failed", zap.Error(err))
				} else {
					p.logger.Info("volume_created",
						append(audit.LogIdentityShortFields(auditID), zap.String("volume_name", createResp.Name))...)
				}
			}
		}
		isolation.CopyHeaders(w, resp.Header)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)

	case authz.ActionVolumeList:
		body, err := isolation.ReadFullBody(resp.Body)
		if err != nil {
			writeDockerError(w, http.StatusBadGateway, "read upstream response failed")
			return
		}
		totalCount = isolation.CountVolumeList(body)
		filtered, err := isolation.FilterVolumeListResponse(body, id.RealUID, p.db)
		if err != nil {
			p.logger.Error("filter_volumes_failed", zap.Error(err))
			emptyBody, _ := json.Marshal(struct {
				Volumes  []json.RawMessage `json:"Volumes"`
				Warnings []string          `json:"Warnings"`
			}{Volumes: []json.RawMessage{}, Warnings: nil})
			filtered = emptyBody
		}
		filteredCount = isolation.CountVolumeList(filtered)
		isolation.CopyHeaders(w, resp.Header)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(filtered)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(filtered)

	case authz.ActionVolumeRemove:
		if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
			volName := isolation.ExtractVolumeName(requestURI)
			if volName != "" {
				_ = p.db.DeleteVolume(volName)
			}
		}
		isolation.CopyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)

	case authz.ActionSystemInfo:
		body, err := isolation.ReadFullBody(resp.Body)
		if err != nil {
			p.logger.Error("read_response_body_failed", zap.String("action", "info"), zap.Error(err))
			writeDockerError(w, http.StatusBadGateway, "read upstream response failed")
			return
		}

		// root 用户直接透传，不做过滤
		if id.RealUID == 0 || resp.StatusCode != http.StatusOK {
			isolation.CopyHeaders(w, resp.Header)
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(body)
			return
		}

		// 查询用户容器 ID 列表，再查实际运行状态
		containerIDs, _ := p.db.GetContainerIDsByOwner(id.RealUID)
		states := p.queryUserContainerStates(containerIDs)

		// 查询用户可访问的镜像数量
		imageCount, _ := p.db.CountAccessibleImages(id.RealUID)

		// 将响应 JSON 解析为 map，替换计数字段后返回
		var info map[string]json.RawMessage
		if err := json.Unmarshal(body, &info); err != nil {
			// 解析失败则透传原始响应
			isolation.CopyHeaders(w, resp.Header)
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(body)
			return
		}

		info["Containers"] = json.RawMessage(strconv.Itoa(states.Total))
		info["ContainersRunning"] = json.RawMessage(strconv.Itoa(states.Running))
		info["ContainersPaused"] = json.RawMessage(strconv.Itoa(states.Paused))
		info["ContainersStopped"] = json.RawMessage(strconv.Itoa(states.Stopped))
		info["Images"] = json.RawMessage(strconv.Itoa(imageCount))

		filtered, err := json.Marshal(info)
		if err != nil {
			isolation.CopyHeaders(w, resp.Header)
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(body)
			return
		}

		isolation.CopyHeaders(w, resp.Header)
		w.Header().Set("Content-Length", strconv.Itoa(len(filtered)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(filtered)

	default:
		isolation.CopyHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.Copy(w, resp.Body)
	}

	if !isAuxiliaryCall(id.DockerCommand, action, "", requestURI) {
		p.auditLog.WriteEntry(func() audit.AuditEntry {
			e := makeAuditEntry(id, r, action, "allow", "", "", resp.StatusCode)
			e.URI = requestURI
			return e
		}())
	}
	return
}

// makeAuditEntry 从 identity 和 HTTP request 构建基础 AuditEntry（含 ClientIP/Method）
func makeAuditEntry(id *auth.CallerIdentity, r *http.Request, action, result, denyReason, containerID string, statusCode int) audit.AuditEntry {
	method := ""
	uri := ""
	if r != nil {
		method = r.Method
		uri = r.URL.RequestURI()
	}
	return audit.AuditEntry{
		User:        id.RealUsername,
		UID:         id.RealUID,
		ClientIP:    id.ClientAddr,
		AuthSource:  string(id.AuthSource),
		Method:      method,
		Action:      action,
		URI:         uri,
		Result:      result,
		DenyReason:  denyReason,
		ContainerID: containerID,
		StatusCode:  statusCode,
	}
}

// toAuditIdentity 将 auth.CallerIdentity 转换为 audit.IdentityInfo
func toAuditIdentity(id *auth.CallerIdentity) *audit.IdentityInfo {
	return &audit.IdentityInfo{
		RealUsername:      id.RealUsername,
		RealUID:           id.RealUID,
		RealGID:           id.RealGID,
		EffectiveUsername: id.EffectiveUsername,
		EffectiveUID:      id.EffectiveUID,
		PID:               id.PID,
		CmdLine:           id.CmdLine,
		UserType:          id.UserType.String(),
		AuthSource:        string(id.AuthSource),
	}
}

// isAuxiliaryCall 判断请求是否为辅助调用（不受策略检查）
func isAuxiliaryCall(dockerCmd, action, method, path string) bool {
	if (method == "GET" || method == "HEAD") &&
		(path == "/_ping" || strings.HasSuffix(path, "/_ping")) {
		return true
	}

	if dockerCmd == "" {
		// 无法识别命令来源时，只放行 _ping（健康检查），其余走正常策略检查
		return false
	}

	cmdTargetActions := map[string][]string{
		"run":     {authz.ActionPull, authz.ActionCreateContainer, authz.ActionStartContainer, authz.ActionRemoveContainer},
		"create":  {authz.ActionCreateContainer},
		"start":   {authz.ActionStartContainer},
		"stop":    {authz.ActionStop},
		"restart": {authz.ActionRestart},
		"kill":    {authz.ActionStop},
		"rm":      {authz.ActionRemoveContainer},
		"exec":    {authz.ActionExec},
		"attach":  {authz.ActionAttach},
		"logs":    {authz.ActionLogs},
		"stats":   {authz.ActionLogs},
		"top":     {authz.ActionLogs},
		"cp":      {authz.ActionCp},
		"commit":  {authz.ActionCommit},
		"ps":      {authz.ActionPS},
		"inspect": {authz.ActionInspect},
		"pause":   {authz.ActionStop},
		"unpause": {authz.ActionStop},
		"wait":    {authz.ActionWait},
		"rename":  {authz.ActionRename},
		"diff":    {authz.ActionDiff},
		"pull":    {authz.ActionPull},
		"import":  {authz.ActionImport},
		"push":    {authz.ActionPush},
		"build":   {authz.ActionBuild},
		"images":  {authz.ActionImages},
		"rmi":     {authz.ActionRemoveImage},
		"tag":     {authz.ActionTag},
		"save":    {authz.ActionSave},
		"load":    {authz.ActionLoad},
		"search":  {authz.ActionSearch},
		"info":    {authz.ActionSystemInfo},
		"version": {authz.ActionSystemVersion},
		"events":  {authz.ActionSystemEvents},
		"login":   {authz.ActionSystemLogin},
		"logout":  {authz.ActionSystemLogin},
		"df":      {authz.ActionSystemDF},
		"prune":   {authz.ActionPrune},
	}

	// 其他命令（如 docker run、docker ps 等）附带触发的 info/version 请求
	// 属于辅助调用，跳过策略检查；用户直接执行 docker info/version 则走正常检查
	if (action == authz.ActionSystemInfo || action == authz.ActionSystemVersion) &&
		dockerCmd != "info" && dockerCmd != "version" {
		return true
	}

	targetActions, known := cmdTargetActions[dockerCmd]
	if !known {
		return false
	}

	for _, t := range targetActions {
		if action == t {
			return false
		}
	}
	return true
}

// isHijackRequest 判断请求是否需要 HTTP hijack（双向流）
func isHijackRequest(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Upgrade"), "tcp") {
		return true
	}
	for _, v := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}
	path := authz.StripAPIVersion(r.URL.Path)
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
func (p *ProxyServer) handleHijack(w http.ResponseWriter, r *http.Request, id *auth.CallerIdentity) {
	action := authz.ClassifyAction(r.Method, r.URL.RequestURI())
	p.logger.Debug("hijack_request",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
		zap.String("action", action),
		zap.String("uri", r.URL.RequestURI()),
	)

	policy := p.getPolicy()
	isAuxiliary := isAuxiliaryCall(id.DockerCommand, action, r.Method, r.URL.Path)
	isDenied := !isAuxiliary && policy.IsDenied(id, action)

	// 对于升级请求（Connection: Upgrade），ResponseWriter.WriteHeader 可能不会立即
	// 发给客户端；需要先 hijack 连接，再通过原始 TCP 写拒绝响应并关闭。
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.logger.Error("hijack_not_supported")
		writeDockerError(w, http.StatusInternalServerError, "hijack not supported")
		return
	}

	if isDenied {
		auditID := toAuditIdentity(id)
		audit.LogAuthzDeniedCommand(p.logger, auditID, action, r.URL.RequestURI())
		errMsg := fmt.Sprintf("user '%s'(uid=%d) not permitted to perform: %s", id.RealUsername, id.RealUID, action)
		// hijack 后写拒绝响应，确保客户端能立即收到并退出
		conn, _, hijackErr := hijacker.Hijack()
		if hijackErr != nil {
			writeDockerError(w, http.StatusForbidden, errMsg)
			return
		}
		body := fmt.Sprintf(`{"message":%q}`, errMsg)
		resp := fmt.Sprintf("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		_, _ = conn.Write([]byte(resp))
		conn.Close()
		return
	}
	if _, ok := p.checkOwnershipPreRequest(w, r, id, action); !ok {
		return
	}
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		p.logger.Error("hijack_failed", zap.Error(err))
		writeDockerError(w, http.StatusInternalServerError, "hijack failed: "+err.Error())
		return
	}
	defer clientConn.Close()

	upstreamConn, err := net.DialTimeout("unix", p.upstreamSock, 5*time.Second)
	if err != nil {
		p.logger.Error("upstream_dial_failed", zap.Error(err))
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\nupstream dial failed: %s", err.Error())
		return
	}
	defer upstreamConn.Close()

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

	upstreamReader := bufio.NewReader(upstreamConn)
	statusLine, err := upstreamReader.ReadString('\n')
	if err != nil {
		p.logger.Error("read_upstream_status_failed", zap.Error(err))
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\nread upstream status failed: %s", err.Error())
		return
	}

	// 判断是否真正升级为双向流（101）；exec 非 TTY 时 dockerd 返回 200
	is101 := strings.HasPrefix(statusLine, "HTTP/1.1 101") || strings.HasPrefix(statusLine, "HTTP/1.0 101")

	// 读取并收集所有响应头（直到空行），同时检测 Transfer-Encoding
	peeked := statusLine
	isChunked := false
	for {
		line, err := upstreamReader.ReadString('\n')
		if err != nil {
			p.logger.Error("read_upstream_header_failed", zap.Error(err))
			return
		}
		peeked += line
		if strings.HasPrefix(strings.ToLower(line), "transfer-encoding:") &&
			strings.Contains(strings.ToLower(line), "chunked") {
			isChunked = true
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	if !is101 && isChunked {
		// exec 非 TTY + chunked：dockerd 发 0\r\n\r\n 结束但不关闭 TCP。
		// 把头部原样转发给客户端（保留 Transfer-Encoding: chunked），
		// 再把 chunked body 原样透传；当读到终止块 0\r\n\r\n 时停止，避免永久阻塞。
		if _, err := clientConn.Write([]byte(peeked)); err != nil {
			return
		}
		// 逐 chunk 读取并转发，直到终止块
		for {
			// 读 chunk size 行
			sizeLine, err := upstreamReader.ReadString('\n')
			if err != nil {
				return
			}
			clientConn.Write([]byte(sizeLine))
			// 解析 chunk size（十六进制，可能带扩展）
			sizeStr := strings.TrimSpace(strings.SplitN(sizeLine, ";", 2)[0])
			size, err := strconv.ParseInt(sizeStr, 16, 64)
			if err != nil {
				return
			}
			if size == 0 {
				// 终止块：读并转发剩余的 \r\n
				trailer, _ := upstreamReader.ReadString('\n')
				clientConn.Write([]byte(trailer))
				return
			}
			// 读 chunk data + \r\n
			buf := make([]byte, size+2)
			if _, err := io.ReadFull(upstreamReader, buf); err != nil {
				return
			}
			clientConn.Write(buf)
		}
	}

	// 101 升级 或 非 chunked 的 200（raw-stream）：
	// 先把已收集的头部发给客户端，再双向透传直到任意一端关闭。
	if _, err := clientConn.Write([]byte(peeked)); err != nil {
		p.logger.Error("write_status_to_client_failed", zap.Error(err))
		return
	}

	upstreamDone := make(chan struct{})
	clientDone := make(chan struct{})
	go func() {
		io.Copy(upstreamConn, clientConn)
		// 客户端→上游方向结束：半关闭上游写端，通知上游不再有输入
		type closeWriter interface{ CloseWrite() error }
		if cw, ok := upstreamConn.(closeWriter); ok {
			cw.CloseWrite()
		}
		close(clientDone)
	}()
	go func() {
		io.Copy(clientConn, upstreamReader)
		close(upstreamDone)
	}()
	// 优先等待上游→客户端方向结束（exec 输出完毕）；
	// 若客户端先断开（TTY Ctrl+C 等），也能正常退出。
	select {
	case <-upstreamDone:
		// 上游输出完毕，关闭客户端连接
		clientConn.Close()
		upstreamConn.Close()
		<-clientDone
	case <-clientDone:
		// 客户端→上游方向结束（无 stdin 或 TTY 退出）；
		// 半关闭上游写端（不关闭读端），等上游把剩余输出发完再关闭。
		type closeWriter interface{ CloseWrite() error }
		if cw, ok := upstreamConn.(closeWriter); ok {
			cw.CloseWrite()
		}
		<-upstreamDone
		clientConn.Close()
		upstreamConn.Close()
	}

	p.logger.Debug("hijack_done",
		zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
		zap.String("action", action),
	)
}

// systemUser 从 /etc/passwd 读取的用户信息
type systemUser struct {
	Username string
	UID      int
	GID      int
	HomeDir  string
}

// listSystemUsers 返回有 shell 的系统用户（含 root）
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
		shell := ""
		if len(fields) >= 7 {
			shell = strings.TrimSpace(fields[6])
		}
		if shell == "" || strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "false") {
			continue
		}
		// 跳过系统用户（uid 1~999），root(uid=0) 和普通用户(uid>=1000) 保留
		if uid != 0 && uid < 1000 {
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

// setUserDockerHost 将 DOCKER_HOST 环境变量写入用户的 shell 配置文件。
// 同时写入 ~/.bashrc（交互式 shell）和 ~/.bash_profile / ~/.profile（登录 shell
// 及非交互式登录，如 su -c、SSH 非交互执行等），确保各场景均能生效。
func setUserDockerHost(u systemUser, socketDir string, logger *zap.Logger) {
	if u.HomeDir == "" {
		return
	}
	sockPath := "unix://" + filepath.Join(socketDir, u.Username, "docker.sock")
	exportLine := fmt.Sprintf("export DOCKER_HOST=%s", sockPath)
	marker := "# docker-authz-proxy: DOCKER_HOST"

	// 候选配置文件：bashrc（交互式）+ bash_profile / profile（登录/非交互式登录）
	candidates := []string{
		filepath.Join(u.HomeDir, ".bashrc"),
		filepath.Join(u.HomeDir, ".bash_profile"),
		filepath.Join(u.HomeDir, ".profile"),
	}

	for _, cfgFile := range candidates {
		writeDockerHostToFile(cfgFile, u, exportLine, marker, logger)
	}
}

// writeDockerHostToFile 向单个 shell 配置文件写入或更新 DOCKER_HOST。
func writeDockerHostToFile(cfgFile string, u systemUser, exportLine, marker string, logger *zap.Logger) {
	existing, err := os.ReadFile(cfgFile)
	if err == nil {
		content := string(existing)
		if strings.Contains(content, exportLine) {
			return // 已是最新，无需修改
		}
		if strings.Contains(content, marker) {
			// marker 存在但路径是旧格式，替换整行
			oldPattern := marker + "\nexport DOCKER_HOST=unix:///run/docker-authz/" + u.Username + ".sock"
			newContent := strings.ReplaceAll(content, oldPattern, marker+"\n"+exportLine)
			if err := os.WriteFile(cfgFile, []byte(newContent), 0644); err != nil {
				logger.Warn("failed to update DOCKER_HOST in shell config",
					zap.String("username", u.Username),
					zap.String("file", cfgFile),
					zap.Error(err))
			}
			return
		}
	} else if !os.IsNotExist(err) {
		// 文件存在但读取失败，跳过
		return
	}

	f, err := os.OpenFile(cfgFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logger.Warn("failed to write DOCKER_HOST to shell config",
			zap.String("username", u.Username),
			zap.String("file", cfgFile),
			zap.Error(err))
		return
	}
	defer f.Close()

	if _, err = fmt.Fprintf(f, "\n%s\n%s\n", marker, exportLine); err != nil {
		logger.Warn("failed to write DOCKER_HOST to shell config",
			zap.String("username", u.Username),
			zap.String("file", cfgFile),
			zap.Error(err))
		return
	}
	_ = os.Chown(cfgFile, u.UID, u.GID)
	logger.Info("set DOCKER_HOST in shell config",
		zap.String("username", u.Username),
		zap.String("file", cfgFile),
		zap.String("docker_host", exportLine))
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
	// 只截断看起来像 sha256 的十六进制 ID（至少 12 位十六进制字符）
	if len(id) > 12 {
		isHex := true
		for _, c := range id[:12] {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				isHex = false
				break
			}
		}
		if isHex {
			return id[:12]
		}
	}
	return id
}

// parseImageRefFromURI 从 docker pull 的请求 URI 中提取镜像引用
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

// fetchContainerLabels 通过 Docker API 获取容器的 Labels，失败返回 nil
func (p *ProxyServer) fetchContainerLabels(containerID string) map[string]string {
	upstreamURL := &url.URL{
		Scheme: "http",
		Host:   "docker",
		Path:   "/containers/" + containerID + "/json",
	}
	req, err := http.NewRequest("GET", upstreamURL.String(), nil)
	if err != nil {
		return nil
	}
	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var info struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil
	}
	return info.Config.Labels
}

// checkContainerOwnershipByLabel 在归属数据库未记录容器时，通过 Docker API 读取容器标签核验归属。
// 依次检查 system.authz.owner.uid 标签和 owner 标签；两者均不匹配时拒绝请求。
func (p *ProxyServer) checkContainerOwnershipByLabel(w http.ResponseWriter, id *auth.CallerIdentity,
	containerID, action string) bool {

	auditID := toAuditIdentity(id)
	labels := p.fetchContainerLabels(containerID)
	if labels == nil {
		// 容器不存在（Docker 返回 404）。若为 ActionInspect，用户可能是在 inspect 镜像
		// （docker inspect 先请求 /containers/{id}/json，404 后 CLI 会重试 /images/{id}/json）。
		// 此时放行，让 Docker 返回 404，CLI 自动重试镜像端点。
		if action == authz.ActionInspect {
			if imgID := p.resolveImageIDByRef(containerID); imgID != "" {
				// 确认是镜像引用，放行让 Docker daemon 返回 404，CLI 会自动重试 /images/
				return true
			}
		}
		// 容器不存在时，rm/stop 等操作直接放行，让 Docker 返回 404（幂等操作）
		if action == authz.ActionRemoveContainer || action == authz.ActionStop {
			return true
		}
		// 无法获取容器信息（容器不存在或网络故障），拒绝以确保安全
		audit.LogAuthzDeniedNotTracked(p.logger, auditID, "container", truncID(containerID), action)
		p.auditLog.WriteEntry(audit.AuditEntry{
			User: id.RealUsername, UID: id.RealUID, ClientIP: id.ClientAddr,
			AuthSource: string(id.AuthSource), Action: action, Result: "deny",
			DenyReason: "container_not_found", ContainerID: truncID(containerID), StatusCode: http.StatusForbidden,
		})
		writeDockerNotFound(w, "container", containerID)
		return false
	}

	// 检查 system.authz.owner.uid 标签（防篡改）
	if uidStr := isolation.GetLastLabelValue(labels[isolation.LabelOwnerUID]); uidStr != "" {
		uid := 0
		valid := true
		for _, c := range uidStr {
			if c < '0' || c > '9' {
				valid = false
				break
			}
			uid = uid*10 + int(c-'0')
		}
		if valid && uid == id.RealUID {
			p.logger.Info("container_ownership_verified_by_label",
				zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
				zap.String("container_id", truncID(containerID)),
				zap.String("via", "uid_label"))
			p.auditLog.WriteEntry(audit.AuditEntry{
				User: id.RealUsername, UID: id.RealUID, ClientIP: id.ClientAddr,
				AuthSource: string(id.AuthSource), Action: action, Result: "allow",
				DenyReason: "label_ownership_verified", ContainerID: truncID(containerID), StatusCode: http.StatusOK,
			})
			return true
		}
	}

	// 检查 owner 标签（用户可见标签，防篡改）
	if ownerName := isolation.GetLastLabelValue(labels[isolation.LabelOwner]); ownerName != "" && ownerName == id.RealUsername {
		p.logger.Info("container_ownership_verified_by_label",
			zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
			zap.String("container_id", truncID(containerID)),
			zap.String("via", "owner_label"))
		p.auditLog.WriteEntry(audit.AuditEntry{
			User: id.RealUsername, UID: id.RealUID, ClientIP: id.ClientAddr,
			AuthSource: string(id.AuthSource), Action: action, Result: "allow",
			DenyReason: "label_ownership_verified", ContainerID: truncID(containerID), StatusCode: http.StatusOK,
		})
		return true
	}

	// 标签均不匹配，拒绝
	audit.LogAuthzDeniedNotTracked(p.logger, auditID, "container", truncID(containerID), action)
	p.auditLog.WriteEntry(audit.AuditEntry{
		User: id.RealUsername, UID: id.RealUID, ClientIP: id.ClientAddr,
		AuthSource: string(id.AuthSource), Action: action, Result: "deny",
		DenyReason: "container_not_owned_label", ContainerID: truncID(containerID), StatusCode: http.StatusForbidden,
	})
	writeDockerNotFound(w, "container", containerID)
	return false
}

// writeDockerNotFound 以 Docker daemon 标准 404 JSON 格式响应，
// 避免向调用方泄露资源归属信息（统一伪装成"不存在"）。
func writeDockerNotFound(w http.ResponseWriter, kind, name string) {
	var msg string
	switch kind {
	case "volume":
		msg = fmt.Sprintf("get %s: no such volume", name)
	case "image":
		msg = fmt.Sprintf("No such image: %s", name)
	case "network":
		msg = fmt.Sprintf("network %s not found", name)
	default:
		msg = fmt.Sprintf("No such container: %s", name)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprintf(w, `{"message":%q}`, msg)
}

// writeDockerError 以 Docker daemon 标准 JSON 错误格式响应，
// 确保 Docker CLI 能正确解析错误信息而不产生冗余输出。
func writeDockerError(w http.ResponseWriter, statusCode int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = fmt.Fprintf(w, `{"message":%q}`, msg)
}

// resolveImageIDByRef 查询 dockerd 获取镜像的真实内容 ID
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

// containerStateCounts 查询用户容器的运行状态统计
type containerStateCounts struct {
	Total   int
	Running int
	Paused  int
	Stopped int
}

// queryUserContainerStates 通过 Docker API 查询用户容器的实际运行状态
func (p *ProxyServer) queryUserContainerStates(containerIDs []string) containerStateCounts {
	if len(containerIDs) == 0 {
		return containerStateCounts{}
	}

	upstreamURL := &url.URL{
		Scheme:   "http",
		Host:     "docker",
		Path:     "/containers/json",
		RawQuery: "all=1",
	}
	req, err := http.NewRequest("GET", upstreamURL.String(), nil)
	if err != nil {
		return containerStateCounts{Total: len(containerIDs)}
	}
	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		return containerStateCounts{Total: len(containerIDs)}
	}
	defer resp.Body.Close()

	var containers []struct {
		ID    string `json:"Id"`
		State string `json:"State"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return containerStateCounts{Total: len(containerIDs)}
	}

	// 构建用户容器 ID 集合（支持短 ID 匹配）
	idSet := make(map[string]bool, len(containerIDs))
	for _, id := range containerIDs {
		idSet[id] = true
	}

	var counts containerStateCounts
	for _, c := range containers {
		// 全 ID 或短 ID（12位）匹配
		if !idSet[c.ID] && !idSet[c.ID[:min(12, len(c.ID))]] {
			continue
		}
		counts.Total++
		switch c.State {
		case "running":
			counts.Running++
		case "paused":
			counts.Paused++
		default:
			counts.Stopped++
		}
	}
	return counts
}

// resolveContainerDockerID 通过容器名称（或短 ID）查询 dockerd 获取容器的真实 Docker ID
func (p *ProxyServer) resolveContainerDockerID(nameOrID string) string {
	upstreamURL := &url.URL{
		Scheme: "http",
		Host:   "docker",
		Path:   "/containers/" + nameOrID + "/json",
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
	var c struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return ""
	}
	return c.ID
}

// streamAndCaptureLoadedImageIDs 流式转发 docker load 响应，捕获加载的镜像 ID
func streamAndCaptureLoadedImageIDs(w http.ResponseWriter, resp *http.Response) []string {
	flusher, canFlush := w.(http.Flusher)
	var imageIDs []string

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		_, _ = w.Write([]byte(line + "\n"))
		if canFlush {
			flusher.Flush()
		}
		var msg struct {
			Stream string `json:"stream"`
		}
		if err := json.Unmarshal([]byte(line), &msg); err == nil {
			if strings.HasPrefix(msg.Stream, "Loaded image ID: ") {
				id := strings.TrimSpace(strings.TrimPrefix(msg.Stream, "Loaded image ID: "))
				if id != "" {
					imageIDs = append(imageIDs, id)
				}
			}
		}
	}
	return imageIDs
}

// extractContainerIDFromCreateResponse 从容器创建响应体中提取容器 ID
func extractContainerIDFromCreateResponse(body []byte) string {
	var resp struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}
	return resp.ID
}

// streamAndCaptureImageID 流式转发 build/pull 响应，同时从末尾提取镜像 ID
func streamAndCaptureImageID(w http.ResponseWriter, resp *http.Response, source string) string {
	flusher, canFlush := w.(http.Flusher)

	const keepLines = 20
	var lastLines []string

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		_, _ = w.Write([]byte(line + "\n"))
		if canFlush {
			flusher.Flush()
		}
		lastLines = append(lastLines, line)
		if len(lastLines) > keepLines {
			lastLines = lastLines[1:]
		}
	}

	return extractImageIDFromStreamLines(lastLines, source)
}

// extractImageIDFromStreamLines 从 build/pull 的末尾流行中提取镜像 ID
func extractImageIDFromStreamLines(lines []string, source string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]

		if source == "build" {
			// BuildKit 格式：{"aux":{"ID":"sha256:..."}}
			var msg struct {
				Aux *struct {
					ID string `json:"ID"`
				} `json:"aux"`
			}
			if err := json.Unmarshal([]byte(line), &msg); err == nil && msg.Aux != nil && msg.Aux.ID != "" {
				return strings.TrimPrefix(msg.Aux.ID, "sha256:")
			}
			// 旧版 builder JSON 格式：{"stream":"Successfully built <id>\n"}
			var streamMsg struct {
				Stream string `json:"stream"`
			}
			if err := json.Unmarshal([]byte(line), &streamMsg); err == nil {
				s := strings.TrimSpace(streamMsg.Stream)
				if strings.HasPrefix(s, "Successfully built ") {
					return strings.TrimPrefix(s, "Successfully built ")
				}
			}
			// 纯文本格式（兼容）
			if strings.HasPrefix(line, "Successfully built ") {
				return strings.TrimPrefix(line, "Successfully built ")
			}
		}

		if source == "pull" {
			var msg struct {
				Aux *struct {
					Tag    string `json:"Tag"`
					Digest string `json:"Digest"`
					Size   int64  `json:"Size"`
				} `json:"aux"`
			}
			if err := json.Unmarshal([]byte(line), &msg); err == nil {
				if msg.Aux != nil && msg.Aux.Digest != "" {
					return msg.Aux.Digest
				}
			}
		}
	}
	return ""
}

// logQuotaCheck 记录配额校验详情到运营日志（INFO 级别）
// 包含：用户请求参数、配额上限、校验结果、最终注入值
func logQuotaCheck(logger *zap.Logger, id *audit.IdentityInfo, qr *isolation.QuotaCheckResult) {
	if qr == nil {
		return
	}
	fields := append(audit.LogIdentityShortFields(id),
		zap.Float64("quota_cpu_cores", qr.QuotaCPUCores),
		zap.Int("quota_mem_mb", qr.QuotaMemMB),
		zap.Int("quota_storage_gb", qr.QuotaStorageGB),
		zap.Int("quota_max_containers", qr.MaxContainers),
		zap.Float64("req_cpu_cores", qr.RequestedCPUCores),
		zap.Int64("req_mem_mb", qr.RequestedMemMB),
		zap.Int("req_storage_gb", qr.RequestedStorageGB),
		zap.Int64("req_cpu_shares", qr.RequestedCpuShares),
		zap.String("req_cpuset_cpus", qr.RequestedCpusetCpus),
		zap.Bool("allowed", qr.Allowed),
	)
	if qr.Allowed {
		fields = append(fields,
			zap.Float64("injected_cpu_cores", qr.InjectedCPUCores),
			zap.Int64("injected_mem_mb", qr.InjectedMemMB),
			zap.Int("injected_storage_gb", qr.InjectedStorageGB),
		)
		logger.Info("quota_check_pass", fields...)
	} else {
		fields = append(fields,
			zap.String("denied_resource", qr.DeniedResource),
			zap.String("denied_requested", qr.DeniedRequested),
			zap.String("denied_limit", qr.DeniedLimit),
			zap.String("denied_excess", qr.DeniedExcess),
		)
		logger.Warn("quota_check_deny", fields...)
	}
}

// ensureUserBridge 确保用户专属桥接网络存在，并将网络 ID 记录到 DB
func (p *ProxyServer) ensureUserBridge(u systemUser) {
	networkID, err := p.bridge.EnsureUserBridge(u.UID, u.Username)
	if err != nil {
		p.logger.Error("ensure_user_bridge_failed",
			zap.String("username", u.Username),
			zap.Int("uid", u.UID),
			zap.Error(err))
		return
	}
	// 将桥接网络记录到归属 DB（owner 为系统，uid=0 表示代理管理）
	// 使用特殊标记 uid=-1 表示"代理自动创建，归属于该用户"
	bridgeName := isolation.UserBridgeName(u.UID)
	if err := p.db.SetManagedNetworkOwner(networkID, bridgeName, u.UID, u.Username); err != nil {
		p.logger.Warn("save_bridge_network_owner_failed",
			zap.String("network_id", truncID(networkID)),
			zap.String("username", u.Username),
			zap.Error(err))
	} else {
		p.logger.Info("user_bridge_ready",
			zap.String("username", u.Username),
			zap.Int("uid", u.UID),
			zap.String("network", bridgeName),
			zap.String("network_id", truncID(networkID)))
	}
}

// ensureUserStorageDir 确保用户专属存储目录存在，并设置正确的文件归属
func (p *ProxyServer) ensureUserStorageDir(u systemUser) {
	if err := isolation.EnsureUserStorageDir(p.storageBase, u.UID, u.GID); err != nil {
		p.logger.Warn("ensure_user_storage_dir_failed",
			zap.String("username", u.Username),
			zap.Int("uid", u.UID),
			zap.Error(err))
		return
	}
	p.logger.Info("user_storage_dir_ready",
		zap.String("username", u.Username),
		zap.Int("uid", u.UID),
		zap.String("dir", isolation.UserStorageRoot(p.storageBase, u.UID)))
}

// StartStorageCleanup 启动定期存储清理协程（孤立 Volume + 空废弃目录）
// interval 为 0 时不启动清理。应在 Start() 之后调用。
func (p *ProxyServer) StartStorageCleanup(ctx context.Context, interval time.Duration) {
	if interval <= 0 || p.storage == nil {
		return
	}
	p.storage.StartCleanup(ctx, p.db, p.logger, p.auditLog, interval)
	p.logger.Info("storage_cleanup_started",
		zap.Duration("interval", interval),
		zap.String("storage_base", p.storageBase))
}

// checkPortConflict 检查端口冲突（查询 DB 全局端口记录表），并记录审计日志
// 通过后不在此处写入 DB，等容器创建成功后在 postprocessResponse 中写入
func (p *ProxyServer) checkPortConflict(w http.ResponseWriter, r *http.Request,
	id *auth.CallerIdentity, body []byte) bool {

	mappings := isolation.ExtractPortMappings(body)
	if len(mappings) == 0 {
		return true
	}

	for _, m := range mappings {
		p.logger.Info("port_mapping_requested",
			zap.String("user", id.RealUsername),
			zap.Int("uid", id.RealUID),
			zap.Int("host_port", m.HostPort),
			zap.Int("container_port", m.ContainerPort),
			zap.String("protocol", m.Protocol),
		)
		// 查询 DB 中是否已有该端口的记录
		existing, occupied := p.db.GetPortMapping(m.HostPort, m.Protocol)
		if occupied {
			p.logger.Warn("port_conflict_detected",
				zap.String("user", id.RealUsername),
				zap.Int("uid", id.RealUID),
				zap.Int("port", m.HostPort),
				zap.String("protocol", m.Protocol),
				zap.String("existing_container", existing.ContainerID),
				zap.String("existing_owner", existing.OwnerUsername),
			)
			msg := fmt.Sprintf("port %d/%s already in use by container %s (owner: %s)",
				m.HostPort, m.Protocol, existing.ContainerID[:min(12, len(existing.ContainerID))],
				existing.OwnerUsername)
			p.auditLog.WriteEntry(makeAuditEntry(id, r, "container_create", "deny", "port_conflict", msg, http.StatusConflict))
			writeDockerError(w, http.StatusConflict, msg)
			return false
		}
	}
	return true
}

// PeerOptions 配置网络互通的选项
type PeerOptions struct {
	// ContainerIDA/B 非空时为容器级互通，只有这两个容器可以互通；
	// 为空时为用户级互通，双方所有容器（含未来新建容器）均可互通。
	ContainerIDA string // 用户 A 的容器 ID（完整 ID 或短 ID）
	ContainerIDB string // 用户 B 的容器 ID（完整 ID 或短 ID）
}

// AllowNetworkPeer 开启两个用户之间的网络互通（管理员调用）
//
// opts.ContainerIDA/B 均为空 → 用户级互通：双方所有已有容器接入辅助网络，新容器创建时自动接入。
// opts.ContainerIDA/B 均非空 → 容器级互通：只将指定的两个容器接入辅助网络，其他容器不受影响，
//
//	新容器创建时也不会自动接入。
func (p *ProxyServer) AllowNetworkPeer(uidA, uidB int, opts PeerOptions) error {
	containerLevel := opts.ContainerIDA != "" || opts.ContainerIDB != ""

	if containerLevel {
		// 容器级：两个容器 ID 必须同时指定
		if opts.ContainerIDA == "" || opts.ContainerIDB == "" {
			return fmt.Errorf("container-level peer requires both --container-a and --container-b")
		}
		// 幂等检查
		if _, exists := p.db.GetContainerPeer(uidA, uidB, opts.ContainerIDA, opts.ContainerIDB); exists {
			return nil
		}
	} else {
		// 用户级：幂等检查
		if _, exists := p.db.GetNetworkPeer(uidA, uidB); exists {
			return nil
		}
	}

	// 创建共享辅助网络
	// 容器级互通使用独立网络（名称含容器 ID 短串），与用户级 peer 网络严格隔离
	var (
		peerNetworkID string
		err           error
	)
	if containerLevel {
		shortA := opts.ContainerIDA
		if len(shortA) > 12 {
			shortA = shortA[:12]
		}
		shortB := opts.ContainerIDB
		if len(shortB) > 12 {
			shortB = shortB[:12]
		}
		peerNetworkID, err = p.bridge.CreateContainerPeerNetwork(uidA, uidB, shortA, shortB)
	} else {
		peerNetworkID, err = p.bridge.CreatePeerNetwork(uidA, uidB)
	}
	if err != nil {
		return fmt.Errorf("create peer network: %w", err)
	}

	if containerLevel {
		// 只连接指定的两个容器
		for _, cid := range []string{opts.ContainerIDA, opts.ContainerIDB} {
			if err := p.bridge.ConnectContainerToPeerNetwork(cid, peerNetworkID); err != nil {
				p.logger.Warn("connect_container_to_peer_failed",
					zap.String("container", cid[:min(12, len(cid))]),
					zap.Error(err))
			}
		}
	} else {
		// 用户级：将双方所有已有容器连接到辅助网络
		for _, uid := range []int{uidA, uidB} {
			containers, err := p.bridge.GetContainersByOwner(uid)
			if err != nil {
				p.logger.Warn("list_containers_for_peer_failed",
					zap.Int("uid", uid), zap.Error(err))
				continue
			}
			for _, cid := range containers {
				if err := p.bridge.ConnectContainerToPeerNetwork(cid, peerNetworkID); err != nil {
					p.logger.Warn("connect_container_to_peer_failed",
						zap.String("container", cid[:min(12, len(cid))]),
						zap.Int("uid", uid),
						zap.Error(err))
				}
			}
		}
	}

	// 记录到 DB
	if err := p.db.AddNetworkPeer(uidA, uidB, peerNetworkID, opts.ContainerIDA, opts.ContainerIDB); err != nil {
		return fmt.Errorf("save peer record: %w", err)
	}

	p.logger.Info("network_peer_allowed",
		zap.Int("uid_a", uidA),
		zap.Int("uid_b", uidB),
		zap.Bool("container_level", containerLevel),
		zap.String("container_a", opts.ContainerIDA),
		zap.String("container_b", opts.ContainerIDB),
		zap.String("peer_network_id", peerNetworkID[:min(12, len(peerNetworkID))]),
	)
	return nil
}

// DenyNetworkPeer 撤销网络互通，恢复隔离（管理员调用）
//
// opts.ContainerIDA/B 均为空 → 删除该用户对的所有互通记录（含容器级），删除所有辅助网络。
// opts.ContainerIDA/B 均非空 → 只删除指定容器级互通记录，删除对应辅助网络。
func (p *ProxyServer) DenyNetworkPeer(uidA, uidB int, opts PeerOptions) error {
	peerNetworkIDs, err := p.db.RemoveNetworkPeer(uidA, uidB, opts.ContainerIDA, opts.ContainerIDB)
	if err != nil {
		return fmt.Errorf("remove peer record: %w", err)
	}
	if len(peerNetworkIDs) == 0 {
		return ErrPeerNotFound
	}

	// 删除辅助网络（Docker 自动断开所有已连接的容器）
	for _, netID := range peerNetworkIDs {
		if err := p.bridge.DeletePeerNetwork(netID); err != nil {
			p.logger.Warn("delete_peer_network_failed",
				zap.String("peer_network_id", netID[:min(12, len(netID))]),
				zap.Error(err))
		}
	}

	p.logger.Info("network_peer_denied",
		zap.Int("uid_a", uidA),
		zap.Int("uid_b", uidB),
		zap.String("container_a", opts.ContainerIDA),
		zap.String("container_b", opts.ContainerIDB),
		zap.Int("networks_removed", len(peerNetworkIDs)),
	)
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// connectContainerToPeerNetworks 将新容器连接到该用户所有已配置的用户级互通辅助网络。
// 容器级互通不在此处处理（只有指定容器才接入，新容器不自动加入）。
func (p *ProxyServer) connectContainerToPeerNetworks(containerID string, uid int) {
	peers, err := p.db.GetNetworkPeersByUID(uid)
	if err != nil {
		p.logger.Warn("connect_peer_get_peers_failed", zap.Int("uid", uid), zap.Error(err))
		return
	}
	p.logger.Info("connect_peer_networks_check",
		zap.String("container_id", containerID[:min(12, len(containerID))]),
		zap.Int("uid", uid),
		zap.Int("peer_count", len(peers)))
	for _, peer := range peers {
		// 只处理用户级互通（container_id_a/b 均为空）
		if !peer.IsUserLevel() {
			continue
		}
		if err := p.bridge.ConnectContainerToPeerNetwork(containerID, peer.PeerNetworkID); err != nil {
			p.logger.Warn("connect_new_container_to_peer_failed",
				zap.String("container_id", containerID[:min(12, len(containerID))]),
				zap.Int("uid", uid),
				zap.String("peer_network_id", peer.PeerNetworkID[:min(12, len(peer.PeerNetworkID))]),
				zap.Error(err))
		} else {
			p.logger.Info("connect_new_container_to_peer_ok",
				zap.String("container_id", containerID[:min(12, len(containerID))]),
				zap.Int("uid", uid),
				zap.String("peer_network_id", peer.PeerNetworkID[:min(12, len(peer.PeerNetworkID))]))
		}
	}
}

// StartDockerEventListener 启动 Docker 事件监听协程
// 监听容器 die/destroy 事件，自动释放端口记录
// 应在 Start() 之后调用
func (p *ProxyServer) StartDockerEventListener(ctx context.Context) {
	listener := isolation.NewDockerEventListener(p.upstreamSock)
	ch := make(chan isolation.DockerEvent, 32)

	go func() {
		backoff := 2 * time.Second
		const maxBackoff = 60 * time.Second
		for {
			if err := listener.Listen(ctx, ch); err != nil {
				if ctx.Err() != nil {
					return // 正常退出
				}
				p.logger.Warn("docker_event_listener_error", zap.Error(err))
				// 指数退避重连，避免 Docker daemon 重启期间狂刷日志
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff < maxBackoff {
					backoff *= 2
				}
			} else {
				// Listen 返回 nil 表示正常断连（EOF），短暂等待后重连，重置退避
				backoff = 2 * time.Second
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-ch:
				// 监听容器销毁事件（die = 容器停止，destroy = 容器删除）
				if event.Type == "container" && (event.Action == "destroy" || event.Action == "die") {
					containerID := event.Actor.ID
					if containerID == "" {
						continue
					}
					if event.Action == "destroy" {
						// 容器彻底删除时释放端口记录
						if err := p.db.ReleasePortMappings(containerID); err != nil {
							p.logger.Warn("release_port_mappings_event_failed",
								zap.String("container_id", containerID[:min(12, len(containerID))]),
								zap.Error(err))
						} else {
							p.logger.Debug("port_mappings_released_by_event",
								zap.String("container_id", containerID[:min(12, len(containerID))]),
							)
						}
					}
				}
			}
		}
	}()
}

// checkCreateContainerNetworks 检查容器创建请求中显式指定的网络是否都可被该用户访问。
// 读取请求体后会还原，不影响后续处理。
// 返回 non-nil error 表示已向客户端写入拒绝响应。
func (p *ProxyServer) checkCreateContainerNetworks(w http.ResponseWriter, r *http.Request,
	id *auth.CallerIdentity, action string) error {

	if r.Body == nil {
		return nil
	}
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	networks := isolation.ExtractRequestedNetworks(body)
	if len(networks) == 0 {
		return nil
	}

	prefix := isolation.UserResourcePrefix(id)
	bridgeName := isolation.UserBridgeName(id.RealUID)

	for _, netName := range networks {
		// 跳过 Docker 默认网络名（不带 --network 时 CLI 自动填入，由 InjectUserNetwork 覆盖）
		if netName == "default" || netName == "bridge" || netName == "host" || netName == "none" {
			continue
		}
		// 跳过用户自己的专属 bridge 网络（由 InjectUserNetwork 注入，始终允许）
		if netName == bridgeName {
			continue
		}
		// 跳过已带用户前缀的网络名（用户自己创建的网络）
		if strings.HasPrefix(netName, prefix) {
			continue
		}

		// 尝试按用户前缀名查找真实 network ID
		lookupName := prefix + netName
		lookupID := netName
		if docID, found := p.db.GetNetworkIDByName(lookupName); found {
			lookupID = docID
		}

		ok, err := p.db.CanUserAccessNetwork(lookupID, id.RealUID)
		if err != nil || !ok {
			auditID := toAuditIdentity(id)
			p.logger.Warn("AUTHZ_DENY",
				append(audit.LogIdentityFields(auditID),
					zap.String("reason", "network_not_accessible_on_create"),
					zap.String("network", netName),
					zap.String("action", action),
				)...)
			p.auditLog.WriteEntry(makeAuditEntry(id, r, action, "deny", "network_not_accessible", netName, http.StatusNotFound))
			writeDockerNotFound(w, "network", netName)
			return fmt.Errorf("network not accessible")
		}
	}
	return nil
}

