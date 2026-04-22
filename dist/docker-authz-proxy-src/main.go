package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"time"

	"docker-authz-proxy/internal/audit"
	"docker-authz-proxy/internal/auth"
	"docker-authz-proxy/internal/authz"
	"docker-authz-proxy/internal/config"
	"docker-authz-proxy/internal/forward"
	"docker-authz-proxy/internal/isolation"

	"go.uber.org/zap"
)

func main() {
	var (
		socketDir    = flag.String("socket-dir", "/run/docker-authz", "per-user socket 目录")
		upstreamSock = flag.String("upstream", "/var/run/docker.sock", "Docker daemon socket 路径")
		policyFile   = flag.String("policy", "/etc/docker-authz/policy.yaml", "授权策略配置文件")
		dbPath       = flag.String("db", "/var/lib/docker-authz/owners.db", "归属数据库路径")
		logLevel     = flag.String("log-level", "info", "日志级别: debug/info/warn/error")
		logFormat    = flag.String("log-format", "json", "日志格式: json/text")
		logFile      = flag.String("log-file", "", "日志文件路径（空表示输出到 stdout）")
		// 连接与并发控制
		requestTimeout = flag.Int("request-timeout", 30, "单请求超时秒数（含等待上游响应），0 表示不限制")
		maxConcurrent  = flag.Int("max-concurrent", 100, "最大并发请求数，0 表示不限制")
		// 存储资源隔离
		storageRoot            = flag.String("storage-root", "/var/docker/user-storage", "用户存储根目录")
		storageCleanupInterval = flag.Int("storage-cleanup-interval", 5, "存储清理间隔（分钟），0 表示不启用清理")
		// 资源配额
		quotaFile = flag.String("quota-file", "", "资源配额配置文件（空表示不限制）")
		// 审计日志
		auditLogDir = flag.String("audit-log-dir", "/var/log/docker-authz", "审计日志目录")
		// JWT 认证
		jwtPort   = flag.String("jwt-port", "", "JWT 认证 TCP 监听地址（如 127.0.0.1:2376，空表示不启用）")
		jwtSecret = flag.String("jwt-secret", "", "JWT HMAC-SHA256 密钥")
		// mTLS 证书认证
		certPort    = flag.String("cert-port", "", "mTLS 认证 TCP 监听地址（如 0.0.0.0:2377，空表示不启用）")
		certFile    = flag.String("cert-file", "", "服务端证书文件（PEM）")
		certKeyFile = flag.String("cert-key", "", "服务端私钥文件（PEM）")
		certCAFile  = flag.String("cert-ca", "", "CA 证书文件（PEM），用于验证客户端证书")
		// 查询子命令标志
		queryType  = flag.String("query", "", "查询资源归属（images/containers/networks/volumes/log），查询后退出")
		queryImage = flag.String("image", "", "过滤指定镜像 ID（配合 --query images 使用）")
		queryUser  = flag.String("user", "", "过滤指定用户名（配合 --query 使用）")
		// 日志查询专用标志（配合 --query log 使用）
		queryLogType = flag.String("log-type", "operation", "日志类型: operation/auth/container/proxy")
		queryUID     = flag.Int("uid", -1, "按 UID 过滤日志（-1 表示不过滤）")
		queryAction  = flag.String("action", "", "按操作类型过滤日志（如 ps/run/rm）")
		queryResult  = flag.String("result", "", "按操作结果过滤日志: allow/deny")
		queryLevel   = flag.String("level", "", "按日志级别过滤（proxy 类型专用，如 info/warn/error）")
		querySince   = flag.String("since", "", "日志起始时间（RFC3339，如 2025-01-01T00:00:00Z）")
		queryUntil   = flag.String("until", "", "日志结束时间（RFC3339）")
		queryLimit   = flag.Int("limit", 0, "最多返回日志条数（0 表示不限制）")
	)
	flag.Parse()

	// --query 模式：直接查 DB 输出结果后退出，不启动代理
	if *queryType != "" {
		if *queryType == "log" {
			audit.RunLogQuery(audit.LogQueryOptions{
				LogDir:   *auditLogDir,
				LogType:  *queryLogType,
				Username: *queryUser,
				UID:      *queryUID,
				Action:   *queryAction,
				Result:   *queryResult,
				Level:    *queryLevel,
				Since:    *querySince,
				Until:    *queryUntil,
				Limit:    *queryLimit,
			})
		} else {
			authz.RunQuery(*dbPath, *queryType, *queryImage, *queryUser)
		}
		return
	}

	// 初始化代理层运行日志（写入 proxy-run/ 目录）
	var proxyRunLogger *audit.ProxyLogger
	if *auditLogDir != "" {
		if pl, err := audit.NewProxyRunLogger(*auditLogDir); err == nil {
			proxyRunLogger = pl
			defer pl.Close()
		}
	}

	// 初始化 zap logger（同时写入 stdout 和 proxy-run/ 文件）
	var logger *zap.Logger
	var err error
	if proxyRunLogger != nil {
		logger, err = audit.NewLoggerWithWriter(*logLevel, *logFormat, proxyRunLogger)
	} else {
		logger, err = audit.NewLogger(*logLevel, *logFormat, *logFile)
	}
	if err != nil {
		panic("failed to init logger: " + err.Error())
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("docker-authz-proxy starting",
		zap.String("socket_dir", *socketDir),
		zap.String("upstream", *upstreamSock),
		zap.String("policy", *policyFile),
		zap.String("db", *dbPath),
		zap.String("log_level", *logLevel),
		zap.Int("request_timeout_sec", *requestTimeout),
		zap.Int("max_concurrent", *maxConcurrent),
		zap.String("storage_root", *storageRoot),
		zap.Int("storage_cleanup_interval_min", *storageCleanupInterval),
	)

	// 确保数据库目录存在
	if err := os.MkdirAll(config.GetDirOf(*dbPath), 0750); err != nil {
		logger.Fatal("create db dir failed", zap.Error(err))
	}

	// 初始化归属数据库
	db, err := authz.NewOwnershipDB(*dbPath)
	if err != nil {
		logger.Fatal("open ownership db failed",
			zap.String("path", *dbPath),
			zap.Error(err))
	}
	defer db.Close()

	// 加载授权策略
	policy, err := authz.LoadPolicy(*policyFile)
	if err != nil {
		logger.Warn("load policy failed, using default allow-all policy",
			zap.String("policy_file", *policyFile),
			zap.Error(err))
		policy = authz.DefaultAllowPolicy()
	} else {
		logPolicyLoadResult(logger, *policyFile, policy)
	}

	// 加载资源配额
	quota := isolation.DefaultQuotaManager()
	if *quotaFile != "" {
		if qm, err := isolation.LoadQuotaManager(*quotaFile); err != nil {
			logger.Warn("load quota file failed, using no-limit defaults",
				zap.String("quota_file", *quotaFile),
				zap.Error(err))
		} else {
			quota = qm
			logger.Info("quota config loaded", zap.String("quota_file", *quotaFile))
		}
	}

	// 初始化审计日志
	auditLog, err := audit.NewAuditLogger(*auditLogDir)
	if err != nil {
		logger.Warn("init audit logger failed, audit logging disabled",
			zap.String("audit_log_dir", *auditLogDir),
			zap.Error(err))
		auditLog = nil
	} else {
		logger.Info("audit logger initialized", zap.String("audit_log_dir", *auditLogDir))
	}

	// 初始化容器运行日志
	var containerLogger *audit.ContainerLogger
	if *auditLogDir != "" {
		if cl, err := audit.NewContainerLogger(*auditLogDir, *upstreamSock); err != nil {
			logger.Warn("init container logger failed",
				zap.String("audit_log_dir", *auditLogDir),
				zap.Error(err))
		} else {
			containerLogger = cl
			logger.Info("container logger initialized",
				zap.String("dir", *auditLogDir+"/container-run/"))
		}
	}

	// 构建可插拔认证器列表
	var authenticators []auth.Authenticator
	if *jwtSecret != "" {
		authenticators = append(authenticators, auth.NewJWTAuthenticator(*jwtSecret))
		logger.Info("JWT authenticator enabled")
	}
	if *certCAFile != "" {
		certAuth, err := auth.NewCertAuthenticator(*certCAFile)
		if err != nil {
			logger.Fatal("init cert authenticator failed", zap.Error(err))
		}
		authenticators = append(authenticators, certAuth)
		logger.Info("mTLS cert authenticator enabled", zap.String("ca", *certCAFile))
	}

	// 确保用户存储根目录存在
	if err := os.MkdirAll(*storageRoot, 0755); err != nil {
		logger.Fatal("create storage root failed", zap.String("dir", *storageRoot), zap.Error(err))
	}

	// 创建并启动代理服务
	proxyOpts := forward.ProxyOptions{
		RequestTimeout:         time.Duration(*requestTimeout) * time.Second,
		MaxConcurrent:          *maxConcurrent,
		StorageBase:            *storageRoot,
		StorageCleanupInterval: time.Duration(*storageCleanupInterval) * time.Minute,
	}
	proxy := forward.NewProxyServer(*socketDir, *upstreamSock, policy, db, logger, quota, auditLog, authenticators, proxyOpts)
	if err := proxy.Start(); err != nil {
		logger.Fatal("start proxy failed", zap.Error(err))
	}

	logger.Info("docker-authz-proxy started, listening on per-user sockets",
		zap.String("socket_dir", *socketDir),
		zap.String("storage_root", *storageRoot))

	// 写入 PID 文件（供 logrotate 发送 SIGUSR1）
	pidFile := "/run/docker-authz-proxy.pid"
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644); err != nil {
		logger.Warn("write pid file failed", zap.String("path", pidFile), zap.Error(err))
	} else {
		defer os.Remove(pidFile)
	}

	// 启动 JWT TCP 监听器
	if *jwtPort != "" {
		if err := proxy.StartTCPListener(*jwtPort, nil); err != nil {
			logger.Fatal("start jwt tcp listener failed", zap.Error(err))
		}
	}

	// 启动 mTLS TCP 监听器
	if *certPort != "" {
		if *certFile == "" || *certKeyFile == "" {
			logger.Fatal("cert-port requires --cert-file and --cert-key")
		}
		tlsCfg, err := auth.BuildServerTLSConfig(*certFile, *certKeyFile, *certCAFile)
		if err != nil {
			logger.Fatal("build tls config failed", zap.Error(err))
		}
		if err := proxy.StartTCPListener(*certPort, tlsCfg); err != nil {
			logger.Fatal("start mtls tcp listener failed", zap.Error(err))
		}
	}

	// 启动配置文件监控（定期检查文件修改时间）
	var lastModTime time.Time
	if stat, err := os.Stat(*policyFile); err == nil {
		lastModTime = stat.ModTime()
		logger.Info("watching configuration file for changes",
			zap.String("policy_file", *policyFile),
			zap.Time("last_modified", lastModTime))

		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()

			for range ticker.C {
				stat, err := os.Stat(*policyFile)
				if err != nil {
					logger.Error("failed to stat config file", zap.Error(err))
					continue
				}

				if stat.ModTime().After(lastModTime) {
					logger.Info("configuration file changed, reloading",
						zap.String("policy_file", *policyFile),
						zap.Time("old_time", lastModTime),
						zap.Time("new_time", stat.ModTime()))

					lastModTime = stat.ModTime()

					newPolicy, err := authz.LoadPolicy(*policyFile)
					if err != nil {
						logger.Error("reload policy failed, keeping old policy",
							zap.String("policy_file", *policyFile),
							zap.Error(err))
						continue
					}

					proxy.UpdatePolicy(newPolicy)
					logPolicyLoadResult(logger, *policyFile, newPolicy)
				}
			}
		}()
	} else {
		logger.Warn("failed to watch config file", zap.Error(err))
	}

	// 启动 Docker 事件监听 + 存储清理（共用同一个 context，收到信号时统一退出）
	{
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		proxy.StartDockerEventListener(ctx)
		proxy.StartStorageCleanup(ctx, proxyOpts.StorageCleanupInterval)

		// 启动容器运行日志监听
		if containerLogger != nil {
			containerLogger.Start(ctx, func(containerID string) (string, int, bool) {
				owner, found := db.GetContainerOwner(containerID)
				if !found {
					return "", 0, false
				}
				return owner.Username, owner.UID, true
			})
			logger.Info("container event logger started")
		}
	}

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1)

	for {
		sig := <-sigCh
		switch sig {
		case syscall.SIGUSR1:
			// logrotate 后重新打开日志文件
			logger.Info("received SIGUSR1, reopening log files")
			auditLog.Reopen()
			if proxyRunLogger != nil {
				proxyRunLogger.Reopen()
			}
			if containerLogger != nil {
				containerLogger.Reopen()
			}

		case syscall.SIGHUP:
			logger.Info("received SIGHUP, reloading policy configuration",
				zap.String("policy_file", *policyFile))

			newPolicy, err := authz.LoadPolicy(*policyFile)
			if err != nil {
				logger.Error("reload policy failed, keeping old policy",
					zap.String("policy_file", *policyFile),
					zap.Error(err))
				continue
			}

			proxy.UpdatePolicy(newPolicy)
			logPolicyLoadResult(logger, *policyFile, newPolicy)

		case syscall.SIGINT, syscall.SIGTERM:
			logger.Info("shutting down", zap.String("signal", sig.String()))
			proxy.Stop()
			if containerLogger != nil {
				containerLogger.Close()
			}
			logger.Info("docker-authz-proxy stopped")
			return
		}
	}
}

// logPolicyLoadResult 统一记录策略加载/重载结果
func logPolicyLoadResult(logger *zap.Logger, policyFile string, p *authz.Policy) {
	logger.Info("policy loaded successfully",
		zap.String("policy_file", policyFile),
		zap.Int("deny_rules_count", len(p.Config.DenyRules)),
		zap.Int("resolved_rules_count", len(p.ResolvedDenyRules)))

	for i, rule := range p.ResolvedDenyRules {
		actions := make([]string, 0, len(rule.Actions))
		for action := range rule.Actions {
			actions = append(actions, action)
		}
		sort.Strings(actions)

		userEntries := make([]string, len(rule.UIDs))
		for j, uid := range rule.UIDs {
			if j < len(rule.Usernames) {
				userEntries[j] = fmt.Sprintf("%s(uid=%d)", rule.Usernames[j], uid)
			} else {
				userEntries[j] = fmt.Sprintf("uid=%d", uid)
			}
		}
		groupEntries := make([]string, len(rule.GIDs))
		for j, gid := range rule.GIDs {
			if j < len(rule.Groups) {
				groupEntries[j] = fmt.Sprintf("%s(gid=%d)", rule.Groups[j], gid)
			} else {
				groupEntries[j] = fmt.Sprintf("gid=%d", gid)
			}
		}

		logger.Info("deny_rule_active",
			zap.Int("rule_index", i),
			zap.Strings("users", userEntries),
			zap.Strings("groups", groupEntries),
			zap.Strings("actions", actions))
	}

	for _, name := range p.UnresolvedNames {
		logger.Warn("deny_rule_unresolved_name",
			zap.String("policy_file", policyFile),
			zap.String("name", name),
			zap.String("hint", "rule will NOT be enforced for this user/group"))
	}
}
