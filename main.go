package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	)
	flag.Parse()

	// 初始化日志
	logger, err := newLogger(*logLevel, *logFormat, *logFile)
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
	)

	// 确保数据库目录存在
	if err := os.MkdirAll(getDirOf(*dbPath), 0750); err != nil {
		logger.Fatal("create db dir failed", zap.Error(err))
	}

	// 初始化归属数据库
	db, err := newOwnershipDB(*dbPath)
	if err != nil {
		logger.Fatal("open ownership db failed",
			zap.String("path", *dbPath),
			zap.Error(err))
	}
	defer db.Close()

	// 加载授权策略
	policy, err := loadPolicy(*policyFile)
	if err != nil {
		// 策略文件不存在时使用默认全部允许策略（方便初次部署）
		logger.Warn("load policy failed, using default allow-all policy",
			zap.String("policy_file", *policyFile),
			zap.Error(err))
		policy = defaultAllowPolicy()
	} else {
		// 记录策略加载信息
		logger.Info("policy loaded successfully",
			zap.String("policy_file", *policyFile),
			zap.Int("deny_rules_count", len(policy.config.DenyRules)),
			zap.Int("resolved_rules_count", len(policy.resolvedDenyRules)))

		// 调试：输出解析后的规则
		for i, rule := range policy.resolvedDenyRules {
			actions := []string{}
			for action := range rule.Actions {
				actions = append(actions, action)
			}
			logger.Debug("resolved_deny_rule",
				zap.Int("rule_index", i),
				zap.Ints("uids", rule.UIDs),
				zap.Ints("gids", rule.GIDs),
				zap.Strings("actions", actions))
		}
	}

	// 创建并启动代理服务
	proxy := newProxyServer(*socketDir, *upstreamSock, policy, db, logger)
	if err := proxy.Start(); err != nil {
		logger.Fatal("start proxy failed", zap.Error(err))
	}

	logger.Info("docker-authz-proxy started, listening on per-user sockets",
		zap.String("socket_dir", *socketDir))

	// 启动配置文件监控（使用标准库定期检查文件修改时间）
	var lastModTime time.Time
	if stat, err := os.Stat(*policyFile); err == nil {
		lastModTime = stat.ModTime()
		logger.Info("watching configuration file for changes",
			zap.String("policy_file", *policyFile),
			zap.Time("last_modified", lastModTime))

		// 启动文件监控协程
		go func() {
			ticker := time.NewTicker(2 * time.Second) // 每 2 秒检查一次
			defer ticker.Stop()

			for range ticker.C {
				stat, err := os.Stat(*policyFile)
				if err != nil {
					logger.Error("failed to stat config file", zap.Error(err))
					continue
				}

				// 检查文件修改时间是否变化
				if stat.ModTime().After(lastModTime) {
					logger.Info("configuration file changed, reloading",
						zap.String("policy_file", *policyFile),
						zap.Time("old_time", lastModTime),
						zap.Time("new_time", stat.ModTime()))

					lastModTime = stat.ModTime()

					newPolicy, err := loadPolicy(*policyFile)
					if err != nil {
						logger.Error("reload policy failed, keeping old policy",
							zap.String("policy_file", *policyFile),
							zap.Error(err))
						continue
					}

					proxy.UpdatePolicy(newPolicy)
					logger.Info("policy configuration reloaded successfully",
						zap.String("policy_file", *policyFile))
				}
			}
		}()
	} else {
		logger.Warn("failed to watch config file", zap.Error(err))
	}

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigCh
		switch sig {
		case syscall.SIGHUP:
			// 手动重新加载配置（兼容旧方式）
			logger.Info("received SIGHUP, reloading policy configuration",
				zap.String("policy_file", *policyFile))

			newPolicy, err := loadPolicy(*policyFile)
			if err != nil {
				logger.Error("reload policy failed, keeping old policy",
					zap.String("policy_file", *policyFile),
					zap.Error(err))
				continue
			}

			proxy.UpdatePolicy(newPolicy)
			logger.Info("policy configuration reloaded successfully",
				zap.String("policy_file", *policyFile))

		case syscall.SIGINT, syscall.SIGTERM:
			// 终止信号
			logger.Info("shutting down", zap.String("signal", sig.String()))
			proxy.Stop()
			logger.Info("docker-authz-proxy stopped")
			return
		}
	}
}

// defaultAllowPolicy 策略文件缺失时的兜底策略（白名单模式，全部允许）
func defaultAllowPolicy() *Policy {
	return &Policy{
		config: PolicyConfig{
			Version:       1,
			DefaultAction: "allow",
		},
	}
}

func getDirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
