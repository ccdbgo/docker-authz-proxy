package main

import (
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// shortCallerEncoder 自定义 caller 编码器，只输出文件名和行号（不含模块路径）
// 例如：proxy.go:358 而不是 docker-authz-proxy/proxy.go:358
func shortCallerEncoder(caller zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
	// 只保留文件名（去掉完整路径）
	enc.AppendString(filepath.Base(caller.File) + ":" + fmt.Sprintf("%d", caller.Line))
}

func newLogger(level, format, filePath string) (*zap.Logger, error) {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	encCfg := zap.NewProductionEncoderConfig()
	// 日志格式优化：
	// - 不输出 time（systemd/journald 已有时间戳，避免重复）
	// - 使用自定义 caller encoder（只显示文件名:行号，不含模块路径）
	// - 输出顺序：level -> caller -> msg -> fields
	encCfg.TimeKey = ""                                // 不输出时间（避免与 systemd 重复）
	encCfg.LevelKey = "level"
	encCfg.CallerKey = "caller"
	encCfg.MessageKey = "msg"
	encCfg.EncodeLevel = zapcore.CapitalLevelEncoder   // INFO / WARN / ERROR
	encCfg.EncodeCaller = shortCallerEncoder           // proxy.go:358（自定义，去掉模块路径）
	encCfg.LineEnding = zapcore.DefaultLineEnding
	encCfg.FunctionKey = ""                            // 不输出函数名

	var encoder zapcore.Encoder
	if format == "text" {
		encoder = zapcore.NewConsoleEncoder(encCfg)
	} else {
		encoder = zapcore.NewJSONEncoder(encCfg)
	}

	var cores []zapcore.Core
	cores = append(cores, zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), zapLevel))

	if filePath != "" {
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		cores = append(cores, zapcore.NewCore(encoder, zapcore.AddSync(f), zapLevel))
	}

	// zap.AddCaller() 启用 caller 字段；AddCallerSkip(0) 是默认值
	return zap.New(zapcore.NewTee(cores...), zap.AddCaller()), nil
}

// ── 身份字段构建 ──────────────────────────────────────────────

// logIdentityFields 完整身份字段，用于授权拒绝等需要完整上下文的场景
func logIdentityFields(id *CallerIdentity) []zap.Field {
	return []zap.Field{
		zap.String("user", fmt.Sprintf("%s(uid=%d,gid=%d)", id.RealUsername, id.RealUID, id.RealGID)),
		zap.String("effective", fmt.Sprintf("%s(uid=%d)", id.EffectiveUsername, id.EffectiveUID)),
		zap.String("user_type", id.UserType.String()),
		zap.Int("pid", id.PID),
		zap.String("cmdline", id.CmdLine),
	}
}

// logIdentityShort 精简身份字段，用于授权通过等高频场景
func logIdentityShort(id *CallerIdentity) []zap.Field {
	return []zap.Field{
		zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
		zap.String("user_type", id.UserType.String()),
	}
}

// logOwnerFields 资源归属字段
func logOwnerFields(prefix string, owner *OwnerInfo) []zap.Field {
	return []zap.Field{
		zap.String(prefix, fmt.Sprintf("%s(uid=%d,gid=%d)", owner.Username, owner.UID, owner.GID)),
	}
}

// ── 授权日志函数 ──────────────────────────────────────────────
// 每个函数都调用 WithOptions(zap.AddCallerSkip(1))，使 caller 字段
// 指向调用处（proxy.go:NNN），而不是本文件内的包装函数。

// logAuthzAllowed 授权通过（精简身份，高频场景）
func logAuthzAllowed(logger *zap.Logger, id *CallerIdentity, action, uri string) {
	logger.WithOptions(zap.AddCallerSkip(1)).Info("AUTHZ_ALLOW",
		append(logIdentityShort(id),
			zap.String("action", action),
			zap.String("uri", uri),
		)...)
}

// logAuthzDeniedCommand 命令策略拒绝
func logAuthzDeniedCommand(logger *zap.Logger, id *CallerIdentity, action, uri string) {
	logger.WithOptions(zap.AddCallerSkip(1)).Warn("AUTHZ_DENY",
		append(logIdentityFields(id),
			zap.String("reason", "command_not_permitted"),
			zap.String("action", action),
			zap.String("uri", uri),
		)...)
}

// logAuthzDeniedOwnership 资源归属拒绝
func logAuthzDeniedOwnership(logger *zap.Logger, id *CallerIdentity, owner *OwnerInfo,
	resourceType, resourceID, action string) {
	logger.WithOptions(zap.AddCallerSkip(1)).Warn("AUTHZ_DENY",
		append(logIdentityFields(id),
			append(logOwnerFields("owner", owner),
				zap.String("reason", "not_your_"+resourceType),
				zap.String(resourceType+"_id", resourceID),
				zap.String("action", action),
			)...)...)
}

// logAuthzDeniedNotTracked 容器/镜像未在代理中注册，拒绝非 root 用户访问
func logAuthzDeniedNotTracked(logger *zap.Logger, id *CallerIdentity,
	resourceType, resourceID, action string) {
	logger.WithOptions(zap.AddCallerSkip(1)).Warn("AUTHZ_DENY",
		append(logIdentityFields(id),
			zap.String("reason", resourceType+"_not_tracked"),
			zap.String(resourceType+"_id", resourceID),
			zap.String("action", action),
		)...)
}

// logAuthzDeniedImageAccess 镜像访问拒绝
func logAuthzDeniedImageAccess(logger *zap.Logger, id *CallerIdentity, imageRef, action, reason string) {
	logger.WithOptions(zap.AddCallerSkip(1)).Warn("AUTHZ_DENY",
		append(logIdentityFields(id),
			zap.String("reason", reason),
			zap.String("image", imageRef),
			zap.String("action", action),
		)...)
}

// logAuthzRequest 仅在 DEBUG 级别记录原始请求
func logAuthzRequest(logger *zap.Logger, id *CallerIdentity, action, method, uri string) {
	logger.WithOptions(zap.AddCallerSkip(1)).Debug("AUTHZ_REQUEST",
		append(logIdentityShort(id),
			zap.String("action", action),
			zap.String("method", method),
			zap.String("uri", uri),
		)...)
}
