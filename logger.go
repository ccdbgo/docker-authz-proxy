package main

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

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
	encCfg.TimeKey = "time"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encCfg.LineEnding = zapcore.DefaultLineEnding

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

	return zap.New(zapcore.NewTee(cores...)), nil
}

// ── 身份字段构建 ──────────────────────────────────────────────

// logIdentityFields 完整身份字段，用于授权拒绝等需要完整上下文的场景
// 格式：username(uid) / effective(uid) / type / pid / cmdline
func logIdentityFields(id *CallerIdentity) []zap.Field {
	return []zap.Field{
		// 真实身份（资源归属检查依据）
		zap.String("user", fmt.Sprintf("%s(uid=%d,gid=%d)", id.RealUsername, id.RealUID, id.RealGID)),
		// sudo 时展示内核身份；普通用户与真实身份相同则省略
		zap.String("effective", fmt.Sprintf("%s(uid=%d)", id.EffectiveUsername, id.EffectiveUID)),
		zap.String("user_type", id.UserType.String()),
		zap.Int("pid", id.PID),
		zap.String("cmdline", id.CmdLine),
	}
}

// logIdentityShort 精简身份字段，用于授权通过等高频场景（避免日志膨胀）
// 格式：username(uid)
func logIdentityShort(id *CallerIdentity) []zap.Field {
	return []zap.Field{
		zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
		zap.String("user_type", id.UserType.String()),
	}
}

// logOwnerFields 资源归属字段（顺序：username → uid → gid）
func logOwnerFields(prefix string, owner *OwnerInfo) []zap.Field {
	return []zap.Field{
		zap.String(prefix, fmt.Sprintf("%s(uid=%d,gid=%d)", owner.Username, owner.UID, owner.GID)),
	}
}

// ── 授权日志函数 ──────────────────────────────────────────────
// 所有授权相关日志统一带 "AUTHZ" 前缀事件名，便于 grep 过滤

// logAuthzAllowed 授权通过（合并了 request+allowed，减少日志条数）
// 只记录精简身份，高频无需完整上下文
func logAuthzAllowed(logger *zap.Logger, id *CallerIdentity, action, uri string) {
	logger.Info("AUTHZ_ALLOW",
		append(logIdentityShort(id),
			zap.String("action", action),
			zap.String("uri", uri),
		)...)
}

// logAuthzDeniedCommand 命令策略拒绝（完整身份 + 原因）
func logAuthzDeniedCommand(logger *zap.Logger, id *CallerIdentity, action, uri string) {
	logger.Warn("AUTHZ_DENY",
		append(logIdentityFields(id),
			zap.String("reason", "command_not_permitted"),
			zap.String("action", action),
			zap.String("uri", uri),
		)...)
}

// logAuthzDeniedOwnership 资源归属拒绝（完整身份 + 资源归属）
func logAuthzDeniedOwnership(logger *zap.Logger, id *CallerIdentity, owner *OwnerInfo,
	resourceType, resourceID, action string) {
	logger.Warn("AUTHZ_DENY",
		append(logIdentityFields(id),
			append(logOwnerFields("owner", owner),
				zap.String("reason", "not_your_"+resourceType),
				zap.String(resourceType+"_id", resourceID),
				zap.String("action", action),
			)...)...)
}

// logAuthzDeniedImageAccess 镜像访问拒绝（完整身份 + 镜像引用）
func logAuthzDeniedImageAccess(logger *zap.Logger, id *CallerIdentity, imageRef, action, reason string) {
	logger.Warn("AUTHZ_DENY",
		append(logIdentityFields(id),
			zap.String("reason", reason),
			zap.String("image", imageRef),
			zap.String("action", action),
		)...)
}

// logAuthzRequest 仅在 DEBUG 级别记录原始请求（生产环境通常关闭）
func logAuthzRequest(logger *zap.Logger, id *CallerIdentity, action, method, uri string) {
	logger.Debug("AUTHZ_REQUEST",
		append(logIdentityShort(id),
			zap.String("action", action),
			zap.String("method", method),
			zap.String("uri", uri),
		)...)
}
