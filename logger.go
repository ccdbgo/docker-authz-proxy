package main

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func newLogger(level, format, filePath string) (*zap.Logger, error) {
	// 日志级别
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

	// 编码器配置（单行 JSON）
	encCfg := zap.NewProductionEncoderConfig()
	encCfg.TimeKey = "time"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encCfg.LineEnding = zapcore.DefaultLineEnding // 确保单行输出

	var encoder zapcore.Encoder
	if format == "text" {
		encoder = zapcore.NewConsoleEncoder(encCfg)
	} else {
		encoder = zapcore.NewJSONEncoder(encCfg)
	}

	// 同时输出到控制台和文件
	var cores []zapcore.Core

	// 控制台输出
	consoleCore := zapcore.NewCore(
		encoder,
		zapcore.AddSync(os.Stdout),
		zapLevel,
	)
	cores = append(cores, consoleCore)

	// 文件输出（如果指定）
	if filePath != "" {
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		fileCore := zapcore.NewCore(
			encoder,
			zapcore.AddSync(f),
			zapLevel,
		)
		cores = append(cores, fileCore)
	}

	// 合并多个 core
	core := zapcore.NewTee(cores...)
	return zap.New(core), nil
}

// logFields 构建公共身份字段（顺序：username → uid → gid）
func logIdentityFields(id *CallerIdentity) []zap.Field {
	return []zap.Field{
		zap.String("real_username", id.RealUsername),
		zap.Int("real_uid", id.RealUID),
		zap.Int("real_gid", id.RealGID),
		zap.String("effective_username", id.EffectiveUsername),
		zap.Int("effective_uid", id.EffectiveUID),
		zap.String("user_type", id.UserType.String()),
		zap.String("process_name", id.ProcessName),
		zap.String("cmdline", id.CmdLine),
		zap.Int("pid", id.PID),
	}
}

// logOwnerFields 构建资源归属字段（顺序：username → uid → gid）
func logOwnerFields(prefix string, owner *OwnerInfo) []zap.Field {
	return []zap.Field{
		zap.String(prefix+"_username", owner.Username),
		zap.Int(prefix+"_uid", owner.UID),
		zap.Int(prefix+"_gid", owner.GID),
	}
}

// ── 授权日志辅助函数（统一标识，方便查找）────────────────────────

// logAuthzRequest 记录授权请求（每次 API 调用）
func logAuthzRequest(logger *zap.Logger, id *CallerIdentity, action, method, uri string) {
	logger.Info("authz_request",
		append(logIdentityFields(id),
			zap.String("event_category", "AUTHORIZATION"),
			zap.String("authz_phase", "request"),
			zap.String("action", action),
			zap.String("http_method", method),
			zap.String("http_uri", uri),
		)...)
}

// logAuthzAllowed 记录授权通过
func logAuthzAllowed(logger *zap.Logger, id *CallerIdentity, action, uri string) {
	logger.Info("authz_allowed",
		append(logIdentityFields(id),
			zap.String("event_category", "AUTHORIZATION"),
			zap.String("authz_result", "ALLOW"),
			zap.String("authz_phase", "final"),
			zap.String("action", action),
			zap.String("http_uri", uri),
		)...)
}

// logAuthzDeniedCommand 记录命令授权被拒绝
func logAuthzDeniedCommand(logger *zap.Logger, id *CallerIdentity, action, method, uri, reason string) {
	logger.Warn("authz_denied_command",
		append(logIdentityFields(id),
			zap.String("event_category", "AUTHORIZATION"),
			zap.String("authz_result", "DENY"),
			zap.String("authz_phase", "command_check"),
			zap.String("deny_reason", reason),
			zap.String("action", action),
			zap.String("http_method", method),
			zap.String("http_uri", uri),
		)...)
}

// logAuthzDeniedOwnership 记录资源归属检查被拒绝
func logAuthzDeniedOwnership(logger *zap.Logger, id *CallerIdentity, owner *OwnerInfo,
	resourceType, resourceID, action, reason string) {
	logger.Warn("authz_denied_ownership",
		append(logIdentityFields(id),
			append(logOwnerFields("owner", owner),
				zap.String("event_category", "AUTHORIZATION"),
				zap.String("authz_result", "DENY"),
				zap.String("authz_phase", "ownership_check"),
				zap.String("deny_reason", reason),
				zap.String("resource_type", resourceType),
				zap.String("resource_id", resourceID),
				zap.String("action", action),
			)...)...)
}

// logAuthzDeniedImageAccess 记录镜像访问被拒绝
func logAuthzDeniedImageAccess(logger *zap.Logger, id *CallerIdentity,
	imageRef, action, reason string) {
	logger.Warn("authz_denied_image_access",
		append(logIdentityFields(id),
			zap.String("event_category", "AUTHORIZATION"),
			zap.String("authz_result", "DENY"),
			zap.String("authz_phase", "image_access_check"),
			zap.String("deny_reason", reason),
			zap.String("image_ref", imageRef),
			zap.String("action", action),
		)...)
}

// logVirtualImageDelete 记录虚拟镜像删除
func logVirtualImageDelete(logger *zap.Logger, id *CallerIdentity, imageID string, realDelete bool) {
	logger.Info("virtual_image_delete",
		append(logIdentityFields(id),
			zap.String("event_category", "AUTHORIZATION"),
			zap.String("authz_result", "ALLOW"),
			zap.String("authz_phase", "virtual_delete"),
			zap.String("image_id", imageID),
			zap.Bool("real_delete", realDelete),
		)...)
}
