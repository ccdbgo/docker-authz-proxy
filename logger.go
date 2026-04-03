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
