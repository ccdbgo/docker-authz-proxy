package audit

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// shortCallerEncoder 自定义 caller 编码器，只输出文件名和行号（不含模块路径）
func shortCallerEncoder(caller zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(filepath.Base(caller.File) + ":" + fmt.Sprintf("%d", caller.Line))
}

// timeFirstWriter 包装 io.Writer，将每行 JSON 中的 time 字段移到最前面
type timeFirstWriter struct {
	w       io.Writer
	timeKey []byte // e.g. `"time":`
}

func newTimeFirstWriter(w io.Writer, timeKey string) *timeFirstWriter {
	return &timeFirstWriter{w: w, timeKey: []byte(`"` + timeKey + `":`)}
}

func (t *timeFirstWriter) Write(p []byte) (int, error) {
	// 处理每一行（zap 每次 Write 一行）
	line := bytes.TrimRight(p, "\n")
	if len(line) < 2 || line[0] != '{' || line[len(line)-1] != '}' {
		return t.w.Write(p)
	}
	inner := line[1 : len(line)-1] // 去掉外层 {}

	key := t.timeKey
	idx := bytes.Index(inner, key)
	if idx < 0 {
		// 未找到 time 字段，直接输出内容（无 {}）
		var buf bytes.Buffer
		buf.Write(inner)
		buf.WriteByte('\n')
		n, err := t.w.Write(buf.Bytes())
		if err != nil {
			return n, err
		}
		return len(p), nil
	}

	// 定位 time 值的范围
	valStart := idx + len(key)
	valEnd := valStart
	if valStart < len(inner) && inner[valStart] == '"' {
		valEnd = valStart + 1
		for valEnd < len(inner) {
			if inner[valEnd] == '\\' {
				valEnd += 2
				continue
			}
			if inner[valEnd] == '"' {
				valEnd++
				break
			}
			valEnd++
		}
	} else {
		for valEnd < len(inner) && inner[valEnd] != ',' && inner[valEnd] != '}' {
			valEnd++
		}
	}

	timeKV := inner[idx:valEnd] // "time":"2026-..."

	// 从 inner 中移除 time KV 及相邻逗号
	var rest []byte
	if idx > 0 && inner[idx-1] == ',' {
		// time 不是第一个字段
		rest = append(append([]byte(nil), inner[:idx-1]...), inner[valEnd:]...)
	} else if valEnd < len(inner) && inner[valEnd] == ',' {
		// time 是第一个字段，后面还有其他字段
		rest = append([]byte(nil), inner[valEnd+1:]...)
	}
	// 否则 time 是唯一字段，rest 为空

	// 输出格式："time":"...",<其余字段>\n
	var buf bytes.Buffer
	buf.Write(timeKV)
	if len(rest) > 0 {
		buf.WriteByte(',')
		buf.Write(rest)
	}
	buf.WriteByte('\n')

	n, err := t.w.Write(buf.Bytes())
	if err != nil {
		return n, err
	}
	return len(p), nil // 返回原始长度，避免 short write 错误
}

func (t *timeFirstWriter) Sync() error {
	if s, ok := t.w.(interface{ Sync() error }); ok {
		return s.Sync()
	}
	return nil
}

// newTimeFirstSyncer 创建将 time 字段置于最前的 WriteSyncer
func newTimeFirstSyncer(ws zapcore.WriteSyncer, timeKey string) zapcore.WriteSyncer {
	return newTimeFirstWriter(ws, timeKey)
}




// ProxyLogger 代理层运行日志，写入 <logDir>/proxy-run/ 目录，支持 Reopen
type ProxyLogger struct {
	mu      sync.Mutex
	file    *os.File
	path    string
}

// NewProxyRunLogger 在 logDir/proxy-run/ 下创建代理运行日志文件（按日期命名）
// 返回文件路径和文件句柄，供 NewLogger 使用
func NewProxyRunLogger(logDir string) (*ProxyLogger, error) {
	dir := filepath.Join(logDir, "proxy-run")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create proxy-run log dir: %w", err)
	}
	date := time.Now().Format("2006-01-02")
	path := filepath.Join(dir, "proxy-"+date+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open proxy run log: %w", err)
	}
	return &ProxyLogger{file: f, path: path}, nil
}

// Write 实现 io.Writer，供 zapcore.AddSync 使用
func (p *ProxyLogger) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file == nil {
		return 0, nil
	}
	return p.file.Write(b)
}

// Reopen 重新打开日志文件（logrotate 后调用）
func (p *ProxyLogger) Reopen() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file != nil {
		_ = p.file.Close()
	}
	f, err := os.OpenFile(p.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err == nil {
		p.file = f
	} else {
		p.file = nil
	}
}

// Sync 实现 zapcore.WriteSyncer
func (p *ProxyLogger) Sync() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file != nil {
		return p.file.Sync()
	}
	return nil
}

// Close 关闭日志文件
func (p *ProxyLogger) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file != nil {
		_ = p.file.Close()
		p.file = nil
	}
}

func NewLogger(level, format, filePath string) (*zap.Logger, error) {
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
	encCfg.LevelKey = "level"
	encCfg.CallerKey = "caller"
	encCfg.MessageKey = "msg"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encCfg.EncodeLevel = zapcore.CapitalLevelEncoder
	encCfg.EncodeCaller = shortCallerEncoder
	encCfg.LineEnding = zapcore.DefaultLineEnding
	encCfg.FunctionKey = ""

	var encoder zapcore.Encoder
	if format == "text" {
		encoder = zapcore.NewConsoleEncoder(encCfg)
	} else {
		encoder = zapcore.NewJSONEncoder(encCfg)
	}

	var cores []zapcore.Core
	if format == "text" {
		cores = append(cores, zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), zapLevel))
	} else {
		cores = append(cores, zapcore.NewCore(encoder, newTimeFirstSyncer(zapcore.AddSync(os.Stdout), encCfg.TimeKey), zapLevel))
	}

	if filePath != "" {
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		if format == "text" {
			cores = append(cores, zapcore.NewCore(encoder, zapcore.AddSync(f), zapLevel))
		} else {
			cores = append(cores, zapcore.NewCore(encoder, newTimeFirstSyncer(zapcore.AddSync(f), encCfg.TimeKey), zapLevel))
		}
	}

	return zap.New(zapcore.NewTee(cores...), zap.AddCaller()), nil
}

// NewLoggerWithWriter 创建 zap logger，额外写入指定 writer（如 ProxyLogger）
func NewLoggerWithWriter(level, format string, extra zapcore.WriteSyncer) (*zap.Logger, error) {
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
	encCfg.LevelKey = "level"
	encCfg.CallerKey = "caller"
	encCfg.MessageKey = "msg"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encCfg.EncodeLevel = zapcore.CapitalLevelEncoder
	encCfg.EncodeCaller = shortCallerEncoder
	encCfg.LineEnding = zapcore.DefaultLineEnding
	encCfg.FunctionKey = ""

	encoder := zapcore.NewJSONEncoder(encCfg)

	cores := []zapcore.Core{
		zapcore.NewCore(encoder, newTimeFirstSyncer(zapcore.AddSync(os.Stdout), encCfg.TimeKey), zapLevel),
	}
	if extra != nil {
		cores = append(cores, zapcore.NewCore(encoder, newTimeFirstSyncer(extra, encCfg.TimeKey), zapLevel))
	}

	return zap.New(zapcore.NewTee(cores...), zap.AddCaller()), nil
}

// ── 身份字段构建 ──────────────────────────────────────────────

// IdentityInfo 供日志函数使用的身份摘要（避免循环依赖 auth 包）
type IdentityInfo struct {
	RealUsername      string
	RealUID           int
	RealGID           int
	EffectiveUsername string
	EffectiveUID      int
	PID               int
	CmdLine           string
	UserType          string
	AuthSource        string
}

// OwnerInfo 供日志函数使用的归属摘要
type OwnerInfo struct {
	Username string
	UID      int
	GID      int
}

func logIdentityFields(id *IdentityInfo) []zap.Field {
	return []zap.Field{
		zap.String("user", fmt.Sprintf("%s(uid=%d,gid=%d)", id.RealUsername, id.RealUID, id.RealGID)),
		zap.String("effective", fmt.Sprintf("%s(uid=%d)", id.EffectiveUsername, id.EffectiveUID)),
		zap.String("user_type", id.UserType),
		zap.Int("pid", id.PID),
		zap.String("cmdline", id.CmdLine),
	}
}

// LogIdentityFields 返回完整身份日志字段（供外部包使用）
func LogIdentityFields(id *IdentityInfo) []zap.Field {
	return logIdentityFields(id)
}

func logIdentityShort(id *IdentityInfo) []zap.Field {
	return []zap.Field{
		zap.String("user", fmt.Sprintf("%s(uid=%d)", id.RealUsername, id.RealUID)),
		zap.String("user_type", id.UserType),
	}
}

// LogIdentityShortFields 返回精简身份日志字段（供外部包使用）
func LogIdentityShortFields(id *IdentityInfo) []zap.Field {
	return logIdentityShort(id)
}

func logOwnerFields(prefix string, owner *OwnerInfo) []zap.Field {
	return []zap.Field{
		zap.String(prefix, fmt.Sprintf("%s(uid=%d,gid=%d)", owner.Username, owner.UID, owner.GID)),
	}
}

// LogAuthzAllowed 授权通过（精简身份，高频场景）
func LogAuthzAllowed(logger *zap.Logger, id *IdentityInfo, action, uri string) {
	logger.WithOptions(zap.AddCallerSkip(1)).Info("AUTHZ_ALLOW",
		append(logIdentityShort(id),
			zap.String("action", action),
			zap.String("uri", uri),
		)...)
}

// LogAuthzDeniedCommand 命令策略拒绝
func LogAuthzDeniedCommand(logger *zap.Logger, id *IdentityInfo, action, uri string) {
	logger.WithOptions(zap.AddCallerSkip(1)).Warn("AUTHZ_DENY",
		append(logIdentityFields(id),
			zap.String("reason", "command_not_permitted"),
			zap.String("action", action),
			zap.String("uri", uri),
		)...)
}

// LogAuthzDeniedOwnership 资源归属拒绝
func LogAuthzDeniedOwnership(logger *zap.Logger, id *IdentityInfo, owner *OwnerInfo,
	resourceType, resourceID, action string) {
	logger.WithOptions(zap.AddCallerSkip(1)).Warn("AUTHZ_DENY",
		append(logIdentityFields(id),
			append(logOwnerFields("owner", owner),
				zap.String("reason", "not_your_"+resourceType),
				zap.String(resourceType+"_id", resourceID),
				zap.String("action", action),
			)...)...)
}

// LogAuthzDeniedNotTracked 容器/镜像未在代理中注册，拒绝非 root 用户访问
func LogAuthzDeniedNotTracked(logger *zap.Logger, id *IdentityInfo,
	resourceType, resourceID, action string) {
	logger.WithOptions(zap.AddCallerSkip(1)).Warn("AUTHZ_DENY",
		append(logIdentityFields(id),
			zap.String("reason", resourceType+"_not_tracked"),
			zap.String(resourceType+"_id", resourceID),
			zap.String("action", action),
		)...)
}

// LogAuthzDeniedImageAccess 镜像访问拒绝
func LogAuthzDeniedImageAccess(logger *zap.Logger, id *IdentityInfo, imageRef, action, reason string) {
	logger.WithOptions(zap.AddCallerSkip(1)).Warn("AUTHZ_DENY",
		append(logIdentityFields(id),
			zap.String("reason", reason),
			zap.String("image", imageRef),
			zap.String("action", action),
		)...)
}

// LogAuthzRequest 仅在 DEBUG 级别记录原始请求
func LogAuthzRequest(logger *zap.Logger, id *IdentityInfo, action, method, uri string) {
	logger.WithOptions(zap.AddCallerSkip(1)).Debug("AUTHZ_REQUEST",
		append(logIdentityShort(id),
			zap.String("action", action),
			zap.String("method", method),
			zap.String("uri", uri),
		)...)
}
