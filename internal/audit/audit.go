package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuthAuditEntry 身份认证专项审计记录（连接建立时写入）
// 独立于操作审计，专注于"谁连接了代理"这一事件
type AuthAuditEntry struct {
	Time    string `json:"time"`
	Event   string `json:"event"` // "auth_success" | "auth_failure" | "auth_forgery"
	PID     int    `json:"pid"`
	// 客户端地址（Unix socket 为空，TCP 为 IP:port）
	ClientAddr string `json:"client_addr,omitempty"`

	// 有效身份（SO_PEERCRED eUID，sudo/su 时为 root 或目标用户）
	EffectiveUID      int    `json:"effective_uid"`
	EffectiveUsername string `json:"effective_username,omitempty"`

	// 原始登录身份（/proc/PID/loginuid，内核维护，不可伪造）
	LoginUID      int    `json:"login_uid"`
	LoginUsername string `json:"login_username,omitempty"`

	// 真实身份（资源归属依据；sudo/su 时等于 loginuid 对应用户）
	RealUID      int    `json:"real_uid"`
	RealUsername string `json:"real_username,omitempty"`

	// 身份切换信息
	SwitchedIdentity bool   `json:"switched_identity"`          // 是否发生了 sudo/su
	SwitchType       string `json:"switch_type,omitempty"`      // "sudo" | "su" | ""

	// 比对结果
	PasswdVerified bool   `json:"passwd_verified"`            // /etc/passwd 比对是否通过
	FailureReason  string `json:"failure_reason,omitempty"`   // 失败原因
	ForgeryDetail  string `json:"forgery_detail,omitempty"`   // 伪造尝试详情
}

// AuditEntry 单条操作审计记录
type AuditEntry struct {
	Time          string            `json:"time"`
	User          string            `json:"user"`
	UID           int               `json:"uid"`
	ClientIP      string            `json:"client_ip,omitempty"`      // 操作来源 IP（Unix socket 为空，TCP 为 IP:port）
	AuthSource    string            `json:"auth_source"`
	Method        string            `json:"method,omitempty"`         // HTTP 方法（GET/POST/DELETE 等）
	Action        string            `json:"action"`
	URI           string            `json:"uri"`
	RewrittenPath string            `json:"rewritten_path,omitempty"` // 改写后的资源路径/名称
	Result        string            `json:"result"`                   // "allow" | "deny"
	DenyReason    string            `json:"deny_reason,omitempty"`
	ContainerID   string            `json:"container_id,omitempty"`
	StatusCode    int               `json:"status_code"`
	LatencyMs     int64             `json:"latency_ms,omitempty"`     // 请求耗时（毫秒）
	TotalCount    int               `json:"total_count,omitempty"`    // 过滤前资源数量
	FilteredCount int               `json:"filtered_count,omitempty"` // 过滤后资源数量
	ResourceUsage map[string]string `json:"resource_usage,omitempty"` // cpu_cores/mem_mb/storage 等
}

// AuditLogger 专用审计日志（独立于 zap 运营日志）
// 每个用户一个日志文件：<logDir>/user-operation/<username>.log
// 身份认证日志写入：<logDir>/auth.log（所有用户共用，便于安全审计）
type AuditLogger struct {
	logDir  string
	mu      sync.Mutex
	files   map[string]*os.File
	authLog *os.File
}

func NewAuditLogger(logDir string) (*AuditLogger, error) {
	dir := filepath.Join(logDir, "user-operation")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create audit log dir: %w", err)
	}
	authLogPath := filepath.Join(logDir, "auth.log")
	authLog, err := os.OpenFile(authLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open auth log: %w", err)
	}
	return &AuditLogger{
		logDir:  logDir,
		files:   make(map[string]*os.File),
		authLog: authLog,
	}, nil
}

// LogAuth 写入一条身份认证审计记录
func (a *AuditLogger) LogAuth(entry AuthAuditEntry) {
	if a == nil {
		return
	}
	if entry.Time == "" {
		entry.Time = time.Now().UTC().Format(time.RFC3339)
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	// 去掉外层 {}，输出格式："time":"...","event":"...",...
	inner := line
	if len(inner) >= 2 && inner[0] == '{' && inner[len(inner)-1] == '}' {
		inner = inner[1 : len(inner)-1]
	}
	out := append(inner, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.authLog != nil {
		_, _ = a.authLog.Write(out)
	}
}

// Log 写入一条操作审计记录
func (a *AuditLogger) Log(username string, uid int, authSource, action, uri, result, denyReason, containerID string, statusCode int) {
	a.LogFull(username, uid, authSource, action, uri, "", result, denyReason, containerID, statusCode, 0, 0, 0, nil)
}

// LogWithResources 写入一条带资源使用情况的操作审计记录
func (a *AuditLogger) LogWithResources(username string, uid int, authSource, action, uri, result, denyReason, containerID string, statusCode int, resourceUsage map[string]string) {
	a.LogFull(username, uid, authSource, action, uri, "", result, denyReason, containerID, statusCode, 0, 0, 0, resourceUsage)
}

// LogFull 写入完整审计记录，包含耗时、过滤计数、改写路径
func (a *AuditLogger) LogFull(username string, uid int, authSource, action, uri, rewrittenPath, result, denyReason, containerID string, statusCode int, latencyMs int64, totalCount, filteredCount int, resourceUsage map[string]string) {
	a.WriteEntry(AuditEntry{
		User:          username,
		UID:           uid,
		AuthSource:    authSource,
		Action:        action,
		URI:           uri,
		RewrittenPath: rewrittenPath,
		Result:        result,
		DenyReason:    denyReason,
		ContainerID:   containerID,
		StatusCode:    statusCode,
		LatencyMs:     latencyMs,
		TotalCount:    totalCount,
		FilteredCount: filteredCount,
		ResourceUsage: resourceUsage,
	})
}

// WriteEntry 写入一条完整的 AuditEntry（支持所有字段，推荐在新代码中使用）
func (a *AuditLogger) WriteEntry(entry AuditEntry) {
	if a == nil {
		return
	}
	if entry.Time == "" {
		entry.Time = time.Now().UTC().Format(time.RFC3339)
	}
	if entry.AuthSource == "" {
		entry.AuthSource = "os_peercred"
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	// 去掉外层 {}，输出格式："time":"...","user":"...",...
	inner := line
	if len(inner) >= 2 && inner[0] == '{' && inner[len(inner)-1] == '}' {
		inner = inner[1 : len(inner)-1]
	}
	out := append(inner, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()

	f, err := a.getFile(entry.User)
	if err != nil {
		return
	}
	_, _ = f.Write(out)
}

func (a *AuditLogger) getFile(username string) (*os.File, error) {
	if f, ok := a.files[username]; ok {
		return f, nil
	}
	path := filepath.Join(a.logDir, "user-operation", username+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	a.files[username] = f
	return f, nil
}

// Reopen 重新打开所有日志文件（logrotate 轮转后调用，避免继续写入已被移走的旧文件）
func (a *AuditLogger) Reopen() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	// 重开用户操作日志
	for username, f := range a.files {
		path := f.Name()
		_ = f.Close()
		newF, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err == nil {
			a.files[username] = newF
		} else {
			delete(a.files, username)
		}
	}

	// 重开认证日志
	if a.authLog != nil {
		path := a.authLog.Name()
		_ = a.authLog.Close()
		newF, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err == nil {
			a.authLog = newF
		} else {
			a.authLog = nil
		}
	}
}

// Close 关闭所有打开的日志文件
func (a *AuditLogger) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, f := range a.files {
		_ = f.Close()
	}
	if a.authLog != nil {
		_ = a.authLog.Close()
	}
}


