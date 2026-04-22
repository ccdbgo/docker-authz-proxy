package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// jsonPartOf 将日志行转换为可解析的 JSON 对象。
// 支持三种格式：
//
//	新格式（无花括号）: "time":"...","level":"INFO",...  → 包上 {}
//	旧格式（有花括号）: {"time":"...","level":"INFO",...} → 原样返回
//	中间格式（时间前缀）: 2026-04-15T... {...}            → 取 { 之后部分
func jsonPartOf(data []byte) []byte {
	line := bytes.TrimRight(data, "\n")
	if len(line) == 0 {
		return line
	}
	switch line[0] {
	case '{':
		return line
	case '"':
		// 新格式：无花括号，包上 {} 使其成为合法 JSON
		out := make([]byte, 0, len(line)+2)
		out = append(out, '{')
		out = append(out, line...)
		out = append(out, '}')
		return out
	default:
		// 中间格式：时间前缀 + JSON
		if i := bytes.IndexByte(line, '{'); i > 0 {
			return line[i:]
		}
	}
	return line
}

// ── AuditLogger ───────────────────────────────────────────────────────────────

func newTestAuditLogger(t *testing.T) (*AuditLogger, string) {
	t.Helper()
	dir := t.TempDir()
	logger, err := NewAuditLogger(dir)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { logger.Close() })
	return logger, dir
}

func TestAuditLogger_WriteEntry_CreatesFile(t *testing.T) {
	logger, dir := newTestAuditLogger(t)

	logger.WriteEntry(AuditEntry{
		User:       "alice",
		UID:        1001,
		AuthSource: "os_peercred",
		Action:     "ps",
		URI:        "/containers/json",
		Result:     "allow",
		StatusCode: 200,
	})

	path := filepath.Join(dir, "user-operation", "alice.log")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("log file not created: %v", err)
	}
	if len(data) == 0 {
		t.Error("log file is empty")
	}

	var entry AuditEntry
	if err := json.Unmarshal(jsonPartOf(data), &entry); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}
	if entry.User != "alice" {
		t.Errorf("User = %q, want alice", entry.User)
	}
	if entry.Action != "ps" {
		t.Errorf("Action = %q, want ps", entry.Action)
	}
	if entry.Result != "allow" {
		t.Errorf("Result = %q, want allow", entry.Result)
	}
}

func TestAuditLogger_WriteEntry_SetsTime(t *testing.T) {
	logger, dir := newTestAuditLogger(t)

	before := time.Now().UTC().Truncate(time.Second)
	logger.WriteEntry(AuditEntry{User: "bob", UID: 1002, Action: "run", Result: "deny", StatusCode: 403})
	after := time.Now().UTC().Add(time.Second)

	path := filepath.Join(dir, "user-operation", "bob.log")
	data, _ := os.ReadFile(path)

	var entry AuditEntry
	_ = json.Unmarshal(jsonPartOf(data), &entry)

	ts, err := time.Parse(time.RFC3339, entry.Time)
	if err != nil {
		t.Fatalf("parse time %q: %v", entry.Time, err)
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("timestamp %v out of range [%v, %v]", ts, before, after)
	}
}

func TestAuditLogger_WriteEntry_ClientIPAndMethod(t *testing.T) {
	logger, dir := newTestAuditLogger(t)

	logger.WriteEntry(AuditEntry{
		User:       "alice",
		UID:        1001,
		ClientIP:   "192.168.1.10:54321",
		Method:     "POST",
		AuthSource: "jwt",
		Action:     "run",
		URI:        "/containers/create",
		Result:     "allow",
		StatusCode: 201,
	})

	path := filepath.Join(dir, "user-operation", "alice.log")
	data, _ := os.ReadFile(path)

	var entry AuditEntry
	_ = json.Unmarshal(jsonPartOf(data), &entry)

	if entry.ClientIP != "192.168.1.10:54321" {
		t.Errorf("ClientIP = %q, want 192.168.1.10:54321", entry.ClientIP)
	}
	if entry.Method != "POST" {
		t.Errorf("Method = %q, want POST", entry.Method)
	}
}

func TestAuditLogger_WriteEntry_PerUserFiles(t *testing.T) {
	logger, dir := newTestAuditLogger(t)

	logger.WriteEntry(AuditEntry{User: "alice", UID: 1001, Action: "ps", Result: "allow", StatusCode: 200})
	logger.WriteEntry(AuditEntry{User: "bob", UID: 1002, Action: "run", Result: "deny", StatusCode: 403})
	logger.WriteEntry(AuditEntry{User: "alice", UID: 1001, Action: "images", Result: "allow", StatusCode: 200})

	alicePath := filepath.Join(dir, "user-operation", "alice.log")
	bobPath := filepath.Join(dir, "user-operation", "bob.log")

	aliceData, _ := os.ReadFile(alicePath)
	bobData, _ := os.ReadFile(bobPath)

	aliceLines := strings.Split(strings.TrimSpace(string(aliceData)), "\n")
	bobLines := strings.Split(strings.TrimSpace(string(bobData)), "\n")

	if len(aliceLines) != 2 {
		t.Errorf("alice should have 2 log lines, got %d", len(aliceLines))
	}
	if len(bobLines) != 1 {
		t.Errorf("bob should have 1 log line, got %d", len(bobLines))
	}
}

func TestAuditLogger_LogAuth_WritesToAuthLog(t *testing.T) {
	logger, dir := newTestAuditLogger(t)

	logger.LogAuth(AuthAuditEntry{
		Event:        "auth_success",
		PID:          12345,
		EffectiveUID: 1001,
		RealUID:      1001,
		LoginUID:     1001,
	})

	path := filepath.Join(dir, "auth.log")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("auth.log not created: %v", err)
	}

	var entry AuthAuditEntry
	if err := json.Unmarshal(jsonPartOf(data), &entry); err != nil {
		t.Fatalf("unmarshal auth entry: %v", err)
	}
	if entry.Event != "auth_success" {
		t.Errorf("Event = %q, want auth_success", entry.Event)
	}
	if entry.PID != 12345 {
		t.Errorf("PID = %d, want 12345", entry.PID)
	}
}

func TestAuditLogger_NilSafe(t *testing.T) {
	var logger *AuditLogger
	// 不应 panic
	logger.WriteEntry(AuditEntry{User: "alice"})
	logger.LogAuth(AuthAuditEntry{})
	logger.Reopen()
	logger.Close()
}

func TestAuditLogger_Reopen(t *testing.T) {
	logger, dir := newTestAuditLogger(t)

	logger.WriteEntry(AuditEntry{User: "alice", UID: 1001, Action: "ps", Result: "allow", StatusCode: 200})

	// 模拟 logrotate：移走旧文件
	oldPath := filepath.Join(dir, "user-operation", "alice.log")
	rotatedPath := filepath.Join(dir, "user-operation", "alice.log.1")
	_ = os.Rename(oldPath, rotatedPath)

	// Reopen 后应创建新文件
	logger.Reopen()
	logger.WriteEntry(AuditEntry{User: "alice", UID: 1001, Action: "images", Result: "allow", StatusCode: 200})

	newData, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatalf("new log file not created after Reopen: %v", err)
	}
	if len(newData) == 0 {
		t.Error("new log file is empty after Reopen")
	}
}

func TestAuditLogger_WriteEntry_LatencyAndCounts(t *testing.T) {
	logger, dir := newTestAuditLogger(t)

	logger.WriteEntry(AuditEntry{
		User:          "alice",
		UID:           1001,
		Action:        "ps",
		URI:           "/containers/json",
		Result:        "allow",
		StatusCode:    200,
		LatencyMs:     42,
		TotalCount:    10,
		FilteredCount: 3,
	})

	path := filepath.Join(dir, "user-operation", "alice.log")
	data, _ := os.ReadFile(path)

	var entry AuditEntry
	_ = json.Unmarshal(jsonPartOf(data), &entry)

	if entry.LatencyMs != 42 {
		t.Errorf("LatencyMs = %d, want 42", entry.LatencyMs)
	}
	if entry.TotalCount != 10 {
		t.Errorf("TotalCount = %d, want 10", entry.TotalCount)
	}
	if entry.FilteredCount != 3 {
		t.Errorf("FilteredCount = %d, want 3", entry.FilteredCount)
	}
}

// ── LogQueryOptions / RunLogQuery ─────────────────────────────────────────────

func writeTestLogLines(t *testing.T, path string, lines []AuditEntry) {
	t.Helper()
	_ = os.MkdirAll(filepath.Dir(path), 0750)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	for _, e := range lines {
		if e.Time == "" {
			e.Time = time.Now().UTC().Format(time.RFC3339)
		}
		b, _ := json.Marshal(e)
		_, _ = f.Write(append(b, '\n'))
	}
}

func captureRunLogQuery(opts LogQueryOptions) string {
	// 重定向 stdout 捕获输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	RunLogQuery(opts)

	w.Close()
	os.Stdout = old

	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		buf.Write(tmp[:n])
		if err != nil {
			break
		}
	}
	return buf.String()
}

func TestRunLogQuery_FilterByUser(t *testing.T) {
	dir := t.TempDir()
	writeTestLogLines(t, filepath.Join(dir, "user-operation", "alice.log"), []AuditEntry{
		{User: "alice", UID: 1001, Action: "ps", Result: "allow", StatusCode: 200},
		{User: "alice", UID: 1001, Action: "run", Result: "deny", StatusCode: 403},
	})
	writeTestLogLines(t, filepath.Join(dir, "user-operation", "bob.log"), []AuditEntry{
		{User: "bob", UID: 1002, Action: "ps", Result: "allow", StatusCode: 200},
	})

	out := captureRunLogQuery(LogQueryOptions{
		LogDir:   dir,
		LogType:  "operation",
		Username: "alice",
		UID:      -1,
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines for alice, got %d:\n%s", len(lines), out)
	}
}

func TestRunLogQuery_FilterByResult(t *testing.T) {
	dir := t.TempDir()
	writeTestLogLines(t, filepath.Join(dir, "user-operation", "alice.log"), []AuditEntry{
		{User: "alice", UID: 1001, Action: "ps", Result: "allow", StatusCode: 200},
		{User: "alice", UID: 1001, Action: "run", Result: "deny", StatusCode: 403},
		{User: "alice", UID: 1001, Action: "rm", Result: "deny", StatusCode: 403},
	})

	out := captureRunLogQuery(LogQueryOptions{
		LogDir:   dir,
		LogType:  "operation",
		Username: "alice",
		UID:      -1,
		Result:   "deny",
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 deny lines, got %d", len(lines))
	}
}

func TestRunLogQuery_FilterByAction(t *testing.T) {
	dir := t.TempDir()
	writeTestLogLines(t, filepath.Join(dir, "user-operation", "alice.log"), []AuditEntry{
		{User: "alice", UID: 1001, Action: "ps", Result: "allow", StatusCode: 200},
		{User: "alice", UID: 1001, Action: "run", Result: "allow", StatusCode: 201},
		{User: "alice", UID: 1001, Action: "ps", Result: "allow", StatusCode: 200},
	})

	out := captureRunLogQuery(LogQueryOptions{
		LogDir:   dir,
		LogType:  "operation",
		Username: "alice",
		UID:      -1,
		Action:   "ps",
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 ps lines, got %d", len(lines))
	}
}

func TestRunLogQuery_Limit(t *testing.T) {
	dir := t.TempDir()
	entries := make([]AuditEntry, 10)
	for i := range entries {
		entries[i] = AuditEntry{User: "alice", UID: 1001, Action: "ps", Result: "allow", StatusCode: 200}
	}
	writeTestLogLines(t, filepath.Join(dir, "user-operation", "alice.log"), entries)

	out := captureRunLogQuery(LogQueryOptions{
		LogDir:   dir,
		LogType:  "operation",
		Username: "alice",
		UID:      -1,
		Limit:    3,
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines with limit=3, got %d", len(lines))
	}
}

func TestRunLogQuery_SinceUntil(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()

	writeTestLogLines(t, filepath.Join(dir, "user-operation", "alice.log"), []AuditEntry{
		{User: "alice", UID: 1001, Action: "ps", Result: "allow", StatusCode: 200,
			Time: now.Add(-2 * time.Hour).Format(time.RFC3339)},
		{User: "alice", UID: 1001, Action: "run", Result: "allow", StatusCode: 201,
			Time: now.Format(time.RFC3339)},
		{User: "alice", UID: 1001, Action: "rm", Result: "allow", StatusCode: 200,
			Time: now.Add(2 * time.Hour).Format(time.RFC3339)},
	})

	out := captureRunLogQuery(LogQueryOptions{
		LogDir:   dir,
		LogType:  "operation",
		Username: "alice",
		UID:      -1,
		Since:    now.Add(-30 * time.Minute).Format(time.RFC3339),
		Until:    now.Add(30 * time.Minute).Format(time.RFC3339),
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 line in time range, got %d:\n%s", len(lines), out)
	}
}

func TestRunLogQuery_ProxyLogType(t *testing.T) {
	dir := t.TempDir()
	proxyDir := filepath.Join(dir, "proxy-run")
	_ = os.MkdirAll(proxyDir, 0750)

	// 写入 zap JSON 格式日志
	logPath := filepath.Join(proxyDir, "proxy-2025-01-01.log")
	f, _ := os.Create(logPath)
	_, _ = f.WriteString(`{"level":"info","time":"2025-01-01T10:00:00Z","msg":"started"}` + "\n")
	_, _ = f.WriteString(`{"level":"warn","time":"2025-01-01T10:01:00Z","msg":"policy reload"}` + "\n")
	_, _ = f.WriteString(`{"level":"error","time":"2025-01-01T10:02:00Z","msg":"upstream error"}` + "\n")
	f.Close()

	out := captureRunLogQuery(LogQueryOptions{
		LogDir:  dir,
		LogType: "proxy",
		UID:     -1,
		Level:   "warn",
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 warn line, got %d:\n%s", len(lines), out)
	}
}

func TestRunLogQuery_AuthLogType(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.log")
	f, _ := os.Create(authPath)
	for i := 0; i < 3; i++ {
		entry := AuthAuditEntry{
			Event:    "auth_success",
			PID:      1000 + i,
			LoginUID: 1001,
			Time:     time.Now().UTC().Format(time.RFC3339),
		}
		b, _ := json.Marshal(entry)
		_, _ = f.Write(append(b, '\n'))
	}
	f.Close()

	out := captureRunLogQuery(LogQueryOptions{
		LogDir:  dir,
		LogType: "auth",
		UID:     -1,
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 auth lines, got %d", len(lines))
	}
}
