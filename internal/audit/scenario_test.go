package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)
// ── 场景测试：AuditLogger 并发写入安全 ───────────────────────────────────────

// 场景：多 goroutine 并发写入同一用户日志不崩溃，且每行都是合法 JSON
func TestAuditLogger_ConcurrentWrites_Safe(t *testing.T) {
	logger, dir := newTestAuditLogger(t)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			logger.WriteEntry(AuditEntry{
				User:       "alice",
				UID:        1001,
				AuthSource: "os_peercred",
				Action:     "ps",
				URI:        "/containers/json",
				Result:     "allow",
				StatusCode: 200,
			})
		}(i)
	}
	wg.Wait()

	path := filepath.Join(dir, "user-operation", "alice.log")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal(jsonPartOf(line), &e); err != nil {
			t.Errorf("invalid JSON line: %s", line)
		}
		count++
	}
	if count != n {
		t.Errorf("expected %d log lines, got %d", n, count)
	}
}

// 场景：多用户并发写入各自独立的日志文件
func TestAuditLogger_MultiUser_SeparateFiles(t *testing.T) {
	logger, dir := newTestAuditLogger(t)

	users := []string{"alice", "bob", "charlie"}
	var wg sync.WaitGroup
	for _, u := range users {
		wg.Add(1)
		go func(username string) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				logger.WriteEntry(AuditEntry{
					User:       username,
					UID:        1001,
					AuthSource: "os_peercred",
					Action:     "ps",
					URI:        "/containers/json",
					Result:     "allow",
					StatusCode: 200,
				})
			}
		}(u)
	}
	wg.Wait()

	for _, u := range users {
		path := filepath.Join(dir, "user-operation", u+".log")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("log file for %s not found: %v", u, err)
			continue
		}
		lines := 0
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			if len(scanner.Bytes()) > 0 {
				lines++
			}
		}
		if lines != 10 {
			t.Errorf("user %s: expected 10 lines, got %d", u, lines)
		}
	}
}

// ── 场景测试：LogAuth 写入认证日志 ───────────────────────────────────────────

// 场景：LogAuth 写入 auth.log，字段正确
func TestAuditLogger_LogAuth_WritesAuthLog(t *testing.T) {
	logger, dir := newTestAuditLogger(t)

	logger.LogAuth(AuthAuditEntry{
		Event:        "auth_success",
		PID:          12345,
		EffectiveUID: 1001,
		RealUID:      1001,
		RealUsername: "alice",
	})

	path := filepath.Join(dir, "auth.log")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("auth.log not found: %v", err)
	}

	var entry AuthAuditEntry
	if err := json.Unmarshal(jsonPartOf(data), &entry); err != nil {
		t.Fatalf("unmarshal auth entry: %v", err)
	}
	if entry.Event != "auth_success" {
		t.Errorf("Event = %q, want auth_success", entry.Event)
	}
	if entry.RealUsername != "alice" {
		t.Errorf("RealUsername = %q, want alice", entry.RealUsername)
	}
	if entry.PID != 12345 {
		t.Errorf("PID = %d, want 12345", entry.PID)
	}
}

// 场景：LogAuth 自动填充 Time 字段
func TestAuditLogger_LogAuth_AutoFillsTime(t *testing.T) {
	logger, dir := newTestAuditLogger(t)

	before := time.Now().UTC().Truncate(time.Second)
	logger.LogAuth(AuthAuditEntry{
		Event:    "auth_failure",
		RealUID:  1001,
	})
	after := time.Now().UTC().Add(time.Second)

	path := filepath.Join(dir, "auth.log")
	data, _ := os.ReadFile(path)
	var entry AuthAuditEntry
	_ = json.Unmarshal(jsonPartOf(data), &entry)

	t2, err := time.Parse(time.RFC3339, entry.Time)
	if err != nil {
		t.Fatalf("parse time %q: %v", entry.Time, err)
	}
	if t2.Before(before) || t2.After(after) {
		t.Errorf("time %v not in expected range [%v, %v]", t2, before, after)
	}
}

// ── 场景测试：WriteEntry 字段完整性 ──────────────────────────────────────────

// 场景：WriteEntry 自动填充 AuthSource 默认值
func TestAuditLogger_WriteEntry_DefaultAuthSource(t *testing.T) {
	logger, dir := newTestAuditLogger(t)

	logger.WriteEntry(AuditEntry{
		User:       "alice",
		UID:        1001,
		Action:     "ps",
		URI:        "/containers/json",
		Result:     "allow",
		StatusCode: 200,
		// AuthSource 故意留空
	})

	path := filepath.Join(dir, "user-operation", "alice.log")
	data, _ := os.ReadFile(path)
	var entry AuditEntry
	_ = json.Unmarshal(jsonPartOf(data), &entry)

	if entry.AuthSource != "os_peercred" {
		t.Errorf("AuthSource = %q, want os_peercred (default)", entry.AuthSource)
	}
}

// 场景：WriteEntry 写入完整字段（含 LatencyMs、TotalCount、FilteredCount）
func TestAuditLogger_WriteEntry_FullFields(t *testing.T) {
	logger, dir := newTestAuditLogger(t)

	logger.WriteEntry(AuditEntry{
		User:          "alice",
		UID:           1001,
		AuthSource:    "jwt",
		Method:        "GET",
		Action:        "ps",
		URI:           "/containers/json",
		Result:        "allow",
		StatusCode:    200,
		LatencyMs:     42,
		TotalCount:    10,
		FilteredCount: 3,
		ResourceUsage: map[string]string{"cpu_cores": "2.0", "mem_mb": "512"},
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
	if entry.ResourceUsage["cpu_cores"] != "2.0" {
		t.Errorf("ResourceUsage[cpu_cores] = %q, want 2.0", entry.ResourceUsage["cpu_cores"])
	}
}

// ── 场景测试：Reopen 日志轮转 ─────────────────────────────────────────────────

// 场景：Reopen 后继续写入不报错
func TestAuditLogger_Reopen_ContinuesWriting(t *testing.T) {
	logger, dir := newTestAuditLogger(t)

	// 写入第一条
	logger.WriteEntry(AuditEntry{User: "alice", UID: 1001, Action: "ps", URI: "/containers/json", Result: "allow", StatusCode: 200})

	// 模拟 logrotate：重命名日志文件
	oldPath := filepath.Join(dir, "user-operation", "alice.log")
	newPath := filepath.Join(dir, "user-operation", "alice.log.1")
	_ = os.Rename(oldPath, newPath)

	// Reopen 后写入第二条（应创建新文件）
	logger.Reopen()
	logger.WriteEntry(AuditEntry{User: "alice", UID: 1001, Action: "rm", URI: "/containers/abc", Result: "allow", StatusCode: 204})

	// 新文件应存在且包含第二条记录
	data, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatalf("new log file not created after Reopen: %v", err)
	}
	if len(data) == 0 {
		t.Error("new log file is empty after Reopen")
	}
}

// ── 场景测试：nil AuditLogger 安全 ───────────────────────────────────────────

// 场景：nil AuditLogger 调用不 panic
func TestAuditLogger_Nil_Safe(t *testing.T) {
	var logger *AuditLogger
	// 不应 panic
	logger.WriteEntry(AuditEntry{User: "alice"})
	logger.LogAuth(AuthAuditEntry{Event: "auth_success"})
	logger.Reopen()
	logger.Close()
}

// ── helpers ───────────────────────────────────────────────────────────────────
// newTestAuditLogger 已在 audit_test.go 中定义（同包），此处无需重复声明

