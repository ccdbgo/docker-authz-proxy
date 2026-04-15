package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LogQueryOptions 日志查询参数
type LogQueryOptions struct {
	LogDir  string // 审计日志根目录
	LogType string // "operation" | "auth" | "container" | "proxy"
	// 过滤条件
	Username string // 按用户名过滤（空表示所有用户）
	UID      int    // 按 UID 过滤（-1 表示不过滤）
	Action   string // 按操作类型过滤（空表示所有）
	Result   string // "allow" | "deny" | ""
	Level    string // 按日志级别过滤（proxy 类型专用，如 info/warn/error）
	Since    string // RFC3339 起始时间（空表示不限）
	Until    string // RFC3339 结束时间（空表示不限）
	Limit    int    // 最多返回条数（0 表示不限）
}

// RunLogQuery 执行日志查询并输出到 stdout
func RunLogQuery(opts LogQueryOptions) {
	var sinceT, untilT time.Time
	if opts.Since != "" {
		t, err := time.Parse(time.RFC3339, opts.Since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --since: %v\n", err)
			os.Exit(1)
		}
		sinceT = t
	}
	if opts.Until != "" {
		t, err := time.Parse(time.RFC3339, opts.Until)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --until: %v\n", err)
			os.Exit(1)
		}
		untilT = t
	}

	var files []string
	switch opts.LogType {
	case "auth":
		files = []string{filepath.Join(opts.LogDir, "auth.log")}
	case "container":
		files = globLogFiles(filepath.Join(opts.LogDir, "container-run"), opts.Username)
	case "proxy":
		files = globLogFiles(filepath.Join(opts.LogDir, "proxy-run"), "")
	default: // "operation"
		files = globLogFiles(filepath.Join(opts.LogDir, "user-operation"), opts.Username)
	}

	count := 0
	for _, path := range files {
		if opts.Limit > 0 && count >= opts.Limit {
			break
		}
		n := queryFile(path, opts, sinceT, untilT, opts.Limit-count)
		count += n
	}
}

func globLogFiles(dir, username string) []string {
	if username != "" {
		return []string{filepath.Join(dir, username+".log")}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".log") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	return files
}

// queryFile 扫描单个日志文件，返回匹配条数
func queryFile(path string, opts LogQueryOptions, since, until time.Time, remaining int) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if remaining > 0 && count >= remaining {
			break
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// 解析公共字段（兼容 operation/auth/container/proxy 日志格式）
		// 新格式：每行以 "<时间戳> {json}" 开头；旧格式：直接以 "{json}" 开头
		var base struct {
			Time   string `json:"time"`
			User   string `json:"user"`
			UID    int    `json:"uid"`
			Action string `json:"action"`
			Result string `json:"result"`
			Level  string `json:"level"` // proxy-run zap JSON 日志字段
		}
		// 兼容三种格式：
		//   新格式: "time":"...","level":"INFO",...  （无花括号）
		//   旧格式: {"time":"...","level":"INFO",...} （有花括号）
		//   中间格式: 2026-04-15T... {"..."}          （时间前缀+JSON）
		var jsonLine []byte
		if len(line) > 0 {
			switch line[0] {
			case '{':
				jsonLine = line
			case '"':
				jsonLine = make([]byte, 0, len(line)+2)
				jsonLine = append(jsonLine, '{')
				jsonLine = append(jsonLine, line...)
				jsonLine = append(jsonLine, '}')
			default:
				if i := bytes.IndexByte(line, '{'); i > 0 {
					jsonLine = line[i:]
				}
			}
		}
		if err := json.Unmarshal(jsonLine, &base); err != nil {
			continue
		}

		// 时间过滤
		if !since.IsZero() || !until.IsZero() {
			t, err := time.Parse(time.RFC3339, base.Time)
			if err != nil {
				continue
			}
			if !since.IsZero() && t.Before(since) {
				continue
			}
			if !until.IsZero() && t.After(until) {
				continue
			}
		}

		// 用户名过滤
		if opts.Username != "" && base.User != opts.Username {
			continue
		}

		// UID 过滤
		if opts.UID >= 0 && base.UID != opts.UID {
			continue
		}

		// 操作类型过滤
		if opts.Action != "" && !strings.EqualFold(base.Action, opts.Action) {
			continue
		}

		// 结果过滤
		if opts.Result != "" && !strings.EqualFold(base.Result, opts.Result) {
			continue
		}

		// 日志级别过滤（proxy 类型）
		if opts.Level != "" && !strings.EqualFold(base.Level, opts.Level) {
			continue
		}

		fmt.Println(string(line))
		count++
	}
	return count
}
