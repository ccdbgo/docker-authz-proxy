package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ContainerEvent 容器运行日志条目
type ContainerEvent struct {
	Time        string `json:"time"`
	ContainerID string `json:"container_id"`
	Action      string `json:"action"` // start/stop/die/kill/oom/create/destroy 等
	Image       string `json:"image,omitempty"`
	Username    string `json:"username,omitempty"`
	UID         int    `json:"uid,omitempty"`
	ExitCode    string `json:"exit_code,omitempty"`
	Error       string `json:"error,omitempty"`
}

// ContainerLogger 容器运行日志，写入 <logDir>/container-run/<username>.log
// 通过 Docker Events API 监听容器生命周期事件，关联用户 ID
type ContainerLogger struct {
	logDir     string
	dockerSock string
	mu         sync.Mutex
	files      map[string]*os.File
}

// NewContainerLogger 创建容器运行日志记录器
func NewContainerLogger(logDir, dockerSock string) (*ContainerLogger, error) {
	dir := filepath.Join(logDir, "container-run")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create container-run log dir: %w", err)
	}
	return &ContainerLogger{
		logDir:     logDir,
		dockerSock: dockerSock,
		files:      make(map[string]*os.File),
	}, nil
}

// Start 启动 Docker Events 监听，ctx 取消时退出
func (c *ContainerLogger) Start(ctx context.Context, ownerLookup func(containerID string) (username string, uid int, found bool)) {
	go c.run(ctx, ownerLookup)
}

func (c *ContainerLogger) run(ctx context.Context, ownerLookup func(string) (string, int, bool)) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "unix", c.dockerSock)
		},
	}
	client := &http.Client{Transport: transport}

	for {
		if err := c.stream(ctx, client, ownerLookup); err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				// 重连退避
				time.Sleep(5 * time.Second)
			}
		} else {
			return
		}
	}
}

func (c *ContainerLogger) stream(ctx context.Context, client *http.Client, ownerLookup func(string) (string, int, bool)) error {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://docker/events?filters=%7B%22type%22%3A%5B%22container%22%5D%7D", nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var raw struct {
			Status string `json:"status"` // Docker API v1.21 以前
			Action string `json:"Action"` // Docker API v1.22+
			Actor  struct {
				ID         string            `json:"ID"`
				Attributes map[string]string `json:"Attributes"`
			} `json:"Actor"`
			Time int64 `json:"time"`
		}
		if err := json.Unmarshal(line, &raw); err != nil {
			continue
		}

		action := raw.Action
		if action == "" {
			action = raw.Status
		}
		// 只记录关键生命周期事件
		switch action {
		case "create", "start", "stop", "die", "kill", "oom", "destroy", "pause", "unpause", "restart":
		default:
			continue
		}

		containerID := raw.Actor.ID
		if len(containerID) > 12 {
			containerID = containerID[:12]
		}

		image := raw.Actor.Attributes["image"]
		exitCode := raw.Actor.Attributes["exitCode"]

		username, uid, _ := ownerLookup(raw.Actor.ID)

		entry := ContainerEvent{
			Time:        time.Unix(raw.Time, 0).UTC().Format(time.RFC3339),
			ContainerID: containerID,
			Action:      action,
			Image:       image,
			Username:    username,
			UID:         uid,
			ExitCode:    exitCode,
		}

		c.write(username, entry)
	}

	return scanner.Err()
}

func (c *ContainerLogger) write(username string, entry ContainerEvent) {
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	// 去掉外层 {}，输出格式："time":"...","container_id":"...",...
	inner := line
	if len(inner) >= 2 && inner[0] == '{' && inner[len(inner)-1] == '}' {
		inner = inner[1 : len(inner)-1]
	}
	out := append(inner, '\n')

	c.mu.Lock()
	defer c.mu.Unlock()

	key := username
	if key == "" {
		key = "unknown"
	}
	f, err := c.getFile(key)
	if err != nil {
		return
	}
	_, _ = f.Write(out)
}

func (c *ContainerLogger) getFile(username string) (*os.File, error) {
	if f, ok := c.files[username]; ok {
		return f, nil
	}
	path := filepath.Join(c.logDir, "container-run", username+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	c.files[username] = f
	return f, nil
}

// Reopen 重新打开所有日志文件（logrotate 后调用）
func (c *ContainerLogger) Reopen() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for username, f := range c.files {
		path := f.Name()
		_ = f.Close()
		newF, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err == nil {
			c.files[username] = newF
		} else {
			delete(c.files, username)
		}
	}
}

// Close 关闭所有日志文件
func (c *ContainerLogger) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range c.files {
		_ = f.Close()
	}
}
