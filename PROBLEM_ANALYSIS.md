# 问题分析与修复方案

## 问题 2：docker run 卡死

### 可能的原因

1. **身份解析阻塞**
   - `resolveCallerIdentity` 读取 `/proc/<pid>/environ` 或 `/proc/<pid>/cmdline` 时阻塞
   - 进程已退出但 PID 仍在使用

2. **数据库锁**
   - SQLite 写入时锁住整个数据库
   - 并发请求导致死锁

3. **上游 Docker 连接问题**
   - `forward()` 调用上游 Docker 时超时
   - HTTP transport 配置问题

4. **请求体读取问题**
   - `extractImageRefFromBody` 读取请求体后没有正确重置
   - 导致转发时请求体为空

### 诊断方法

```bash
# 1. 启用 DEBUG 日志
--log-level=debug

# 2. 使用 strace 追踪系统调用
strace -f -tt -o /tmp/trace.log docker run --rm alpine echo test

# 3. 检查是否卡在特定系统调用
grep -E "read|write|connect|poll" /tmp/trace.log | tail -50
```

## 问题 3：容器隔离失效

### 可能的原因

1. **过滤函数未被调用**
   - `postprocessResponse` 中的 `filterContainerListResponse` 没有执行
   - action 分类错误，没有匹配到 `ActionPS`

2. **数据库查询失败**
   - `GetContainerIDsByOwner` 返回空列表
   - 容器创建时 `SetContainerOwner` 没有成功写入

3. **归属检查被绕过**
   - `checkOwnershipPreRequest` 中的逻辑有漏洞
   - `extractContainerID` 提取失败

4. **root 豁免逻辑错误**
   - 所有用户都被当作 root 处理
   - `identity.RealUID` 解析错误

### 诊断方法

```bash
# 1. 检查数据库内容
sqlite3 /var/lib/docker-authz/owners.db "SELECT * FROM containers;"

# 2. 检查日志中的 action 分类
grep "action" /var/log/docker-authz/authz.log | tail -20

# 3. 检查用户身份解析
grep "user" /var/log/docker-authz/authz.log | tail -20
```

## 修复方案

### 修复 1：防止请求体读取导致的卡死

**问题**：`extractImageRefFromBody` 读取请求体后，`forward()` 时请求体已被消耗

**修复**：
```go
func extractImageRefFromBody(r *http.Request) string {
    if r.Body == nil {
        return ""
    }
    body, err := io.ReadAll(r.Body)
    r.Body.Close()
    if err != nil {
        return ""
    }
    // 重新设置 Body 供后续读取
    r.Body = io.NopCloser(bytes.NewReader(body))

    var req struct {
        Image string `json:"Image"`
    }
    _ = json.Unmarshal(body, &req)
    return req.Image
}
```

### 修复 2：添加超时保护

**问题**：上游 Docker 调用可能无限期阻塞

**修复**：
```go
transport := &http.Transport{
    DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
        return net.Dial("unix", upstreamSock)
    },
    MaxIdleConns:        100,
    IdleConnTimeout:     90 * time.Second,
    ResponseHeaderTimeout: 30 * time.Second,  // 添加响应头超时
    DisableCompression:  true,
}
```

### 修复 3：确保容器归属正确记录

**问题**：容器创建成功但归属没有写入数据库

**修复**：在 `postprocessResponse` 中添加详细日志
```go
if resp.StatusCode == http.StatusCreated {
    if containerID := extractContainerIDFromCreateResponse(body); containerID != "" {
        p.logger.Debug("saving_container_owner",
            zap.String("container_id", containerID),
            zap.String("username", id.RealUsername),
            zap.Int("uid", id.RealUID))

        if err := p.db.SetContainerOwner(containerID, id); err != nil {
            p.logger.Error("save_container_owner_failed", ...)
        } else {
            p.logger.Info("container_owner_saved", ...)
        }
    } else {
        p.logger.Warn("container_id_extraction_failed",
            zap.String("response_body", string(body)))
    }
}
```

### 修复 4：确保过滤函数被调用

**问题**：action 分类可能不正确

**修复**：添加调试日志
```go
case ActionPS:
    p.logger.Debug("filtering_container_list",
        zap.Int("uid", id.RealUID),
        zap.String("username", id.RealUsername))

    body, err := readFullBody(resp.Body)
    if err != nil {
        p.logger.Error("read_response_failed", zap.Error(err))
        http.Error(w, "read upstream response failed", http.StatusBadGateway)
        return
    }

    p.logger.Debug("before_filter",
        zap.Int("container_count", strings.Count(string(body), `"Id"`)))

    filtered, err := filterContainerListResponse(body, id.RealUID, p.db)
    if err != nil {
        p.logger.Error("filter_failed", zap.Error(err))
    }

    p.logger.Debug("after_filter",
        zap.Int("container_count", strings.Count(string(filtered), `"Id"`)))
```

## 下一步行动

1. **部署带详细日志的版本**
   - 添加所有 DEBUG 日志
   - 启用 `--log-level=debug`

2. **运行诊断脚本**
   ```bash
   ./diagnose.sh > diagnose-output.txt 2>&1
   ```

3. **分析日志输出**
   - 查找卡死时的最后一条日志
   - 检查容器归属是否正确记录
   - 验证过滤函数是否被调用

4. **根据日志结果进行针对性修复**
