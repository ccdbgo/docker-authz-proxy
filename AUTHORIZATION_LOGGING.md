# 授权日志改进方案

## 目标

在日志中突出显示授权相关的内容，方便查找和定位问题。

## 改进措施

### 1. 统一的日志字段标识

所有授权相关的日志都包含以下标准字段：

```json
{
  "event_category": "AUTHORIZATION",  // 大写，方便 grep 过滤
  "authz_result": "ALLOW" | "DENY",   // 授权结果
  "authz_phase": "request" | "command_check" | "ownership_check" | "image_access_check" | "final",
  "deny_reason": "...",               // 拒绝原因（仅 DENY 时）
  ...
}
```

### 2. 授权阶段（authz_phase）

| 阶段 | 说明 | 日志级别 |
|------|------|----------|
| `request` | 收到 API 请求 | INFO |
| `command_check` | 命令授权检查（白名单） | WARN（拒绝时） |
| `ownership_check` | 资源归属检查 | WARN（拒绝时） |
| `image_access_check` | 镜像访问权限检查 | WARN（拒绝时） |
| `virtual_delete` | 虚拟镜像删除 | INFO |
| `final` | 最终授权通过 | INFO |

### 3. 日志事件类型

| 事件名称 | 说明 | 级别 | 结果 |
|---------|------|------|------|
| `authz_request` | 每次 API 请求 | INFO | - |
| `authz_allowed` | 授权通过 | INFO | ALLOW |
| `authz_denied_command` | 命令被拒绝 | WARN | DENY |
| `authz_denied_ownership` | 资源归属检查失败 | WARN | DENY |
| `authz_denied_image_access` | 镜像访问被拒绝 | WARN | DENY |
| `virtual_image_delete` | 虚拟镜像删除 | INFO | ALLOW |

### 4. 拒绝原因（deny_reason）

| 原因代码 | 说明 |
|---------|------|
| `command_not_permitted` | 用户无权执行该命令（白名单拒绝） |
| `not_your_container` | 容器不属于该用户 |
| `not_your_image` | 镜像不属于该用户 |
| `image_not_permitted` | 用户无权访问该镜像 |
| `public_image_delete_denied` | 非 root 用户不能删除公共镜像 |

## 日志查询示例

### 查看所有授权相关日志
```bash
grep '"event_category":"AUTHORIZATION"' /var/log/docker-authz/authz.log
```

### 查看所有拒绝记录
```bash
grep '"authz_result":"DENY"' /var/log/docker-authz/authz.log
```

### 查看特定用户的拒绝记录
```bash
grep '"real_username":"bob"' /var/log/docker-authz/authz.log | grep '"authz_result":"DENY"'
```

### 查看命令授权拒绝
```bash
grep '"authz_phase":"command_check"' /var/log/docker-authz/authz.log
```

### 查看资源归属拒绝
```bash
grep '"authz_phase":"ownership_check"' /var/log/docker-authz/authz.log
```

### 查看虚拟镜像删除
```bash
grep '"authz_phase":"virtual_delete"' /var/log/docker-authz/authz.log
```

### 统计各类拒绝原因
```bash
grep '"authz_result":"DENY"' /var/log/docker-authz/authz.log | \
  jq -r '.deny_reason' | sort | uniq -c
```

### 统计各用户的拒绝次数
```bash
grep '"authz_result":"DENY"' /var/log/docker-authz/authz.log | \
  jq -r '.real_username' | sort | uniq -c
```

## 日志示例

### 1. 授权请求（每次 API 调用）
```json
{
  "time": "2024-01-15T10:23:45Z",
  "level": "INFO",
  "event": "authz_request",
  "event_category": "AUTHORIZATION",
  "authz_phase": "request",
  "real_username": "bob",
  "real_uid": 1002,
  "real_gid": 1002,
  "effective_username": "root",
  "effective_uid": 0,
  "user_type": "sudo",
  "process_name": "docker",
  "cmdline": "docker ps",
  "pid": 12345,
  "action": "ps",
  "http_method": "GET",
  "http_uri": "/v1.41/containers/json"
}
```

### 2. 命令授权被拒绝
```json
{
  "time": "2024-01-15T10:23:45Z",
  "level": "WARN",
  "event": "authz_denied_command",
  "event_category": "AUTHORIZATION",
  "authz_result": "DENY",
  "authz_phase": "command_check",
  "deny_reason": "command_not_permitted",
  "real_username": "bob",
  "real_uid": 1002,
  "real_gid": 1002,
  "effective_username": "root",
  "effective_uid": 0,
  "user_type": "sudo",
  "process_name": "docker",
  "cmdline": "docker build -t test .",
  "pid": 12345,
  "action": "build",
  "http_method": "POST",
  "http_uri": "/v1.41/build"
}
```

### 3. 资源归属检查被拒绝
```json
{
  "time": "2024-01-15T10:23:45Z",
  "level": "WARN",
  "event": "authz_denied_ownership",
  "event_category": "AUTHORIZATION",
  "authz_result": "DENY",
  "authz_phase": "ownership_check",
  "deny_reason": "not_your_container",
  "real_username": "bob",
  "real_uid": 1002,
  "real_gid": 1002,
  "effective_username": "root",
  "effective_uid": 0,
  "user_type": "sudo",
  "process_name": "docker",
  "cmdline": "docker stop alice-container",
  "pid": 12345,
  "owner_username": "alice",
  "owner_uid": 1001,
  "owner_gid": 1001,
  "resource_type": "container",
  "resource_id": "abc123def456",
  "action": "stop"
}
```

### 4. 镜像访问被拒绝
```json
{
  "time": "2024-01-15T10:23:45Z",
  "level": "WARN",
  "event": "authz_denied_image_access",
  "event_category": "AUTHORIZATION",
  "authz_result": "DENY",
  "authz_phase": "image_access_check",
  "deny_reason": "image_not_permitted",
  "real_username": "bob",
  "real_uid": 1002,
  "real_gid": 1002,
  "effective_username": "root",
  "effective_uid": 0,
  "user_type": "sudo",
  "process_name": "docker",
  "cmdline": "docker run alice-image",
  "pid": 12345,
  "image_ref": "alice-image:latest",
  "action": "run"
}
```

### 5. 虚拟镜像删除
```json
{
  "time": "2024-01-15T10:23:45Z",
  "level": "INFO",
  "event": "virtual_image_delete",
  "event_category": "AUTHORIZATION",
  "authz_result": "ALLOW",
  "authz_phase": "virtual_delete",
  "real_username": "bob",
  "real_uid": 1002,
  "real_gid": 1002,
  "effective_username": "root",
  "effective_uid": 0,
  "user_type": "sudo",
  "process_name": "docker",
  "cmdline": "docker rmi nginx",
  "pid": 12345,
  "image_id": "sha256:abc123...",
  "real_delete": false
}
```

### 6. 授权通过
```json
{
  "time": "2024-01-15T10:23:45Z",
  "level": "INFO",
  "event": "authz_allowed",
  "event_category": "AUTHORIZATION",
  "authz_result": "ALLOW",
  "authz_phase": "final",
  "real_username": "bob",
  "real_uid": 1002,
  "real_gid": 1002,
  "effective_username": "root",
  "effective_uid": 0,
  "user_type": "sudo",
  "process_name": "docker",
  "cmdline": "docker ps",
  "pid": 12345,
  "action": "ps",
  "http_uri": "/v1.41/containers/json"
}
```

## 实现代码

### logger.go 新增函数

```go
// logAuthzRequest 记录授权请求（每次 API 调用）
func logAuthzRequest(logger *zap.Logger, id *CallerIdentity, action, method, uri string)

// logAuthzAllowed 记录授权通过
func logAuthzAllowed(logger *zap.Logger, id *CallerIdentity, action, uri string)

// logAuthzDeniedCommand 记录命令授权被拒绝
func logAuthzDeniedCommand(logger *zap.Logger, id *CallerIdentity, action, method, uri, reason string)

// logAuthzDeniedOwnership 记录资源归属检查被拒绝
func logAuthzDeniedOwnership(logger *zap.Logger, id *CallerIdentity, owner *OwnerInfo,
    resourceType, resourceID, action, reason string)

// logAuthzDeniedImageAccess 记录镜像访问被拒绝
func logAuthzDeniedImageAccess(logger *zap.Logger, id *CallerIdentity,
    imageRef, action, reason string)

// logVirtualImageDelete 记录虚拟镜像删除
func logVirtualImageDelete(logger *zap.Logger, id *CallerIdentity, imageID string, realDelete bool)
```

### proxy.go 使用示例

```go
// 记录请求
logAuthzRequest(p.logger, identity, action, r.Method, r.URL.RequestURI())

// 命令授权拒绝
logAuthzDeniedCommand(p.logger, identity, action, r.Method, r.URL.RequestURI(), "command_not_permitted")

// 资源归属拒绝
logAuthzDeniedOwnership(p.logger, identity, owner, "container", containerID, action, "not_your_container")

// 镜像访问拒绝
logAuthzDeniedImageAccess(p.logger, identity, imageRef, action, "image_not_permitted")

// 虚拟镜像删除
logVirtualImageDelete(p.logger, identity, imageID, false)

// 授权通过
logAuthzAllowed(p.logger, identity, action, r.URL.RequestURI())
```

## 监控和告警建议

### 1. 实时监控拒绝事件
```bash
tail -f /var/log/docker-authz/authz.log | grep '"authz_result":"DENY"'
```

### 2. 统计每小时拒绝次数
```bash
grep '"authz_result":"DENY"' /var/log/docker-authz/authz.log | \
  jq -r '.time' | cut -d'T' -f2 | cut -d':' -f1 | sort | uniq -c
```

### 3. 告警规则（Prometheus/Grafana）
- 某用户 5 分钟内拒绝次数 > 10：可能是攻击或配置错误
- 某个 deny_reason 突然增多：可能是策略配置问题
- 某个容器/镜像被多个用户尝试访问：可能是权限配置错误

## 优势

1. **快速定位问题**：通过 `event_category: "AUTHORIZATION"` 快速过滤所有授权日志
2. **结构化查询**：使用 jq 可以方便地统计和分析
3. **清晰的授权流程**：通过 `authz_phase` 了解请求在哪个阶段被拒绝
4. **详细的拒绝原因**：`deny_reason` 提供明确的拒绝原因代码
5. **完整的上下文**：包含用户身份、进程信息、资源信息等完整上下文
