# 部署和验证指南

## 修复内容

### 1. 日志格式修复
**文件**: `logger.go`
- 恢复时间字段输出
- 格式：`时间 日志级别 日志所在文件 日志消息内容`
- 示例：
```json
{
  "time": "2024-01-15T10:23:45Z",
  "level": "WARN",
  "caller": "proxy.go:377",
  "msg": "AUTHZ_DENY",
  "reason": "container_not_tracked",
  "user": "alice(uid=1001)",
  "container_id": "abc123def456"
}
```

### 2. docker run 卡死修复
**文件**: `proxy.go`
- **根因**: `resolveImageIDByRef` 在请求前同步调用上游 Docker API 导致死锁
- **修复**: 移除所有 `checkOwnershipPreRequest` 中的镜像 ID 解析调用
- **策略**: 直接用镜像名查 DB，尝试原始名称和 `sha256:` 前缀两种方式
- **影响**:
  - 未追踪镜像（不在 DB）会被 `CanUseImage` 放行（兼容存量）
  - 已追踪镜像仍然受权限控制

### 3. 容器隔离修复
**文件**: `filter.go`, `proxy.go`

#### filter.go 修复
- **fail-secure 原则**: DB 错误或 JSON 解析失败时返回空列表 `[]`
- **root 豁免**: uid=0 可见所有容器/镜像（系统管理需要）
- **修复前**: DB 错误时返回未过滤的完整列表（暴露所有用户资源）
- **修复后**: 任何错误均返回空列表，不暴露其他用户资源

#### proxy.go 修复
- **严格归属检查**: 未追踪容器（不在 DB）只允许 root 操作
- **修复前**: `if found && owner.UID != id.RealUID` → 未追踪容器直接放行
- **修复后**:
  ```go
  if !found {
      if id.RealUID != 0 {
          // 拒绝非 root 用户
          return false
      }
  } else if owner.UID != id.RealUID {
      // 拒绝归属不匹配
      return false
  }
  ```

## 部署步骤

### 1. 编译（在 Linux 服务器上）
```bash
cd /path/to/docker-authz-proxy
go build -o docker-authz-proxy .
```

### 2. 停止旧服务
```bash
systemctl stop docker-authz
```

### 3. 替换二进制文件
```bash
cp docker-authz-proxy /usr/local/bin/docker-authz-proxy
chmod +x /usr/local/bin/docker-authz-proxy
```

### 4. 启动新服务
```bash
systemctl start docker-authz
systemctl status docker-authz
```

### 5. 检查日志
```bash
# 查看启动日志
journalctl -u docker-authz -n 50 --no-pager

# 查看授权日志文件
tail -f /var/log/docker-authz/authz.log
```

## 验证步骤

### 方式一：使用自动化测试脚本
```bash
chmod +x test-isolation.sh
./test-isolation.sh
```

### 方式二：手动验证

#### 1. 创建测试用户（如果不存在）
```bash
useradd -m alice
useradd -m bob
```

#### 2. 测试容器隔离

**重要说明**: `sudo -u alice docker` 不会继承 alice 的 `~/.bashrc` 中的 `DOCKER_HOST`，必须显式传入：

```bash
# 定义辅助函数（确保通过代理 socket）
docker_as() {
    local user="$1"; shift
    sudo -u "$user" env DOCKER_HOST="unix:///run/docker-authz/${user}.sock" docker "$@"
}

# alice 创建容器
docker_as alice run -d --name alice-container nginx:alpine

# bob 创建容器
docker_as bob run -d --name bob-container nginx:alpine

# alice 列出容器（应只看到 alice-container）
docker_as alice ps

# bob 列出容器（应只看到 bob-container）
docker_as bob ps

# alice 尝试停止 bob 的容器（应被拒绝）
docker_as alice stop bob-container
# 预期输出: Error response from daemon: container 'xxx' not tracked by proxy...

# bob 尝试删除 alice 的容器（应被拒绝）
docker_as bob rm -f alice-container
# 预期输出: Error response from daemon: container 'xxx' not tracked by proxy...
```

#### 3. 测试 root 权限
```bash
# root 直接使用默认 socket，可以看到所有容器
docker ps

# root 可以操作任意容器
docker stop alice-container
docker stop bob-container
```

#### 4. 测试 docker run 不卡死
```bash
# 以普通用户身份运行（应立即返回）
time docker_as alice run --rm alpine echo "test"
# 预期: 2-5 秒内完成，不卡死
```

#### 5. 检查日志格式
```bash
# 查看最近的授权日志
tail -10 /var/log/docker-authz/authz.log | jq '.'

# 验证日志包含必需字段
tail -10 /var/log/docker-authz/authz.log | jq 'select(.time and .level and .caller and .msg)'
```

## 预期行为

### 容器隔离
- ✓ alice 只能看到自己的容器
- ✓ bob 只能看到自己的容器
- ✓ alice 无法操作 bob 的容器（stop/rm/exec/logs 等）
- ✓ bob 无法操作 alice 的容器
- ✓ root 可以看到和操作所有容器
- ✓ 未追踪容器（部署前已存在）只允许 root 操作

### 日志格式
```json
{
  "time": "2024-01-15T10:23:45Z",
  "level": "INFO",
  "caller": "proxy.go:358",
  "msg": "AUTHZ_ALLOW",
  "user": "alice(uid=1001)",
  "user_type": "regular",
  "action": "run",
  "uri": "/v1.41/containers/create"
}
```

### docker run 性能
- ✓ `docker run` 命令 2-5 秒内完成（取决于镜像大小）
- ✓ 不出现长时间卡死（超过 30 秒）

## 故障排查

### 问题 1: docker run 仍然卡死
**检查点**:
1. 查看代理日志是否有 `resolveImageIDByRef` 相关错误
2. 检查上游 Docker daemon 是否正常：`docker -H unix:///var/run/docker.sock ps`
3. 检查是否有其他进程占用 Docker socket

**排查命令**:
```bash
# 查看代理进程状态
ps aux | grep docker-authz-proxy

# 查看 Docker daemon 状态
systemctl status docker

# 查看代理日志中的错误
grep -i "error\|timeout\|deadlock" /var/log/docker-authz/authz.log | tail -20
```

### 问题 2: 容器隔离仍然失效
**检查点**:
1. 确认所有用户的 `DOCKER_HOST` 指向代理 socket
2. 检查容器是否在 DB 中有归属记录
3. 查看授权拒绝日志

**排查命令**:
```bash
# 检查用户环境变量
sudo -u alice env | grep DOCKER_HOST
# 预期: DOCKER_HOST=unix:///var/run/docker-authz/alice.sock

# 检查 DB 中的容器归属
sqlite3 /var/lib/docker-authz/owners.db "SELECT id, owner_username, owner_uid FROM containers;"

# 查看授权拒绝日志
grep "AUTHZ_DENY" /var/log/docker-authz/authz.log | tail -20
```

### 问题 3: 日志格式不正确
**检查点**:
1. 确认使用的是新编译的二进制文件
2. 检查日志配置参数

**排查命令**:
```bash
# 检查二进制文件修改时间
ls -lh /usr/local/bin/docker-authz-proxy

# 查看服务启动参数
systemctl cat docker-authz | grep ExecStart

# 查看原始日志输出
journalctl -u docker-authz -n 20 --no-pager
```

## 回滚方案

如果新版本出现问题，可以快速回滚：

```bash
# 停止服务
systemctl stop docker-authz

# 恢复旧版本二进制文件（假设已备份）
cp /usr/local/bin/docker-authz-proxy.backup /usr/local/bin/docker-authz-proxy

# 启动服务
systemctl start docker-authz
```

## 联系支持

如果问题仍然存在，请提供以下信息：
1. 完整的错误日志：`tail -100 /var/log/docker-authz/authz.log`
2. 系统信息：`uname -a`
3. Docker 版本：`docker version`
4. 代理版本：`/usr/local/bin/docker-authz-proxy --version`（如果支持）
5. 测试脚本输出：`./test-isolation.sh 2>&1 | tee test-output.log`
