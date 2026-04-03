# Docker CLI API 调用序列测试

## 测试目的
验证 Docker CLI 在执行不同命令时的实际 API 调用序列，以便区分用户主动调用和系统自动调用。

## 测试方法
在 Linux 服务器上使用 `strace` 或查看代理日志，观察实际的 API 调用。

## 预期结果

### 1. docker info（用户主动执行）
```
GET /info
```
**只有一个请求**，没有其他后续请求。

### 2. docker version（用户主动执行）
```
GET /version
```
**只有一个请求**，没有其他后续请求。

### 3. docker images（用户主动执行）
```
GET /_ping 或 HEAD /_ping    （健康检查）
GET /images/json             （实际业务请求）
```
**有两个请求**，先健康检查，后业务请求。

### 4. docker ps（用户主动执行）
```
GET /_ping 或 HEAD /_ping    （健康检查）
GET /containers/json         （实际业务请求）
```
**有两个请求**，先健康检查，后业务请求。

## 关键发现

Docker CLI 的健康检查主要使用 `/_ping`，而不是 `/info`。

因此：
- **只对 `/_ping` 放行**（不受策略限制）
- **对 `/info` 和 `/version` 仍然进行策略检查**

这样就能完美区分：
- `docker images` → 先调用 `/_ping`（放行）→ 再调用 `/images/json`（策略检查）
- `docker info` → 只调用 `/info`（策略检查，如果禁止则拦截）

## 需要在 Linux 服务器上验证

请在 Linux 服务器上执行以下命令验证：

```bash
# 1. 清空日志
> /var/log/docker-authz/authz.log

# 2. 执行 docker info
docker info > /dev/null

# 3. 查看日志中的 API 调用
tail -20 /var/log/docker-authz/authz.log | jq -r 'select(.event=="authz_request") | "\(.http_method) \(.http_uri)"'

# 4. 清空日志
> /var/log/docker-authz/authz.log

# 5. 执行 docker images
docker images > /dev/null

# 6. 查看日志中的 API 调用
tail -20 /var/log/docker-authz/authz.log | jq -r 'select(.event=="authz_request") | "\(.http_method) \(.http_uri)"'
```

如果验证结果符合预期，则当前的修改方案是正确的。
