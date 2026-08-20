# docker-authz-proxy 使用手册

---

## 一、安装部署

### 1.1 系统要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Linux x86_64 / ARM64（内核 3.2+） |
| Docker | 20.10+ |
| systemd | 237+ |
| Go | 1.21+（仅源码编译时需要） |
| 权限 | root |

### 1.2 一键部署（推荐）

```bash
# 1. 构建部署包（开发机上，仅首次）
bash build-release.sh

# 2. 部署到服务器
bash deploy-from-windows.sh -h 192.168.1.100

# 升级已有部署
bash deploy-from-windows.sh -h 192.168.1.100 --upgrade

# 指定用户和端口
bash deploy-from-windows.sh -h 192.168.1.100 -u admin -p 2222
```

### 1.3 手动部署

```bash
scp dist/docker-authz-proxy-deploy-linux-amd64.tar.gz root@server:/tmp/
ssh root@server
cd /tmp && tar xzf docker-authz-proxy-deploy-linux-amd64.tar.gz
sudo bash docker-authz-proxy-deploy-linux-amd64/install.sh          # 首次
sudo bash docker-authz-proxy-deploy-linux-amd64/install.sh --upgrade # 升级
```

### 1.4 ARM 架构部署

```bash
bash build-src-package.sh
scp dist/docker-authz-proxy-src.tar.gz root@arm-server:/tmp/
ssh root@arm-server
cd /tmp && tar xzf docker-authz-proxy-src.tar.gz
sudo bash docker-authz-proxy-src/build-and-install.sh
```

### 1.5 安装后目录

| 路径 | 说明 |
|------|------|
| `/usr/local/bin/docker-authz-proxy` | 代理主程序 |
| `/usr/local/bin/docker-authz-proxy-ctl` | 管理工具 |
| `/etc/docker-authz/policy.yaml` | 授权策略 |
| `/etc/docker-authz/quota.yaml` | 资源配额 |
| `/var/lib/docker-authz/owners.db` | 归属数据库（SQLite） |
| `/var/log/docker-authz/` | 审计日志 |
| `/run/docker-authz/<user>/docker.sock` | 每用户 socket（权限 600） |

### 1.6 卸载

```bash
sudo bash install.sh --uninstall
```

卸载后 `/etc/docker-authz/`、`/var/lib/docker-authz/`、`/var/log/docker-authz/` 保留，需手动删除。

---

## 二、服务管理

### 2.1 启停控制

```bash
systemctl start   docker-authz      # 启动
systemctl stop    docker-authz      # 停止
systemctl restart docker-authz      # 重启
systemctl status  docker-authz      # 查看状态
systemctl enable  docker-authz      # 开机自启
```

### 2.2 热重载配置

修改 `policy.yaml` 或 `quota.yaml` 后，无需重启：

```bash
systemctl reload docker-authz
# 或
kill -HUP $(pgrep docker-authz-proxy)
```

### 2.3 日志查看

```bash
# systemd 日志
journalctl -u docker-authz -f              # 实时跟踪
journalctl -u docker-authz -n 100          # 最近 100 行
journalctl -u docker-authz --since today   # 今天的日志

# 审计日志（JSON 格式）
tail -f /var/log/docker-authz/authz.log | jq .
```

### 2.4 信号说明

| 信号 | 行为 |
|------|------|
| `SIGTERM` / `SIGINT` | 优雅停机 |
| `SIGHUP` | 重载 policy.yaml + quota.yaml |
| `SIGUSR1` | 重新打开日志文件（logrotate 用） |

---

## 三、用户使用

### 3.1 环境配置

安装后用户重新登录即可，`DOCKER_HOST` 已通过 `/etc/profile.d/docker-authz.sh` 自动配置：

```bash
echo $DOCKER_HOST
# unix:///run/docker-authz/alice/docker.sock
```

也可手动指定：

```bash
export DOCKER_HOST=unix:///run/docker-authz/$USER/docker.sock
```

### 3.2 日常使用

```bash
docker ps               # 只显示自己的容器
docker images            # 只显示自己的镜像 + 公共镜像
docker run -d nginx      # 创建的容器归属自己
docker network ls        # 只显示自己的网络
docker volume ls         # 只显示自己的存储卷
```

所有操作和直接使用 Docker 完全一致，代理在后台透明地完成隔离。

### 3.3 sudo 使用

```bash
sudo docker ps           # 看到所有容器
sudo docker run -d nginx # 创建的容器标记为 privileged_context
```

sudo 创建的资源对该用户非 sudo 模式不可见，仅 sudo 下可见。

### 3.4 Docker Compose

完全支持，`docker compose` 自动使用 `DOCKER_HOST`：

```bash
docker compose up -d
docker compose ps
```

---

## 四、配置说明

### 4.1 授权策略 `/etc/docker-authz/policy.yaml`

```yaml
version: 1
default_action: allow   # 默认允许

deny_rules:
  - users: [bob]
    actions: [exec, build, push, commit, load, save, swarm, plugin, secret, config]

  - users: [alice]
    actions: [ps, exec, build, push]
```

**操作别名（自动展开）：**

| 别名 | 展开为 |
|------|--------|
| `run` | `create_container` + `start` |
| `swarm` | 所有 swarm/node/service/task/secret/config 操作 |
| `secret` | `secret_ls/create/inspect/update/rm` |
| `config` | `config_ls/create/inspect/update/rm` |
| `plugin` | `plugin_ls/inspect/install/rm/enable/disable/upgrade/set/push/create` |

**细粒度控制示例**（允许 service 管理，仅禁止集群管理）：

```yaml
deny_rules:
  - users: [bob]
    actions: [swarm_init, swarm_join, swarm_leave, swarm_update, node_update, node_rm]
```

### 4.2 资源配额 `/etc/docker-authz/quota.yaml`

```yaml
version: 1
defaults:
  cpu_cores: 2.0       # 0 = 不限制
  mem_mb: 2048         # 0 = 不限制
  tmpfs_size_mb: 512

users:
  root:
    cpu_cores: 0
    mem_mb: 0
  alice:
    cpu_cores: 1.0
    mem_mb: 1024

groups:
  sudo:
    cpu_cores: 0
    mem_mb: 4096
```

优先级：`users` > `groups` > `defaults`

### 4.3 代理启动参数

常用参数（均有默认值，通常无需修改）：

```bash
--socket-dir /run/docker-authz           # 用户 socket 目录
--upstream /var/run/docker.sock          # 上游 Docker socket
--policy /etc/docker-authz/policy.yaml   # 策略文件
--db /var/lib/docker-authz/owners.db     # 归属数据库
--quota-file /etc/docker-authz/quota.yaml # 配额文件
--log-level info                         # 日志级别：debug|info|warn|error
--max-concurrent 0                       # 最大并发（0=不限）
--request-timeout 30                     # 请求超时秒数
```

---

## 五、管理工具（docker-authz-proxy-ctl）

需 root 或 sudo 执行。

### 5.1 查看资源归属

```bash
docker-authz-proxy-ctl list-containers --user alice
docker-authz-proxy-ctl list-images     --user alice
docker-authz-proxy-ctl list-networks   --user alice
docker-authz-proxy-ctl list-volumes    --user alice
docker-authz-proxy-ctl list-services   --user alice    # Swarm
docker-authz-proxy-ctl list-secrets    --user alice    # Swarm
docker-authz-proxy-ctl list-configs    --user alice    # Swarm
```

### 5.2 镜像管理

```bash
# 设为公共镜像（所有用户可见）
docker-authz-proxy-ctl set-public   --image nginx:latest

# 取消公共
docker-authz-proxy-ctl unset-public --image nginx:latest
```

### 5.3 跨用户网络互通

```bash
# 允许 alice 和 bob 的容器互通
docker-authz-proxy-ctl allow-network-peer --user1 alice --user2 bob

# 撤销互通
docker-authz-proxy-ctl deny-network-peer  --user1 alice --user2 bob

# 查看所有互通关系
docker-authz-proxy-ctl list-peers
```

### 5.4 审计日志查询

```bash
docker-authz-proxy-ctl audit-query --user alice --since "2024-01-01"
```

也可直接用代理程序查询：

```bash
docker-authz-proxy --query log --user alice --action create_container --result deny --limit 10
docker-authz-proxy --query log --since 2025-01-01T00:00:00Z --until 2025-01-31T23:59:59Z
docker-authz-proxy --query containers --user alice
docker-authz-proxy --query images --user alice
```

### 5.5 数据库直查

```bash
sqlite3 /var/lib/docker-authz/owners.db \
  "SELECT owner_username, id FROM containers ORDER BY created_at DESC LIMIT 10"

sqlite3 /var/lib/docker-authz/owners.db \
  "SELECT image_id, owner_username, is_public FROM images WHERE owner_uid = 1001"
```

---

## 六、日志体系

### 6.1 日志文件

| 路径 | 内容 | 格式 |
|------|------|------|
| `/var/log/docker-authz/user-operation/<user>.log` | 用户操作审计 | JSON，每行一条 |
| `/var/log/docker-authz/proxy-run/` | 代理运行日志 | zap JSON |
| `/var/log/docker-authz/container-run/` | 容器生命周期 | JSON |
| `/var/log/docker-authz/auth.log` | 认证事件 | JSON |

### 6.2 审计日志字段

```json
{
  "time": "2025-01-15T10:30:45.123456Z",
  "user": "alice",
  "uid": 1001,
  "user_type": "regular",
  "action": "create_container",
  "result": "allow",
  "path": "/containers/create",
  "http_status": 201,
  "latency_ms": 45,
  "total_count": 5,
  "filtered_count": 3
}
```

### 6.3 日志轮转

已配置 logrotate，每日自动轮转并压缩，轮转后发送 `SIGUSR1` 重新打开文件。

手动测试：

```bash
logrotate -d /etc/logrotate.d/docker-authz   # dry-run
logrotate -f /etc/logrotate.d/docker-authz   # 强制轮转
```

---

## 七、数据库备份与恢复

### 7.1 热备份（推荐）

```bash
sqlite3 /var/lib/docker-authz/owners.db ".backup /tmp/owners.db.bak"
```

### 7.2 文件拷贝

```bash
cp /var/lib/docker-authz/owners.db* /backup/
```

WAL 模式下需同时拷贝 `.db`、`.db-wal`、`.db-shm` 三个文件。

### 7.3 恢复

```bash
systemctl stop docker-authz
cp /backup/owners.db /var/lib/docker-authz/owners.db
systemctl start docker-authz
```

---

## 八、权限模型速查

| 操作 | 普通用户 | sudo 用户 | root |
|------|----------|-----------|------|
| `docker ps/images/network ls/volume ls` | 只看自己的 | 看全部 | 看全部 |
| 容器/镜像归属检查 | 只能操作自己的 | 跳过 | 跳过 |
| CPU / 内存配额 | 受限 | 跳过 | 跳过 |
| bind mount 路径 | 仅允许自己的目录 | 跳过 | 跳过 |
| policy deny 规则 | **受限** | **受限** | **受限** |

> policy deny 规则对所有用户（含 sudo/root）生效。sudo 只绕过资源隔离，不绕过显式 deny。

---

## 九、性能测试

### 9.1 运行 Benchmark

```bash
# 全部 benchmark
go test -bench=. -benchmem ./internal/authz/ ./internal/isolation/

# 指定某个 benchmark
go test -bench=BenchmarkFilterContainerListResponse -benchmem ./internal/isolation/

# 多次运行取稳定值
go test -bench=. -benchmem -count=5 ./internal/authz/ | tee bench.txt
```

### 9.2 CPU 热力图（pprof）

```bash
# 生成 profile
go test -bench=BenchmarkFilterContainerListResponse -cpuprofile=cpu.prof ./internal/isolation/

# 浏览器查看火焰图
go tool pprof -http=:6060 cpu.prof

# 终端查看 top 热点
go tool pprof -top cpu.prof
```

### 9.3 参考性能数据

| 操作 | 耗时 | 内存分配 |
|------|------|---------|
| ClassifyAction（请求分类） | 18~183 ns | 0 alloc |
| FilterContainerList（100容器+500他人） | 3.7 ms | 17k alloc |
| CanSeeImage（单镜像可见性） | ~10 μs | 45 alloc |
| SetContainerOwner（DB 写入） | 70 μs | 18 alloc |
| 特权用户短路 | 2.1 ns | 0 alloc |
