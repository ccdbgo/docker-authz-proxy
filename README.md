# Docker Authorization Proxy

多用户 Docker 资源隔离与访问控制代理 —— 基于 Unix socket 代理模式，无需修改 Docker 守护进程。

## 功能特性

- **多用户完全隔离**：每个用户只能看到和操作自己的容器、镜像、网络、存储卷
- **不可伪造身份**：通过 `SO_PEERCRED` + `/proc/<pid>/loginuid` 获取内核级身份，区分 root / sudo / 普通用户
- **细粒度访问控制**：基于 `policy.yaml` 白名单，按用户/组配置允许的操作（支持 50+ 个独立 action）
- **Swarm 集群支持**：Service、Secret、Config 归属管理与响应过滤；Node、Task 权限控制；支持细粒度子操作授权
- **资源配额**：限制每用户容器数、CPU、内存，防止资源滥用
- **镜像引用计数**：公共镜像共享，删除时自动检查引用，防止误删他人使用的镜像
- **网络互通**：`allow-network-peer` 机制允许指定用户间容器跨用户通信
- **操作审计**：所有 Docker API 操作记录结构化 JSON 审计日志
- **管理工具**：`docker-authz-proxy-ctl` 提供归属查询、配额管理、互通配置等运维操作

## 架构原理

```
用户 alice                       用户 bob
    │                                │
    ▼                                ▼
/run/docker-authz/alice/docker.sock  /run/docker-authz/bob/docker.sock
    │                                │
    └──────────────┬─────────────────┘
                   ▼
         docker-authz-proxy
                   │
                   ├─ SO_PEERCRED + loginuid  身份识别（不可伪造）
                   ├─ policy.Evaluate()       策略授权
                   ├─ OwnershipDB 归属检查    资源归属验证
                   ├─ QuotaManager            配额检查
                   ├─ FilterManager           响应过滤（只返回自己的资源）
                   ├─ Labels 注入             容器标签追踪
                   └─ AuditLogger             审计日志
                   │
                   ▼
         /var/run/docker.sock
                   │
                   ▼
               dockerd
```

每个用户通过专属 socket 访问 Docker，socket 权限 `600` 仅所有者可读写，代理从内核获取连接进程的真实身份，无法伪造。

## 系统要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Linux x86_64（内核 3.2+） |
| Docker | 20.10+ |
| systemd | 237+ |
| Go | 1.21+（仅编译时需要） |
| 权限 | root（安装时） |

## 快速部署

### 方式一：一键部署（推荐，无需目标机安装 Go）

在 Windows 开发机上执行，自动构建并部署到目标 Linux 服务器：

```bash
# 步骤 1：构建 Linux 二进制包（仅首次或代码更新后需要）
bash build-release.sh
# 输出：dist/docker-authz-proxy-deploy-linux-amd64.tar.gz (约 9MB)

# 步骤 2：一键传输并部署到目标服务器
bash deploy-from-windows.sh -h 192.168.1.100

# 升级已有部署
bash deploy-from-windows.sh -h 192.168.1.100 --upgrade

# 指定用户和端口
bash deploy-from-windows.sh -h 192.168.1.100 -u admin -p 2222
```

### 方式二：手动部署（直接在目标机操作）

```bash
# 将部署包传输到目标机
scp dist/docker-authz-proxy-deploy-linux-amd64.tar.gz root@server:/tmp/

# 在目标机上解压并安装
ssh root@server
cd /tmp && tar xzf docker-authz-proxy-deploy-linux-amd64.tar.gz
sudo bash docker-authz-proxy-deploy-linux-amd64/install.sh
```

`install.sh` 支持的选项：

```bash
sudo bash install.sh             # 首次安装
sudo bash install.sh --upgrade   # 升级（备份并覆盖配置）
sudo bash install.sh --uninstall # 卸载
```

### 方式三：ARM 架构部署（源码包，目标机需安装 Go）

适用于 ARM64（树莓派 4、AWS Graviton 等）、ARMv7 等非 x86_64 架构：

```bash
# 步骤 1：构建源码部署包（在开发机上，无需 Go）
bash build-src-package.sh
# 输出：dist/docker-authz-proxy-src.tar.gz (约 120KB)

# 步骤 2：传输到 ARM 机器
scp dist/docker-authz-proxy-src.tar.gz root@arm-server:/tmp/

# 步骤 3：在 ARM 机器上编译并安装（需要 Go 1.21+）
ssh root@arm-server
cd /tmp && tar xzf docker-authz-proxy-src.tar.gz
sudo bash docker-authz-proxy-src/build-and-install.sh
```

ARM 机器上安装 Go（如未安装）：

```bash
# ARM64 (aarch64)
wget https://go.dev/dl/go1.21.13.linux-arm64.tar.gz
tar -C /usr/local -xzf go1.21.13.linux-arm64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# ARMv7
wget https://go.dev/dl/go1.21.13.linux-armv6l.tar.gz
tar -C /usr/local -xzf go1.21.13.linux-armv6l.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

`build-and-install.sh` 支持的选项：

```bash
sudo bash build-and-install.sh             # 编译并安装
sudo bash build-and-install.sh --upgrade   # 升级（备份并覆盖配置）
sudo bash build-and-install.sh --uninstall # 卸载
```

### 方式四：源码编译部署（目标机需安装 Go）

```bash
# 在目标 Linux 机器上
git clone <repo> && cd docker-authz-proxy
sudo bash deploy-to-linux.sh
```

## 安装后路径

| 路径 | 说明 |
|------|------|
| `/usr/local/bin/docker-authz-proxy` | 主代理程序 |
| `/usr/local/bin/docker-authz-proxy-ctl` | 管理工具 |
| `/etc/docker-authz/policy.yaml` | 授权策略配置 |
| `/etc/docker-authz/quota.yaml` | 资源配额配置 |
| `/var/lib/docker-authz/owners.db` | 归属数据库（SQLite） |
| `/var/log/docker-authz/authz.log` | 审计日志 |
| `/run/docker-authz/<user>/docker.sock` | 每用户专属 socket |
| `/etc/systemd/system/docker-authz.service` | systemd 服务文件 |

## 用户使用

安装后，用户重新登录即可直接使用 `docker` 命令（`DOCKER_HOST` 已自动配置）：

```bash
# 重新登录后环境变量自动生效
echo $DOCKER_HOST
# unix:///run/docker-authz/alice/docker.sock

# 正常使用 docker，只能看到自己的资源
docker ps           # 只显示自己的容器
docker images       # 只显示自己的镜像 + 公共镜像
docker run -d nginx # 创建的容器归属于自己

# 也可临时指定 socket
docker -H unix:///run/docker-authz/alice/docker.sock ps
```

## 配置说明

### 授权策略 `/etc/docker-authz/policy.yaml`

```yaml
version: 1
default_action: allow   # 默认允许，通过 deny_rules 禁止特定操作

deny_rules:
  # 普通用户禁止 exec/build/push 等高危操作，以及所有 Swarm 集群操作
  - users: [bob]
    actions: [exec, build, push, commit, load, save, swarm, plugin, secret, config]

  # 受限用户进一步禁止 ps
  - users: [alice]
    actions: [ps, exec, build, push, commit, load, save, prune, swarm, plugin, secret, config]
```

#### 操作别名说明

`deny_rules` 中以下名称为别名，代理会自动展开为多个子操作：

| 别名 | 展开为 |
|------|--------|
| `run` | `create_container` + `start` |
| `swarm` | `swarm_init/join/leave/update/unlock/inspect` + `node_ls/inspect/update/rm` + `service_ls/create/inspect/update/rm/logs` + `task_ls/inspect` + `secret_ls/create/inspect/update/rm` + `config_ls/create/inspect/update/rm` |
| `secret` | `secret_ls` + `secret_create` + `secret_inspect` + `secret_update` + `secret_rm` |
| `config` | `config_ls` + `config_create` + `config_inspect` + `config_update` + `config_rm` |
| `plugin` | `plugin_ls/inspect/install/rm/enable/disable/upgrade/set/push/create` |

**细粒度控制示例**：如需允许普通用户管理自己的 service/secret/config，仅禁止集群管理类操作：

```yaml
deny_rules:
  - users: [bob]
    actions:
      # 禁止集群级管理（影响整个 Swarm 集群）
      - swarm_init
      - swarm_join
      - swarm_leave
      - swarm_update
      - node_update
      - node_rm
      # 其余 service/secret/config CRUD 允许（代理有归属隔离，用户只能操作自己的资源）
```

修改配置后发送 `SIGHUP` 热重载，无需重启服务：

```bash
systemctl reload docker-authz
# 或
kill -HUP $(pgrep docker-authz-proxy)
```

### 资源配额 `/etc/docker-authz/quota.yaml`

```yaml
version: 1
defaults:
  cpu_cores: 2.0
  mem_mb: 2048

users:
  root:
    cpu_cores: 0    # 0 = 不限制
    mem_mb: 0
  bob:
    cpu_cores: 2.0
    mem_mb: 2048
```

## 管理工具

```bash
# 查看用户资源
docker-authz-proxy-ctl list-containers --user alice
docker-authz-proxy-ctl list-images     --user alice
docker-authz-proxy-ctl list-networks   --user alice
docker-authz-proxy-ctl list-volumes    --user alice

# Swarm 资源（需 Swarm 模式已启用）
docker-authz-proxy-ctl list-services --user alice
docker-authz-proxy-ctl list-secrets  --user alice
docker-authz-proxy-ctl list-configs  --user alice

# 镜像公共化（所有用户可见）
docker-authz-proxy-ctl set-public   --image nginx:latest
docker-authz-proxy-ctl unset-public --image nginx:latest

# 网络互通管理
docker-authz-proxy-ctl allow-network-peer --user1 alice --user2 bob
docker-authz-proxy-ctl deny-network-peer  --user1 alice --user2 bob
docker-authz-proxy-ctl list-peers

# 查询审计日志
docker-authz-proxy-ctl audit-query --user alice --since "2024-01-01"
```

## 服务管理

```bash
# 状态 / 启停
systemctl status  docker-authz
systemctl start   docker-authz
systemctl stop    docker-authz
systemctl restart docker-authz

# 日志
journalctl -u docker-authz -f
tail -f /var/log/docker-authz/authz.log | jq .

# 数据库查询
sqlite3 /var/lib/docker-authz/owners.db \
  "SELECT owner_username, id FROM containers ORDER BY created_at"
```

## 目录结构

```
docker-authz-proxy/
├── cmd/
│   ├── proxy/          # 主程序入口 (main.go)
│   └── ctl/            # 管理工具入口 (main.go)
├── internal/
│   ├── auth/           # 身份认证 (SO_PEERCRED + loginuid)
│   ├── authz/          # 授权核心 (policy.go, ownership.go)
│   ├── forward/        # 代理服务器 (proxy.go)
│   ├── isolation/      # 资源隔离 (network/quota/filter/storage/labels)
│   ├── config/         # 配置加载
│   └── audit/          # 审计日志
├── config/             # 默认配置文件
├── deploy/             # systemd 服务文件、logrotate 配置
├── dist/               # 构建输出（二进制部署包）
├── build-release.sh    # 构建 Linux amd64 发布包
├── build-src-package.sh    # 构建源码部署包（适用于 ARM 等架构）
├── deploy-from-windows.sh  # Windows 一键部署脚本
└── deploy-to-linux.sh      # Linux 端编译部署脚本
```

## Sudo 用户处理逻辑

### 身份识别

连接建立时，代理通过三个内核数据源确定调用方身份：

```
SO_PEERCRED       →  eUID = 0（sudo 提权后的有效 UID）
/proc/PID/loginuid →  loginUID = 1001（原始登录用户，内核 audit 维护，不可伪造）
/etc/passwd        →  loginUsername = "alice"
```

判断规则：

| eUID | loginUID | 结论 | UserType |
|------|----------|------|----------|
| != 0 | 任意 | 普通用户（或 su 到普通用户） | `UserTypeRegular` |
| 0 | > 0 | 普通用户通过 sudo/su 获得 root | `UserTypeSudo` |
| 0 | 0 或未设置 | 直接以 root 身份登录 | `UserTypeRoot` |

sudo 用户的 `RealUID` 保持原始登录 UID（如 1001），**不会**改为 0。

### 权限判断

```go
func (id *CallerIdentity) IsPrivileged() bool {
    return id.RealUID == 0 || id.UserType == UserTypeSudo
}
```

代理中所有权限判断均调用 `IsPrivileged()`，sudo 用户与直接 root 享有相同的资源访问权限。

### 实际效果

| 检查项 | 普通用户 | sudo 用户 | root |
|--------|----------|-----------|------|
| `docker ps/images/network ls/volume ls` 列表过滤 | 只看自己的 | 看全部 | 看全部 |
| 容器 / 镜像 ownership 检查 | 只能操作自己的 | 跳过 | 跳过 |
| 资源配额（CPU / 内存 / 容器数） | 受限 | 跳过 | 跳过 |
| 网络注入（强制接入私有桥） | 强制注入 | 跳过 | 跳过 |
| bind mount / volume 路径校验 | 受限 | 跳过 | 跳过 |
| policy deny 规则 | 受限 | **受限** | **受限** |

> **注意**：policy deny 规则对 sudo 用户仍然生效。`IsDenied()` 使用 `RealUID`（原始登录 UID），若 policy 中禁止了该用户的某个操作，sudo 后依然被拒绝。sudo 只绕过资源隔离，不绕过显式的 deny 规则。

### 审计追踪

审计日志中记录的始终是 `RealUID` 和 `RealUsername`（原始登录用户），而非 root，确保操作可追溯到具体执行人。

```json
{"user": "alice", "uid": 1001, "user_type": "sudo", "action": "ps", "result": "allow"}
```

## 安全说明

- **Socket 权限**：每用户 socket 权限 `600`，仅所有者可访问
- **身份不可伪造**：`SO_PEERCRED` 由内核填充，进程无法伪造 PID/UID/GID
- **sudo 检测**：`loginuid` 在 PAM 登录时设置，普通进程无法修改，准确区分 sudo 提权
- **镜像安全删除**：引用计数机制防止删除其他用户仍在使用的镜像
- **端口冲突防护**：端口映射全局唯一检查，防止用户间端口冲突

## 常见问题

**Q: 用户执行 docker 命令提示 `permission denied`？**
A: 检查 socket 权限：`ls -la /run/docker-authz/<user>/docker.sock`，确认所有者正确。

**Q: `Cannot connect to the Docker daemon`？**
A: 确认 `DOCKER_HOST` 已设置：`echo $DOCKER_HOST`，若未设置请重新登录或手动 `export DOCKER_HOST=unix:///run/docker-authz/$USER/docker.sock`。

**Q: root 用户也受限吗？**
A: 是的，所有用户（含 root）均需通过授权检查。root 默认不受 deny_rules 限制，但仍记录审计日志。

**Q: 支持 Docker Compose 吗？**
A: 支持，`docker compose` 会自动使用 `DOCKER_HOST` 环境变量。

**Q: 如何区分直接 root 和 sudo？**
A: 通过 `/proc/<pid>/loginuid`：sudo 用户的 `loginuid` 为原始登录用户 UID，直接 root 登录的 `loginuid` 为 0。

**Q: 归属数据库如何备份？**
A: 直接复制 `/var/lib/docker-authz/owners.db`（SQLite WAL 模式，可热备份）。

## 卸载

```bash
sudo bash /tmp/docker-authz-proxy-deploy-linux-amd64/install.sh --uninstall
```

卸载会移除二进制、服务文件、环境变量配置，保留数据目录（`/etc/docker-authz/`、`/var/lib/docker-authz/`、`/var/log/docker-authz/`）。

## 许可证

MIT License
