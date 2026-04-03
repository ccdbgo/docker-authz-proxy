# Docker Authorization Proxy

多用户 Docker 容器与镜像资源隔离方案 - 基于代理模式实现完全的可见性隔离。

## 概述

在多租户共享 Linux 服务器环境中，本方案通过代理模式实现不同用户对 Docker 容器和镜像的完全隔离：

- **完全可见性隔离**：不同用户只能看到和操作自己的容器/镜像
- **所有用户受限**：包括 root 用户在内，所有用户均需通过授权检查
- **身份识别**：准确识别 root/sudo/普通用户，携带 UID+GID+username
- **命令授权**：基于白名单的命令访问控制
- **资源归属**：容器和镜像按用户隔离，支持公共镜像共享
- **系统标签**：独立命名空间，不覆盖用户标签
- **结构化日志**：JSON 格式，记录完整调用上下文

## 架构原理

```
用户 alice                    用户 bob
    │                             │
    ▼                             ▼
alice.sock                    bob.sock
    │                             │
    └─────────┬───────────────────┘
              ▼
      docker-authz-proxy
              │
              ├─ SO_PEERCRED 身份解析（区分 root/sudo/普通用户）
              ├─ 命令授权检查（policy.yaml 白名单）
              ├─ 资源归属验证（owners.db）
              ├─ 响应过滤（只返回用户自己的资源）
              └─ 系统标签注入
              │
              ▼
      /var/run/docker.sock
              │
              ▼
          dockerd
```

### 工作原理

1. **每用户专属 Socket**：每个用户通过自己的 Unix socket 访问 Docker
   - alice 用户：`/run/docker-authz/alice.sock`
   - bob 用户：`/run/docker-authz/bob.sock`
   - Socket 文件权限：`srw------- alice alice`（只有所有者可访问）

2. **身份解析**：代理通过 `SO_PEERCRED` 获取连接的真实 UID/GID
   - 普通用户：直接获取 UID
   - sudo 用户：从 `/proc/<pid>/environ` 读取 `SUDO_UID`
   - root 用户：区分直接登录 root 和 sudo

3. **双重授权**：
   - **层次一**：命令授权（白名单检查）
   - **层次二**：资源归属检查（容器/镜像归属验证）

4. **响应过滤**：
   - `docker ps`：只返回用户自己的容器
   - `docker images`：只返回用户自己的镜像 + 公共镜像

## 系统要求

- Linux 操作系统（内核 3.2+，支持 SO_PEERCRED）
- Docker Engine（任意版本，保持标准 root dockerd）
- Go 1.19+ （仅编译时需要）
- systemd（用于服务管理）

## 快速开始

**注意**：本程序必须在 Linux 环境下编译和运行（依赖 Linux 特定的系统调用和 /proc 文件系统）。

### 方式一：自动化部署（推荐）

从 Windows 开发环境直接部署到 Linux 服务器：

```bash
# 在 Windows Git Bash 中执行
./deploy-from-windows.sh -h <Linux服务器IP> -u root

# 或使用环境变量
export LINUX_SERVER=192.168.1.100
export LINUX_USER=root
./deploy-from-windows.sh
```

脚本会自动完成：
1. 打包代码
2. 传输到 Linux 服务器
3. 在服务器上编译
4. 安装并配置服务
5. 询问是否启动服务和运行测试

### 方式二：手动部署

#### 1. 传输代码到 Linux 服务器

```bash
# 在 Windows 上打包
tar czf docker-authz-proxy.tar.gz .

# 传输到 Linux 服务器
scp docker-authz-proxy.tar.gz user@linux-server:/tmp/

# 在 Linux 服务器上解压
ssh user@linux-server
cd /tmp
tar xzf docker-authz-proxy.tar.gz
cd docker-authz-proxy
```

#### 2. 在 Linux 服务器上部署

```bash
# 一键部署（编译 + 安装 + 配置）
sudo ./deploy-to-linux.sh
```

部署脚本会自动完成：
- 编译程序
- 停止现有服务（如果存在）
- 创建必要的目录
- 安装二进制文件到 `/usr/local/bin/`
- 安装配置文件到 `/etc/docker-authz/`
- 安装 systemd 服务
- 配置用户环境变量

#### 3. 启动服务

```bash
sudo systemctl start docker-authz
sudo systemctl status docker-authz
```

#### 4. 运行测试

```bash
sudo ./test-on-linux.sh
```

测试脚本会验证：
- Socket 文件创建
- 策略配置生效
- 容器归属隔离
- 可见性过滤
- 日志格式
- sudo 用户识别

### 用户使用

用户重新登录后，环境变量 `DOCKER_HOST` 会自动设置为自己的 socket：

```bash
# alice 用户登录后
echo $DOCKER_HOST
# 输出：unix:///run/docker-authz/alice.sock

# 正常使用 docker 命令
docker ps        # 只显示 alice 的容器
docker images    # 只显示 alice 的镜像和公共镜像
docker run -d nginx
```

## 配置说明

### 策略配置文件

配置文件位置：`/etc/docker-authz/policy.yaml`

```yaml
version: 1
default_action: allow  # 白名单模式：默认允许

# 禁止规则（优先于 default_action）
deny_rules:
  - groups: [intern]           # 限制 intern 组
    actions: [build, push, exec, rm, rmi]

  - users: [untrusted-user]    # 限制特定用户
    actions: [build, push, exec, pull]
```

**配置说明**：
- 只需填写用户名/组名，程序启动时自动从 `/etc/passwd`、`/etc/group` 解析 UID/GID
- 所有用户（含 root）均受此策略约束，无豁免
- 支持的操作名称：`ps`, `create_container`, `start`, `stop`, `rm`, `exec`, `inspect`, `logs`, `images`, `pull`, `build`, `push`, `rmi`, `tag`

### 配置热重载（自动检测，无需手动操作）⭐

程序会自动监控配置文件的变化，当你编辑并保存配置文件后，配置会立即生效，**无需执行任何命令**。

```bash
# 只需编辑配置文件
sudo vi /etc/docker-authz/policy.yaml

# 保存后，程序自动检测变化并重新加载
# 无需执行任何命令！
```

**工作原理**：
- 程序使用 `fsnotify` 监控配置文件所在目录
- 检测到配置文件被修改时，自动重新加载
- 配置验证失败时，保持旧配置不变
- 所有操作自动记录到日志

**特性**：
- ✅ 完全自动化，无需手动操作
- ✅ 配置立即生效，无需重启服务
- ✅ 不影响现有连接
- ✅ 不中断正在进行的操作
- ✅ 配置错误时自动回退到旧配置
- ✅ 自动记录重载日志

**兼容手动重载**（可选）：

如果你更喜欢手动控制，仍然可以使用传统方式：

```bash
# 方式 1: 使用 systemctl reload
sudo systemctl reload docker-authz

# 方式 2: 发送 SIGHUP 信号
sudo kill -HUP $(pidof docker-authz-proxy)
```

**查看重载日志**：
```bash
# 查看自动重载日志
sudo journalctl -u docker-authz -f | grep -i "configuration file changed"

# 或查看文件日志
sudo tail -f /var/log/docker-authz/authz.log | jq 'select(.event | contains("changed"))'
```

**测试自动重载**：
```bash
# 运行自动化测试脚本
sudo ./test-reload.sh
```

### 公共镜像配置

如需设置公共镜像（所有用户可见），修改数据库：

```bash
sqlite3 /var/lib/docker-authz/owners.db
```

```sql
-- 查看所有镜像
SELECT image_id, owner_username, is_public FROM images;

-- 设置镜像为公共
UPDATE images SET is_public = 1 WHERE image_id = 'sha256:abc123...';

-- 或按镜像名称模糊匹配（需要先查询 image_id）
```

**推荐做法**：管理员预先 pull 常用基础镜像（nginx, redis, mysql 等），然后标记为公共。

## 日志说明

### 日志级别

- `DEBUG`：每次 API 请求的完整上下文（高频，生产环境建议关闭）
- `INFO`：授权通过的关键操作（容器创建/删除、镜像 pull/build）
- `WARN`：授权被拒绝（命令未授权、资源归属不匹配）
- `ERROR`：插件内部错误（DB 故障、身份解析失败）

### 查看日志

```bash
# systemd 日志
sudo journalctl -u docker-authz -f

# JSON 格式日志（推荐使用 jq 格式化）
sudo tail -f /var/log/docker-authz/authz.log | jq .
```

### 日志示例

授权通过：
```json
{
  "time": "2024-04-02T10:23:45Z",
  "level": "INFO",
  "event": "authz_allowed",
  "real_username": "alice",
  "real_uid": 1001,
  "real_gid": 1001,
  "user_type": "regular",
  "action": "create_container",
  "uri": "/v1.41/containers/create"
}
```

授权拒绝（资源归属不匹配）：
```json
{
  "time": "2024-04-02T10:25:30Z",
  "level": "WARN",
  "event": "authz_denied_ownership",
  "reason": "not_your_container",
  "real_username": "bob",
  "real_uid": 1002,
  "real_gid": 1002,
  "user_type": "sudo",
  "effective_uid": 0,
  "container_id": "abc123def456",
  "owner_username": "alice",
  "owner_uid": 1001,
  "action": "stop"
}
```

## 测试

项目提供了完整的测试套件，位于 `test/test-suite.sh`。

### 运行测试

```bash
cd /d/code/docker-authz-plugin/test
sudo ./test-suite.sh
```

测试覆盖：
- 环境变量检查
- 连接性测试
- 容器归属隔离
- 可见性过滤（`docker ps`、`docker images`）
- 镜像归属隔离
- sudo 用户身份识别
- 系统标签注入
- 策略规则验证
- 短 ID/全 ID 支持

## 故障排查

### 问题：用户执行 docker 命令报错 "Cannot connect to the Docker daemon"

**原因**：用户的 socket 文件不存在或 `DOCKER_HOST` 未设置。

**解决**：
1. 检查服务是否运行：`sudo systemctl status docker-authz`
2. 检查 socket 目录：`ls -la /run/docker-authz/`
3. 用户重新登录（加载 `/etc/profile.d/docker-authz.sh`）
4. 或手动设置：`export DOCKER_HOST=unix:///run/docker-authz/$(whoami).sock`

### 问题：用户可以看到其他用户的容器

**原因**：用户直接访问了 `/var/run/docker.sock`，绕过了代理。

**解决**：
1. 限制 `/var/run/docker.sock` 权限：
   ```bash
   sudo chmod 600 /var/run/docker.sock
   sudo chown root:root /var/run/docker.sock
   ```
2. 确保用户不在 `docker` 组：
   ```bash
   sudo gpasswd -d alice docker
   ```

### 问题：sudo docker 命令被拒绝

**原因**：sudo 后 `DOCKER_HOST` 环境变量未传递。

**解决**：
1. 配置 sudoers 保留环境变量：
   ```bash
   sudo visudo
   # 添加：
   Defaults env_keep += "DOCKER_HOST"
   ```
2. 或使用 `sudo -E`：
   ```bash
   sudo -E docker ps
   ```

### 问题：日志显示 "identity resolution failed"

**原因**：无法读取 `/proc/<pid>/environ` 或 `/proc/<pid>/comm`。

**解决**：
1. 检查 systemd 服务配置中的 `ProtectSystem` 设置
2. 确保代理进程有权限读取 `/proc`
3. 查看详细错误：`sudo journalctl -u docker-authz -n 50`

## 文件结构

```
/usr/local/bin/docker-authz-proxy          # 主程序
/etc/docker-authz/
  └── policy.yaml                          # 策略配置
/var/lib/docker-authz/
  └── owners.db                            # 归属数据库（JSON 格式）
/var/log/docker-authz/
  └── authz.log                            # 结构化日志
/run/docker-authz/
  ├── alice.sock                           # alice 用户 socket
  ├── bob.sock                             # bob 用户 socket
  └── ...
/etc/profile.d/docker-authz.sh             # 环境变量配置
/etc/systemd/system/docker-authz.service   # systemd 服务
```

## 高级功能

### 存量数据迁移

如果服务器上已有容器和镜像，使用迁移脚本：

```bash
sudo ./deploy/migrate.sh
```

脚本会：
- 扫描现有容器，从标签中提取归属信息
- 扫描现有镜像，默认标记为公共镜像
- 写入归属数据库

### RBAC 扩展

当前版本使用白名单模式（`deny_rules`），后期可扩展为 RBAC：

```yaml
# 未来版本支持
roles:
  readonly:  [ps, inspect, logs, images]
  developer: [ps, inspect, logs, images, run, stop, rm, pull, build]
  advanced:  [ps, inspect, logs, images, run, stop, rm, pull, build, push, exec]

user_roles:
  alice: developer
  bob:   readonly
  groups:
    devops: advanced
```

## 性能说明

- **延迟开销**：代理增加 <1ms 延迟（身份解析 + 授权检查）
- **吞吐量**：不受影响，dockerd 是真正的瓶颈
- **并发**：支持多用户并发，每个连接独立处理
- **连接池**：代理维护到 dockerd 的连接池，复用 TCP 连接

## 安全说明

1. **Socket 权限**：每个用户的 socket 文件权限为 `600`，只有所有者可访问
2. **身份验证**：通过 `SO_PEERCRED` 获取内核级身份，无法伪造
3. **sudo 检测**：准确识别 sudo 用户，使用真实 UID 进行授权
4. **标签防伪造**：系统标签使用独立命名空间（`system.authz.*`），追加模式防止覆盖
5. **日志审计**：所有操作记录完整上下文，包括 PID、进程名、命令行

## 卸载

如需完全卸载程序：

```bash
# 在 Linux 服务器上执行
sudo ./uninstall.sh
```

卸载脚本会：
1. 停止并禁用服务
2. 删除二进制文件
3. 删除配置文件
4. 询问是否删除数据文件（包含归属数据库）
5. 删除日志文件
6. 删除运行时文件（socket）
7. 删除环境变量配置
8. 重载 systemd

**注意**：
- 卸载后用户需要重新登录以清除 DOCKER_HOST 环境变量
- 如果保留数据目录，重新安装时可以恢复归属信息

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request。

## 常见问题

**Q: 为什么不使用 Docker rootless 或 Podman？**
A: 本方案保留标准 root dockerd，兼容现有环境，无需迁移。

**Q: root 用户也受限吗？**
A: 是的，所有用户（含 root）均需通过授权检查，无豁免。

**Q: 如何区分直接 root 和 sudo？**
A: 代理通过 `/proc/<pid>/environ` 检测 `SUDO_UID` 环境变量，准确识别 sudo 用户。

**Q: 性能影响有多大？**
A: 代理增加 <1ms 延迟，对实际使用无感知影响。

**Q: 支持 Docker Compose 吗？**
A: 支持，`docker-compose` 命令会自动使用 `DOCKER_HOST` 环境变量。

**Q: 如何备份归属数据？**
A: 归属数据存储在 `/var/lib/docker-authz/owners.db`（JSON 格式），直接复制即可。
