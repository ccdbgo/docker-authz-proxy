# 快速使用指南

## 一、从 Windows 自动部署到 Linux 服务器

### 前提条件

1. 确保可以 SSH 连接到 Linux 服务器
2. 配置 SSH 密钥认证（推荐）或准备密码

### 部署步骤

```bash
# 在 Windows Git Bash 中执行
cd /d/code/docker-authz-proxy

# 方式 1: 使用命令行参数
./deploy-from-windows.sh -h 192.168.1.100 -u root

# 方式 2: 使用环境变量
export LINUX_SERVER=192.168.1.100
export LINUX_USER=root
export LINUX_PORT=22
./deploy-from-windows.sh
```

脚本会自动：
1. ✅ 打包代码
2. ✅ 传输到 Linux 服务器
3. ✅ 在服务器上编译
4. ✅ 安装并配置服务
5. ✅ 询问是否启动服务
6. ✅ 询问是否运行测试

## 二、在 Linux 服务器上手动部署

如果你已经在 Linux 服务器上，可以直接运行：

```bash
cd /path/to/docker-authz-proxy
sudo ./deploy-to-linux.sh
```

## 三、测试功能

### 自动化测试

```bash
sudo ./test-on-linux.sh
```

测试内容包括：
- ✅ Socket 文件创建
- ✅ 策略配置生效（alice 禁止执行 docker ps）
- ✅ 容器归属隔离（bob 无法操作 alice 的容器）
- ✅ 可见性过滤（alice 只能看到自己的容器）
- ✅ 日志格式验证（单行 JSON）
- ✅ sudo 用户身份识别

### 手动测试

#### 1. 创建测试用户

```bash
# 创建 alice 和 bob 用户
sudo useradd -m -s /bin/bash alice
sudo useradd -m -s /bin/bash bob
```

#### 2. 测试策略限制

```bash
# alice 执行 docker ps（应该被拒绝）
sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice.sock docker ps
# 预期输出：user 'alice'(uid=1001) not permitted to perform: ps

# bob 执行 docker ps（应该成功）
sudo -u bob DOCKER_HOST=unix:///run/docker-authz/bob.sock docker ps
# 预期输出：容器列表
```

#### 3. 测试容器隔离

```bash
# alice 创建容器
sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice.sock \
    docker run -d --name alice-nginx nginx:alpine

# bob 尝试停止 alice 的容器（应该被拒绝）
sudo -u bob DOCKER_HOST=unix:///run/docker-authz/bob.sock \
    docker stop alice-nginx
# 预期输出：container 'alice-nginx' belongs to 'alice'(uid=1001), not 'bob'(uid=1002)

# alice 停止自己的容器（应该成功）
sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice.sock \
    docker stop alice-nginx
```

#### 4. 测试可见性过滤

```bash
# alice 创建容器
sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice.sock \
    docker run -d --name alice-container nginx:alpine

# bob 创建容器
sudo -u bob DOCKER_HOST=unix:///run/docker-authz/bob.sock \
    docker run -d --name bob-container nginx:alpine

# alice 查看容器列表（只能看到自己的）
sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice.sock docker ps
# 预期输出：只显示 alice-container

# bob 查看容器列表（只能看到自己的）
sudo -u bob DOCKER_HOST=unix:///run/docker-authz/bob.sock docker ps
# 预期输出：只显示 bob-container
```

## 四、查看日志

### 实时日志（控制台 + 文件）

```bash
# 查看 systemd 日志
sudo journalctl -u docker-authz -f

# 查看文件日志（JSON 格式，单行）
sudo tail -f /var/log/docker-authz/authz.log | jq .
```

### 日志示例

授权通过：
```json
{"time":"2024-04-02T20:00:00Z","level":"INFO","event":"authz_allowed","real_username":"alice","real_uid":1001,"real_gid":1001,"user_type":"regular","action":"create_container","http_uri":"/v1.41/containers/create"}
```

授权拒绝：
```json
{"time":"2024-04-02T20:00:01Z","level":"WARN","event":"authz_denied_command","reason":"command_not_permitted","real_username":"alice","real_uid":1001,"real_gid":1001,"user_type":"regular","action":"ps"}
```

## 五、配置策略

### 编辑策略文件

```bash
sudo vi /etc/docker-authz/policy.yaml
```

### 示例配置

```yaml
version: 1
default_action: allow

# 禁止 alice 执行 ps 命令
deny_rules:
  - users: [alice]
    actions: [ps]

# 禁止 intern 组执行危险操作
  - groups: [intern]
    actions: [build, push, exec, rm, rmi]
```

### 配置自动重载（完全自动化）⭐

程序会自动监控配置文件的变化，**无需执行任何命令**！

```bash
# 只需编辑配置文件
sudo vi /etc/docker-authz/policy.yaml

# 保存后，程序自动检测变化并重新加载
# 完全自动化，无需任何手动操作！
```

**工作原理**：
1. 程序使用 `fsnotify` 监控配置文件所在目录
2. 检测到配置文件被修改（Write/Create 事件）
3. 自动重新加载配置文件
4. 验证配置是否有效
5. 如果有效，更新内存中的策略
6. 如果无效，保持旧配置并记录错误
7. 记录重载成功/失败日志

**特性**：
- ✅ 完全自动化，编辑保存即生效
- ✅ 配置立即生效，无需重启服务
- ✅ 不影响现有连接
- ✅ 不中断正在进行的操作
- ✅ 配置错误时自动回退到旧配置
- ✅ 自动记录重载日志

**查看自动重载日志**：
```bash
# 实时监控自动重载日志
sudo journalctl -u docker-authz -f | grep -i "configuration file changed"

# 或查看文件日志
sudo tail -f /var/log/docker-authz/authz.log | jq 'select(.event | contains("changed"))'
```

**日志示例**：
```json
{"time":"2024-04-02T20:30:00Z","level":"INFO","event":"configuration file changed, reloading","policy_file":"/etc/docker-authz/policy.yaml","operation":"WRITE"}
{"time":"2024-04-02T20:30:00Z","level":"INFO","event":"policy configuration reloaded successfully","policy_file":"/etc/docker-authz/policy.yaml"}
```

### 兼容手动重载（可选）

如果你更喜欢手动控制，仍然可以使用传统方式：

```bash
# 方式 1: 使用 systemctl reload
sudo systemctl reload docker-authz

# 方式 2: 发送 SIGHUP 信号
sudo kill -HUP $(pidof docker-authz-proxy)
```

### 测试配置重载

```bash
# 运行自动化测试脚本
sudo ./test-reload.sh
```

测试脚本会：
1. 备份当前配置
2. 修改配置（添加测试规则）
3. 等待程序自动检测并重新加载
4. 验证新配置是否生效
5. 恢复原配置

## 六、服务管理

```bash
# 启动服务
sudo systemctl start docker-authz

# 停止服务
sudo systemctl stop docker-authz

# 重启服务
sudo systemctl restart docker-authz

# 查看状态
sudo systemctl status docker-authz

# 开机自启
sudo systemctl enable docker-authz

# 禁用自启
sudo systemctl disable docker-authz
```

## 七、故障排查

### 问题 1: 用户执行 docker 命令报错 "Cannot connect to the Docker daemon"

**解决方案**：
```bash
# 1. 检查服务是否运行
sudo systemctl status docker-authz

# 2. 检查 socket 文件
ls -la /run/docker-authz/

# 3. 用户重新登录（加载环境变量）
exit
# 重新登录

# 4. 或手动设置环境变量
export DOCKER_HOST=unix:///run/docker-authz/$(whoami).sock
```

### 问题 2: 策略配置不生效

**解决方案**：
```bash
# 1. 检查配置文件语法
cat /etc/docker-authz/policy.yaml

# 2. 查看日志中的错误
sudo journalctl -u docker-authz -n 50

# 3. 重启服务
sudo systemctl restart docker-authz

# 4. 查看调试日志
sudo journalctl -u docker-authz -f
```

### 问题 3: 日志未输出到文件

**解决方案**：
```bash
# 1. 检查日志目录权限
ls -la /var/log/docker-authz/

# 2. 检查服务配置
cat /etc/systemd/system/docker-authz.service

# 3. 手动创建日志文件
sudo mkdir -p /var/log/docker-authz
sudo touch /var/log/docker-authz/authz.log
sudo chmod 640 /var/log/docker-authz/authz.log

# 4. 重启服务
sudo systemctl restart docker-authz
```

## 八、卸载

### 一键卸载

```bash
# 在 Linux 服务器上执行
sudo ./uninstall.sh
```

卸载脚本会自动完成：
1. ✅ 停止并禁用服务
2. ✅ 删除二进制文件
3. ✅ 删除 systemd 服务文件
4. ✅ 删除配置文件
5. ✅ 询问是否删除数据文件（包含归属数据库）
6. ✅ 删除日志文件
7. ✅ 删除运行时文件（socket）
8. ✅ 删除环境变量配置
9. ✅ 重载 systemd

### 卸载后注意事项

1. **用户需要重新登录**：清除 DOCKER_HOST 环境变量
2. **数据保留选项**：卸载时可以选择保留数据目录，重新安装时可恢复归属信息
3. **Docker 访问恢复**：用户现在可以直接访问 `/var/run/docker.sock`（如果有权限）

### 手动卸载（如果脚本不可用）

```bash
# 停止并禁用服务
sudo systemctl stop docker-authz
sudo systemctl disable docker-authz

# 删除文件
sudo rm -f /usr/local/bin/docker-authz-proxy
sudo rm -f /etc/systemd/system/docker-authz.service
sudo rm -rf /etc/docker-authz
sudo rm -rf /var/lib/docker-authz
sudo rm -rf /var/log/docker-authz
sudo rm -rf /run/docker-authz
sudo rm -f /etc/profile.d/docker-authz.sh

# 重载 systemd
sudo systemctl daemon-reload
```

## 九、常见问题

**Q: 为什么必须在 Linux 环境下运行？**
A: 程序依赖 Linux 特定的系统调用（SO_PEERCRED）和 /proc 文件系统。

**Q: 如何添加新用户？**
A: 创建用户后，重启服务即可自动为新用户创建 socket。

**Q: 如何设置公共镜像？**
A: 编辑 `/var/lib/docker-authz/owners.db`，将镜像的 `is_public` 字段设为 `true`。

**Q: 日志文件会无限增长吗？**
A: 建议配置 logrotate 定期轮转日志文件。

**Q: 支持 Docker Compose 吗？**
A: 支持，docker-compose 会自动使用 DOCKER_HOST 环境变量。
