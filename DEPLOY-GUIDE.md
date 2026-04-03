# 🚀 快速部署指南 - 解决新用户 Socket 问题

## 📋 问题说明

**问题**: 安装程序时只为当时存在的用户创建 socket，后来添加的 alice、bob 等用户没有对应的 socket 文件。

**解决**: 程序现在会每 10 秒自动扫描系统用户，为新用户自动创建 socket。

## ✅ 已完成的修改

### 1. 代码修改
- ✅ `proxy.go` - 添加 `watchNewUsers()` 函数
- ✅ 每 10 秒自动扫描系统用户
- ✅ 检测到新用户后自动创建 socket
- ✅ 自动记录日志

### 2. 配置自动重载
- ✅ `main.go` - 使用 Go 标准库实现
- ✅ 每 2 秒检查配置文件修改时间
- ✅ 检测到变化后自动重新加载

## 🎯 在 Linux 服务器上部署

### 方式一：从 Windows 自动部署（推荐）

在 Windows Git Bash 中执行：

```bash
cd /d/code/docker-authz-proxy

# 自动部署到 Linux 服务器
./deploy-from-windows.sh -h <Linux服务器IP> -u root
```

脚本会自动：
1. 打包代码
2. 传输到服务器
3. 编译程序
4. 安装配置
5. 启动服务

### 方式二：在 Linux 服务器上手动部署

#### 步骤 1: 传输代码到 Linux 服务器

```bash
# 在 Windows 上打包
cd /d/code
tar czf docker-authz-proxy.tar.gz docker-authz-proxy/

# 传输到 Linux 服务器（使用你的方式，如 scp、sftp 等）
scp docker-authz-proxy.tar.gz root@<Linux服务器IP>:/tmp/
```

#### 步骤 2: 在 Linux 服务器上解压

```bash
# SSH 登录到 Linux 服务器
ssh root@<Linux服务器IP>

# 解压
cd /tmp
tar xzf docker-authz-proxy.tar.gz
cd docker-authz-proxy
```

#### 步骤 3: 运行快速部署脚本

```bash
# 一键部署和验证
sudo ./quick-deploy.sh
```

这个脚本会自动：
1. ✅ 编译程序
2. ✅ 停止旧服务
3. ✅ 安装新版本
4. ✅ 创建测试用户（alice、bob）
5. ✅ 启动服务
6. ✅ 验证 socket 创建
7. ✅ 测试用户访问

## 🔍 验证新功能

### 1. 检查 socket 文件

```bash
# 查看所有用户的 socket
ls -la /run/docker-authz/

# 应该看到：
# srw------- 1 root  root  0 Apr  2 20:00 root.sock
# srw------- 1 alice alice 0 Apr  2 21:00 alice.sock
# srw------- 1 bob   bob   0 Apr  2 21:00 bob.sock
```

### 2. 测试新用户自动创建

```bash
# 创建新用户
sudo useradd -m -s /bin/bash testuser

# 等待 10 秒（程序自动扫描）
sleep 10

# 验证 socket 已创建
ls -la /run/docker-authz/testuser.sock

# 应该看到：
# srw------- 1 testuser testuser 0 Apr  2 21:01 testuser.sock
```

### 3. 查看自动创建日志

```bash
# 实时监控新用户 socket 创建
sudo journalctl -u docker-authz -f | grep "created socket for new user"

# 或查看最近的日志
sudo journalctl -u docker-authz -n 50 | grep "created socket"
```

### 4. 测试用户访问

```bash
# 测试 alice 用户
sudo -u alice bash -c 'export DOCKER_HOST=unix:///run/docker-authz/alice.sock && docker ps'

# 测试 bob 用户
sudo -u bob bash -c 'export DOCKER_HOST=unix:///run/docker-authz/bob.sock && docker ps'
```

## 📊 日志示例

### 新用户 socket 创建成功

```json
{"time":"2024-04-02T21:00:00Z","level":"INFO","event":"created socket for new user","username":"alice","uid":1001}
{"time":"2024-04-02T21:00:00Z","level":"INFO","event":"created socket for new user","username":"bob","uid":1002}
```

### 配置自动重载成功

```json
{"time":"2024-04-02T21:00:10Z","level":"INFO","event":"configuration file changed, reloading","policy_file":"/etc/docker-authz/policy.yaml"}
{"time":"2024-04-02T21:00:10Z","level":"INFO","event":"policy configuration reloaded successfully","policy_file":"/etc/docker-authz/policy.yaml"}
```

## 🛠️ 故障排查

### 问题 1: 新用户 socket 没有自动创建

**诊断**：
```bash
sudo ./diagnose.sh
```

**检查**：
1. 服务是否正在运行
2. 用户是否有有效的 shell（不是 nologin）
3. 查看日志是否有错误

**解决**：
```bash
# 如果用户 shell 是 nologin，修改为 bash
sudo usermod -s /bin/bash alice

# 重启服务
sudo systemctl restart docker-authz
```

### 问题 2: 环境变量没有生效

**检查**：
```bash
# 查看用户 ~/.bashrc 是否已配置
grep "docker-authz" /home/alice/.bashrc

# 如果未配置，说明安装时该用户不存在（新用户）
# 程序会在创建 socket 时自动写入 ~/.bashrc，等待 10 秒后检查
grep "docker-authz" /home/alice/.bashrc

# 或立即手动设置
source /home/alice/.bashrc
echo $DOCKER_HOST

# 系统级配置文件（新用户登录时生效）
cat /etc/profile.d/docker-authz.sh
```

### 问题 3: 策略不生效

**诊断**：
```bash
sudo ./diagnose.sh
```

查看输出，检查：
1. 配置文件格式是否正确
2. 用户名是否存在
3. 策略是否正确加载

## 📝 用户使用方法

### 新用户首次使用

```bash
# 1. 管理员创建用户
sudo useradd -m -s /bin/bash alice

# 2. 等待 10 秒（程序自动扫描：创建 socket + 写入 ~/.bashrc）
sleep 10

# 3. 验证 socket 和环境变量配置
ls -la /run/docker-authz/alice.sock
grep "DOCKER_HOST" /home/alice/.bashrc

# 4. 用户登录（或 source ~/.bashrc 立即生效）
su - alice

# 5. 验证环境变量
echo $DOCKER_HOST
# 应该输出: unix:///run/docker-authz/alice.sock

# 6. 使用 Docker
docker ps
docker images
```

## 🎯 核心功能总结

### ✅ 自动功能
1. **配置自动重载** - 每 2 秒检查，编辑保存后自动生效
2. **新用户自动支持** - 每 10 秒扫描，自动创建 socket
3. **环境变量自动设置** - 用户登录后自动加载

### ✅ 无需手动操作
- ❌ 不需要手动重载配置
- ❌ 不需要手动创建 socket
- ❌ 不需要手动设置环境变量（重新登录即可）

## 📞 获取帮助

如遇问题，请提供以下信息：

```bash
# 1. 运行诊断工具
sudo ./diagnose.sh > diagnose-output.txt

# 2. 查看服务日志
sudo journalctl -u docker-authz -n 100 > service-logs.txt

# 3. 查看配置文件
cat /etc/docker-authz/policy.yaml > policy-config.txt
```

然后把这三个文件的内容发给我。

---

**部署时间**: < 5 分钟
**验证时间**: < 2 分钟
**总计**: < 10 分钟

🎉 **现在就开始部署吧！**
