# Docker Authorization Proxy - 文件清单

## 📦 项目结构

```
docker-authz-proxy/
├── README.md                    # 完整项目文档
├── QUICKSTART.md                # 快速使用指南
├── go.mod                       # Go 模块依赖
├── go.sum                       # Go 依赖校验
│
├── 源代码文件
├── main.go                      # 主程序入口
├── proxy.go                     # 代理服务器核心逻辑
├── policy.go                    # 策略加载和检查
├── identity.go                  # 用户身份解析
├── ownership.go                 # 资源归属管理
├── filter.go                    # 响应过滤
├── labels.go                    # 系统标签注入
├── logger.go                    # 日志配置
│
├── 配置文件
├── config/
│   └── policy.yaml              # 策略配置示例
│
├── 部署文件
├── deploy/
│   ├── docker-authz.service     # systemd 服务配置
│   ├── install.sh               # 安装脚本（仅安装）
│   └── migrate.sh               # 数据迁移脚本
│
├── 部署脚本
├── deploy-from-windows.sh       # Windows 端自动部署
├── deploy-to-linux.sh           # Linux 端编译+部署
│
├── 测试脚本
├── test-on-linux.sh             # 完整功能测试
├── test-reload.sh               # 配置重载测试
│
├── 调试工具
├── diagnose.sh                  # 策略诊断工具
├── debug-policy.sh              # 策略调试脚本
│
└── 卸载脚本
    └── uninstall.sh             # 一键卸载

```

## 🚀 使用流程

### 1. 部署（三种方式）

#### 方式一：从 Windows 自动部署（推荐）
```bash
./deploy-from-windows.sh -h <Linux服务器IP> -u root
```

#### 方式二：在 Linux 上编译并部署
```bash
sudo ./deploy-to-linux.sh
```

#### 方式三：安装已编译的二进制文件
```bash
sudo ./deploy/install.sh
```

### 2. 测试

```bash
# 完整功能测试
sudo ./test-on-linux.sh

# 配置重载测试
sudo ./test-reload.sh

# 策略诊断
sudo ./diagnose.sh
```

### 3. 配置

```bash
# 编辑配置文件
sudo vi /etc/docker-authz/policy.yaml

# 保存后自动生效（2秒内）
# 无需手动重载！
```

### 4. 卸载

```bash
sudo ./uninstall.sh
```

## 📝 核心功能

### ✅ 自动配置重载
- 使用 Go 标准库（无外部依赖）
- 每 2 秒检查文件修改时间
- 检测到变化后自动重新加载
- 配置错误时保持旧配置

### ✅ 用户隔离
- 每用户专属 Unix socket
- 完全可见性隔离
- 资源归属检查
- 响应过滤

### ✅ 策略控制
- 白名单模式
- 用户/组级别控制
- 操作级别控制
- 所有用户受限（含 root）

## 🔧 维护命令

```bash
# 启动服务
sudo systemctl start docker-authz

# 停止服务
sudo systemctl stop docker-authz

# 重启服务
sudo systemctl restart docker-authz

# 查看状态
sudo systemctl status docker-authz

# 查看日志
sudo journalctl -u docker-authz -f

# 手动重载配置（可选）
sudo systemctl reload docker-authz
```

## 📊 文件说明

### 部署脚本

| 文件 | 用途 | 运行环境 |
|------|------|----------|
| `deploy-from-windows.sh` | Windows 端自动部署 | Windows Git Bash |
| `deploy-to-linux.sh` | 编译+安装+配置 | Linux |
| `deploy/install.sh` | 仅安装（需已编译） | Linux |

### 测试脚本

| 文件 | 用途 | 说明 |
|------|------|------|
| `test-on-linux.sh` | 完整功能测试 | 测试所有隔离功能 |
| `test-reload.sh` | 配置重载测试 | 测试自动重载功能 |
| `diagnose.sh` | 策略诊断工具 | 诊断策略不生效问题 |
| `debug-policy.sh` | 策略调试脚本 | 查看策略加载详情 |

### 配置文件

| 文件 | 位置 | 说明 |
|------|------|------|
| `policy.yaml` | `/etc/docker-authz/` | 策略配置 |
| `docker-authz.service` | `/etc/systemd/system/` | systemd 服务 |
| `owners.db` | `/var/lib/docker-authz/` | 归属数据库 |
| `authz.log` | `/var/log/docker-authz/` | 日志文件 |

## 🎯 版本信息

- Go 版本要求: 1.21+
- 依赖: 仅使用 Go 标准库 + zap 日志库
- 系统要求: Linux (内核 3.2+)
- Docker 版本: 任意版本

## 📚 文档

- `README.md` - 完整项目文档（架构、配置、故障排查）
- `QUICKSTART.md` - 快速使用指南（部署、测试、配置）

## 🔄 更新日志

### 最新版本
- ✅ 使用 Go 标准库实现配置自动重载
- ✅ 移除 fsnotify 外部依赖
- ✅ 添加详细的策略调试工具
- ✅ 完善的测试和诊断脚本
- ✅ 统一的部署和卸载流程
