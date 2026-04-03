#!/bin/bash
# 快速部署和验证脚本 - 解决新用户 socket 问题
# 在 Linux 服务器上运行此脚本

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[→]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

echo "========================================="
echo "Docker AuthZ Proxy - 快速部署和验证"
echo "解决新用户 socket 自动创建问题"
echo "========================================="
echo ""

# 1. 检查是否为 root
if [ "$EUID" -ne 0 ]; then
    log_error "请使用 root 权限运行: sudo $0"
    exit 1
fi

# 2. 编译程序
log_step "步骤 1/6: 编译程序"
if go build -o docker-authz-proxy . 2>/dev/null; then
    log_info "编译成功"
else
    log_error "编译失败，请检查 Go 环境"
    exit 1
fi
echo ""

# 3. 停止服务
log_step "步骤 2/6: 停止现有服务"
if systemctl is-active --quiet docker-authz 2>/dev/null; then
    systemctl stop docker-authz
    log_info "服务已停止"
else
    log_info "服务未运行"
fi
echo ""

# 4. 安装新版本
log_step "步骤 3/6: 安装新版本"
cp docker-authz-proxy /usr/local/bin/
chmod 755 /usr/local/bin/docker-authz-proxy
log_info "二进制文件已更新"
echo ""

# 5. 创建测试用户
log_step "步骤 4/6: 创建测试用户"
for user in alice bob; do
    if id "$user" &>/dev/null; then
        log_info "用户 $user 已存在"
    else
        useradd -m -s /bin/bash "$user"
        log_info "已创建用户 $user"
    fi
done
echo ""

# 6. 启动服务
log_step "步骤 5/6: 启动服务"
systemctl start docker-authz
sleep 2

if systemctl is-active --quiet docker-authz; then
    log_info "服务已启动"
else
    log_error "服务启动失败"
    journalctl -u docker-authz -n 20 --no-pager
    exit 1
fi
echo ""

# 7. 验证 socket 创建
log_step "步骤 6/6: 验证 socket 文件"
echo ""
echo "等待 12 秒让程序扫描用户并创建 socket..."
sleep 12

echo ""
echo "Socket 文件列表:"
ls -la /run/docker-authz/ || log_error "Socket 目录不存在"
echo ""

# 检查每个用户的 socket
for user in root alice bob; do
    if [ -S "/run/docker-authz/${user}.sock" ]; then
        log_info "${user}.sock 已创建"
    else
        log_warn "${user}.sock 未创建"
    fi
done
echo ""

# 8. 查看日志
log_step "查看最近的日志"
echo ""
journalctl -u docker-authz -n 30 --no-pager | grep -E "created socket|user socket created|watching" || log_warn "未找到相关日志"
echo ""

# 9. 测试用户访问
log_step "测试用户访问"
echo ""

for user in alice bob; do
    echo "测试 $user 用户:"
    if sudo -u "$user" DOCKER_HOST="unix:///run/docker-authz/${user}.sock" docker version --format '{{.Server.Version}}' 2>/dev/null; then
        log_info "$user 可以连接 Docker"
    else
        log_warn "$user 无法连接 Docker"
    fi
done
echo ""

# 10. 配置环境变量到用户 ~/.bashrc
log_step "配置用户 DOCKER_HOST 环境变量"
echo ""
for user in alice bob root; do
    homedir=$(getent passwd "$user" 2>/dev/null | cut -d: -f6)
    uid=$(id -u "$user" 2>/dev/null || echo "")
    gid=$(id -g "$user" 2>/dev/null || echo "")
    [ -z "$homedir" ] || [ -z "$uid" ] || [ ! -d "$homedir" ] && continue
    bashrc="${homedir}/.bashrc"
    marker="# docker-authz-proxy: DOCKER_HOST"
    export_line="export DOCKER_HOST=unix:///run/docker-authz/${user}.sock"
    if grep -q "$marker" "$bashrc" 2>/dev/null; then
        log_info "$user: ~/.bashrc 已配置"
    else
        printf '\n%s\n%s\n' "$marker" "$export_line" >> "$bashrc"
        chown "${uid}:${gid}" "$bashrc" 2>/dev/null || true
        log_info "$user: 已写入 ~/.bashrc"
    fi
done
echo ""

# 显示环境变量配置
log_step "环境变量配置文件"
echo ""
echo "配置文件: /etc/profile.d/docker-authz.sh"
cat /etc/profile.d/docker-authz.sh
echo ""

# 11. 总结
echo "========================================="
echo "部署完成！"
echo "========================================="
echo ""
log_info "新功能: 程序每 10 秒自动扫描新用户并创建 socket"
echo ""
echo "用户使用方法:"
echo "  1. 用户重新登录（加载环境变量）"
echo "  2. 或手动设置: export DOCKER_HOST=unix:///run/docker-authz/\$(whoami).sock"
echo "  3. 执行: docker ps"
echo ""
echo "查看实时日志:"
echo "  journalctl -u docker-authz -f"
echo ""
echo "验证新用户自动创建:"
echo "  1. 创建新用户: useradd -m -s /bin/bash testuser"
echo "  2. 等待 10 秒"
echo "  3. 检查: ls -la /run/docker-authz/testuser.sock"
echo ""
