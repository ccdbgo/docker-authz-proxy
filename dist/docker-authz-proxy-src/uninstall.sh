#!/bin/bash
# 卸载脚本 - 彻底卸载 docker-authz-proxy
# 在 Linux 服务器上运行

set -euo pipefail

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否为 root
if [ "$EUID" -ne 0 ]; then
    log_error "请使用 root 权限运行此脚本: sudo $0"
    exit 1
fi

# 配置变量
INSTALL_BIN="/usr/local/bin/docker-authz-proxy"
CONFIG_DIR="/etc/docker-authz"
DATA_DIR="/var/lib/docker-authz"
LOG_DIR="/var/log/docker-authz"
SOCKET_DIR="/run/docker-authz"
SERVICE_FILE="/etc/systemd/system/docker-authz.service"
ENV_FILE="/etc/profile.d/docker-authz.sh"

echo "========================================="
echo "Docker Authorization Proxy 卸载程序"
echo "========================================="
echo ""

# 显示将要删除的内容
log_warn "将要删除以下内容："
echo ""
echo "  服务:"
echo "    - $SERVICE_FILE"
echo ""
echo "  二进制文件:"
echo "    - $INSTALL_BIN"
echo ""
echo "  配置文件:"
echo "    - $CONFIG_DIR/"
echo ""
echo "  数据文件:"
echo "    - $DATA_DIR/ (包含容器/镜像归属数据库)"
echo ""
echo "  日志文件:"
echo "    - $LOG_DIR/"
echo ""
echo "  运行时文件:"
echo "    - $SOCKET_DIR/ (用户 socket 文件)"
echo ""
echo "  环境变量配置:"
echo "    - $ENV_FILE"
echo ""

# 询问确认
read -p "确认卸载？此操作不可恢复！(yes/no) " -r
echo
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    log_info "已取消卸载"
    exit 0
fi

# 步骤 1: 停止服务
log_info "步骤 1/8: 停止服务..."
if systemctl is-active --quiet docker-authz 2>/dev/null; then
    systemctl stop docker-authz
    log_info "服务已停止"
else
    log_info "服务未运行"
fi

# 步骤 2: 禁用服务
log_info "步骤 2/8: 禁用服务..."
if systemctl is-enabled --quiet docker-authz 2>/dev/null; then
    systemctl disable docker-authz
    log_info "服务已禁用"
else
    log_info "服务未启用"
fi

# 步骤 3: 删除 systemd 服务文件
log_info "步骤 3/8: 删除 systemd 服务文件..."
if [ -f "$SERVICE_FILE" ]; then
    rm -f "$SERVICE_FILE"
    log_info "已删除: $SERVICE_FILE"
else
    log_info "文件不存在: $SERVICE_FILE"
fi

# 步骤 4: 删除二进制文件
log_info "步骤 4/8: 删除二进制文件..."
if [ -f "$INSTALL_BIN" ]; then
    rm -f "$INSTALL_BIN"
    log_info "已删除: $INSTALL_BIN"
else
    log_info "文件不存在: $INSTALL_BIN"
fi

# 步骤 5: 删除配置文件
log_info "步骤 5/8: 删除配置文件..."
if [ -d "$CONFIG_DIR" ]; then
    rm -rf "$CONFIG_DIR"
    log_info "已删除: $CONFIG_DIR"
else
    log_info "目录不存在: $CONFIG_DIR"
fi

# 步骤 6: 删除数据文件（询问确认）
log_info "步骤 6/8: 删除数据文件..."
if [ -d "$DATA_DIR" ]; then
    echo ""
    log_warn "数据目录包含容器和镜像的归属信息数据库"
    read -p "确认删除数据目录？(yes/no) " -r
    echo
    if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        rm -rf "$DATA_DIR"
        log_info "已删除: $DATA_DIR"
    else
        log_warn "保留数据目录: $DATA_DIR"
    fi
else
    log_info "目录不存在: $DATA_DIR"
fi

# 步骤 7: 删除日志文件
log_info "步骤 7/8: 删除日志文件..."
if [ -d "$LOG_DIR" ]; then
    rm -rf "$LOG_DIR"
    log_info "已删除: $LOG_DIR"
else
    log_info "目录不存在: $LOG_DIR"
fi

# 步骤 8: 删除运行时文件
log_info "步骤 8/8: 删除运行时文件..."
if [ -d "$SOCKET_DIR" ]; then
    rm -rf "$SOCKET_DIR"
    log_info "已删除: $SOCKET_DIR"
else
    log_info "目录不存在: $SOCKET_DIR"
fi

# 步骤 9: 删除环境变量配置
log_info "删除环境变量配置..."
if [ -f "$ENV_FILE" ]; then
    rm -f "$ENV_FILE"
    log_info "已删除: $ENV_FILE"
else
    log_info "文件不存在: $ENV_FILE"
fi

# 步骤 10: 清理用户 ~/.bashrc 中的 DOCKER_HOST 设置
log_info "清理用户 ~/.bashrc 中的 DOCKER_HOST 配置..."
marker="# docker-authz-proxy: DOCKER_HOST"
while IFS=: read -r username _ uid gid _ homedir shell; do
    case "$shell" in
        *nologin|*false|"") continue ;;
    esac
    bashrc="${homedir}/.bashrc"
    if [ -f "$bashrc" ] && grep -q "$marker" "$bashrc" 2>/dev/null; then
        # 删除 marker 行和紧随其后的 export 行
        sed -i "/^${marker}$/,/^export DOCKER_HOST=/d" "$bashrc"
        # 清理可能留下的空行
        sed -i '/^$/N;/^\n$/d' "$bashrc" 2>/dev/null || true
        log_info "  已清理 $username 的 ~/.bashrc"
    fi
done < /etc/passwd

# 步骤 11: 重载 systemd
log_info "重载 systemd..."
systemctl daemon-reload
log_info "systemd 已重载"

echo ""
log_info "========================================="
log_info "卸载完成！"
log_info "========================================="
echo ""
log_info "docker-authz-proxy 已彻底卸载"
echo ""
log_warn "注意事项："
echo "  1. 用户 ~/.bashrc 中的 DOCKER_HOST 配置已自动清理"
echo "  2. 用户需要重新登录或执行 unset DOCKER_HOST 使清理生效"
echo "  3. 如果保留了数据目录，可以在重新安装时恢复归属信息"
echo "  4. 用户现在可以直接访问 /var/run/docker.sock（如果有权限）"
echo ""
