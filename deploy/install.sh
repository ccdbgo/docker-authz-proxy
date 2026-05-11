#!/bin/bash
# docker-authz-proxy 安装脚本
# 用途：安装已编译好的二进制文件（不包含编译步骤）
# 如需编译+安装，请使用 deploy-to-linux.sh

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

# 检查是否在 Linux 环境
if [ "$(uname -s)" != "Linux" ]; then
    log_error "此脚本只能在 Linux 环境下运行"
    exit 1
fi

# 配置变量
INSTALL_BIN="/usr/local/bin/docker-authz-proxy"
CONFIG_DIR="/etc/docker-authz"
DATA_DIR="/var/lib/docker-authz"
LOG_DIR="/var/log/docker-authz"
SOCKET_DIR="/run/docker-authz"
SERVICE_FILE="/etc/systemd/system/docker-authz.service"
LOGROTATE_FILE="/etc/logrotate.d/docker-authz"

# 检查二进制文件是否存在
if [ ! -f "docker-authz-proxy" ]; then
    log_error "未找到二进制文件 docker-authz-proxy"
    log_error "请先编译程序: go build -o docker-authz-proxy ."
    log_error "或使用 deploy-to-linux.sh 脚本（包含编译步骤）"
    exit 1
fi

log_info "开始安装 docker-authz-proxy..."
echo ""

# 步骤 1: 停止现有服务（如果存在）
if systemctl is-active --quiet docker-authz 2>/dev/null; then
    log_info "步骤 1/5: 停止现有服务..."
    systemctl stop docker-authz
else
    log_info "步骤 1/5: 无现有服务运行"
fi

# 步骤 2: 创建目录
log_info "步骤 2/5: 创建目录..."
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$SOCKET_DIR"
chmod 750 "$DATA_DIR" "$LOG_DIR"
chmod 755 "$SOCKET_DIR"

# 步骤 3: 安装二进制文件
log_info "步骤 3/5: 安装二进制文件..."
cp docker-authz-proxy "$INSTALL_BIN"
chmod 755 "$INSTALL_BIN"
log_info "已安装: $INSTALL_BIN"

# 步骤 4: 安装配置文件
log_info "步骤 4/5: 安装配置文件..."
if [ ! -f "$CONFIG_DIR/policy.yaml" ]; then
    if [ -f "config/policy.yaml" ]; then
        cp config/policy.yaml "$CONFIG_DIR/policy.yaml"
        log_info "已安装默认 policy.yaml"
    else
        log_error "未找到 config/policy.yaml"
        exit 1
    fi
else
    log_warn "policy.yaml 已存在，跳过（避免覆盖）"
    log_warn "如需更新配置，请手动编辑: $CONFIG_DIR/policy.yaml"
fi

# 步骤 5: 安装 systemd service 和 logrotate
log_info "步骤 5/6: 安装并启动 systemd 服务..."
if [ -f "deploy/docker-authz.service" ]; then
    cp deploy/docker-authz.service "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable docker-authz
    systemctl start docker-authz
    log_info "已安装、启用并启动服务"
else
    log_error "未找到 deploy/docker-authz.service"
    exit 1
fi

# 步骤 6: 安装 logrotate 配置
log_info "步骤 6/6: 安装 logrotate 配置..."
if [ -f "deploy/logrotate.conf" ]; then
    cp deploy/logrotate.conf "$LOGROTATE_FILE"
    chmod 644 "$LOGROTATE_FILE"
    log_info "已安装: $LOGROTATE_FILE"
else
    log_warn "未找到 deploy/logrotate.conf，跳过 logrotate 配置"
fi

# 配置用户环境变量
log_info "配置用户环境变量..."

# 系统级：新用户登录时自动生效
cat > /etc/profile.d/docker-authz.sh << 'EOF'
# docker-authz-proxy: 每个用户通过自己的 socket 访问 Docker
if [ -S "/run/docker-authz/$(whoami)/docker.sock" ]; then
    export DOCKER_HOST="unix:///run/docker-authz/$(whoami)/docker.sock"
fi
EOF
chmod 644 /etc/profile.d/docker-authz.sh

# 为当前所有有效用户写入 ~/.bashrc（立即生效，无需重新登录）
setup_user_docker_host() {
    local username="$1"
    local uid="$2"
    local gid="$3"
    local homedir="$4"
    local bashrc="${homedir}/.bashrc"
    local marker="# docker-authz-proxy: DOCKER_HOST"
    local export_line="export DOCKER_HOST=unix:///run/docker-authz/${username}/docker.sock"

    [ -z "$homedir" ] && return
    [ ! -d "$homedir" ] && return

    # 检查是否已设置
    if grep -q "$marker" "$bashrc" 2>/dev/null; then
        log_info "  $username: ~/.bashrc 已配置，跳过"
        return
    fi

    printf '\n%s\n%s\n' "$marker" "$export_line" >> "$bashrc"
    chown "${uid}:${gid}" "$bashrc" 2>/dev/null || true
    log_info "  $username: 已写入 ~/.bashrc → $export_line"
}

log_info "为系统用户配置 DOCKER_HOST..."
while IFS=: read -r username _ uid gid _ homedir shell; do
    # 跳过无效 shell 的系统账户
    case "$shell" in
        *nologin|*false|"") continue ;;
    esac
    setup_user_docker_host "$username" "$uid" "$gid" "$homedir"
done < /etc/passwd

# 配置 sudo 保留 DOCKER_HOST 环境变量（使 sudo docker 通过代理）
SUDOERS_ENV_FILE="/etc/sudoers.d/docker-authz-env"
if [ ! -f "$SUDOERS_ENV_FILE" ]; then
    echo 'Defaults env_keep += "DOCKER_HOST"' > "$SUDOERS_ENV_FILE"
    chmod 440 "$SUDOERS_ENV_FILE"
    log_info "已配置 sudo 保留 DOCKER_HOST（$SUDOERS_ENV_FILE）"
else
    log_info "sudo DOCKER_HOST 配置已存在，跳过"
fi

echo ""
log_info "========================================="
log_info "安装完成！服务已自动启动"
log_info "========================================="
echo ""
echo "查看状态："
echo "  systemctl status docker-authz"
echo ""
echo "查看日志："
echo "  journalctl -u docker-authz -f"
echo "  tail -f /var/log/docker-authz/authz.log | jq ."
echo ""
echo "配置文件："
echo "  策略配置: $CONFIG_DIR/policy.yaml"
echo "  服务配置: $SERVICE_FILE"
echo ""
echo "用户使用方式（需重新登录以加载环境变量）："
echo "  docker ps        # 只显示自己的容器"
echo "  docker images    # 只显示自己的镜像和公共镜像"
echo ""
