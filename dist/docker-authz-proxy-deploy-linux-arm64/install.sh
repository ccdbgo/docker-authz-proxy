#!/bin/bash
# docker-authz-proxy 一键安装脚本 (arm64)
# 用法：sudo bash install.sh [--upgrade] [--uninstall]

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "\n${BLUE}══ Step $1${NC}"; }
log_ok()    { echo -e "  ${GREEN}✓${NC} $1"; }

UPGRADE=false
UNINSTALL=false
for arg in "$@"; do
    case "$arg" in
        --upgrade)   UPGRADE=true ;;
        --uninstall) UNINSTALL=true ;;
        --help|-h)   echo "用法: sudo bash install.sh [--upgrade] [--uninstall]"; exit 0 ;;
        *) echo "未知参数: $arg"; exit 1 ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    log_error "请用 root 权限运行: sudo bash install.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BIN_PROXY="/usr/local/bin/docker-authz-proxy"
BIN_CTL="/usr/local/bin/docker-authz-proxy-ctl"
CONFIG_DIR="/etc/docker-authz"
DATA_DIR="/var/lib/docker-authz"
LOG_DIR="/var/log/docker-authz"
SOCKET_DIR="/run/docker-authz"
SERVICE_FILE="/etc/systemd/system/docker-authz.service"

if [ "$UNINSTALL" = true ]; then
    systemctl stop docker-authz 2>/dev/null || true
    systemctl disable docker-authz 2>/dev/null || true
    rm -f /etc/systemd/system/docker-authz.service
    systemctl daemon-reload
    rm -f "$BIN_PROXY" "$BIN_CTL"
    rm -f /etc/profile.d/docker-authz.sh /etc/sudoers.d/docker-authz-env
    echo "卸载完成"
    exit 0
fi

log_step "1/5  停止现有服务"
if systemctl is-active --quiet docker-authz 2>/dev/null; then
    systemctl stop docker-authz
    log_ok "已停止"
else
    log_ok "无运行中的服务"
fi

log_step "2/5  创建目录"
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$SOCKET_DIR"
chmod 750 "$DATA_DIR" "$LOG_DIR"
chmod 755 "$SOCKET_DIR"
log_ok "目录已创建"

log_step "3/5  安装二进制文件"
install -m 755 "${SCRIPT_DIR}/bin/docker-authz-proxy" "$BIN_PROXY"
install -m 755 "${SCRIPT_DIR}/bin/docker-authz-proxy-ctl" "$BIN_CTL"
log_ok "$BIN_PROXY"
log_ok "$BIN_CTL"

log_step "4/5  安装配置文件"
install_config() {
    local src="$1" dst="$2"
    if [ ! -f "$dst" ] || [ "$UPGRADE" = true ]; then
        [ -f "$dst" ] && cp "$dst" "${dst}.bak.$(date +%Y%m%d%H%M%S)"
        install -m 640 "$src" "$dst"
        log_ok "已安装: $dst"
    else
        log_warn "$(basename $dst) 已存在，跳过（--upgrade 覆盖）"
    fi
}
[ -f "${SCRIPT_DIR}/config/policy.yaml" ] && install_config "${SCRIPT_DIR}/config/policy.yaml" "$CONFIG_DIR/policy.yaml"
[ -f "${SCRIPT_DIR}/config/quota.yaml" ] && install_config "${SCRIPT_DIR}/config/quota.yaml" "$CONFIG_DIR/quota.yaml"
[ -f "${SCRIPT_DIR}/config/network_policy.yaml" ] && install_config "${SCRIPT_DIR}/config/network_policy.yaml" "$CONFIG_DIR/network_policy.yaml"

log_step "5/5  安装 systemd 服务并启动"
install -m 644 "${SCRIPT_DIR}/deploy/docker-authz.service" "$SERVICE_FILE"
[ -f "${SCRIPT_DIR}/deploy/logrotate.conf" ] && install -m 644 "${SCRIPT_DIR}/deploy/logrotate.conf" /etc/logrotate.d/docker-authz
systemctl daemon-reload
systemctl enable docker-authz
systemctl start docker-authz
sleep 2
if systemctl is-active --quiet docker-authz; then
    log_ok "服务已启动 (active)"
else
    log_error "服务启动失败，请查看: journalctl -u docker-authz -n 50 --no-pager"
    exit 1
fi

# 配置 sudo 保留 DOCKER_HOST
SUDOERS_ENV_FILE="/etc/sudoers.d/docker-authz-env"
if [ ! -f "$SUDOERS_ENV_FILE" ]; then
    echo 'Defaults env_keep += "DOCKER_HOST"' > "$SUDOERS_ENV_FILE"
    chmod 440 "$SUDOERS_ENV_FILE"
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  部署完成！docker-authz-proxy 已启动运行      ${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo ""
echo "  服务状态:  systemctl status docker-authz"
echo "  实时日志:  journalctl -u docker-authz -f"
echo ""
