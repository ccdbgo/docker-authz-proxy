#!/bin/bash
# build-release.sh - 构建 Linux 发布包
# 在 Windows (Git Bash / WSL) 或 Linux 开发机上运行
# 输出：docker-authz-proxy-deploy-linux-amd64.tar.gz

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "\n${BLUE}══ $1${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VERSION="${VERSION:-v1.0}"
DIST_DIR="dist"
PKG_NAME="docker-authz-proxy-deploy-linux-amd64"
PKG_DIR="${DIST_DIR}/${PKG_NAME}"
OUTPUT_TAR="${DIST_DIR}/${PKG_NAME}.tar.gz"

# ── 检查依赖 ────────────────────────────────────────────────────────────────
log_step "检查编译环境"
if ! command -v go &>/dev/null; then
    log_error "未找到 Go 编译器，请先安装 Go 1.21+"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}')
log_info "Go 版本: $GO_VERSION"
log_info "目标平台: linux/amd64"

# ── 清理并创建目录 ──────────────────────────────────────────────────────────
log_step "准备输出目录"
rm -rf "$PKG_DIR"
mkdir -p "${PKG_DIR}/bin" "${PKG_DIR}/config" "${PKG_DIR}/deploy"
log_info "输出目录: $PKG_DIR"

# ── 交叉编译 ────────────────────────────────────────────────────────────────
log_step "交叉编译 (linux/amd64, CGO_ENABLED=0)"

BUILD_FLAGS="-trimpath -ldflags=-s -ldflags=-w"

log_info "编译 docker-authz-proxy ..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o "${PKG_DIR}/bin/docker-authz-proxy" . && \
    log_info "  -> ${PKG_DIR}/bin/docker-authz-proxy"

log_info "编译 docker-authz-proxy-ctl ..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o "${PKG_DIR}/bin/docker-authz-proxy-ctl" ./cmd/ctl/ && \
    log_info "  -> ${PKG_DIR}/bin/docker-authz-proxy-ctl"

# 显示文件大小
PROXY_SIZE=$(du -sh "${PKG_DIR}/bin/docker-authz-proxy" | cut -f1)
CTL_SIZE=$(du -sh "${PKG_DIR}/bin/docker-authz-proxy-ctl" | cut -f1)
log_info "二进制大小: proxy=${PROXY_SIZE}, ctl=${CTL_SIZE}"

# ── 复制配置文件 ────────────────────────────────────────────────────────────
log_step "打包配置文件"
cp config/policy.yaml    "${PKG_DIR}/config/"
cp config/quota.yaml     "${PKG_DIR}/config/"
[ -f config/network_policy.yaml ] && cp config/network_policy.yaml "${PKG_DIR}/config/" || true
cp deploy/docker-authz.service "${PKG_DIR}/deploy/"
[ -f deploy/logrotate.conf ] && cp deploy/logrotate.conf "${PKG_DIR}/deploy/" || true
log_info "配置文件已复制"

# ── 生成 install.sh ─────────────────────────────────────────────────────────
log_step "生成一键安装脚本"
cat > "${PKG_DIR}/install.sh" << 'INSTALL_SCRIPT'
#!/bin/bash
# docker-authz-proxy 一键安装脚本
# 用法：sudo bash install.sh [--upgrade] [--uninstall]
# 直接解压目录后运行即可，无需 Go 环境
#
# 功能：
#   - 安装 docker-authz-proxy 和 docker-authz-proxy-ctl 到 /usr/local/bin
#   - 安装 systemd 服务并启动
#   - 安装配置文件（已有则跳过，--upgrade 强制覆盖）
#   - 配置所有用户的 DOCKER_HOST 环境变量
#   --upgrade   : 升级模式（覆盖已有配置）
#   --uninstall : 卸载

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
        --help|-h)
            echo "用法: sudo bash install.sh [--upgrade] [--uninstall]"
            exit 0 ;;
        *) echo "未知参数: $arg"; exit 1 ;;
    esac
done

# ── 卸载模式 ────────────────────────────────────────────────────────────────
if [ "$UNINSTALL" = true ]; then
    echo -e "${RED}[UNINSTALL]${NC} 开始卸载 docker-authz-proxy ..."
    systemctl stop docker-authz 2>/dev/null || true
    systemctl disable docker-authz 2>/dev/null || true
    rm -f /etc/systemd/system/docker-authz.service
    systemctl daemon-reload
    rm -f /usr/local/bin/docker-authz-proxy
    rm -f /usr/local/bin/docker-authz-proxy-ctl
    rm -f /etc/profile.d/docker-authz.sh
    rm -f /etc/logrotate.d/docker-authz
    echo ""
    echo -e "${YELLOW}[NOTE]${NC} 以下目录包含数据，已保留（如需彻底清除请手动删除）："
    echo "  /etc/docker-authz/      (配置文件)"
    echo "  /var/lib/docker-authz/  (归属数据库)"
    echo "  /var/log/docker-authz/  (日志)"
    echo "  /run/docker-authz/      (运行时 socket)"
    echo ""
    echo -e "${GREEN}卸载完成${NC}"
    exit 0
fi

# ── 前置检查 ────────────────────────────────────────────────────────────────
log_step "0/6  前置检查"

if [ "$EUID" -ne 0 ]; then
    log_error "请用 root 权限运行: sudo bash install.sh"
    exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
    log_error "仅支持 Linux 系统"
    exit 1
fi

ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ]; then
    log_error "当前仅提供 x86_64 架构二进制，当前架构: $ARCH"
    exit 1
fi

if ! command -v systemctl &>/dev/null; then
    log_error "未找到 systemctl，仅支持 systemd 系统"
    exit 1
fi

if ! command -v docker &>/dev/null; then
    log_warn "未检测到 docker 命令，请确保 Docker 已安装"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 检查二进制文件
for bin in docker-authz-proxy docker-authz-proxy-ctl; do
    if [ ! -f "${SCRIPT_DIR}/bin/${bin}" ]; then
        log_error "缺少文件: bin/${bin}"
        log_error "请确保完整解压部署包"
        exit 1
    fi
done

log_ok "环境检查通过 (Linux x86_64, systemd)"

# ── 路径变量 ────────────────────────────────────────────────────────────────
BIN_PROXY="/usr/local/bin/docker-authz-proxy"
BIN_CTL="/usr/local/bin/docker-authz-proxy-ctl"
CONFIG_DIR="/etc/docker-authz"
DATA_DIR="/var/lib/docker-authz"
LOG_DIR="/var/log/docker-authz"
SOCKET_DIR="/run/docker-authz"
SERVICE_FILE="/etc/systemd/system/docker-authz.service"
LOGROTATE_FILE="/etc/logrotate.d/docker-authz"

# ── Step 1: 停止现有服务 ────────────────────────────────────────────────────
log_step "1/6  停止现有服务（如存在）"
if systemctl is-active --quiet docker-authz 2>/dev/null; then
    systemctl stop docker-authz
    log_ok "已停止 docker-authz 服务"
else
    log_ok "无运行中的服务"
fi

# ── Step 2: 创建目录 ─────────────────────────────────────────────────────────
log_step "2/6  创建目录"
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$SOCKET_DIR"
chmod 750 "$DATA_DIR" "$LOG_DIR"
chmod 755 "$SOCKET_DIR"
log_ok "目录已创建"

# ── Step 3: 安装二进制文件 ──────────────────────────────────────────────────
log_step "3/6  安装二进制文件"
install -m 755 "${SCRIPT_DIR}/bin/docker-authz-proxy" "$BIN_PROXY"
install -m 755 "${SCRIPT_DIR}/bin/docker-authz-proxy-ctl" "$BIN_CTL"
log_ok "$BIN_PROXY"
log_ok "$BIN_CTL"

PROXY_VER=$("$BIN_PROXY" --version 2>/dev/null || echo "unknown")
log_ok "版本: $PROXY_VER"

# ── Step 4: 安装配置文件 ────────────────────────────────────────────────────
log_step "4/6  安装配置文件"

install_config() {
    local src="$1"
    local dst="$2"
    local name="$(basename "$dst")"
    if [ ! -f "$dst" ] || [ "$UPGRADE" = true ]; then
        if [ -f "$dst" ] && [ "$UPGRADE" = true ]; then
            cp "$dst" "${dst}.bak.$(date +%Y%m%d%H%M%S)"
            log_warn "$name 已存在，已备份原文件"
        fi
        install -m 640 "$src" "$dst"
        log_ok "已安装: $dst"
    else
        log_warn "$name 已存在，跳过（使用 --upgrade 覆盖）"
    fi
}

[ -f "${SCRIPT_DIR}/config/policy.yaml" ] && \
    install_config "${SCRIPT_DIR}/config/policy.yaml" "$CONFIG_DIR/policy.yaml"
[ -f "${SCRIPT_DIR}/config/quota.yaml" ] && \
    install_config "${SCRIPT_DIR}/config/quota.yaml" "$CONFIG_DIR/quota.yaml"
[ -f "${SCRIPT_DIR}/config/network_policy.yaml" ] && \
    install_config "${SCRIPT_DIR}/config/network_policy.yaml" "$CONFIG_DIR/network_policy.yaml"

# ── Step 5: 安装 systemd 服务 ───────────────────────────────────────────────
log_step "5/6  安装 systemd 服务"
install -m 644 "${SCRIPT_DIR}/deploy/docker-authz.service" "$SERVICE_FILE"

# 安装 logrotate（可选）
if [ -f "${SCRIPT_DIR}/deploy/logrotate.conf" ]; then
    install -m 644 "${SCRIPT_DIR}/deploy/logrotate.conf" "$LOGROTATE_FILE"
    log_ok "logrotate 配置已安装"
fi

systemctl daemon-reload
systemctl enable docker-authz
systemctl start docker-authz

# 等待服务就绪
sleep 2
if systemctl is-active --quiet docker-authz; then
    log_ok "服务已启动: docker-authz (active)"
else
    log_error "服务启动失败，请查看日志："
    echo "  journalctl -u docker-authz -n 50 --no-pager"
    exit 1
fi

# ── Step 6: 配置用户环境变量 ────────────────────────────────────────────────
log_step "6/6  配置用户 DOCKER_HOST 环境变量"

# 系统级 profile.d：新用户登录自动生效
cat > /etc/profile.d/docker-authz.sh << 'PROFILE_EOF'
# docker-authz-proxy: 每个用户通过自己的 socket 访问 Docker
if [ -S "/run/docker-authz/$(whoami)/docker.sock" ]; then
    export DOCKER_HOST="unix:///run/docker-authz/$(whoami)/docker.sock"
fi
PROFILE_EOF
chmod 644 /etc/profile.d/docker-authz.sh
log_ok "已写入 /etc/profile.d/docker-authz.sh"

# 为已有用户写入 ~/.bashrc（立即生效，无需重新登录）
CONFIGURED=0
while IFS=: read -r uname _ uid gid _ homedir shell; do
    case "$shell" in
        *nologin|*false|"") continue ;;
    esac
    [ -z "$homedir" ] || [ ! -d "$homedir" ] && continue
    local_uid=$(id -u "$uname" 2>/dev/null || echo "")
    [ -z "$local_uid" ] && continue

    bashrc="${homedir}/.bashrc"
    marker="# docker-authz-proxy: DOCKER_HOST"
    export_line="export DOCKER_HOST=unix:///run/docker-authz/${uname}/docker.sock"

    if grep -q "$marker" "$bashrc" 2>/dev/null; then
        continue
    fi
    printf '\n%s\n%s\n' "$marker" "$export_line" >> "$bashrc"
    chown "${uid}:${gid}" "$bashrc" 2>/dev/null || true
    log_ok "  $uname: ~/.bashrc 已配置"
    CONFIGURED=$((CONFIGURED + 1))
done < /etc/passwd
[ "$CONFIGURED" -eq 0 ] && log_ok "所有用户已配置（或无需配置）"

# ── 完成 ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  部署完成！docker-authz-proxy 已启动运行      ${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo ""
echo "  服务状态:  systemctl status docker-authz"
echo "  实时日志:  journalctl -u docker-authz -f"
echo "  审计日志:  tail -f /var/log/docker-authz/authz.log | jq ."
echo ""
echo "  配置文件:  $CONFIG_DIR/policy.yaml"
echo "  数据库:    $DATA_DIR/owners.db"
echo ""
echo "  用户使用（重新登录后生效）:"
echo "    docker ps          # 只显示自己的容器"
echo "    docker images      # 只显示自己的镜像"
echo "    docker-authz-proxy-ctl --help  # 管理工具"
echo ""
echo "  socket 路径: /run/docker-authz/<username>/docker.sock"
echo ""
INSTALL_SCRIPT

chmod +x "${PKG_DIR}/install.sh"
log_info "install.sh 已生成"

# ── 生成 README ──────────────────────────────────────────────────────────────
cat > "${PKG_DIR}/README.txt" << 'README_EOF'
docker-authz-proxy 部署包
==========================

使用方式：
  sudo bash install.sh           # 首次安装
  sudo bash install.sh --upgrade # 升级（保留数据，覆盖配置）
  sudo bash install.sh --uninstall # 卸载

目录结构：
  bin/
    docker-authz-proxy       - 主代理程序 (linux/amd64)
    docker-authz-proxy-ctl   - 管理工具 (linux/amd64)
  config/
    policy.yaml              - 授权策略配置（可按需编辑后再安装）
    quota.yaml               - 资源配额配置
  deploy/
    docker-authz.service     - systemd 服务文件
  install.sh                 - 一键安装脚本

安装后路径：
  /usr/local/bin/docker-authz-proxy
  /usr/local/bin/docker-authz-proxy-ctl
  /etc/docker-authz/policy.yaml
  /etc/docker-authz/quota.yaml
  /var/lib/docker-authz/owners.db  (运行时生成)
  /var/log/docker-authz/authz.log  (运行时生成)
  /run/docker-authz/<user>/docker.sock (运行时生成)

系统要求：
  - Linux x86_64
  - systemd
  - Docker 20.10+
  - root 权限
README_EOF

# ── 打包 ─────────────────────────────────────────────────────────────────────
log_step "打包为 tar.gz"
cd "$DIST_DIR"
tar czf "${PKG_NAME}.tar.gz" "$PKG_NAME"
cd ..

PKG_SIZE=$(du -sh "${OUTPUT_TAR}" | cut -f1)

echo ""
echo -e "${GREEN}════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  构建完成！${NC}"
echo -e "${GREEN}════════════════════════════════════════════════${NC}"
echo ""
echo "  输出包: ${OUTPUT_TAR}  (${PKG_SIZE})"
echo ""
echo "  部署方式（将包传输到目标机器）："
echo "    scp ${OUTPUT_TAR} user@server:/tmp/"
echo "    ssh user@server"
echo "    cd /tmp && tar xzf ${PKG_NAME}.tar.gz"
echo "    sudo bash ${PKG_NAME}/install.sh"
echo ""
echo "  或通过 deploy-from-windows.sh 一键传输+部署："
echo "    bash deploy-from-windows.sh -h <server-ip>"
echo ""
