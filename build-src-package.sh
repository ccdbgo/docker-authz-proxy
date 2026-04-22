#!/bin/bash
# build-src-package.sh - 构建源码部署包（适用于 ARM 等非 amd64 架构）
#
# 输出：dist/docker-authz-proxy-src.tar.gz
# 目标机器需要：Go 1.21+、systemd、root 权限
#
# 用法：
#   bash build-src-package.sh
#
# 部署到 ARM 机器：
#   scp dist/docker-authz-proxy-src.tar.gz root@arm-server:/tmp/
#   ssh root@arm-server
#   cd /tmp && tar xzf docker-authz-proxy-src.tar.gz
#   sudo bash docker-authz-proxy-src/build-and-install.sh

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
PKG_NAME="docker-authz-proxy-src"
PKG_DIR="${DIST_DIR}/${PKG_NAME}"
OUTPUT_TAR="${DIST_DIR}/${PKG_NAME}.tar.gz"

# ── 准备输出目录 ──────────────────────────────────────────────────────────────
log_step "准备输出目录"
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"
log_info "输出目录: $PKG_DIR"

# ── 复制源码 ──────────────────────────────────────────────────────────────────
log_step "复制源码"

# 复制 Go 源码目录
cp -r cmd         "$PKG_DIR/"
cp -r internal    "$PKG_DIR/"
cp -r config      "$PKG_DIR/"
cp -r deploy      "$PKG_DIR/"
cp    go.mod      "$PKG_DIR/"
cp    go.sum      "$PKG_DIR/"
cp    main.go     "$PKG_DIR/"

SRC_SIZE=$(du -sh "$PKG_DIR" | cut -f1)
log_info "源码已复制 (${SRC_SIZE})"

# ── 生成 build-and-install.sh ─────────────────────────────────────────────────
log_step "生成一键编译安装脚本"
cat > "${PKG_DIR}/build-and-install.sh" << 'BUILD_INSTALL_SCRIPT'
#!/bin/bash
# docker-authz-proxy 源码编译安装脚本
# 适用于 ARM64 / ARMv7 / x86_64 等任意 Linux 架构
#
# 用法：sudo bash build-and-install.sh [--upgrade] [--uninstall]
#
# 系统要求：
#   - Linux（任意架构）
#   - Go 1.21+
#   - systemd
#   - root 权限

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
            echo "用法: sudo bash build-and-install.sh [--upgrade] [--uninstall]"
            exit 0 ;;
        *) echo "未知参数: $arg"; exit 1 ;;
    esac
done

# ── 卸载模式 ──────────────────────────────────────────────────────────────────
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

# ── 前置检查 ──────────────────────────────────────────────────────────────────
log_step "0/7  前置检查"

if [ "$EUID" -ne 0 ]; then
    log_error "请用 root 权限运行: sudo bash build-and-install.sh"
    exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
    log_error "仅支持 Linux 系统"
    exit 1
fi

ARCH=$(uname -m)
log_info "目标架构: $ARCH"

if ! command -v systemctl &>/dev/null; then
    log_error "未找到 systemctl，仅支持 systemd 系统"
    exit 1
fi

if ! command -v go &>/dev/null; then
    log_error "未找到 Go 编译器，请先安装 Go 1.21+"
    echo ""
    echo "  ARM64 安装 Go 参考："
    echo "    wget https://go.dev/dl/go1.21.13.linux-arm64.tar.gz"
    echo "    tar -C /usr/local -xzf go1.21.13.linux-arm64.tar.gz"
    echo "    export PATH=\$PATH:/usr/local/go/bin"
    echo ""
    echo "  ARMv7 安装 Go 参考："
    echo "    wget https://go.dev/dl/go1.21.13.linux-armv6l.tar.gz"
    echo "    tar -C /usr/local -xzf go1.21.13.linux-armv6l.tar.gz"
    echo "    export PATH=\$PATH:/usr/local/go/bin"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}')
log_ok "Go 版本: $GO_VERSION"

if ! command -v docker &>/dev/null; then
    log_warn "未检测到 docker 命令，请确保 Docker 已安装"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log_ok "环境检查通过 (Linux ${ARCH}, systemd, Go)"

# ── 路径变量 ──────────────────────────────────────────────────────────────────
BIN_PROXY="/usr/local/bin/docker-authz-proxy"
BIN_CTL="/usr/local/bin/docker-authz-proxy-ctl"
CONFIG_DIR="/etc/docker-authz"
DATA_DIR="/var/lib/docker-authz"
LOG_DIR="/var/log/docker-authz"
SOCKET_DIR="/run/docker-authz"
SERVICE_FILE="/etc/systemd/system/docker-authz.service"
LOGROTATE_FILE="/etc/logrotate.d/docker-authz"
BUILD_DIR="${SCRIPT_DIR}/_build"

# ── Step 1: 停止现有服务 ──────────────────────────────────────────────────────
log_step "1/7  停止现有服务（如存在）"
if systemctl is-active --quiet docker-authz 2>/dev/null; then
    systemctl stop docker-authz
    log_ok "已停止 docker-authz 服务"
else
    log_ok "无运行中的服务"
fi

# ── Step 2: 编译 ──────────────────────────────────────────────────────────────
log_step "2/7  编译程序"
mkdir -p "$BUILD_DIR"
cd "$SCRIPT_DIR"

log_info "编译 docker-authz-proxy ..."
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o "${BUILD_DIR}/docker-authz-proxy" . && \
    log_ok "  -> ${BUILD_DIR}/docker-authz-proxy"

log_info "编译 docker-authz-proxy-ctl ..."
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o "${BUILD_DIR}/docker-authz-proxy-ctl" ./cmd/ctl/ && \
    log_ok "  -> ${BUILD_DIR}/docker-authz-proxy-ctl"

PROXY_SIZE=$(du -sh "${BUILD_DIR}/docker-authz-proxy" | cut -f1)
CTL_SIZE=$(du -sh "${BUILD_DIR}/docker-authz-proxy-ctl" | cut -f1)
log_ok "二进制大小: proxy=${PROXY_SIZE}, ctl=${CTL_SIZE}"

# ── Step 3: 创建目录 ──────────────────────────────────────────────────────────
log_step "3/7  创建目录"
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$SOCKET_DIR"
chmod 750 "$DATA_DIR" "$LOG_DIR"
chmod 755 "$SOCKET_DIR"
log_ok "目录已创建"

# ── Step 4: 安装二进制文件 ────────────────────────────────────────────────────
log_step "4/7  安装二进制文件"
install -m 755 "${BUILD_DIR}/docker-authz-proxy" "$BIN_PROXY"
install -m 755 "${BUILD_DIR}/docker-authz-proxy-ctl" "$BIN_CTL"
log_ok "$BIN_PROXY"
log_ok "$BIN_CTL"

PROXY_VER=$("$BIN_PROXY" --version 2>/dev/null || echo "unknown")
log_ok "版本: $PROXY_VER"

# ── Step 5: 安装配置文件 ──────────────────────────────────────────────────────
log_step "5/7  安装配置文件"

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

# ── Step 6: 安装 systemd 服务 ─────────────────────────────────────────────────
log_step "6/7  安装 systemd 服务"
install -m 644 "${SCRIPT_DIR}/deploy/docker-authz.service" "$SERVICE_FILE"

if [ -f "${SCRIPT_DIR}/deploy/logrotate.conf" ]; then
    install -m 644 "${SCRIPT_DIR}/deploy/logrotate.conf" "$LOGROTATE_FILE"
    log_ok "logrotate 配置已安装"
fi

systemctl daemon-reload
systemctl enable docker-authz
systemctl start docker-authz

sleep 2
if systemctl is-active --quiet docker-authz; then
    log_ok "服务已启动: docker-authz (active)"
else
    log_error "服务启动失败，请查看日志："
    echo "  journalctl -u docker-authz -n 50 --no-pager"
    exit 1
fi

# ── Step 7: 配置用户环境变量 ──────────────────────────────────────────────────
log_step "7/7  配置用户 DOCKER_HOST 环境变量"

cat > /etc/profile.d/docker-authz.sh << 'PROFILE_EOF'
# docker-authz-proxy: 每个用户通过自己的 socket 访问 Docker
if [ -S "/run/docker-authz/$(whoami)/docker.sock" ]; then
    export DOCKER_HOST="unix:///run/docker-authz/$(whoami)/docker.sock"
fi
PROFILE_EOF
chmod 644 /etc/profile.d/docker-authz.sh
log_ok "已写入 /etc/profile.d/docker-authz.sh"

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

# ── 清理编译临时目录 ──────────────────────────────────────────────────────────
rm -rf "$BUILD_DIR"

# ── 完成 ──────────────────────────────────────────────────────────────────────
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
BUILD_INSTALL_SCRIPT

chmod +x "${PKG_DIR}/build-and-install.sh"
log_info "build-and-install.sh 已生成"

# ── 生成 README.txt ───────────────────────────────────────────────────────────
cat > "${PKG_DIR}/README.txt" << 'README_EOF'
docker-authz-proxy 源码部署包
==============================
适用于 ARM64 / ARMv7 / x86_64 等任意 Linux 架构

系统要求：
  - Linux（任意架构）
  - Go 1.21+（目标机器上需要）
  - systemd
  - root 权限

使用方式：
  sudo bash build-and-install.sh           # 编译并安装
  sudo bash build-and-install.sh --upgrade # 升级（保留数据，覆盖配置）
  sudo bash build-and-install.sh --uninstall # 卸载

安装 Go（ARM64）：
  wget https://go.dev/dl/go1.21.13.linux-arm64.tar.gz
  tar -C /usr/local -xzf go1.21.13.linux-arm64.tar.gz
  export PATH=$PATH:/usr/local/go/bin

安装 Go（ARMv7）：
  wget https://go.dev/dl/go1.21.13.linux-armv6l.tar.gz
  tar -C /usr/local -xzf go1.21.13.linux-armv6l.tar.gz
  export PATH=$PATH:/usr/local/go/bin

安装后路径：
  /usr/local/bin/docker-authz-proxy
  /usr/local/bin/docker-authz-proxy-ctl
  /etc/docker-authz/policy.yaml
  /etc/docker-authz/quota.yaml
  /var/lib/docker-authz/owners.db  (运行时生成)
  /var/log/docker-authz/authz.log  (运行时生成)
  /run/docker-authz/<user>/docker.sock (运行时生成)
README_EOF

# ── 打包 ──────────────────────────────────────────────────────────────────────
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
echo "  部署到 ARM 机器："
echo "    scp ${OUTPUT_TAR} root@arm-server:/tmp/"
echo "    ssh root@arm-server"
echo "    cd /tmp && tar xzf ${PKG_NAME}.tar.gz"
echo "    sudo bash ${PKG_NAME}/build-and-install.sh"
echo ""
echo "  或通过 deploy-from-windows.sh 一键传输+部署："
echo "    bash deploy-from-windows.sh -h <arm-server-ip> --source"
echo ""
