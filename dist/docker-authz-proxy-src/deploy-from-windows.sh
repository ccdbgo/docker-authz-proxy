#!/bin/bash
# deploy-from-windows.sh - 从 Windows 一键部署到 Linux 服务器
#
# 两种模式（自动选择）：
#   [推荐] 预编译包模式: 直接传输 dist/ 中的二进制包，无需目标机安装 Go
#   [备用] 源码编译模式: 传输源码到目标机，由目标机编译（需要目标机安装 Go）
#
# 用法:
#   bash deploy-from-windows.sh -h <server-ip>
#   bash deploy-from-windows.sh -h <server-ip> --source  # 强制源码编译
#   bash deploy-from-windows.sh -h <server-ip> --upgrade # 升级模式

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "\n${BLUE}══ $1${NC}"; }

# ── 参数默认值 ───────────────────────────────────────────────────────────────
LINUX_SERVER="${LINUX_SERVER:-}"
LINUX_USER="${LINUX_USER:-ywyh}"
LINUX_PORT="${LINUX_PORT:-22}"
REMOTE_DIR="${REMOTE_DIR:-/tmp/docker-authz-deploy}"
MODE="auto"        # auto | binary | source
EXTRA_FLAGS=""     # 传给 install.sh 的额外参数

show_usage() {
    cat << EOF
用法: bash $0 -h <server> [选项]

将 docker-authz-proxy 部署到 Linux 服务器

选项:
  -h, --host HOST    目标服务器地址（必需）
  -u, --user USER    SSH 用户名（默认: root）
  -p, --port PORT    SSH 端口（默认: 22）
  -d, --dir  DIR     远程临时目录（默认: /tmp/docker-authz-deploy）
  --upgrade          升级模式（覆盖已有配置文件）
  --source           强制使用源码编译模式（目标机需安装 Go）
  --help             显示此帮助

环境变量: LINUX_SERVER / LINUX_USER / LINUX_PORT / REMOTE_DIR

示例:
  bash $0 -h 192.168.1.100
  bash $0 -h 192.168.1.100 -u admin -p 2222 --upgrade
  LINUX_SERVER=192.168.1.100 bash $0
EOF
}

# ── 解析参数 ─────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--host)    LINUX_SERVER="$2"; shift 2 ;;
        -u|--user)    LINUX_USER="$2";   shift 2 ;;
        -p|--port)    LINUX_PORT="$2";   shift 2 ;;
        -d|--dir)     REMOTE_DIR="$2";   shift 2 ;;
        --upgrade)    EXTRA_FLAGS="--upgrade"; shift ;;
        --source)     MODE="source"; shift ;;
        --help)       show_usage; exit 0 ;;
        *) log_error "未知选项: $1"; show_usage; exit 1 ;;
    esac
done

if [ -z "$LINUX_SERVER" ]; then
    log_error "未指定目标服务器地址"
    echo ""
    show_usage
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SSH_OPTS="-p $LINUX_PORT -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"
SCP_OPTS="-P $LINUX_PORT -o StrictHostKeyChecking=accept-new"
SSH="ssh $SSH_OPTS"
SCP="scp $SCP_OPTS"
TARGET="$LINUX_USER@$LINUX_SERVER"

# ── 检查 SSH 连通性 ──────────────────────────────────────────────────────────
log_step "检查 SSH 连接"
log_info "目标: $TARGET:$LINUX_PORT"

if ! $SSH -o BatchMode=yes "$TARGET" "echo ok" &>/dev/null; then
    log_warn "SSH 免密登录未配置，部署过程将提示输入密码"
    log_warn "建议先配置 SSH 密钥: ssh-copy-id -p $LINUX_PORT $TARGET"
    echo ""
fi
log_info "SSH 连接正常"

# ── 选择部署模式 ─────────────────────────────────────────────────────────────
PKG_DIR="${SCRIPT_DIR}/dist/docker-authz-proxy-deploy-linux-amd64"
PKG_TAR="${SCRIPT_DIR}/dist/docker-authz-proxy-deploy-linux-amd64.tar.gz"

if [ "$MODE" = "auto" ]; then
    if [ -f "$PKG_TAR" ]; then
        MODE="binary"
        log_info "检测到预编译包: dist/docker-authz-proxy-deploy-linux-amd64.tar.gz"
        log_info "使用【预编译包模式】（无需目标机安装 Go）"
    else
        MODE="source"
        log_warn "未找到预编译包 dist/docker-authz-proxy-deploy-linux-amd64.tar.gz"
        log_warn "使用【源码编译模式】（目标机需安装 Go 1.21+）"
        log_warn "提示：先运行 bash build-release.sh 生成预编译包可更快部署"
    fi
fi

# ════════════════════════════════════════════════════════════════════════════
# 模式A：预编译包模式
# ════════════════════════════════════════════════════════════════════════════
if [ "$MODE" = "binary" ]; then

    log_step "步骤 1/3: 传输预编译包"
    $SSH "$TARGET" "mkdir -p $REMOTE_DIR"
    $SCP "$PKG_TAR" "$TARGET:$REMOTE_DIR/deploy.tar.gz"
    log_info "传输完成"

    log_step "步骤 2/3: 解压"
    $SSH "$TARGET" "cd $REMOTE_DIR && tar xzf deploy.tar.gz && rm deploy.tar.gz"
    log_info "解压完成"

    log_step "步骤 3/3: 执行安装"
    $SSH -t "$TARGET" \
        "cd $REMOTE_DIR/docker-authz-proxy-deploy-linux-amd64 && bash install.sh $EXTRA_FLAGS"

# ════════════════════════════════════════════════════════════════════════════
# 模式B：源码编译模式
# ════════════════════════════════════════════════════════════════════════════
else

    log_step "步骤 1/4: 打包源码"
    TEMP_TAR="$(mktemp /tmp/docker-authz-XXXXXX.tar.gz)"
    tar czf "$TEMP_TAR" \
        --exclude='.git' \
        --exclude='dist' \
        --exclude='*.exe' \
        --exclude='*.db' \
        --exclude='*.log' \
        --exclude='~$*' \
        --exclude='node_modules' \
        --exclude='vendor' \
        .
    SRC_SIZE=$(du -sh "$TEMP_TAR" | cut -f1)
    log_info "打包完成 (${SRC_SIZE}): $TEMP_TAR"

    log_step "步骤 2/4: 传输源码"
    $SSH "$TARGET" "mkdir -p $REMOTE_DIR"
    $SCP "$TEMP_TAR" "$TARGET:$REMOTE_DIR/source.tar.gz"
    rm -f "$TEMP_TAR"
    log_info "传输完成"

    log_step "步骤 3/4: 解压"
    $SSH "$TARGET" "cd $REMOTE_DIR && tar xzf source.tar.gz && rm source.tar.gz"
    log_info "解压完成"

    log_step "步骤 4/4: 编译并安装"
    $SSH -t "$TARGET" "cd $REMOTE_DIR && bash deploy-to-linux.sh"

fi

# ── 完成 ─────────────────────────────────────────────────────────────────────
echo ""
log_info "═══════════════════════════════════════════════════"
log_info "  部署完成！"
log_info "═══════════════════════════════════════════════════"
echo ""
echo "  查看服务状态:"
echo "    ssh -p $LINUX_PORT $TARGET 'systemctl status docker-authz'"
echo ""
echo "  查看实时日志:"
echo "    ssh -p $LINUX_PORT $TARGET 'journalctl -u docker-authz -f'"
echo ""
echo "  管理工具帮助:"
echo "    ssh -p $LINUX_PORT $TARGET 'docker-authz-proxy-ctl --help'"
echo ""
