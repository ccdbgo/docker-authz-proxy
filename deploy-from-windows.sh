#!/bin/bash
# Windows 端自动部署脚本
# 用途：从 Windows 开发环境自动传输代码到 Linux 服务器并部署

set -euo pipefail

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# 配置变量（请根据实际情况修改）
LINUX_SERVER="${LINUX_SERVER:-}"
LINUX_USER="${LINUX_USER:-root}"
LINUX_PORT="${LINUX_PORT:-22}"
REMOTE_DIR="${REMOTE_DIR:-/tmp/docker-authz-proxy}"

# 显示使用说明
show_usage() {
    cat << EOF
用法: $0 [选项]

自动部署 docker-authz-proxy 到 Linux 服务器

选项:
  -h, --host HOST       Linux 服务器地址（必需）
  -u, --user USER       SSH 用户名（默认: root）
  -p, --port PORT       SSH 端口（默认: 22）
  -d, --dir DIR         远程目录（默认: /tmp/docker-authz-proxy）
  --help                显示此帮助信息

环境变量:
  LINUX_SERVER          Linux 服务器地址
  LINUX_USER            SSH 用户名
  LINUX_PORT            SSH 端口
  REMOTE_DIR            远程目录

示例:
  $0 -h 192.168.1.100 -u root
  $0 --host myserver.com --user admin --port 2222

  # 或使用环境变量
  export LINUX_SERVER=192.168.1.100
  export LINUX_USER=root
  $0
EOF
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--host)
            LINUX_SERVER="$2"
            shift 2
            ;;
        -u|--user)
            LINUX_USER="$2"
            shift 2
            ;;
        -p|--port)
            LINUX_PORT="$2"
            shift 2
            ;;
        -d|--dir)
            REMOTE_DIR="$2"
            shift 2
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            log_error "未知选项: $1"
            show_usage
            exit 1
            ;;
    esac
done

# 检查必需参数
if [ -z "$LINUX_SERVER" ]; then
    log_error "未指定 Linux 服务器地址"
    echo ""
    show_usage
    exit 1
fi

# 检查 SSH 连接
log_info "检查 SSH 连接: $LINUX_USER@$LINUX_SERVER:$LINUX_PORT"
if ! ssh -p "$LINUX_PORT" -o ConnectTimeout=5 -o BatchMode=yes "$LINUX_USER@$LINUX_SERVER" "echo 2>&1" &>/dev/null; then
    log_warn "SSH 连接失败，请确保："
    echo "  1. SSH 密钥已配置（或使用密码登录）"
    echo "  2. 服务器地址和端口正确"
    echo "  3. 用户名正确"
    echo ""
    read -p "是否继续？(y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# 获取当前目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log_info "当前目录: $SCRIPT_DIR"
log_info "目标服务器: $LINUX_USER@$LINUX_SERVER:$LINUX_PORT"
log_info "远程目录: $REMOTE_DIR"
echo ""

# 步骤 1: 打包代码
log_info "步骤 1/4: 打包代码..."
TEMP_TAR="/tmp/docker-authz-proxy-$(date +%s).tar.gz"
tar czf "$TEMP_TAR" \
    --exclude='.git' \
    --exclude='*.exe' \
    --exclude='docker-authz-proxy' \
    --exclude='*.db' \
    --exclude='*.log' \
    --exclude='node_modules' \
    --exclude='vendor' \
    . || {
    log_error "打包失败"
    exit 1
}
log_info "打包完成: $TEMP_TAR"

# 步骤 2: 传输到 Linux 服务器
log_info "步骤 2/4: 传输到 Linux 服务器..."
ssh -p "$LINUX_PORT" "$LINUX_USER@$LINUX_SERVER" "mkdir -p $REMOTE_DIR" || {
    log_error "创建远程目录失败"
    rm -f "$TEMP_TAR"
    exit 1
}

scp -P "$LINUX_PORT" "$TEMP_TAR" "$LINUX_USER@$LINUX_SERVER:$REMOTE_DIR/code.tar.gz" || {
    log_error "传输失败"
    rm -f "$TEMP_TAR"
    exit 1
}
log_info "传输完成"

# 清理本地临时文件
rm -f "$TEMP_TAR"

# 步骤 3: 在 Linux 服务器上解压
log_info "步骤 3/4: 在服务器上解压..."
ssh -p "$LINUX_PORT" "$LINUX_USER@$LINUX_SERVER" "cd $REMOTE_DIR && tar xzf code.tar.gz && rm code.tar.gz" || {
    log_error "解压失败"
    exit 1
}
log_info "解压完成"

# 步骤 4: 在 Linux 服务器上执行部署脚本
log_info "步骤 4/4: 执行部署脚本..."
ssh -p "$LINUX_PORT" "$LINUX_USER@$LINUX_SERVER" "cd $REMOTE_DIR && chmod +x deploy-to-linux.sh && ./deploy-to-linux.sh" || {
    log_error "部署失败"
    exit 1
}

echo ""
log_info "========================================="
log_info "部署完成！"
log_info "========================================="
echo ""
echo "启动服务（在 Linux 服务器上执行）："
echo "  ssh -p $LINUX_PORT $LINUX_USER@$LINUX_SERVER 'systemctl start docker-authz'"
echo ""
echo "查看状态："
echo "  ssh -p $LINUX_PORT $LINUX_USER@$LINUX_SERVER 'systemctl status docker-authz'"
echo ""
echo "查看日志："
echo "  ssh -p $LINUX_PORT $LINUX_USER@$LINUX_SERVER 'journalctl -u docker-authz -f'"
echo ""
echo "运行测试："
echo "  ssh -p $LINUX_PORT $LINUX_USER@$LINUX_SERVER 'cd $REMOTE_DIR && chmod +x test-on-linux.sh && ./test-on-linux.sh'"
echo ""

# 询问是否立即启动服务
read -p "是否立即启动服务？(Y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    log_info "启动服务..."
    ssh -p "$LINUX_PORT" "$LINUX_USER@$LINUX_SERVER" "systemctl start docker-authz && systemctl status docker-authz --no-pager" || {
        log_error "启动失败"
        exit 1
    }
    echo ""
    log_info "服务已启动"
fi

# 询问是否运行测试
read -p "是否运行测试？(Y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    log_info "运行测试..."
    ssh -p "$LINUX_PORT" "$LINUX_USER@$LINUX_SERVER" "cd $REMOTE_DIR && chmod +x test-on-linux.sh && ./test-on-linux.sh" || {
        log_warn "测试失败，请查看日志"
    }
fi
