#!/bin/bash
# 策略调试脚本 - 检查策略配置和用户信息

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

echo "========================================="
echo "策略配置调试信息"
echo "========================================="
echo ""

log_info "1. 检查配置文件"
echo ""
if [ -f /etc/docker-authz/policy.yaml ]; then
    cat /etc/docker-authz/policy.yaml
else
    echo "配置文件不存在"
fi

echo ""
log_info "2. 检查 alice 用户信息"
echo ""
if id alice &>/dev/null; then
    log_debug "用户名: alice"
    log_debug "UID: $(id -u alice)"
    log_debug "GID: $(id -g alice)"
    log_debug "所有组: $(id -G alice)"
    log_debug "/etc/passwd 条目: $(grep "^alice:" /etc/passwd || echo '未找到')"
else
    echo "alice 用户不存在"
fi

echo ""
log_info "3. 检查服务日志（最近 30 条）"
echo ""
journalctl -u docker-authz -n 30 --no-pager

echo ""
log_info "4. 测试 alice 执行 docker ps"
echo ""
if id alice &>/dev/null; then
    log_debug "执行命令: sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice.sock docker ps"
    sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice.sock docker ps 2>&1 || true
else
    echo "alice 用户不存在，跳过测试"
fi

echo ""
log_info "5. 检查最近的授权日志"
echo ""
journalctl -u docker-authz -n 50 --no-pager | grep -i "authz_request\|authz_denied\|authz_allowed" | tail -10 || echo "未找到授权日志"

echo ""
