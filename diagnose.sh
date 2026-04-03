#!/bin/bash
# 完整的策略调试和诊断工具

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

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo "========================================="
echo "Docker AuthZ Proxy 策略诊断工具"
echo "========================================="
echo ""

# 1. 检查服务状态
log_info "1. 检查服务状态"
if systemctl is-active --quiet docker-authz 2>/dev/null; then
    echo "✓ 服务正在运行"
else
    log_error "✗ 服务未运行"
    echo "请先启动服务: systemctl start docker-authz"
    exit 1
fi
echo ""

# 2. 检查配置文件
log_info "2. 检查配置文件"
if [ -f /etc/docker-authz/policy.yaml ]; then
    echo "配置文件内容:"
    cat /etc/docker-authz/policy.yaml
else
    log_error "配置文件不存在: /etc/docker-authz/policy.yaml"
    exit 1
fi
echo ""

# 3. 检查测试用户
log_info "3. 检查测试用户 (alice)"
if id alice &>/dev/null; then
    log_debug "用户名: alice"
    log_debug "UID: $(id -u alice)"
    log_debug "GID: $(id -g alice)"
    log_debug "所有组: $(id -G alice)"
    log_debug "组名: $(id -Gn alice)"
    echo ""
    log_debug "/etc/passwd 条目:"
    grep "^alice:" /etc/passwd || log_warn "未找到"
else
    log_warn "alice 用户不存在，创建测试用户..."
    useradd -m -s /bin/bash alice
    log_info "已创建 alice 用户"
fi
echo ""

# 4. 检查 socket 文件
log_info "4. 检查 socket 文件"
if [ -S /run/docker-authz/alice.sock ]; then
    ls -la /run/docker-authz/alice.sock
else
    log_error "alice.sock 不存在"
fi
echo ""

# 5. 检查启动日志中的策略加载信息
log_info "5. 检查策略加载日志"
echo "查找 'policy loaded' 或 'resolved_deny_rule' 日志:"
journalctl -u docker-authz --no-pager | grep -i "policy loaded\|resolved_deny_rule\|deny_rules_count" | tail -20 || log_warn "未找到策略加载日志"
echo ""

# 6. 测试 alice 执行命令
log_info "6. 测试 alice 执行 docker ps"
echo "执行: sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice.sock docker ps"
echo ""
if sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice.sock docker ps 2>&1; then
    log_warn "命令执行成功（如果配置了禁止规则，这里应该失败）"
else
    log_info "命令被拒绝（符合预期）"
fi
echo ""

# 7. 查看最近的授权日志
log_info "7. 查看最近的授权日志"
echo "查找 'authz_request', 'authz_denied', 'authz_allowed' 日志:"
journalctl -u docker-authz -n 100 --no-pager | grep -E "authz_request|authz_denied|authz_allowed" | tail -20 || log_warn "未找到授权日志"
echo ""

# 8. 检查日志级别
log_info "8. 检查日志级别配置"
systemctl cat docker-authz | grep "log-level" || log_warn "未找到日志级别配置"
echo ""

# 9. 建议
echo "========================================="
log_info "诊断建议"
echo "========================================="
echo ""
echo "如果策略不生效，请检查："
echo "  1. 配置文件中的用户名是否正确（区分大小写）"
echo "  2. 用户是否真实存在（id alice 能查到）"
echo "  3. 日志级别是否为 debug（便于查看详细信息）"
echo "  4. 查看日志中是否有 'resolved_deny_rule' 输出"
echo ""
echo "修改日志级别为 debug:"
echo "  1. 编辑 /etc/systemd/system/docker-authz.service"
echo "  2. 将 --log-level=info 改为 --log-level=debug"
echo "  3. 执行: systemctl daemon-reload && systemctl restart docker-authz"
echo ""
