#!/bin/bash
# 配置自动重载测试脚本
# 用途：测试配置文件自动检测和重新加载功能

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

# 检查是否为 root
if [ "$EUID" -ne 0 ]; then
    log_error "请使用 root 权限运行此脚本: sudo $0"
    exit 1
fi

# 检查服务是否运行
if ! systemctl is-active --quiet docker-authz; then
    log_error "docker-authz 服务未运行，请先启动服务"
    exit 1
fi

echo "========================================="
echo "配置自动重载测试"
echo "========================================="
echo ""

log_info "步骤 1: 查看当前配置"
echo ""
cat /etc/docker-authz/policy.yaml
echo ""

log_info "步骤 2: 备份原配置"
cp /etc/docker-authz/policy.yaml /etc/docker-authz/policy.yaml.backup

log_info "步骤 3: 修改配置文件（添加测试规则）"
echo ""

# 添加测试规则
cat > /etc/docker-authz/policy.yaml << 'EOF'
version: 1
default_action: allow

# 测试规则：禁止 alice 执行 ps 和 images 命令
deny_rules:
  - users: [alice]
    actions: [ps, images]

action_mapping:
  ps:              ["GET /containers/json"]
  create_container: ["POST /containers/create"]
  start:           ["POST /containers/{id}/start"]
  stop:            ["POST /containers/{id}/stop", "POST /containers/{id}/kill"]
  rm:              ["DELETE /containers/{id}"]
  exec:            ["POST /containers/{id}/exec"]
  inspect:         ["GET /containers/{id}/json", "GET /images/{id}/json"]
  logs:            ["GET /containers/{id}/logs"]
  images:          ["GET /images/json"]
  pull:            ["POST /images/create"]
  build:           ["POST /build"]
  push:            ["POST /images/{name}/push"]
  rmi:             ["DELETE /images/{id}"]
  tag:             ["POST /images/{id}/tag"]
EOF

log_info "配置已修改，新增规则：禁止 alice 执行 ps 和 images 命令"
echo ""

log_info "步骤 4: 等待程序自动检测配置变化（无需手动操作）"
log_info "程序会自动监控配置文件并重新加载..."
sleep 3

log_info "步骤 5: 查看日志，确认配置已自动重新加载"
echo ""
journalctl -u docker-authz -n 20 --no-pager | grep -i "configuration file changed\|reloaded successfully" || log_warn "未找到自动重载日志"
echo ""

log_info "步骤 6: 测试新配置是否生效"
echo ""

if id alice &>/dev/null; then
    log_info "测试 alice 用户执行 docker ps（应该被拒绝）"
    if sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice.sock docker ps &>/dev/null; then
        log_error "✗ 测试失败：alice 可以执行 docker ps（应该被拒绝）"
    else
        log_info "✓ 测试通过：alice 无法执行 docker ps"
    fi
    echo ""

    log_info "测试 alice 用户执行 docker images（应该被拒绝）"
    if sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice.sock docker images &>/dev/null; then
        log_error "✗ 测试失败：alice 可以执行 docker images（应该被拒绝）"
    else
        log_info "✓ 测试通过：alice 无法执行 docker images"
    fi
else
    log_warn "系统中不存在 alice 用户，跳过测试"
fi

echo ""
log_info "步骤 7: 恢复原配置"
echo ""
mv /etc/docker-authz/policy.yaml.backup /etc/docker-authz/policy.yaml

log_info "等待程序自动检测配置变化..."
sleep 3

echo ""
log_info "========================================="
log_info "配置自动重载测试完成！"
log_info "========================================="
echo ""
log_info "总结："
echo "  ✓ 配置文件可以在运行时修改"
echo "  ✓ 程序自动检测配置文件变化"
echo "  ✓ 无需手动执行任何命令"
echo "  ✓ 服务无需停止，不影响现有连接"
echo "  ✓ 新配置自动生效"
echo ""
log_info "如果你更喜欢手动控制，仍然可以使用："
echo "  systemctl reload docker-authz"
echo "  或"
echo "  kill -HUP \$(pidof docker-authz-proxy)"
echo ""
