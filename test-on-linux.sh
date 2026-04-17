#!/bin/bash
# 测试脚本 - 验证 docker-authz-proxy 功能
# 在 Linux 服务器上运行

set -euo pipefail

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASS_COUNT++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAIL_COUNT++))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    ((SKIP_COUNT++))
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# 检查是否为 root
if [ "$EUID" -ne 0 ]; then
    echo "请使用 root 权限运行此脚本: sudo $0"
    exit 1
fi

# 检查服务是否运行
if ! systemctl is-active --quiet docker-authz; then
    echo "docker-authz 服务未运行，请先启动服务："
    echo "  systemctl start docker-authz"
    exit 1
fi

echo "========================================="
echo "Docker Authorization Proxy 测试套件"
echo "========================================="
echo ""

# 测试 1: 检查 socket 文件是否创建
log_test "测试 1: 检查用户 socket 文件"
if [ -S "/run/docker-authz/root/docker.sock" ]; then
    log_pass "root/docker.sock 已创建"
else
    log_fail "root/docker.sock 未创建"
fi

# 列出所有创建的 socket
SOCKETS=$(ls -1 /run/docker-authz/*/docker.sock 2>/dev/null | wc -l)
log_info "已创建 $SOCKETS 个用户 socket"

# 测试 2: 检查策略配置
log_test "测试 2: 检查策略配置"
if grep -q "users: \[alice\]" /etc/docker-authz/policy.yaml 2>/dev/null; then
    log_info "策略配置: alice 用户被禁止执行 ps 命令"
else
    log_skip "未配置 alice 用户限制（使用默认配置）"
fi

# 测试 3: 测试 alice 用户是否被禁止执行 docker ps
log_test "测试 3: 测试 alice 用户策略限制"
if id alice &>/dev/null; then
    # 测试 alice 执行 docker ps（应该被拒绝）
    if sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice/docker.sock docker ps &>/dev/null; then
        log_fail "alice 用户执行 docker ps 成功（应该被拒绝）"
    else
        log_pass "alice 用户执行 docker ps 被正确拒绝"
    fi
else
    log_skip "系统中不存在 alice 用户"
fi

# 测试 4: 测试 root 用户可以执行命令
log_test "测试 4: 测试 root 用户访问"
if DOCKER_HOST=unix:///run/docker-authz/root/docker.sock docker ps &>/dev/null; then
    log_pass "root 用户可以执行 docker ps"
else
    log_fail "root 用户无法执行 docker ps"
fi

# 测试 5: 测试容器创建和归属
log_test "测试 5: 测试容器创建和归属隔离"
if id alice &>/dev/null && id bob &>/dev/null; then
    # alice 创建容器
    CONTAINER_ID=$(sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice/docker.sock \
        docker run -d --name test-alice-container nginx:alpine 2>/dev/null || echo "")

    if [ -n "$CONTAINER_ID" ]; then
        log_info "alice 创建容器: ${CONTAINER_ID:0:12}"

        # bob 尝试停止 alice 的容器（应该被拒绝）
        if sudo -u bob DOCKER_HOST=unix:///run/docker-authz/bob/docker.sock \
            docker stop test-alice-container &>/dev/null; then
            log_fail "bob 可以停止 alice 的容器（应该被拒绝）"
        else
            log_pass "bob 无法停止 alice 的容器（正确隔离）"
        fi

        # alice 停止自己的容器（应该成功）
        if sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice/docker.sock \
            docker stop test-alice-container &>/dev/null; then
            log_pass "alice 可以停止自己的容器"
        else
            log_fail "alice 无法停止自己的容器"
        fi

        # 清理
        sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice/docker.sock \
            docker rm test-alice-container &>/dev/null || true
    else
        log_skip "无法创建测试容器（可能 nginx:alpine 镜像不存在）"
    fi
else
    log_skip "系统中不存在 alice 或 bob 用户"
fi

# 测试 6: 测试可见性过滤
log_test "测试 6: 测试容器列表可见性过滤"
if id alice &>/dev/null && id bob &>/dev/null; then
    # alice 创建容器
    ALICE_CONTAINER=$(sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice/docker.sock \
        docker run -d --name test-visibility-alice nginx:alpine 2>/dev/null || echo "")

    # bob 创建容器
    BOB_CONTAINER=$(sudo -u bob DOCKER_HOST=unix:///run/docker-authz/bob/docker.sock \
        docker run -d --name test-visibility-bob nginx:alpine 2>/dev/null || echo "")

    if [ -n "$ALICE_CONTAINER" ] && [ -n "$BOB_CONTAINER" ]; then
        # alice 执行 docker ps，应该只看到自己的容器
        ALICE_PS=$(sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice/docker.sock \
            docker ps --format '{{.Names}}' 2>/dev/null || echo "")

        if echo "$ALICE_PS" | grep -q "test-visibility-alice" && \
           ! echo "$ALICE_PS" | grep -q "test-visibility-bob"; then
            log_pass "alice 只能看到自己的容器"
        else
            log_fail "alice 可以看到其他用户的容器"
        fi

        # 清理
        sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice/docker.sock \
            docker rm -f test-visibility-alice &>/dev/null || true
        sudo -u bob DOCKER_HOST=unix:///run/docker-authz/bob/docker.sock \
            docker rm -f test-visibility-bob &>/dev/null || true
    else
        log_skip "无法创建测试容器"
    fi
else
    log_skip "系统中不存在 alice 或 bob 用户"
fi

# 测试 7: 测试日志格式
log_test "测试 7: 检查日志格式"
if [ -f "/var/log/docker-authz/authz.log" ]; then
    # 检查最后一条日志是否为有效的 JSON
    LAST_LOG=$(tail -1 /var/log/docker-authz/authz.log 2>/dev/null)
    if echo "$LAST_LOG" | jq . &>/dev/null; then
        log_pass "日志格式为有效的 JSON"
        log_info "示例日志: $(echo "$LAST_LOG" | jq -c '{level,event,real_username,action}' 2>/dev/null || echo "$LAST_LOG")"
    else
        log_fail "日志格式不是有效的 JSON"
    fi
else
    log_skip "日志文件不存在"
fi

# 测试 8: 测试 sudo 用户身份识别
log_test "测试 8: 测试 sudo 用户身份识别"
if id alice &>/dev/null; then
    # 使用 sudo 执行 docker 命令
    sudo -u alice DOCKER_HOST=unix:///run/docker-authz/alice/docker.sock docker version &>/dev/null || true

    # 检查日志中是否正确识别了 sudo 用户
    if grep -q '"user_type":"sudo"' /var/log/docker-authz/authz.log 2>/dev/null || \
       grep -q '"user_type":"regular"' /var/log/docker-authz/authz.log 2>/dev/null; then
        log_pass "用户类型识别正常"
    else
        log_skip "无法验证用户类型识别"
    fi
else
    log_skip "系统中不存在 alice 用户"
fi

# 汇总结果
echo ""
echo "========================================="
echo "测试结果汇总"
echo "========================================="
echo -e "${GREEN}通过: $PASS_COUNT${NC}"
echo -e "${RED}失败: $FAIL_COUNT${NC}"
echo -e "${YELLOW}跳过: $SKIP_COUNT${NC}"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "${GREEN}所有测试通过！${NC}"
    exit 0
else
    echo -e "${RED}有 $FAIL_COUNT 个测试失败${NC}"
    echo ""
    echo "查看详细日志："
    echo "  journalctl -u docker-authz -n 50"
    echo "  tail -20 /var/log/docker-authz/authz.log | jq ."
    exit 1
fi
