#!/bin/bash
# 容器隔离功能验证脚本
# 使用方法：在 Linux 服务器上以 root 身份运行

set -e

echo "=== 容器隔离功能测试 ==="
echo

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 测试结果统计
PASS=0
FAIL=0

# 代理 socket 目录
SOCKET_DIR="/run/docker-authz"

# 以指定用户身份通过代理 socket 执行 docker 命令
# 原理：显式传入 DOCKER_HOST，确保命令通过代理 socket（不受 sudo 环境变量重置影响）
docker_as() {
    local user="$1"
    shift
    local sock="${SOCKET_DIR}/${user}/docker.sock"
    sudo -u "$user" env DOCKER_HOST="unix://${sock}" docker "$@"
}

test_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASS++))
}

test_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((FAIL++))
}

test_info() {
    echo -e "${YELLOW}ℹ INFO${NC}: $1"
}

# 检查是否有两个测试用户
if ! id alice &>/dev/null || ! id bob &>/dev/null; then
    echo "错误：需要创建测试用户 alice 和 bob"
    echo "运行：useradd -m alice && useradd -m bob"
    exit 1
fi

echo "步骤 1: 清理环境"
docker rm -f alice-container bob-container test-container 2>/dev/null || true
docker rmi -f test-image 2>/dev/null || true
echo

echo "步骤 2: alice 创建容器"
docker_as alice run -d --name alice-container nginx:alpine
if [ $? -eq 0 ]; then
    test_pass "alice 创建容器成功"
else
    test_fail "alice 创建容器失败"
fi
echo

echo "步骤 3: bob 创建容器"
docker_as bob run -d --name bob-container nginx:alpine
if [ $? -eq 0 ]; then
    test_pass "bob 创建容器成功"
else
    test_fail "bob 创建容器失败"
fi
echo

echo "步骤 4: alice 列出容器（应只看到自己的）"
ALICE_PS=$(docker_as alice ps --format '{{.Names}}')
echo "alice 看到的容器: $ALICE_PS"
if echo "$ALICE_PS" | grep -q "alice-container" && ! echo "$ALICE_PS" | grep -q "bob-container"; then
    test_pass "alice 只能看到自己的容器"
else
    test_fail "alice 看到了其他用户的容器或看不到自己的容器"
fi
echo

echo "步骤 5: bob 列出容器（应只看到自己的）"
BOB_PS=$(docker_as bob ps --format '{{.Names}}')
echo "bob 看到的容器: $BOB_PS"
if echo "$BOB_PS" | grep -q "bob-container" && ! echo "$BOB_PS" | grep -q "alice-container"; then
    test_pass "bob 只能看到自己的容器"
else
    test_fail "bob 看到了其他用户的容器或看不到自己的容器"
fi
echo

echo "步骤 6: alice 尝试停止 bob 的容器（应被拒绝）"
if docker_as alice stop bob-container 2>&1 | grep -q "Forbidden\|not permitted\|not tracked\|not your"; then
    test_pass "alice 无法停止 bob 的容器"
else
    test_fail "alice 能够停止 bob 的容器（隔离失效）"
fi
echo

echo "步骤 7: bob 尝试删除 alice 的容器（应被拒绝）"
if docker_as bob rm -f alice-container 2>&1 | grep -q "Forbidden\|not permitted\|not tracked\|not your"; then
    test_pass "bob 无法删除 alice 的容器"
else
    test_fail "bob 能够删除 alice 的容器（隔离失效）"
fi
echo

echo "步骤 8: alice 尝试 exec 进入 bob 的容器（应被拒绝）"
if docker_as alice exec bob-container echo "test" 2>&1 | grep -q "Forbidden\|not permitted\|not tracked\|not your"; then
    test_pass "alice 无法 exec 进入 bob 的容器"
else
    test_fail "alice 能够 exec 进入 bob 的容器（隔离失效）"
fi
echo

echo "步骤 9: root 列出所有容器（应看到所有）"
ROOT_PS=$(docker ps --format '{{.Names}}')
echo "root 看到的容器: $ROOT_PS"
if echo "$ROOT_PS" | grep -q "alice-container" && echo "$ROOT_PS" | grep -q "bob-container"; then
    test_pass "root 可以看到所有容器"
else
    test_fail "root 看不到所有容器"
fi
echo

echo "步骤 10: 检查日志格式"
test_info "检查最近 5 条授权日志"
if [ -f /var/log/docker-authz/authz.log ]; then
    tail -5 /var/log/docker-authz/authz.log | while read line; do
        # 检查是否包含 time, level, caller, msg 字段
        if echo "$line" | jq -e '.time and .level and .caller and .msg' &>/dev/null; then
            echo "  ✓ 日志格式正确: $(echo "$line" | jq -r '.time + " " + .level + " " + .caller + " " + .msg')"
        else
            echo "  ✗ 日志格式错误: $line"
        fi
    done
else
    test_info "日志文件不存在: /var/log/docker-authz/authz.log"
fi
echo

echo "步骤 11: 清理测试容器"
docker rm -f alice-container bob-container 2>/dev/null || true
echo

echo "=== 测试结果 ==="
echo -e "${GREEN}通过: $PASS${NC}"
echo -e "${RED}失败: $FAIL${NC}"
echo

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}所有测试通过！容器隔离功能正常。${NC}"
    exit 0
else
    echo -e "${RED}部分测试失败，请检查日志：${NC}"
    echo "  tail -50 /var/log/docker-authz/authz.log | grep AUTHZ_DENY"
    exit 1
fi
