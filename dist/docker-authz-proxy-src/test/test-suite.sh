#!/bin/bash
# Docker 授权代理完整测试套件
# 用法: sudo bash test/test-suite.sh

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
SKIP=0

# 代理 socket 目录（与启动参数保持一致）
SOCKET_DIR="/run/docker-authz"

# 以指定用户身份通过代理 socket 执行 docker 命令
# 用法：docker_as <username> <docker args...>
# 原理：显式传入 DOCKER_HOST，确保命令通过代理 socket（不受 sudo 环境变量重置影响）
docker_as() {
    local user="$1"
    shift
    local sock="${SOCKET_DIR}/${user}/docker.sock"
    sudo -u "$user" env DOCKER_HOST="unix://${sock}" docker "$@"
}

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# 测试辅助函数
test_case() {
    local desc="$1"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "测试: $desc"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

assert_success() {
    local desc="$1"
    shift
    if "$@" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} PASS: $desc"
        ((PASS++))
        return 0
    else
        echo -e "  ${RED}✗${NC} FAIL: $desc"
        echo "    命令: $*"
        ((FAIL++))
        return 1
    fi
}

assert_fail() {
    local desc="$1"
    shift
    output=$("$@" 2>&1) || true
    if echo "$output" | grep -qiE "denied|forbidden|belongs to|not permitted|not your"; then
        echo -e "  ${GREEN}✓${NC} PASS: $desc (正确拒绝)"
        ((PASS++))
        return 0
    else
        echo -e "  ${RED}✗${NC} FAIL: $desc (预期拒绝但通过了)"
        echo "    命令: $*"
        echo "    输出: $output"
        ((FAIL++))
        return 1
    fi
}

assert_contains() {
    local desc="$1"
    local pattern="$2"
    shift 2
    output=$("$@" 2>&1)
    if echo "$output" | grep -q "$pattern"; then
        echo -e "  ${GREEN}✓${NC} PASS: $desc"
        ((PASS++))
        return 0
    else
        echo -e "  ${RED}✗${NC} FAIL: $desc (未找到: $pattern)"
        echo "    命令: $*"
        echo "    输出: $output"
        ((FAIL++))
        return 1
    fi
}

assert_not_contains() {
    local desc="$1"
    local pattern="$2"
    shift 2
    output=$("$@" 2>&1)
    if ! echo "$output" | grep -q "$pattern"; then
        echo -e "  ${GREEN}✓${NC} PASS: $desc"
        ((PASS++))
        return 0
    else
        echo -e "  ${RED}✗${NC} FAIL: $desc (不应包含: $pattern)"
        echo "    命令: $*"
        echo "    输出: $output"
        ((FAIL++))
        return 1
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 前置检查
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

log_info "开始测试前置检查..."

# 检查是否 root
if [ "$EUID" -ne 0 ]; then
    log_error "请使用 root 权限运行: sudo bash test/test-suite.sh"
    exit 1
fi

# 检查测试用户是否存在
for user in alice bob; do
    if ! id "$user" &>/dev/null; then
        log_warn "测试用户 $user 不存在，正在创建..."
        useradd -m -s /bin/bash "$user"
        usermod -aG docker "$user"
    fi
done

# 检查代理服务是否运行
if ! systemctl is-active --quiet docker-authz.service; then
    log_error "代理服务未运行，请先安装并启动服务"
    exit 1
fi

# 检查用户 socket 是否存在
for user in alice bob; do
    sock="/run/docker-authz/${user}/docker.sock"
    if [ ! -S "$sock" ]; then
        log_error "用户 socket 不存在: $sock"
        exit 1
    fi
done

log_info "前置检查通过"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 测试一：环境变量自动设置
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test_case "环境变量自动设置"

assert_contains "alice 的 DOCKER_HOST 指向专属 socket" \
    "alice/docker.sock" \
    sudo -u alice -i bash -c 'echo $DOCKER_HOST'

assert_contains "bob 的 DOCKER_HOST 指向专属 socket" \
    "bob/docker.sock" \
    sudo -u bob -i bash -c 'echo $DOCKER_HOST'

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 测试二：基础连通性
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test_case "基础连通性"

assert_success "alice 可以执行 docker version" \
    docker_as alice version

assert_success "bob 可以执行 docker version" \
    docker_as bob version

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 测试三：容器归属隔离
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test_case "容器归属隔离"

# 清理旧容器
docker_as alice rm -f test-alice-nginx 2>/dev/null || true
docker_as bob rm -f test-bob-redis 2>/dev/null || true

# alice 创建容器
assert_success "alice 创建容器" \
    docker_as alice run -d --name test-alice-nginx nginx:alpine

# bob 创建容器
assert_success "bob 创建容器" \
    docker_as bob run -d --name test-bob-redis redis:alpine

# 跨用户操作应被拒绝
assert_fail "bob 不能停止 alice 的容器" \
    docker_as bob stop test-alice-nginx

assert_fail "alice 不能删除 bob 的容器" \
    docker_as alice rm -f test-bob-redis

assert_fail "bob 不能进入 alice 的容器" \
    docker_as bob exec test-alice-nginx echo test

# 自己的容器可以操作
assert_success "alice 可以停止自己的容器" \
    docker_as alice stop test-alice-nginx

assert_success "bob 可以删除自己的容器" \
    docker_as bob rm -f test-bob-redis

# 清理
docker_as alice rm -f test-alice-nginx 2>/dev/null || true

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 测试四：容器可见性隔离（docker ps 过滤）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test_case "容器可见性隔离 (docker ps 过滤)"

# 创建测试容器
docker_as alice run -d --name vis-alice-1 nginx:alpine
docker_as alice run -d --name vis-alice-2 nginx:alpine
docker_as bob run -d --name vis-bob-1 redis:alpine

# alice 只能看到自己的容器
assert_contains "alice 能看到自己的容器 vis-alice-1" \
    "vis-alice-1" \
    docker_as alice ps --format '{{.Names}}'

assert_contains "alice 能看到自己的容器 vis-alice-2" \
    "vis-alice-2" \
    docker_as alice ps --format '{{.Names}}'

assert_not_contains "alice 看不到 bob 的容器" \
    "vis-bob-1" \
    docker_as alice ps --format '{{.Names}}'

# bob 只能看到自己的容器
assert_contains "bob 能看到自己的容器" \
    "vis-bob-1" \
    docker_as bob ps --format '{{.Names}}'

assert_not_contains "bob 看不到 alice 的容器 vis-alice-1" \
    "vis-alice-1" \
    docker_as bob ps --format '{{.Names}}'

assert_not_contains "bob 看不到 alice 的容器 vis-alice-2" \
    "vis-alice-2" \
    docker_as bob ps --format '{{.Names}}'

# 清理
docker_as alice rm -f vis-alice-1 vis-alice-2 2>/dev/null || true
docker_as bob rm -f vis-bob-1 2>/dev/null || true

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 测试五：镜像归属隔离
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test_case "镜像归属隔离"

# alice 拉取镜像
assert_success "alice 拉取 busybox" \
    docker_as alice pull busybox:latest

# bob 不能删除 alice 的镜像
assert_fail "bob 不能删除 alice 的镜像" \
    docker_as bob rmi busybox:latest

# alice 可以删除自己的镜像
assert_success "alice 可以删除自己的镜像" \
    docker_as alice rmi busybox:latest

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 测试六：镜像可见性隔离（docker images 过滤）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test_case "镜像可见性隔离 (docker images 过滤)"

# alice 拉取镜像
docker_as alice pull alpine:3.18 >/dev/null 2>&1

# bob 拉取不同镜像
docker_as bob pull alpine:3.19 >/dev/null 2>&1

# alice 只能看到自己的镜像
assert_contains "alice 能看到自己的 alpine:3.18" \
    "alpine.*3.18" \
    docker_as alice images

assert_not_contains "alice 看不到 bob 的 alpine:3.19" \
    "3.19" \
    docker_as alice images

# bob 只能看到自己的镜像
assert_contains "bob 能看到自己的 alpine:3.19" \
    "alpine.*3.19" \
    docker_as bob images

assert_not_contains "bob 看不到 alice 的 alpine:3.18" \
    "3.18" \
    docker_as bob images

# 清理
docker_as alice rmi alpine:3.18 2>/dev/null || true
docker_as bob rmi alpine:3.19 2>/dev/null || true

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 测试七：sudo 身份识别
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test_case "sudo 身份识别"

# alice 通过代理 socket 创建容器（等价于用户环境中的 docker run）
assert_success "alice 通过代理创建容器" \
    docker_as alice run -d --name sudo-test nginx:alpine

# 检查日志确认身份识别正确（真实用户应为 alice，而非 root）
sleep 1
if journalctl -u docker-authz -n 50 --no-pager | grep -q "user=alice.*sudo=true"; then
    echo -e "  ${GREEN}✓${NC} PASS: 日志正确识别 sudo 用户为 alice"
    ((PASS++))
else
    echo -e "  ${RED}✗${NC} FAIL: 日志未正确识别 sudo 用户"
    ((FAIL++))
fi

# bob 不能操作 alice 通过 sudo 创建的容器
assert_fail "bob 不能操作 alice 的 sudo 容器" \
    docker_as bob stop sudo-test

# 清理
docker_as alice rm -f sudo-test 2>/dev/null || true

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 测试八：系统标签注入
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test_case "系统标签注入"

# alice 创建容器（带用户标签）
docker_as alice run -d --name label-test --label myapp=test nginx:alpine

# 检查系统标签是否注入
labels=$(docker_as alice inspect label-test --format '{{json .Config.Labels}}')

if echo "$labels" | grep -q "system.authz.owner.username.*alice"; then
    echo -e "  ${GREEN}✓${NC} PASS: 系统标签包含 owner.username=alice"
    ((PASS++))
else
    echo -e "  ${RED}✗${NC} FAIL: 系统标签未注入 owner.username"
    ((FAIL++))
fi

if echo "$labels" | grep -q "system.authz.owner.uid"; then
    echo -e "  ${GREEN}✓${NC} PASS: 系统标签包含 owner.uid"
    ((PASS++))
else
    echo -e "  ${RED}✗${NC} FAIL: 系统标签未注入 owner.uid"
    ((FAIL++))
fi

if echo "$labels" | grep -q "myapp.*test"; then
    echo -e "  ${GREEN}✓${NC} PASS: 用户标签未被覆盖"
    ((PASS++))
else
    echo -e "  ${RED}✗${NC} FAIL: 用户标签被覆盖"
    ((FAIL++))
fi

# 清理
docker_as alice rm -f label-test 2>/dev/null || true

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 测试九：命令授权（策略规则）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test_case "命令授权（策略规则）"

# 注意：需要在 policy.yaml 中配置 bob 禁止 build
# 这里假设已配置，测试是否生效

# 创建临时 Dockerfile
mkdir -p /tmp/test-build
cat > /tmp/test-build/Dockerfile <<'EOF'
FROM alpine:latest
RUN echo test
EOF

# 如果策略中禁止了 bob build，这应该失败
if grep -q "bob.*build" /etc/docker-authz/policy.yaml 2>/dev/null; then
    assert_fail "bob 被策略禁止 build" \
        docker_as bob build -t test /tmp/test-build
else
    log_warn "跳过 build 授权测试（policy.yaml 未配置 bob 禁止 build）"
    ((SKIP++))
fi

# 清理
rm -rf /tmp/test-build

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 测试十：短 ID 和完整 ID 支持
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test_case "短 ID 和完整 ID 支持"

# alice 创建容器
docker_as alice run -d --name id-test nginx:alpine

# 获取容器 ID
full_id=$(docker_as alice inspect id-test --format '{{.Id}}')
short_id=${full_id:0:12}

# bob 用短 ID 也不能操作
assert_fail "bob 不能用短 ID 操作 alice 的容器" \
    docker_as bob stop "$short_id"

# bob 用完整 ID 也不能操作
assert_fail "bob 不能用完整 ID 操作 alice 的容器" \
    docker_as bob stop "$full_id"

# alice 用短 ID 可以操作
assert_success "alice 可以用短 ID 操作自己的容器" \
    docker_as alice stop "$short_id"

# 清理
docker_as alice rm -f id-test 2>/dev/null || true

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 测试总结
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "测试总结"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}通过: $PASS${NC}"
echo -e "${RED}失败: $FAIL${NC}"
echo -e "${YELLOW}跳过: $SKIP${NC}"
echo "总计: $((PASS + FAIL + SKIP))"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✓ 所有测试通过！${NC}"
    exit 0
else
    echo -e "${RED}✗ 有 $FAIL 个测试失败${NC}"
    exit 1
fi
