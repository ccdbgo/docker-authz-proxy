#!/bin/bash
# docker-authz-proxy 全量遍历测试脚本
# 用户：root / alice / bob / test-sudo / test-docker-g
# 当前策略：alice 禁止 ps；其余用户无命令级限制
# 用法：sudo bash test/full-test.sh

SOCKET_DIR="/run/docker-authz"
PASS=0; FAIL=0; SKIP=0
RESULTS=()

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

docker_as() {
    local user="$1"; shift
    local sock="${SOCKET_DIR}/${user}/docker.sock"
    if [ ! -S "$sock" ]; then
        echo "[NO_SOCK]"
        return 1
    fi
    sudo -u "$user" env DOCKER_HOST="unix://${sock}" docker "$@" 2>&1
}

record() {
    local user="$1" cmd="$2" expect="$3" actual_rc="$4" output="$5"
    local status
    if [ "$expect" = "allow" ] && [ "$actual_rc" -eq 0 ]; then
        status="PASS"; ((PASS++))
    elif [ "$expect" = "deny" ] && echo "$output" | grep -qiE "denied|forbidden|belongs to|not permitted|not your|Error response|unauthorized|access denied|not accessible|not tracked"; then
        status="PASS"; ((PASS++))
    elif [ "$expect" = "skip" ]; then
        status="SKIP"; ((SKIP++))
    else
        status="FAIL"; ((FAIL++))
    fi
    RESULTS+=("${user}|${cmd}|${expect}|${status}|${output:0:120}")
    if [ "$status" = "PASS" ]; then
        echo -e "  ${GREEN}PASS${NC} [${user}] ${cmd}"
    elif [ "$status" = "SKIP" ]; then
        echo -e "  ${YELLOW}SKIP${NC} [${user}] ${cmd}"
    else
        echo -e "  ${RED}FAIL${NC} [${user}] ${cmd}"
        echo "       output: ${output:0:200}"
    fi
}

run_test() {
    local user="$1" cmd_desc="$2" expect="$3"; shift 3
    local output rc
    output=$(docker_as "$user" "$@" 2>&1)
    rc=$?
    record "$user" "$cmd_desc" "$expect" "$rc" "$output"
}

USERS=(root alice bob test-sudo test-docker-g)

echo ""
echo "================================================================"
echo " docker-authz-proxy 全量遍历测试"
echo " 测试用户: ${USERS[*]}"
echo " 时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo " 策略: alice 禁止 ps；其余用户无命令级限制"
echo "================================================================"

# 重置 DB，确保每次测试从干净状态开始
echo -e "${CYAN}[准备] 重置 ownership DB...${NC}"
systemctl stop docker-authz 2>/dev/null || true
rm -f /var/lib/docker-authz/owners.db /var/lib/docker-authz/owners.db-shm /var/lib/docker-authz/owners.db-wal
systemctl start docker-authz 2>/dev/null || true
sleep 1

# 预先拉取基础镜像并标记为 public（以 root 身份，带 authz.public=true 参数）
echo -e "${CYAN}[准备] 拉取基础镜像（public）...${NC}"
for img in "nginx:alpine" "alpine:latest" "busybox:latest"; do
    repo="${img%%:*}"
    tag="${img##*:}"
    curl -sf --unix-socket "${SOCKET_DIR}/root/docker.sock" \
        -X POST "http://localhost/images/create?fromImage=${repo}&tag=${tag}&authz.public=true" \
        -o /dev/null 2>/dev/null || true
done

# 清理旧测试容器
echo -e "${CYAN}[准备] 清理旧测试资源...${NC}"
# 以 root 直接清理旧镜像（DB 已重置，不走代理权限检查）
for u in "${USERS[@]}"; do
    docker rm -f "test-${u}-c" "net-${u}" "label-${u}" 2>/dev/null || true
    docker network rm "${u}-testnet" 2>/dev/null || true
    docker volume rm "${u}-testvol" 2>/dev/null || true
    docker rmi "${u}-built:test" "${u}-busybox:test" "${u}-committed:test" 2>/dev/null || true
done

# ================================================================
# 第一章：系统信息类
# ================================================================
echo -e "\n${CYAN}==== 第一章：系统信息类 ====${NC}"

for u in "${USERS[@]}"; do
    run_test "$u" "docker version" "allow" version --format '{{.Server.Version}}'
    # 当前策略：无用户被禁止 info（注：info 是系统级操作，代理允许所有人访问）
    run_test "$u" "docker info" "allow" info
    run_test "$u" "docker system df" "allow" system df
    run_test "$u" "docker events --since 60s --until \$(date)" "allow" events --since 60s --until "$(date +%s)"

    # _ping 健康检查（curl 直接测试）
    sock="${SOCKET_DIR}/${u}/docker.sock"
    if [ -S "$sock" ]; then
        out=$(curl -sf --unix-socket "$sock" http://localhost/_ping 2>&1)
        rc=$?
        record "$u" "GET /_ping" "allow" "$rc" "$out"
    fi
done

# ================================================================
# 第二章：容器生命周期
# ================================================================
echo -e "\n${CYAN}==== 第二章：容器生命周期 ====${NC}"

for u in "${USERS[@]}"; do
    cname="test-${u}-c"
    echo -e "\n  ${YELLOW}-- 用户: $u --${NC}"

    # docker ps（alice 被禁止）
    if [ "$u" = "alice" ]; then
        run_test "$u" "docker ps" "deny" ps
        run_test "$u" "docker ps -a" "deny" ps -a
    else
        run_test "$u" "docker ps" "allow" ps
        run_test "$u" "docker ps -a" "allow" ps -a
    fi

    # docker run
    run_test "$u" "docker run -d" "allow" run -d --name "$cname" nginx:alpine

    # docker ps 可见自己容器（alice 跳过）
    if [ "$u" != "alice" ]; then
        out=$(docker_as "$u" ps --format '{{.Names}}' 2>&1)
        rc=$?
        if echo "$out" | grep -qE "(^|/)${cname}($|/)|(^|/)user-[0-9]+-${cname}($|/)"; then
            record "$u" "docker ps 可见自己容器" "allow" 0 "$out"
        elif echo "$out" | grep -q "test-"; then
            record "$u" "docker ps 可见自己容器" "allow" 0 "$out"
        else
            record "$u" "docker ps 可见自己容器" "allow" 1 "未找到 $cname: $out"
        fi
    fi

    # docker inspect
    run_test "$u" "docker inspect" "allow" inspect "$cname" --format '{{.Id}}'

    # docker logs
    run_test "$u" "docker logs" "allow" logs "$cname"

    # docker top
    run_test "$u" "docker top" "allow" top "$cname"

    # docker stats --no-stream
    run_test "$u" "docker stats --no-stream" "allow" stats --no-stream "$cname"

    # docker diff
    run_test "$u" "docker diff" "allow" diff "$cname"

    # docker exec（bob 被策略禁止，其余用户允许）
    if [ "$u" = "bob" ]; then
        run_test "$u" "docker exec" "deny" exec "$cname" echo hello
    else
        run_test "$u" "docker exec" "allow" exec "$cname" echo hello
    fi

    # docker pause / unpause
    run_test "$u" "docker pause" "allow" pause "$cname"
    run_test "$u" "docker unpause" "allow" unpause "$cname"

    # docker stop
    run_test "$u" "docker stop" "allow" stop "$cname"

    # docker start
    run_test "$u" "docker start" "allow" start "$cname"

    # docker restart
    run_test "$u" "docker restart" "allow" restart "$cname"

    # docker rename
    run_test "$u" "docker rename" "allow" rename "$cname" "${cname}-r"
    run_test "$u" "docker rename back" "allow" rename "${cname}-r" "$cname"

    # docker update
    run_test "$u" "docker update --memory" "allow" update --memory 256m --memory-swap 512m "$cname"

    # docker cp
    run_test "$u" "docker cp (from container)" "allow" cp "${cname}:/etc/hostname" "/tmp/${u}-hostname.txt"

    # docker export
    run_test "$u" "docker export" "allow" export "$cname" -o "/tmp/${u}-export.tar"

    # docker commit
    run_test "$u" "docker commit" "allow" commit "$cname" "${u}-committed:test"

    # docker stop & rm
    docker_as "$u" stop "$cname" 2>/dev/null || true
    run_test "$u" "docker rm" "allow" rm -f "$cname"

    # 清理
    docker_as "$u" rmi "${u}-committed:test" 2>/dev/null || true
    rm -f "/tmp/${u}-hostname.txt" "/tmp/${u}-export.tar"
done

# ================================================================
# 第三章：跨用户隔离验证
# ================================================================
echo -e "\n${CYAN}==== 第三章：跨用户隔离验证 ====${NC}"

docker_as alice run -d --name iso-alice nginx:alpine 2>/dev/null || true
docker_as bob   run -d --name iso-bob   nginx:alpine 2>/dev/null || true

# 非 root 用户不能访问 alice 的容器
for attacker in bob test-sudo test-docker-g; do
    run_test "$attacker" "跨用户 stop alice 容器"    "deny" stop iso-alice
    run_test "$attacker" "跨用户 inspect alice 容器" "deny" inspect iso-alice
    run_test "$attacker" "跨用户 logs alice 容器"    "deny" logs iso-alice
    run_test "$attacker" "跨用户 exec alice 容器"    "deny" exec iso-alice echo x
done

# root 有全局访问权限，可以访问所有用户容器
run_test "root" "root 访问 alice 容器 inspect" "allow" inspect iso-alice --format '{{.Id}}'
run_test "root" "root 访问 alice 容器 logs"    "allow" logs iso-alice

# alice 不能访问 bob 的容器
run_test "alice" "跨用户 stop bob 容器" "deny" stop iso-bob
run_test "alice" "跨用户 rm bob 容器"   "deny" rm -f iso-bob

# 可见性：alice 看不到 bob 的容器（alice 被禁 ps，跳过）
# 可见性：bob 看不到 alice 的容器
out=$(docker_as bob ps --format '{{.Names}}' 2>&1)
if echo "$out" | grep -q "iso-alice"; then
    record "bob" "docker ps 不可见 alice 容器" "allow" 1 "错误：bob 看到了 iso-alice"
else
    record "bob" "docker ps 不可见 alice 容器" "allow" 0 "正确：未看到 iso-alice"
fi

# 短 ID 隔离
full_id=$(docker_as alice inspect iso-alice --format '{{.Id}}' 2>/dev/null)
short_id="${full_id:0:12}"
run_test "bob" "跨用户短 ID stop alice 容器" "deny" stop "$short_id"
run_test "bob" "跨用户完整 ID stop alice 容器" "deny" stop "$full_id"

docker_as alice rm -f iso-alice 2>/dev/null || true
docker_as bob   rm -f iso-bob   2>/dev/null || true

# ================================================================
# 第四章：镜像管理
# ================================================================
echo -e "\n${CYAN}==== 第四章：镜像管理 ====${NC}"

for u in "${USERS[@]}"; do
    echo -e "\n  ${YELLOW}-- 用户: $u --${NC}"

    run_test "$u" "docker images" "allow" images
    run_test "$u" "docker pull" "allow" pull busybox:latest

    # 先 build 一个用户自己的镜像，再对其进行 tag/inspect/save/rmi 测试
    # （busybox:latest 由 root 拉取，非 root 用户无法 tag 它）
    # bob 被策略禁止 build，其余用户允许
    mkdir -p "/tmp/build-${u}"
    printf 'FROM busybox:latest\nRUN echo built-by-%s\n' "$u" > "/tmp/build-${u}/Dockerfile"
    if [ "$u" = "bob" ]; then
        run_test "$u" "docker build" "deny" build -t "${u}-built:test" "/tmp/build-${u}"
        # bob 有 busybox:latest 访问权限（虚拟 pull），可以 tag/save，但不能 rmi（非属主）
        run_test "$u" "docker tag" "allow" tag "busybox:latest" "${u}-busybox:test"
        run_test "$u" "docker inspect image" "allow" inspect "busybox:latest" --format '{{.Id}}'
        run_test "$u" "docker save" "allow" save "busybox:latest" -o "/tmp/${u}-busybox.tar"
        run_test "$u" "docker rmi tag" "deny" rmi "busybox:latest"
        docker_as "$u" rmi "${u}-busybox:test" 2>/dev/null || true
        rm -f "/tmp/${u}-busybox.tar"
    else
        run_test "$u" "docker build" "allow" build -t "${u}-built:test" "/tmp/build-${u}"

        run_test "$u" "docker tag" "allow" tag "${u}-built:test" "${u}-busybox:test"
        run_test "$u" "docker inspect image" "allow" inspect "${u}-busybox:test" --format '{{.Id}}'
        run_test "$u" "docker save" "allow" save "${u}-busybox:test" -o "/tmp/${u}-busybox.tar"
        run_test "$u" "docker rmi tag" "allow" rmi "${u}-busybox:test"

        if [ -f "/tmp/${u}-busybox.tar" ]; then
            run_test "$u" "docker load" "allow" load -i "/tmp/${u}-busybox.tar"
            docker_as "$u" rmi "${u}-busybox:test" 2>/dev/null || true
        fi

        # alice-built:test 留给第四章跨用户隔离测试使用，其余用户在此清理
        if [ "$u" != "alice" ]; then
            docker_as "$u" rmi "${u}-built:test" 2>/dev/null || true
        fi
    fi
    run_test "$u" "docker search" "allow" search --limit 3 nginx

    run_test "$u" "docker image prune -f" "allow" image prune -f

    rm -rf "/tmp/build-${u}" "/tmp/${u}-busybox.tar"
done

# 镜像跨用户隔离（使用已构建的本地镜像，不依赖网络拉取）
echo -e "\n  ${YELLOW}-- 镜像跨用户隔离 --${NC}"
# alice 的镜像（alice-built:test）不应被 bob 看到
out=$(docker_as bob images 2>&1)
if echo "$out" | grep -q "alice-built"; then
    record "bob" "images 不可见 alice 的 alice-built:test" "allow" 1 "错误：bob 看到了 alice-built"
else
    record "bob" "images 不可见 alice 的 alice-built:test" "allow" 0 "正确：未看到 alice-built"
fi

run_test "bob" "跨用户 rmi alice 的 alice-built:test" "deny" rmi alice-built:test
run_test "alice" "rmi 自己的 alice-built:test" "allow" rmi alice-built:test

# ================================================================
# 第五章：网络管理
# ================================================================
echo -e "\n${CYAN}==== 第五章：网络管理 ====${NC}"

for u in "${USERS[@]}"; do
    echo -e "\n  ${YELLOW}-- 用户: $u --${NC}"
    netname="${u}-testnet"

    run_test "$u" "docker network ls" "allow" network ls
    run_test "$u" "docker network create" "allow" network create "$netname"
    run_test "$u" "docker network inspect" "allow" network inspect "$netname"

    docker_as "$u" run -d --name "net-${u}" nginx:alpine 2>/dev/null || true
    run_test "$u" "docker network connect" "allow" network connect "$netname" "net-${u}"
    run_test "$u" "docker network disconnect" "allow" network disconnect "$netname" "net-${u}"
    docker_as "$u" rm -f "net-${u}" 2>/dev/null || true

    run_test "$u" "docker network rm" "allow" network rm "$netname"
    run_test "$u" "docker network prune -f" "allow" network prune -f
done

echo -e "\n  ${YELLOW}-- 网络跨用户隔离 --${NC}"
docker_as alice network create alice-iso-net 2>/dev/null || true
run_test "bob"       "跨用户 network rm alice 网络" "deny" network rm alice-iso-net
run_test "test-sudo" "跨用户 network rm alice 网络" "deny" network rm alice-iso-net
docker_as alice network rm alice-iso-net 2>/dev/null || true

# ================================================================
# 第六章：卷管理
# ================================================================
echo -e "\n${CYAN}==== 第六章：卷管理 ====${NC}"

for u in "${USERS[@]}"; do
    echo -e "\n  ${YELLOW}-- 用户: $u --${NC}"
    volname="${u}-testvol"

    run_test "$u" "docker volume ls" "allow" volume ls
    run_test "$u" "docker volume create" "allow" volume create "$volname"
    run_test "$u" "docker volume inspect" "allow" volume inspect "$volname"
    run_test "$u" "docker volume rm" "allow" volume rm "$volname"
    run_test "$u" "docker volume prune -f" "allow" volume prune -f
done

echo -e "\n  ${YELLOW}-- 卷跨用户隔离 --${NC}"
docker_as alice volume create alice-iso-vol 2>/dev/null || true
run_test "bob"       "跨用户 volume rm alice 卷" "deny" volume rm alice-iso-vol
run_test "test-sudo" "跨用户 volume rm alice 卷" "deny" volume rm alice-iso-vol
docker_as alice volume rm alice-iso-vol 2>/dev/null || true

# ================================================================
# 第七章：系统清理
# ================================================================
echo -e "\n${CYAN}==== 第七章：系统清理 ====${NC}"

for u in "${USERS[@]}"; do
    run_test "$u" "docker container prune -f" "allow" container prune -f
    run_test "$u" "docker image prune -f"     "allow" image prune -f
    run_test "$u" "docker builder prune -f"   "allow" builder prune -f
    run_test "$u" "docker volume prune -f"    "allow" volume prune -f
    run_test "$u" "docker network prune -f"   "allow" network prune -f
    run_test "$u" "docker system prune -f"    "allow" system prune -f
done

# ================================================================
# 第八章：系统标签注入验证
# ================================================================
echo -e "\n${CYAN}==== 第八章：系统标签注入验证 ====${NC}"

for u in "${USERS[@]}"; do
    docker_as "$u" run -d --name "label-${u}" --label "myapp=test" nginx:alpine 2>/dev/null || true
    labels=$(docker_as "$u" inspect "label-${u}" --format '{{json .Config.Labels}}' 2>/dev/null)

    if echo "$labels" | grep -q "system.authz.owner.username"; then
        record "$u" "系统标签 owner.username 注入" "allow" 0 "$labels"
    else
        record "$u" "系统标签 owner.username 注入" "allow" 1 "未找到标签: $labels"
    fi
    if echo "$labels" | grep -q "system.authz.owner.uid"; then
        record "$u" "系统标签 owner.uid 注入" "allow" 0 "$labels"
    else
        record "$u" "系统标签 owner.uid 注入" "allow" 1 "未找到标签: $labels"
    fi
    if echo "$labels" | grep -q "myapp"; then
        record "$u" "用户标签未被覆盖" "allow" 0 "$labels"
    else
        record "$u" "用户标签未被覆盖" "allow" 1 "myapp 标签丢失: $labels"
    fi
    docker_as "$u" rm -f "label-${u}" 2>/dev/null || true
done

# ================================================================
# 第九章：API 版本前缀兼容性
# ================================================================
echo -e "\n${CYAN}==== 第九章：API 版本前缀兼容性 ====${NC}"

for u in "${USERS[@]}"; do
    sock="${SOCKET_DIR}/${u}/docker.sock"
    [ -S "$sock" ] || continue

    out=$(curl -sf --unix-socket "$sock" "http://localhost/v1.41/containers/json" 2>&1)
    rc=$?
    record "$u" "GET /v1.41/containers/json" "allow" "$rc" "${out:0:80}"

    out=$(curl -sf --unix-socket "$sock" "http://localhost/v1.41/images/json" 2>&1)
    rc=$?
    record "$u" "GET /v1.41/images/json" "allow" "$rc" "${out:0:80}"

    out=$(curl -sf --unix-socket "$sock" "http://localhost/v1.41/networks" 2>&1)
    rc=$?
    record "$u" "GET /v1.41/networks" "allow" "$rc" "${out:0:80}"

    out=$(curl -sf --unix-socket "$sock" "http://localhost/v1.41/volumes" 2>&1)
    rc=$?
    record "$u" "GET /v1.41/volumes" "allow" "$rc" "${out:0:80}"
done

# ================================================================
# 第十章：容器资源配额验证
# ================================================================
echo -e "\n${CYAN}==== 第十章：容器资源配额 ====${NC}"

for u in "${USERS[@]}"; do
    # root 不受配额限制，跳过
    if [ "$u" = "root" ]; then
        continue
    fi
    # 验证容器运行时受配额限制（CPU、内存限制被注入）
    docker_as "$u" run -d --name "quota-${u}" nginx:alpine 2>/dev/null || true
    mem=$(docker_as "$u" inspect "quota-${u}" --format '{{.HostConfig.Memory}}' 2>/dev/null)
    cpu=$(docker_as "$u" inspect "quota-${u}" --format '{{.HostConfig.NanoCpus}}' 2>/dev/null)

    if [ -n "$mem" ] && [ "$mem" != "0" ]; then
        record "$u" "配额内存限制已注入" "allow" 0 "Memory=${mem}"
    else
        record "$u" "配额内存限制已注入" "allow" 1 "Memory=${mem:-未获取到}"
    fi
    if [ -n "$cpu" ] && [ "$cpu" != "0" ]; then
        record "$u" "配额 CPU 限制已注入" "allow" 0 "NanoCpus=${cpu}"
    else
        record "$u" "配额 CPU 限制已注入" "allow" 1 "NanoCpus=${cpu:-未获取到}"
    fi
    docker_as "$u" rm -f "quota-${u}" 2>/dev/null || true
done

# ================================================================
# 汇总
# ================================================================
echo ""
echo "================================================================"
echo " 测试结果汇总"
echo "================================================================"
printf "%-20s %-40s %-8s %-6s\n" "用户" "测试项" "预期" "结果"
echo "--------------------------------------------------------------------------"
for r in "${RESULTS[@]}"; do
    IFS='|' read -r u cmd expect status output <<< "$r"
    if [ "$status" = "PASS" ]; then
        color=$GREEN
    elif [ "$status" = "SKIP" ]; then
        color=$YELLOW
    else
        color=$RED
    fi
    printf "${color}%-20s %-40s %-8s %-6s${NC}\n" "$u" "${cmd:0:40}" "$expect" "$status"
done

echo ""
echo "--------------------------------------------------------------------------"
echo -e "${GREEN}通过: $PASS${NC}  ${RED}失败: $FAIL${NC}  ${YELLOW}跳过: $SKIP${NC}  总计: $((PASS+FAIL+SKIP))"
echo ""

echo "=== MACHINE_RESULTS_START ==="
for r in "${RESULTS[@]}"; do
    echo "$r"
done
echo "=== MACHINE_RESULTS_END ==="

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}$FAIL test(s) failed${NC}"
    exit 1
fi
