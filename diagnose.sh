#!/bin/bash
# 诊断脚本：收集 docker run 卡死和容器隔离失效的详细信息

set -e

echo "=== Docker 授权代理诊断脚本 ==="
echo "时间: $(date)"
echo

# 检查用户
if ! id alice &>/dev/null || ! id bob &>/dev/null; then
    echo "错误：需要创建测试用户 alice 和 bob"
    exit 1
fi

echo "步骤 1: 检查代理进程状态"
ps aux | grep docker-authz-proxy | grep -v grep || echo "代理进程未运行"
echo

echo "步骤 2: 检查用户 DOCKER_HOST 配置"
echo "alice: $(sudo -u alice env | grep DOCKER_HOST || echo '未设置')"
echo "bob: $(sudo -u bob env | grep DOCKER_HOST || echo '未设置')"
echo

echo "步骤 3: 检查 socket 文件"
ls -lh /var/run/docker-authz/*.sock 2>/dev/null || echo "socket 文件不存在"
echo

echo "步骤 4: 测试 docker run（带超时和详细输出）"
echo "--- alice 执行 docker run ---"
timeout 10 sudo -u alice docker run --rm alpine echo "test" 2>&1 || echo "命令超时或失败（退出码: $?）"
echo

echo "步骤 5: 检查数据库内容"
if [ -f /var/lib/docker-authz/owners.db ]; then
    echo "--- 容器归属 ---"
    sqlite3 /var/lib/docker-authz/owners.db "SELECT id, owner_username, owner_uid FROM containers LIMIT 10;" 2>/dev/null || echo "查询失败"
    echo
    echo "--- 镜像归属 ---"
    sqlite3 /var/lib/docker-authz/owners.db "SELECT image_id, owner_username, owner_uid, is_public FROM images LIMIT 10;" 2>/dev/null || echo "查询失败"
else
    echo "数据库文件不存在"
fi
echo

echo "步骤 6: 测试容器隔离"
echo "--- 创建测试容器 ---"
docker rm -f alice-test bob-test 2>/dev/null || true
sudo -u alice docker run -d --name alice-test nginx:alpine 2>&1 || echo "alice 创建容器失败"
sudo -u bob docker run -d --name bob-test nginx:alpine 2>&1 || echo "bob 创建容器失败"
echo

echo "--- alice 列出容器 ---"
sudo -u alice docker ps --format '{{.Names}}' 2>&1
echo

echo "--- bob 列出容器 ---"
sudo -u bob docker ps --format '{{.Names}}' 2>&1
echo

echo "--- alice 尝试停止 bob 的容器 ---"
sudo -u alice docker stop bob-test 2>&1 || echo "被拒绝（预期行为）"
echo

echo "步骤 7: 检查最近的授权日志（最后 20 条）"
if [ -f /var/log/docker-authz/authz.log ]; then
    tail -20 /var/log/docker-authz/authz.log | jq -c '{level,caller,msg,user,action,reason}' 2>/dev/null || tail -20 /var/log/docker-authz/authz.log
else
    echo "日志文件不存在"
fi
echo

echo "步骤 8: 检查系统日志中的错误"
journalctl -u docker-authz -n 20 --no-pager | grep -i "error\|panic\|fatal" || echo "无错误日志"
echo

echo "步骤 9: 清理测试容器"
docker rm -f alice-test bob-test 2>/dev/null || true
echo

echo "=== 诊断完成 ==="
echo "请将以上输出发送给开发者进行分析"
