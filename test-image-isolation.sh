#!/bin/bash
# 测试镜像隔离功能

set -e

echo "=== 测试镜像隔离功能 ==="
echo ""

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. 清理环境
echo "1. 清理测试环境..."
docker rm -f test-alice test-bob 2>/dev/null || true
docker rmi redis:latest nginx:latest 2>/dev/null || true
sqlite3 /var/lib/docker-authz/owners.db "DELETE FROM images WHERE image_id LIKE '%redis%' OR image_id LIKE '%nginx%';"
echo "   清理完成"
echo ""

# 2. alice 拉取 redis 镜像
echo "2. alice 拉取 redis 镜像..."
sudo -u alice docker pull redis:latest
echo "   拉取完成"
echo ""

# 3. bob 拉取 nginx 镜像
echo "3. bob 拉取 nginx 镜像..."
sudo -u bob docker pull nginx:latest
echo "   拉取完成"
echo ""

# 4. 检查数据库中的镜像归属
echo "4. 检查数据库中的镜像归属..."
echo "   镜像归属记录："
sqlite3 /var/lib/docker-authz/owners.db "SELECT substr(image_id, 1, 20) || '...', owner_username, owner_uid, is_public FROM images WHERE image_id LIKE '%redis%' OR image_id LIKE '%nginx%';"
echo ""

# 5. alice 执行 docker images
echo "5. alice 执行 docker images..."
ALICE_IMAGES=$(sudo -u alice docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "redis|nginx" || true)
echo "   alice 看到的镜像："
echo "$ALICE_IMAGES"
echo ""

# 6. bob 执行 docker images
echo "6. bob 执行 docker images..."
BOB_IMAGES=$(sudo -u bob docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "redis|nginx" || true)
echo "   bob 看到的镜像："
echo "$BOB_IMAGES"
echo ""

# 7. 验证隔离效果
echo "7. 验证隔离效果..."
echo ""

# 检查 alice 是否能看到 redis（应该能）
if echo "$ALICE_IMAGES" | grep -q "redis"; then
    echo -e "   ${GREEN}✓${NC} alice 能看到自己的 redis 镜像"
else
    echo -e "   ${RED}✗${NC} alice 看不到自己的 redis 镜像（错误）"
fi

# 检查 alice 是否能看到 nginx（不应该能）
if echo "$ALICE_IMAGES" | grep -q "nginx"; then
    echo -e "   ${RED}✗${NC} alice 能看到 bob 的 nginx 镜像（隔离失败）"
else
    echo -e "   ${GREEN}✓${NC} alice 看不到 bob 的 nginx 镜像"
fi

# 检查 bob 是否能看到 nginx（应该能）
if echo "$BOB_IMAGES" | grep -q "nginx"; then
    echo -e "   ${GREEN}✓${NC} bob 能看到自己的 nginx 镜像"
else
    echo -e "   ${RED}✗${NC} bob 看不到自己的 nginx 镜像（错误）"
fi

# 检查 bob 是否能看到 redis（不应该能）
if echo "$BOB_IMAGES" | grep -q "redis"; then
    echo -e "   ${RED}✗${NC} bob 能看到 alice 的 redis 镜像（隔离失败）"
else
    echo -e "   ${GREEN}✓${NC} bob 看不到 alice 的 redis 镜像"
fi

echo ""
echo "=== 测试完成 ==="
echo ""
echo "如果所有测试都通过（显示绿色 ✓），说明镜像隔离功能正常。"
echo "如果有红色 ✗，说明隔离功能有问题，请检查日志："
echo "  tail -100 /var/log/docker-authz/authz.log | jq -r 'select(.action==\"images\")'"
