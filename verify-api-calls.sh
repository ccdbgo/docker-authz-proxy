#!/bin/bash
# 验证 Docker CLI 的 API 调用序列

echo "=== 验证 Docker CLI 的 API 调用序列 ==="
echo ""

# 测试 1: docker info
echo "1. 测试 docker info（用户主动执行）"
echo "   预期：只调用 GET /info"
echo ""

# 测试 2: docker images
echo "2. 测试 docker images（用户主动执行）"
echo "   预期：先调用 GET /_ping，再调用 GET /images/json"
echo ""

# 测试 3: docker ps
echo "3. 测试 docker ps（用户主动执行）"
echo "   预期：先调用 GET /_ping，再调用 GET /containers/json"
echo ""

echo "请在 Linux 服务器上执行以下命令进行验证："
echo ""
echo "# 1. 清空日志"
echo "> /var/log/docker-authz/authz.log"
echo ""
echo "# 2. 执行 docker info"
echo "docker info > /dev/null 2>&1"
echo ""
echo "# 3. 查看日志中的 API 调用"
echo "tail -20 /var/log/docker-authz/authz.log | jq -r 'select(.event==\"authz_request\") | \"\\(.http_method) \\(.http_uri)\"'"
echo ""
echo "# 4. 清空日志"
echo "> /var/log/docker-authz/authz.log"
echo ""
echo "# 5. 执行 docker images"
echo "docker images > /dev/null 2>&1"
echo ""
echo "# 6. 查看日志中的 API 调用"
echo "tail -20 /var/log/docker-authz/authz.log | jq -r 'select(.event==\"authz_request\") | \"\\(.http_method) \\(.http_uri)\"'"
echo ""
echo "如果验证结果符合预期（docker info 只调用 /info，docker images 先调用 /_ping），"
echo "则当前的修改方案是正确的。"
