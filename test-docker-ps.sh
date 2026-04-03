#!/bin/bash
# 测试脚本：模拟 docker ps 的 API 调用

echo "=== Testing docker ps API calls ==="
echo ""

# Docker CLI 通常会先调用 /_ping 或 /info
echo "1. Simulating /_ping (Docker client health check):"
curl -s --unix-socket /var/run/docker.sock http://docker/_ping
echo ""
echo ""

echo "2. Simulating GET /info (Docker client version negotiation):"
curl -s --unix-socket /var/run/docker.sock http://docker/info | head -20
echo ""
echo "... (truncated)"
echo ""

echo "3. Simulating GET /containers/json (actual docker ps):"
curl -s --unix-socket /var/run/docker.sock http://docker/containers/json | jq '.' 2>/dev/null || cat
echo ""
