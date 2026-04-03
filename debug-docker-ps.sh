#!/bin/bash
# 调试脚本：捕获 docker ps 的实际 API 调用

echo "=== 测试 docker ps 的 API 调用序列 ==="
echo ""

# 使用 strace 跟踪 docker ps 的系统调用，查看它实际访问了哪些 API
echo "执行: docker ps"
echo "预期调用序列："
echo "  1. GET /_ping 或 HEAD /_ping (健康检查)"
echo "  2. GET /v1.xx/containers/json (获取容器列表)"
echo ""

# 检查 classifyAction 对这两个路径的分类
echo "=== 检查 classifyAction 的路径分类 ==="
echo ""
echo "测试路径分类："
echo "  GET /_ping          -> 应该返回: info"
echo "  GET /containers/json -> 应该返回: ps"
echo "  GET /v1.41/containers/json -> 应该返回: ps"
echo ""
