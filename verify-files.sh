#!/bin/bash
# 项目文件整理和验证脚本
# 确保所有文件一致性和最新状态

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_check() {
    echo -e "${BLUE}[→]${NC} $1"
}

echo "========================================="
echo "Docker AuthZ Proxy - 文件整理验证"
echo "========================================="
echo ""

# 1. 检查核心源代码文件
log_check "检查核心源代码文件"
CORE_FILES=(
    "main.go"
    "proxy.go"
    "policy.go"
    "identity.go"
    "ownership.go"
    "filter.go"
    "labels.go"
    "logger.go"
)

for file in "${CORE_FILES[@]}"; do
    if [ -f "$file" ]; then
        log_info "$file"
    else
        echo "  ✗ 缺失: $file"
    fi
done
echo ""

# 2. 检查配置文件
log_check "检查配置文件"
if [ -f "config/policy.yaml" ]; then
    log_info "config/policy.yaml"
else
    echo "  ✗ 缺失: config/policy.yaml"
fi
echo ""

# 3. 检查部署文件
log_check "检查部署文件"
DEPLOY_FILES=(
    "deploy/docker-authz.service"
    "deploy/install.sh"
    "deploy/migrate.sh"
)

for file in "${DEPLOY_FILES[@]}"; do
    if [ -f "$file" ]; then
        log_info "$file"
    else
        echo "  ✗ 缺失: $file"
    fi
done
echo ""

# 4. 检查部署脚本
log_check "检查部署脚本"
DEPLOY_SCRIPTS=(
    "deploy-from-windows.sh"
    "deploy-to-linux.sh"
)

for file in "${DEPLOY_SCRIPTS[@]}"; do
    if [ -f "$file" ] && [ -x "$file" ]; then
        log_info "$file (可执行)"
    elif [ -f "$file" ]; then
        echo "  ⚠ $file (不可执行)"
        chmod +x "$file"
        log_info "  已添加执行权限"
    else
        echo "  ✗ 缺失: $file"
    fi
done
echo ""

# 5. 检查测试脚本
log_check "检查测试脚本"
TEST_SCRIPTS=(
    "test-on-linux.sh"
    "test-reload.sh"
)

for file in "${TEST_SCRIPTS[@]}"; do
    if [ -f "$file" ] && [ -x "$file" ]; then
        log_info "$file (可执行)"
    elif [ -f "$file" ]; then
        echo "  ⚠ $file (不可执行)"
        chmod +x "$file"
        log_info "  已添加执行权限"
    else
        echo "  ✗ 缺失: $file"
    fi
done
echo ""

# 6. 检查调试工具
log_check "检查调试工具"
DEBUG_SCRIPTS=(
    "diagnose.sh"
    "debug-policy.sh"
)

for file in "${DEBUG_SCRIPTS[@]}"; do
    if [ -f "$file" ] && [ -x "$file" ]; then
        log_info "$file (可执行)"
    elif [ -f "$file" ]; then
        echo "  ⚠ $file (不可执行)"
        chmod +x "$file"
        log_info "  已添加执行权限"
    else
        echo "  ✗ 缺失: $file"
    fi
done
echo ""

# 7. 检查卸载脚本
log_check "检查卸载脚本"
if [ -f "uninstall.sh" ] && [ -x "uninstall.sh" ]; then
    log_info "uninstall.sh (可执行)"
elif [ -f "uninstall.sh" ]; then
    echo "  ⚠ uninstall.sh (不可执行)"
    chmod +x "uninstall.sh"
    log_info "  已添加执行权限"
else
    echo "  ✗ 缺失: uninstall.sh"
fi
echo ""

# 8. 检查文档文件
log_check "检查文档文件"
DOC_FILES=(
    "README.md"
    "QUICKSTART.md"
    "FILES.md"
)

for file in "${DOC_FILES[@]}"; do
    if [ -f "$file" ]; then
        log_info "$file"
    else
        echo "  ✗ 缺失: $file"
    fi
done
echo ""

# 9. 检查 Go 模块文件
log_check "检查 Go 模块文件"
if [ -f "go.mod" ]; then
    log_info "go.mod"
    echo "  依赖列表:"
    grep "require" go.mod | head -10
else
    echo "  ✗ 缺失: go.mod"
fi
echo ""

# 10. 统计信息
echo "========================================="
echo "统计信息"
echo "========================================="
echo ""
echo "源代码文件: $(ls -1 *.go 2>/dev/null | wc -l) 个"
echo "脚本文件: $(ls -1 *.sh 2>/dev/null | wc -l) 个"
echo "文档文件: $(ls -1 *.md 2>/dev/null | wc -l) 个"
echo ""

# 11. 检查是否有编译产物
if [ -f "docker-authz-proxy" ]; then
    log_info "已编译的二进制文件存在"
    ls -lh docker-authz-proxy
else
    echo "未找到编译的二进制文件"
    echo "运行 'go build -o docker-authz-proxy .' 进行编译"
fi
echo ""

echo "========================================="
log_info "文件整理验证完成"
echo "========================================="
