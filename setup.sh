#!/usr/bin/env bash
#
# setup.sh - 一键初始化依赖
#
# 适用于 Debian/Ubuntu 系统，自动安装:
#   - git, nmap, curl
#   - python3, python3-pip
#   - requests, openpyxl (Python 模块)
#   - Go >= 1.20
#

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[*]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*"; }

# ── 检测 root ──
if [[ $EUID -ne 0 ]]; then
    warn "非 root 用户，后续操作将使用 sudo"
    SUDO="sudo"
else
    SUDO=""
fi

# ── 检测系统 ──
if [[ ! -f /etc/debian_version ]]; then
    error "此脚本仅支持 Debian/Ubuntu 系统"
    exit 1
fi

info "系统: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo ""

# ── 检测是否在中国大陆 ──
in_china=false
if ping -c 1 -W 1 www.google.com &>/dev/null; then
    ttl=$(ping -c 1 -W 1 www.google.com 2>/dev/null | grep -oP 'ttl=\K\d+' || echo "0")
    if [[ "$ttl" -le 64 ]]; then
        in_china=true
    fi
fi

if $in_china; then
    info "网络环境: 中国大陆（使用国内镜像）"
else
    info "网络环境: 海外（使用官方源）"
fi
echo ""

# ════════════════════════════════════════
# 1. 系统包
# ════════════════════════════════════════
info "安装系统依赖..."

# 切换 apt 源（国内）
if $in_china; then
    if [[ -f /etc/apt/sources.list ]] && ! grep -q "mirrors.aliyun.com" /etc/apt/sources.list; then
        warn "切换为阿里云 apt 源..."
        $SUDO cp /etc/apt/sources.list /etc/apt/sources.list.bak 2>/dev/null || true
        $SUDO tee /etc/apt/sources.list > /dev/null <<'EOF'
deb http://mirrors.aliyun.com/debian stable main contrib non-free
deb http://mirrors.aliyun.com/debian stable-updates main contrib non-free
deb http://mirrors.aliyun.com/debian-security stable-security main contrib non-free
EOF
        $SUDO apt update -y
    fi
fi

$SUDO apt update -y
$SUDO apt install -y git nmap curl python3 python3-pip

# ════════════════════════════════════════
# 2. Python 模块
# ════════════════════════════════════════
info "安装 Python 模块..."

PIP_EXTRA=""
if $in_china; then
    PIP_EXTRA="-i https://pypi.tuna.tsinghua.edu.cn/simple"
fi

pip3 install requests openpyxl --break-system-packages $PIP_EXTRA 2>/dev/null \
    || pip3 install requests openpyxl $PIP_EXTRA

# ════════════════════════════════════════
# 3. Go
# ════════════════════════════════════════
info "检查 Go..."

go_installed=false
go_exec=""
if [[ -x /usr/local/go/bin/go ]]; then
    go_exec="/usr/local/go/bin/go"
elif command -v go &>/dev/null; then
    go_exec="go"
fi

if [[ -n "$go_exec" ]]; then
    go_ver=$($go_exec version 2>/dev/null | grep -oP 'go\K\d+\.\d+' || echo "")
    if [[ -n "$go_ver" ]]; then
        go_major=$(echo "$go_ver" | cut -d. -f1)
        go_minor=$(echo "$go_ver" | cut -d. -f2)
        if [[ "$go_major" -ge 1 && "$go_minor" -ge 20 ]]; then
            info "Go ${go_ver} 已安装，跳过"
            go_installed=true
        fi
    fi
fi

if ! $go_installed; then
    warn "Go 未安装或版本过低，正在安装 Go 1.22.1 ..."

    GO_URL="https://go.dev/dl/go1.22.1.linux-amd64.tar.gz"
    if $in_china; then
        GO_URL="https://studygolang.com/dl/golang/go1.22.1.linux-amd64.tar.gz"
    fi

    curl -Lo /tmp/go.tar.gz "$GO_URL"
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz

    # 写入 PATH
    export_line='export PATH="/usr/local/go/bin:$PATH"'
    profile="/etc/profile"
    if ! grep -q "$export_line" "$profile" 2>/dev/null; then
        echo "$export_line" | $SUDO tee -a "$profile" > /dev/null
    fi
    export PATH="/usr/local/go/bin:$PATH"

    info "Go 安装完成"
fi

# Go 代理
if $in_china; then
    export GOPROXY="https://goproxy.cn,direct"
    export GOSUMDB="sum.golang.google.cn"
    info "Go 代理: goproxy.cn"
else
    export GOPROXY="https://proxy.golang.org,direct"
    export GOSUMDB="sum.golang.org"
    info "Go 代理: proxy.golang.org"
fi

# ════════════════════════════════════════
# 完成
# ════════════════════════════════════════
echo ""
echo "========================================"
echo -e "${GREEN}  依赖安装完成！${NC}"
echo "========================================"
echo ""
echo "可用命令:"
echo "  bash scan_all.sh <网段文件>         # 端口映射自动爆破"
echo "  bash scan_all.sh <网段文件> 6       # 强制 SSH 爆破"
echo ""
