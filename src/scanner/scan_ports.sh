#!/usr/bin/env bash
#
# scan_ports.sh - 批量检测网段清单中各指定端口的开放情况
#
# 用法:
#   bash scan_ports.sh <网段文件> [配置文件]
#
# 网段文件: 每行一个 IP/网段，如 192.168.1.0/24；支持 # 注释和空行
# 配置文件: 默认使用本脚本同目录下的 ports.conf
#
# 输出: 每个开放端口生成一个独立文件，如 scan_result/22_port.txt
#       文件内容每行一个 ip:port，只保留开放端口

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    echo "用法: bash $0 <网段文件> [配置文件]" >&2
    echo "示例: bash $0 subnets.txt" >&2
    echo "      bash $0 subnets.txt /path/to/ports.conf" >&2
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

SUBNET_FILE="$1"
CONF_FILE="${2:-${SCRIPT_DIR}/../../config/ports.conf}"

for f in "$SUBNET_FILE" "$CONF_FILE"; do
    if [[ ! -f "$f" ]]; then
        echo "错误: 找不到文件 $f" >&2
        exit 1
    fi
done

if ! command -v nmap >/dev/null 2>&1; then
    echo "错误: 未找到 nmap，请先安装（如 apt install nmap）" >&2
    exit 1
fi

# 读取配置。兼容 Windows CRLF 换行：取值后再去掉行尾 \r
# shellcheck disable=SC1090
source "$CONF_FILE"

PORTS="${PORTS//$'\r'/}"
OUT_DIR="${OUT_DIR//$'\r'/}"
EXTRA_OPTS="${EXTRA_OPTS//$'\r'/}"

PORTS="${PORTS:-22,53}"
OUT_DIR="${OUT_DIR:-scan_result}"
EXTRA_OPTS="${EXTRA_OPTS:--Pn -T4 -n}"

echo "配置文件: $CONF_FILE"
echo "网段文件: $SUBNET_FILE"
echo "扫描端口: $PORTS"
echo "输出目录: $OUT_DIR"

# 临时文件，脚本结束时自动清理
TMP_LOG="$(mktemp)"
TMP_LIST="$(mktemp)"
trap 'rm -f "$TMP_LOG" "$TMP_LIST"' EXIT

# 预处理网段清单：去掉 \r、去掉首尾空白、忽略 # 注释与空行
awk '{
    gsub(/\r/, "");
    gsub(/^[ \t]+|[ \t]+$/, "");
    if ($0 !~ /^#/ && length($0) > 0) print;
}' "$SUBNET_FILE" > "$TMP_LIST"

if [[ ! -s "$TMP_LIST" ]]; then
    echo "错误: 网段文件里没有有效条目（IP/网段）" >&2
    exit 1
fi

# 准备输出目录，并清空上一次的 *_port.txt 结果
mkdir -p "$OUT_DIR"
if compgen -G "${OUT_DIR}"/*_port.txt >/dev/null 2>&1; then
    rm -f -- "${OUT_DIR}"/*_port.txt
fi

# 把 EXTRA_OPTS 拆成参数数组，再执行扫描
extra_opts=()
if [[ -n "$EXTRA_OPTS" ]]; then
    read -r -a extra_opts <<< "$EXTRA_OPTS"
fi

if [[ ${#extra_opts[@]} -gt 0 ]]; then
    if ! nmap "${extra_opts[@]}" -p "$PORTS" -iL "$TMP_LIST" -oG "$TMP_LOG"; then
        echo "警告: nmap 返回非零退出码，继续解析已有输出..." >&2
    fi
else
    if ! nmap -p "$PORTS" -iL "$TMP_LIST" -oG "$TMP_LOG"; then
        echo "警告: nmap 返回非零退出码，继续解析已有输出..." >&2
    fi
fi

# 解析 grepable 输出：只提取 open 的 tcp/udp 端口，写入 <端口>_port.txt
awk -v outdir="$OUT_DIR" '
/^Host:/ && /Ports:/ {
    ip = $2
    line = $0
    sub(/^.*Ports: /, "", line)
    sub(/Ignored State:.*/, "", line)
    while (match(line, /[0-9]+\/open\/(tcp|udp)/)) {
        rec = substr(line, RSTART, RLENGTH)
        split(rec, a, "/")
        port = a[1]
        if (port != "") {
            outfile = outdir "/" port "_port.txt"
            print ip ":" port > outfile
        }
        line = substr(line, RSTART + RLENGTH)
    }
}
' "$TMP_LOG"

# 去重：同一 ip:port 若同时出现 tcp/udp 两条，只保留一行
if compgen -G "${OUT_DIR}"/*_port.txt >/dev/null 2>&1; then
    for f in "${OUT_DIR}"/*_port.txt; do
        sort -u -o "$f" "$f"
    done
fi

# 汇总
echo ""
echo "扫描完成，各端口开放数量:"
found=0
if compgen -G "${OUT_DIR}"/*_port.txt >/dev/null 2>&1; then
    for f in "${OUT_DIR}"/*_port.txt; do
        cnt=$(wc -l < "$f")
        echo "  $f : $cnt"
        found=1
    done
fi

if [[ $found -eq 0 ]]; then
    echo "  没有发现任何开放端口"
fi
