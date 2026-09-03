# 综合扫描+爆破工具

端口扫描 → 指纹识别 → 自动匹配爆破模式，一键完成。

## 快速开始

```bash
# 准备网段文件（每行一个 IP/网段）
cp config/subnets.example.txt my_subnets.txt
# 编辑 my_subnets.txt 填入目标

# 一键执行：扫描 + 指纹 + 爆破
bash scan_all.sh my_subnets.txt

# 强制指定模式（跳过指纹识别）
bash scan_all.sh my_subnets.txt 1    # XUI
bash scan_all.sh my_subnets.txt 6    # SSH
```

## 目录结构

```
scan/
├── scan_all.sh                  # 统一入口
├── config/
│   ├── ports.conf               # 端口扫描配置
│   ├── rules.conf               # 指纹识别规则
│   ├── config.yaml              # 爆破参数配置
│   └── subnets.example.txt     # 网段示例
├── src/
│   ├── scanner/                 # 扫描模块
│   │   ├── scan_ports.sh       # nmap 端口扫描
│   │   ├── fingerprint.py      # HTTP/HTTPS 指纹识别
│   │   └── selftest.py         # 本地自检
│   └── brute/                   # 爆破模块
│       ├── main.py             # 入口
│       ├── config.yaml         # 爆破配置
│       ├── src/                # Python 源码
│       └── templates/          # Go 代码模板
└── output/
    ├── ports/                  # 端口扫描结果（每次覆盖）
    ├── fingerprint/            # 指纹识别结果（每次覆盖）
    └── brute/
        ├── latest/             # 最新爆破结果
        └── history/            # 历史记录（保留 3 个）
```

## 支持的模式

| 模式 | 服务 | 指纹文件 | 说明 |
|------|------|----------|------|
| 1 | X-UI / 3x-ui | x-ui.txt | POST /login |
| 2 | 哪吒监控 | nezha.txt | POST /api/v1/login |
| 3 | HUI | hui.txt | POST /hui/auth/login |
| 4 | 咸蛋 / Xboard | xiandan.txt | POST /login |
| 5 | SUI | sui.txt | POST /app/api/login |
| 6 | SSH | (无指纹) | 需手动指定 |
| 7 | Sub-Store | substore.txt | GET 路径探测 |
| 8 | OpenWrt | openwrt.txt | POST /cgi-bin/luci/ |

## 配置说明

### ports.conf（端口扫描）

```bash
# 修改扫描端口
PORTS="22,80,443,8080,54321"

# 修改 nmap 参数
EXTRA_OPTS="-Pn -T4 -n"
```

### config.yaml（爆破参数）

```bash
# 并发数
XUI_THREADS: 250

# 每批数量
XUI_BATCH_SIZE: 1000

# 输入文件行数分片
XUI_LINES_PER_FILE: 5000
```

### rules.conf（指纹规则）

新增服务指纹，参考现有格式添加 `[section]`。

## SSH 爆破

SSH 没有指纹识别，需要手动指定：

```bash
# 方式 1: 强制模式 6
bash scan_all.sh subnets.txt 6

# 方式 2: 准备 SSH 目标文件
echo "192.168.1.1:22" > ssh_targets.txt
cd src/brute
python3 main.py -m 6 -i ssh_targets.txt
```

## 单独使用各模块

### 仅端口扫描

```bash
bash src/scanner/scan_ports.sh subnets.txt
# 结果在 output/ports/
```

### 仅指纹识别

```bash
python3 src/scanner/fingerprint.py --result-dir output/ports/ --out-dir output/fingerprint/
# 结果在 output/fingerprint/
```

### 仅爆破

```bash
cd src/brute
python3 main.py -m 1 -i targets.txt
```

## 依赖

- nmap（端口扫描）
- Python 3.6+
- Go 1.20+（爆破模块）
- requests, openpyxl（Python 模块）

Linux 下会自动检测并安装缺失依赖。
