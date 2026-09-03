# Multi-Scan

端口扫描 + 端口映射 + 自动爆破，一键完成。

## 快速开始

```bash
# 1. 安装依赖（首次）
bash setup.sh

# 2. 准备网段文件（每行一个 IP/网段）
cp config/subnets.example.txt my_subnets.txt
# 编辑 my_subnets.txt 填入目标

# 3. 一键执行
bash scan_all.sh my_subnets.txt
```

## 目录结构

```
scan/
├── scan_all.sh                  # 统一入口
├── setup.sh                     # 依赖安装脚本
├── config/
│   ├── ports.conf               # 端口扫描配置
│   ├── rules.conf               # 指纹识别规则（备用）
│   ├── config.yaml              # 爆破参数配置
│   └── subnets.example.txt     # 网段示例
├── src/
│   ├── scanner/                 # 扫描模块
│   │   ├── scan_ports.sh       # nmap 端口扫描
│   │   └── fingerprint.py      # HTTP/HTTPS 指纹识别
│   └── brute/                   # 爆破模块
│       ├── main.py             # 入口
│       ├── config.yaml         # 爆破配置
│       ├── src/                # Python 源码
│       └── templates/          # Go 代码模板
└── output/
    ├── ports/                  # 端口扫描结果（每次覆盖）
    └── brute/
        ├── latest/             # 最新爆破结果
        └── history/            # 历史记录（保留 3 个）
```

## 端口→模式映射

根据扫描到的端口号自动匹配爆破模式：

| 端口 | 爆破模式 | 对应服务 |
|------|----------|----------|
| 22 | 6 | SSH |
| 80 | 1,2,3,4,5,7,8 | 所有 Web 面板 |
| 443 | 1,2,3,4,5,7,8 | 所有 Web 面板 |
| 8080 | 1,2,3,4,5,7,8 | 所有 Web 面板 |
| 8443 | 1,2,3,4,5,7,8 | 所有 Web 面板 |
| 2053 | 1 | 3x-ui 默认端口 |
| 2083 | 1 | Cloudflare 端口 |
| 2087 | 1 | Cloudflare 端口 |
| 2095 | 5 | S-UI 面板端口 |
| 2096 | 5 | S-UI 订阅端口 |
| 54321 | 1 | X-UI 原始默认端口 |
| 8008 | 2 | 哪吒监控默认端口 |
| 3000 | 2,7 | 哪吒 / Sub-Store |
| 3001 | 7 | Sub-Store 默认端口 |

共享端口（80/443/8080/8443）会同时尝试所有面板模式，确保不遗漏。

## 支持的模式

| 模式 | 服务 | 说明 |
|------|------|------|
| 1 | X-UI / 3x-ui | POST /login |
| 2 | 哪吒监控 | POST /api/v1/login |
| 3 | HUI | POST /hui/auth/login |
| 4 | 咸蛋 / Xboard | POST /login |
| 5 | SUI | POST /app/api/login |
| 6 | SSH | SSH 直连 + 蜜罐检测 |
| 7 | Sub-Store | GET 路径探测 |
| 8 | OpenWrt | POST /cgi-bin/luci/ |

## 配置说明

### config.yaml（爆破参数）

```yaml
# 并发线程数（建议 100~500）
XUI_THREADS: 250

# 每批处理数量
XUI_BATCH_SIZE: 1000

# 输入文件分片行数（内存小改小）
XUI_LINES_PER_FILE: 5000

# 分片间冷却时间（秒）
XUI_SLEEP_SECONDS: 2
```

### ports.conf（端口扫描）

```bash
PORTS="22,53,80,443,8080,8443,2053,2083,2087,2096,54321,8008,3000"
EXTRA_OPTS="-Pn -T4 -n"
```

## 单独使用各模块

### 仅端口扫描

```bash
bash src/scanner/scan_ports.sh subnets.txt
# 结果在 output/ports/
```

### 仅爆破

```bash
cd src/brute
python3 main.py -m 1 -i targets.txt
```

## 依赖

- nmap（端口扫描）
- Python 3.6+ 及 requests, openpyxl 模块
- Go 1.20+（爆破模块编译）

Linux 下运行 `bash setup.sh` 自动安装所有依赖。

## 项目结构

- 端口扫描：`src/scanner/scan_ports.sh`
- 爆破引擎：`src/brute/`（Go + Python 混合，生成 Go 代码并发爆破）
- 输出目录：`output/brute/latest/`（最新结果）、`output/brute/history/`（历史，保留 3 个）
