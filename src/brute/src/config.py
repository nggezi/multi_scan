"""配置加载器 —— config.yaml + 环境变量双层覆盖.

优先级: 环境变量 > config.yaml > 代码默认值

config.yaml 放在项目根目录，改完即生效，不需要改 Python.
零外部依赖，不装 pyyaml 也能用.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict

# ── 代码级别默认值（最后兜底）─────────────────────────────
_DEFAULTS: Dict[str, Any] = {
    "XUI_MODE": 0,
    "XUI_INPUT_FILE": "1.txt",
    "XUI_LINES_PER_FILE": 5000,
    "XUI_SLEEP_SECONDS": 2,
    "XUI_THREADS": 250,
    "XUI_BATCH_SIZE": 1000,
    "XUI_USERNAME_FILE": "",
    "XUI_PASSWORD_FILE": "",
    "XUI_BACKDOOR": False,
    "XUI_BACKDOOR_CMD_FILE": "后门命令.txt",
    "XUI_NO_EXCEL": False,
    "TG_BOT_TOKEN": "",
    "TG_CHAT_ID": "",
    "GOPROXY": "",
    "GOSUMDB": "",
}


def _find_config_yaml() -> Path | None:
    """查找 config.yaml."""
    # 优先级: scan/config/ > brute/ > CWD
    scan_root = Path(__file__).resolve().parent.parent.parent.parent
    config_dir = scan_root / "config"
    brute_dir = Path(__file__).resolve().parent.parent
    candidates = [
        config_dir / "config.yaml",
        brute_dir / "config.yaml",
        Path.cwd() / "config.yaml",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def _parse_yaml_value(raw: str) -> Any:
    """解析单行 YAML 值: 数字、布尔、字符串."""
    raw = raw.strip()

    # 带引号的字符串
    if (raw.startswith('"') and raw.endswith('"')) or \
       (raw.startswith("'") and raw.endswith("'")):
        return raw[1:-1]

    # 布尔
    low = raw.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "none", "~"):
        return None

    # 整数
    try:
        return int(raw)
    except ValueError:
        pass

    # 浮点
    try:
        return float(raw)
    except ValueError:
        pass

    # 普通字符串
    return raw


def _load_yaml_file(path: Path) -> Dict[str, Any]:
    """读取 config.yaml 并返回键值对字典.

    支持两种格式:
      1. 单行: KEY: value
      2. 多行列表: KEY:\n  item1\n  item2  (缩进的续行作为列表项)
    """
    result: Dict[str, Any] = {}
    if not path.exists():
        return result

    lines = path.read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        # 跳过注释和空行
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        # 解析 key: value
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", stripped)
        if match:
            key = match.group(1)
            value_str = match.group(2).strip()

            if value_str == "":
                # 可能是多行列表，收集缩进续行
                items = []
                i += 1
                while i < len(lines):
                    next_line = lines[i]
                    # 空行结束列表
                    if next_line.strip() == "":
                        break
                    # 缩进行是列表项
                    if next_line.startswith("  ") or next_line.startswith("\t"):
                        item = next_line.strip()
                        if item and not item.startswith("#"):
                            items.append(item)
                        i += 1
                    else:
                        break
                result[key] = items if items else value_str
                continue
            else:
                result[key] = _parse_yaml_value(value_str)

        i += 1

    return result


def _load_env_overrides() -> Dict[str, Any]:
    """从环境变量读取覆盖值."""
    overrides: Dict[str, Any] = {}
    for key in _DEFAULTS:
        env_val = os.environ.get(key, "")
        if env_val == "":
            continue
        # 根据默认值类型转换
        default = _DEFAULTS[key]
        if isinstance(default, bool):
            overrides[key] = env_val.strip().lower() in ("true", "1", "yes", "y", "on")
        elif isinstance(default, int):
            try:
                overrides[key] = int(env_val)
            except ValueError:
                pass
        else:
            overrides[key] = env_val
    return overrides


def _merge() -> Dict[str, Any]:
    """三级合并: 默认值 ← config.yaml ← 环境变量."""
    merged = dict(_DEFAULTS)

    yaml_path = _find_config_yaml()
    if yaml_path:
        yaml_data = _load_yaml_file(yaml_path)
        merged.update(yaml_data)

    env_data = _load_env_overrides()
    merged.update(env_data)

    return merged


# ── 模块加载时执行合并，导出为模块属性 ────────────────────
_cfg = _merge()

MODE: int = _cfg["XUI_MODE"]
INPUT_FILE: str = _cfg["XUI_INPUT_FILE"]
LINES_PER_FILE: int = _cfg["XUI_LINES_PER_FILE"]
SLEEP_SECONDS: int = _cfg["XUI_SLEEP_SECONDS"]
THREADS: int = _cfg["XUI_THREADS"]
BATCH_SIZE: int = _cfg["XUI_BATCH_SIZE"]
USERNAME_FILE: str = _cfg["XUI_USERNAME_FILE"]
PASSWORD_FILE: str = _cfg["XUI_PASSWORD_FILE"]
ENABLE_BACKDOOR: bool = _cfg["XUI_BACKDOOR"]
BACKDOOR_CMD_FILE: str = _cfg["XUI_BACKDOOR_CMD_FILE"]
NO_EXCEL: bool = _cfg["XUI_NO_EXCEL"]
TELEGRAM_BOT_TOKEN: str = _cfg["TG_BOT_TOKEN"]
TELEGRAM_CHAT_ID: str = _cfg["TG_CHAT_ID"]
GOPROXY: str = _cfg["GOPROXY"]
GOSUMDB: str = _cfg["GOSUMDB"]


def _parse_subnet_urls(raw) -> dict:
    """解析 SUBNET_URLS 配置为 {别名: URL} 字典.

    支持:
      - 多行列表: ["别名|URL", ...]
      - 单行逗号分隔: "别名1|URL1,别名2|URL2"
    """
    entries = {}
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, str) and raw.strip():
        items = [s.strip() for s in raw.split(",") if s.strip()]
    else:
        return entries

    for item in items:
        if "|" in item:
            alias, url = item.split("|", 1)
            entries[alias.strip()] = url.strip()
        else:
            # 没有别名，用 URL 本身作标识
            entries[item.strip()] = item.strip()
    return entries


SUBNET_URLS: dict = _parse_subnet_urls(_cfg.get("SUBNET_URLS", []))

# ── 面板模式常量（不可配置，纯常量）───────────────────────
PANEL_MODES = {
    1: "XUI面板",
    2: "哪吒面板",
    3: "HUI面板",
    4: "咸蛋面板",
    5: "SUI面板",
    6: "SSH",
    7: "Sub Store",
    8: "OpenWrt/iStoreOS",
}

DEFAULT_CREDENTIALS = {
    1: (["admin"], ["admin"]),
    2: (["admin"], ["admin"]),
    3: (["sysadmin"], ["sysadmin"]),
    4: (["admin"], ["admin"]),
    5: (["admin"], ["admin"]),
    6: (["root"], ["password"]),
    7: (["admin"], ["admin"]),
    8: (["root"], ["password"]),
}

OUTPUT_PREFIX = {
    1: "XUI",
    2: "哪吒",
    3: "HUI",
    4: "咸蛋",
    5: "SUI",
    6: "ssh",
    7: "substore",
    8: "OpenWrt",
}

# ── 内部常量 ──────────────────────────────────────────────
TEMP_PART_DIR = "temp_parts"
TEMP_XUI_DIR = "xui_outputs"
TEMP_HMSUCCESS_DIR = "temp_hmsuccess"
TEMP_HMFAIL_DIR = "temp_hmfail"
GO_SOURCE_FILE = "xui.go"
RESULTS_FILE = "results.txt"
OUTPUT_FILE = "xui.txt"
HTTP_TIMEOUT = 3
SSH_TIMEOUT = 2


def dump() -> dict:
    """导出当前生效的全部配置（Token 脱敏）."""
    yaml_path = _find_config_yaml()
    return {
        "config_yaml": str(yaml_path) if yaml_path else "(not found)",
        "MODE": MODE or "(interactive)",
        "INPUT_FILE": INPUT_FILE,
        "THREADS": THREADS,
        "BATCH_SIZE": BATCH_SIZE,
        "LINES_PER_FILE": LINES_PER_FILE,
        "SLEEP_SECONDS": SLEEP_SECONDS,
        "USERNAME_FILE": USERNAME_FILE or "(default)",
        "PASSWORD_FILE": PASSWORD_FILE or "(default)",
        "ENABLE_BACKDOOR": ENABLE_BACKDOOR,
        "BACKDOOR_CMD_FILE": BACKDOOR_CMD_FILE,
        "NO_EXCEL": NO_EXCEL,
        "TELEGRAM_BOT_TOKEN": "***" if TELEGRAM_BOT_TOKEN else "(unset)",
        "TELEGRAM_CHAT_ID": "***" if TELEGRAM_CHAT_ID else "(unset)",
        "GOPROXY": GOPROXY or "(auto-detect)",
        "GOSUMDB": GOSUMDB or "(auto-detect)",
    }
