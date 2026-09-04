"""Go 代码生成器 —— 组装模板生成最终 xui.go."""

import os
from pathlib import Path
from typing import List

from .config import GO_SOURCE_FILE, RESULTS_FILE, OUTPUT_FILE

# 模板目录（项目根目录下的 templates/）
_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def _read_template(name: str) -> str:
    """读取模板文件内容."""
    path = _TEMPLATE_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"模板文件不存在: {path}")
    return path.read_text(encoding="utf-8")


def _go_string_list(items: List[str]) -> str:
    """生成 Go 的 []string{...} 字面量."""
    if not items:
        return "[]string{}"

    def _escape(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')

    parts = ['"' + _escape(i) + '"' for i in items]
    return "[]string{" + ", ".join(parts) + "}"


def _go_bool(val: bool) -> str:
    return "true" if val else "false"


# ── 各模式需要的 import ──
# 所有模式共用 + 各模式独有
_MODE_IMPORTS = {
    # 标准库（所有模式都需要）
    "common": [
        "fmt",
        "net/url",
        "os",
        "runtime",
        "strings",
        "sync/atomic",
        "time",
    ],
    # 模式 1-5, 8 (HTTP runner + handler)
    "http": [
        "context",
        "encoding/json",
        "io",
        "net/http",
        "sync",
    ],
    # 模式 6 (SSH runner + handler)
    "ssh": [
        "sync",
        "golang.org/x/crypto/ssh",
    ],
    # 模式 7 (Sub Store runner + handler)
    "substore": [
        "context",
        "io",
        "net/http",
        "sync",
    ],
}


def _build_import_block(mode_id: int) -> str:
    """根据模式 ID 构建 import 块."""
    imports = list(_MODE_IMPORTS["common"])

    if mode_id == 6:
        imports.extend(_MODE_IMPORTS["ssh"])
    elif mode_id == 7:
        imports.extend(_MODE_IMPORTS["substore"])
    else:
        imports.extend(_MODE_IMPORTS["http"])

    # 去重并排序
    imports = sorted(set(imports))

    # 分离标准库和第三方包
    stdlib = [i for i in imports if not i.startswith("golang.org")]
    thirdparty = [i for i in imports if i.startswith("golang.org")]

    lines = ['package main', '', 'import (']
    for imp in stdlib:
        lines.append(f'\t"{imp}"')
    if thirdparty:
        lines.append('')
        for imp in thirdparty:
            lines.append(f'\t"{imp}"')
    lines.append(')')
    lines.append('')
    return '\n'.join(lines)


def generate_for_mode(
    mode_id: int,
    semaphore_size: int,
    batch_size: int,
    usernames: List[str],
    passwords: List[str],
    enable_backdoor: bool = False,
    backdoor_cmds: List[str] = None,
    input_file: str = RESULTS_FILE,
    output_file: str = OUTPUT_FILE,
) -> str:
    """生成完整的 xui.go 内容并写入文件.

    返回生成的文件路径.
    """
    backdoor_cmds = backdoor_cmds or []

    # 读取公共工具函数（不含 package/import）
    common_code = _read_template("common.go.tmpl")

    # 构建 import 块
    header = _build_import_block(mode_id)

    # ── 模式 7 (Sub Store) 独立处理 ──
    if mode_id == 7:
        runner_tmpl = _read_template("runner_substore.go.tmpl")
        handler_code = _read_template("handler_mode7.go.tmpl")
        code = (
            header
            + "\n"
            + common_code
            + "\n"
            + runner_tmpl.replace("{{.SemaphoreSize}}", str(semaphore_size))
            .replace("{{.BatchSize}}", str(batch_size))
            .replace("{{.PassList}}", _go_string_list(passwords))
            .replace("{{.InputFile}}", input_file)
            .replace("{{.OutputFile}}", output_file)
            .replace("{{.HandlerCode}}", handler_code)
        )
    # ── 模式 6 (SSH) 独立处理 ──
    elif mode_id == 6:
        runner_tmpl = _read_template("runner_ssh.go.tmpl")
        handler_code = _read_template("handler_mode6.go.tmpl")
        code = (
            header
            + "\n"
            + common_code
            + "\n"
            + runner_tmpl.replace("{{.SemaphoreSize}}", str(semaphore_size))
            .replace("{{.BatchSize}}", str(batch_size))
            .replace("{{.UserList}}", _go_string_list(usernames))
            .replace("{{.PassList}}", _go_string_list(passwords))
            .replace("{{.InputFile}}", input_file)
            .replace("{{.OutputFile}}", output_file)
            .replace("{{.EnableBackdoor}}", _go_bool(enable_backdoor))
            .replace("{{.BackdoorCmds}}", _go_string_list(backdoor_cmds))
            .replace("{{.HandlerCode}}", handler_code)
        )
    # ── 模式 1-5, 8 使用通用 runner ──
    else:
        runner_tmpl = _read_template("runner_common.go.tmpl")
        handler_file = f"handler_mode{mode_id}.go.tmpl"
        handler_code = _read_template(handler_file)

        code = (
            header
            + "\n"
            + common_code
            + "\n"
            + runner_tmpl.replace("{{.SemaphoreSize}}", str(semaphore_size))
            .replace("{{.BatchSize}}", str(batch_size))
            .replace("{{.UserList}}", _go_string_list(usernames))
            .replace("{{.PassList}}", _go_string_list(passwords))
            .replace("{{.InputFile}}", input_file)
            .replace("{{.OutputFile}}", output_file)
            .replace("{{.HandlerCode}}", handler_code)
        )

    target_path = Path(GO_SOURCE_FILE)
    target_path.write_text(code, encoding="utf-8")
    return str(target_path)


def validate_generated_code() -> bool:
    """快速校验生成的 Go 代码语法（需要 go fmt）。如果 Go 不可用则跳过。"""
    import subprocess
    import shutil

    go_bin = shutil.which("go")
    if not go_bin:
        return True  # 忽略，非 Linux 环境

    result = subprocess.run(
        [go_bin, "fmt", GO_SOURCE_FILE],
        capture_output=True, text=True,
    )
    return result.returncode == 0
