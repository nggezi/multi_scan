#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
本地自检（不需要 nmap、不需要目标机器）：
在 127.0.0.1 上起几个模拟 HTTP/HTTPS 服务，喂给 fingerprint.py，
验证它能把 X-UI、Sub-Store、OpenWrt 区分出来，并且 HTTPS 目标也能识别。

用法: python3 selftest.py
"""

import http.server
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FP_PATH = os.path.join(SCRIPT_DIR, "fingerprint.py")

XUI_HTML = (
    b"<!doctype html><html><head><meta charset=\"utf-8\"><title>X-UI</title></head>"
    b"<body><div id=\"app\">x-ui login</div></body></html>"
)
XUI_JSON = b'{"msg":"\\u672a\\u767b\\u5f55"}'

SUBSTORE_HTML = (
    b"<!doctype html><html><head><title>Sub-Store</title></head>"
    b"<body><div>sub-store backend</div></body></html>"
)
SUBSTORE_JSON = b'{"status":"success","data":{}}'

OPENWRT_HTML = (
    b"<!doctype html><html><head><title>OpenWrt</title></head>"
    b"<body>LuCI - Lua Configuration Interface</body></html>"
)
LUCI_HTML = b"<!doctype html><html><head><title>LuCI</title></head><body>luci</body></html>"


def make_handler(pages):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            entry = pages.get(self.path)
            if entry is None:
                self.send_response(404)
                self.end_headers()
                return
            body, code = entry
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    return Handler


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_server(pages, use_tls=False, cert=None, key=None):
    port = free_port()
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", port), make_handler(pages)
    )
    if use_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def make_cert(tmp_dir):
    openssl = shutil.which("openssl")
    if not openssl:
        # Windows 上 Git 自带 openssl 但可能不在 PATH 里
        for candidate in (
            "/usr/bin/openssl",
            r"C:\Program Files\Git\usr\bin\openssl.exe",
            r"D:\Program Files\Git\usr\bin\openssl.exe",
        ):
            if os.path.exists(candidate):
                openssl = candidate
                break
    if not openssl:
        return None, None
    cert = os.path.join(tmp_dir, "cert.pem")
    key = os.path.join(tmp_dir, "key.pem")
    subprocess.run(
        [
            openssl, "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key, "-out", cert, "-days", "1", "-nodes",
            "-subj", "/CN=localhost",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert, key


def write_port_file(result_dir, port):
    path = os.path.join(result_dir, "{}_port.txt".format(port))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("127.0.0.1:{}\n".format(port))


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


def main():
    servers = []
    try:
        with tempfile.TemporaryDirectory(prefix="fp_selftest_") as tmp_dir:
            cert, key = make_cert(tmp_dir)

            # HTTP X-UI（验证明文 HTTP 能识别）
            xui_pages = {"/": (XUI_HTML, 200), "/xui/inbound/list": (XUI_JSON, 200)}
            srv_xui, port_xui = start_server(xui_pages)
            servers.append(srv_xui)

            # HTTPS X-UI（验证自签证书的 HTTPS 也能识别）
            if cert:
                srv_https, port_https = start_server(xui_pages, True, cert, key)
                servers.append(srv_https)
            else:
                port_https = None
                print("提示: 未找到 openssl，跳过 HTTPS 模拟")

            # Sub-Store
            sub_pages = {
                "/": (SUBSTORE_HTML, 200),
                "/api/utils/env": (SUBSTORE_JSON, 200),
            }
            srv_sub, port_sub = start_server(sub_pages)
            servers.append(srv_sub)

            # OpenWrt / LuCI
            luci_pages = {
                "/": (OPENWRT_HTML, 200),
                "/cgi-bin/luci/": (LUCI_HTML, 200),
            }
            srv_luci, port_luci = start_server(luci_pages)
            servers.append(srv_luci)

            result_dir = os.path.join(tmp_dir, "scan_result")
            os.makedirs(result_dir, exist_ok=True)
            for port in (
                port_xui,
                port_https,
                port_sub,
                port_luci,
            ):
                if port:
                    write_port_file(result_dir, port)

            print("模拟服务已启动:")
            print("  http  X-UI      :{}".format(port_xui))
            print("  https X-UI      :{}".format(port_https or "跳过"))
            print("  http  Sub-Store :{}".format(port_sub))
            print("  http  OpenWrt   :{}".format(port_luci))
            print("")

            proc = subprocess.run(
                [
                    sys.executable, FP_PATH,
                    "--result-dir", result_dir,
                    "--threads", "4",
                    "--timeout", "3",
                    "--skip-ports", "",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            print(proc.stdout)
            if proc.stderr:
                print(proc.stderr, file=sys.stderr)
            if proc.returncode != 0:
                print("自检失败: fingerprint.py 退出码 {}".format(proc.returncode))
                return 1

            fp_dir = os.path.join(result_dir, "fingerprint")
            xui_hits = read_lines(os.path.join(fp_dir, "x-ui.txt"))
            sub_hits = read_lines(os.path.join(fp_dir, "substore.txt"))
            luci_hits = read_lines(os.path.join(fp_dir, "openwrt.txt"))

            target_xui_http = "127.0.0.1:{}".format(port_xui)
            target_sub = "127.0.0.1:{}".format(port_sub)
            target_luci = "127.0.0.1:{}".format(port_luci)

            ok = True
            for label, hits, target in (
                ("X-UI(HTTP)", xui_hits, target_xui_http),
                ("Sub-Store", sub_hits, target_sub),
                ("OpenWrt", luci_hits, target_luci),
            ):
                if target in hits:
                    print("PASS {} 命中 {}".format(label, target))
                else:
                    print("FAIL {} 未命中 {}".format(label, target))
                    ok = False

            if port_https:
                target_https = "127.0.0.1:{}".format(port_https)
                if target_https in xui_hits:
                    print("PASS X-UI(HTTPS) 命中 {}".format(target_https))
                else:
                    print("FAIL X-UI(HTTPS) 未命中 {}".format(target_https))
                    ok = False

                details = os.path.join(fp_dir, "details.tsv")
                scheme_lines = []
                with open(details, "r", encoding="utf-8") as fh:
                    for line in fh:
                        parts = line.rstrip("\n").split("\t")
                        if (
                            len(parts) >= 3
                            and parts[0] == "127.0.0.1"
                            and parts[1] == str(port_https)
                        ):
                            scheme_lines.append(parts[2])
                if "https" in scheme_lines:
                    print("PASS HTTPS 目标 scheme 被识别为 https")
                else:
                    print("FAIL HTTPS 目标 scheme 不是 https: {}".format(scheme_lines))
                    ok = False

            return 0 if ok else 1
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    sys.exit(main())
