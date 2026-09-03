#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
合规检测 —— HTTP/HTTPS 面板指纹识别（第二段）

只做只读探测：
  1. 对每个 ip:port 先做一次 TCP + TLS 握手判断，能握手就用 HTTPS，
     否则退回 HTTP，因此自签证书的 HTTPS 面板也能识别；
  2. 抓取首页以及特征规则里配置的探测路径（全部 GET，不带任何账号密码）；
  3. 按 title / body / header / 特征路径命中的组合打分，达到阈值的
     主机按服务类型写入独立文件。

用法:
  python3 fingerprint.py --result-dir output
  python3 fingerprint.py --result-dir output --rules rules.conf
"""

import argparse
import configparser
import concurrent.futures
import os
import re
import socket
import ssl
import sys
import time
from urllib import error, request
from urllib.parse import urlparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RULES = os.path.join(SCRIPT_DIR, "../../config/rules.conf")
MAX_BODY = 262144
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


class LimitedRedirectHandler(request.HTTPRedirectHandler):
    """只跟随 http/https 重定向，且最多 4 跳，防止被带偏。"""

    max_redirections = 4

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(newurl).scheme not in ("http", "https"):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_opener():
    return request.build_opener(
        request.ProxyHandler({}),  # 不走系统代理，直连内网目标
        LimitedRedirectHandler(),
        request.HTTPSHandler(context=_SSL_CTX),
    )


OPENER = _build_opener()


def detect_scheme(ip, port, timeout):
    """判断端口上是否跑 TLS。能握手 -> https，否则按 http 尝试。"""
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    with raw:
        raw.settimeout(timeout)
        try:
            with _SSL_CTX.wrap_socket(raw, server_hostname=None) as tls:
                return "https"
        except (ssl.SSLError, OSError, ValueError):
            return "http"


def fetch(ip, port, scheme, path, timeout):
    """GET 抓取一个路径，返回状态码/响应头/正文；任何 4xx/3xx 也照常返回。"""
    url = "{}://{}:{}{}".format(scheme, ip, port, path)
    req = request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        },
    )
    resp = None
    try:
        resp = OPENER.open(req, timeout=timeout)
    except error.HTTPError as exc:
        resp = exc  # 401/403/404 这类响应也有指纹价值
    except Exception:
        return None

    try:
        status = getattr(resp, "status", None)
        if status is None:
            status = getattr(resp, "code", 0)
        header_text = "\n".join(
            "{}: {}".format(k.lower(), v) for k, v in resp.headers.items()
        )
        raw = resp.read(MAX_BODY + 1)
    except Exception:
        return None

    final_url = getattr(resp, "geturl", lambda: url)()
    final_scheme = urlparse(final_url).scheme or scheme

    charset = None
    content_type = resp.headers.get("Content-Type", "")
    m = re.search(r"charset=([\w-]+)", content_type, re.IGNORECASE)
    if m:
        charset = m.group(1)

    body = None
    for enc in (charset, "utf-8", "latin-1"):
        if not enc:
            continue
        try:
            body = raw[:MAX_BODY].decode(enc)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    if body is None:
        body = raw[:MAX_BODY].decode("utf-8", "replace")

    return {
        "status": status,
        "headers": header_text,
        "body": body,
        "scheme": final_scheme,
    }


def _split_patterns(raw):
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def load_rules(path):
    cp = configparser.ConfigParser(interpolation=None)
    cp.read(path, encoding="utf-8")
    rules = []
    for section in cp.sections():
        def get_bool(name, default=False):
            return cp.getboolean(section, name, fallback=default)

        def get_int(name, default=0):
            return cp.getint(section, name, fallback=default)

        rules.append(
            {
                "id": section,
                "name": cp.get(section, "name", fallback=section),
                "title": _split_patterns(cp.get(section, "title", fallback="")),
                "body": _split_patterns(cp.get(section, "body", fallback="")),
                "header": _split_patterns(cp.get(section, "header", fallback="")),
                "probe_path": cp.get(section, "probe_path", fallback="").strip(),
                "probe_body": _split_patterns(cp.get(section, "probe_body", fallback="")),
                "probe_status": {
                    int(x.strip())
                    for x in cp.get(section, "probe_status", fallback="200").split(",")
                    if x.strip().isdigit()
                },
                "probe_any": get_bool("probe_any", False),
                "min_score": get_int("min_score", 3),
            }
        )
    return rules


def _title_of(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not m:
        return ""
    title = re.sub(r"<[^>]+>", "", m.group(1))
    return title.strip()[:200]


def classify_rule(rule, page, ip, port, timeout, min_score_override=None):
    """对单个规则打分。返回 (记录字典) 或 None。"""
    title = _title_of(page["body"])
    body_low = page["body"].lower()
    header_low = page["headers"].lower()
    title_low = title.lower()

    score = 0
    reasons = []

    def add_hits(kind, patterns, text, weight):
        nonlocal score
        for pattern in patterns:
            if pattern in text:
                score += weight
                reasons.append("{}={}".format(kind, pattern))
                break

    add_hits("title", rule["title"], title_low, 3)
    add_hits("body", rule["body"], body_low, 2)
    add_hits("header", rule["header"], header_low, 1)

    # 首页没有任何线索、且规则没开 probe_any 时，不做额外探测，省流量
    if rule["probe_path"] and (rule["probe_any"] or score > 0):
        probe_page = fetch(ip, port, page["scheme"], rule["probe_path"], timeout)
        if probe_page is not None:
            probe_status = probe_page["status"]
            probe_text = (probe_page["headers"] + "\n" + probe_page["body"]).lower()
            if probe_status in rule["probe_status"]:
                for pattern in rule["probe_body"]:
                    if pattern in probe_text:
                        score += 3
                        reasons.append(
                            "probe={}({})={}".format(
                                rule["probe_path"], probe_status, pattern
                            )
                        )
                        break

    threshold = rule["min_score"]
    if min_score_override is not None:
        threshold = max(threshold, min_score_override)
    if score < threshold:
        return None

    return {
        "ip": ip,
        "port": port,
        "scheme": page["scheme"],
        "service_id": rule["id"],
        "service_name": rule["name"],
        "score": score,
        "reasons": "; ".join(reasons) if reasons else "matched-by-score",
        "title": title,
    }


def scan_one(target, rules, timeout, min_score_override):
    ip, port = target
    scheme = detect_scheme(ip, port, timeout)
    if scheme is None:
        return []
    page = fetch(ip, port, scheme, "/", timeout)
    if page is None:
        return []

    found = []
    for rule in rules:
        hit = classify_rule(rule, page, ip, port, timeout, min_score_override)
        if hit is not None:
            found.append(hit)
    return found


def collect_targets(result_dir, skip_ports):
    targets = set()
    if not os.path.isdir(result_dir):
        return targets
    for filename in sorted(os.listdir(result_dir)):
        if not filename.endswith("_port.txt"):
            continue
        filepath = os.path.join(result_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("["):  # 暂不支持 IPv6
                        continue
                    ip, _, port = line.rpartition(":")
                    if not ip or not port.isdigit():
                        continue
                    port_int = int(port)
                    if port_int in skip_ports:
                        continue
                    targets.add((ip, port_int))
        except OSError:
            continue
    return sorted(targets)


def write_results(out_dir, hits):
    os.makedirs(out_dir, exist_ok=True)
    # 清空上一次指纹结果（只删本目录内的普通结果文件）
    for filename in os.listdir(out_dir):
        filepath = os.path.join(out_dir, filename)
        if os.path.isfile(filepath) and (
            filename.endswith(".txt") or filename.endswith(".tsv")
        ):
            os.remove(filepath)

    by_service = {}
    details_path = os.path.join(out_dir, "details.tsv")
    with open(details_path, "w", encoding="utf-8") as details:
        details.write("ip\tport\tscheme\tservice\tscore\treasons\ttitle\n")
        for hit in hits:
            by_service.setdefault(hit["service_id"], set()).add(
                "{}:{}".format(hit["ip"], hit["port"])
            )
            details.write(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\n".format(
                    hit["ip"],
                    hit["port"],
                    hit["scheme"],
                    hit["service_name"],
                    hit["score"],
                    hit["reasons"],
                    hit["title"].replace("\t", " ").replace("\n", " "),
                )
            )

    summary = []
    for service_id in sorted(by_service):
        out_path = os.path.join(out_dir, service_id + ".txt")
        lines = sorted(by_service[service_id])
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + ("\n" if lines else ""))
        summary.append("  {} : {} 台".format(out_path, len(lines)))

    return summary, details_path


def main():
    parser = argparse.ArgumentParser(description="HTTP/HTTPS 面板指纹识别")
    parser.add_argument(
        "--result-dir",
        default="output",
        help="nmap 输出目录（存放 *_port.txt），默认 output",
    )
    parser.add_argument("--rules", default=DEFAULT_RULES, help="指纹规则文件")
    parser.add_argument(
        "--out-dir",
        default=None,
        help="指纹结果目录，默认 <result-dir>/fingerprint",
    )
    parser.add_argument("--threads", type=int, default=32, help="并发数，默认 32")
    parser.add_argument("--timeout", type=float, default=4.0, help="单次连接超时秒数")
    parser.add_argument(
        "--skip-ports",
        default="22,53",
        help="跳过这些端口（默认 22,53，不是 HTTP 服务，省时间）",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=None,
        help="全局最低分覆盖（只会更严格，不会更宽松）",
    )
    args = parser.parse_args()

    rules_path = args.rules
    if not os.path.exists(rules_path):
        print("错误: 找不到规则文件 {}".format(rules_path), file=sys.stderr)
        return 1
    rules = load_rules(rules_path)
    if not rules:
        print("错误: 规则文件里没有任何 [服务] 段", file=sys.stderr)
        return 1

    skip_ports = {
        int(x.strip()) for x in args.skip_ports.split(",") if x.strip().isdigit()
    }
    targets = collect_targets(args.result_dir, skip_ports)
    print("规则文件: {}".format(rules_path))
    print("输入目录: {}".format(args.result_dir))
    print("待识别目标: {} 个（已跳过端口: {}）".format(len(targets), sorted(skip_ports)))
    if not targets:
        print("没有可识别的目标，请先运行 scan_ports.sh")
        return 0

    start = time.time()
    hits = []
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(
                scan_one, target, rules, args.timeout, args.min_score
            ): target
            for target in targets
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                hits.extend(future.result())
            except Exception as exc:  # 单个目标异常不中断整体
                print("警告: {} 识别失败: {}".format(futures[future], exc))
            done += 1
            if done % 100 == 0 or done == len(targets):
                print("  进度: {}/{}".format(done, len(targets)))

    out_dir = args.out_dir or os.path.join(args.result_dir, "fingerprint")
    summary, details_path = write_results(out_dir, hits)

    print("")
    print("识别完成，耗时 {:.1f}s".format(time.time() - start))
    print("详情: {}".format(details_path))
    if summary:
        print("命中（ip:port 每行一个，按服务分文件）:")
        for line in summary:
            print(line)
    else:
        print("未识别到规则库中的服务")
    return 0


if __name__ == "__main__":
    sys.exit(main())
