#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
家宽优选节点生成器 v2（对应博客 2026-10「重大升级」版规格）

工作流：
  1. 从 OPTIMAL_API（优选测速接口，逗号分隔可多个）拉取按运营商测速后的
     Cloudflare 优选 IP，逐个做 TCP+TLS 握手探测（SNI=你的 edgetunnel 域名），
     按延迟排序保留最快的；
  2. 合并 EDGE_HOSTS（静态优选域名/IP 池，逗号分隔，须带端口），同样探测；
  3. 尝试抓取 VPN Gate 公开节点列表，筛选支持 SSTP 的高分节点并做 443 端口
     存活探测（被反爬时自动降级跳过，不影响主流程）；
  4. 输出到 public/：
       nodes.txt —— 博客版格式，可直接粘贴进 edgetunnel 后台「自定义优选IP」
                    （家宽行备注内含 $sstp:// 链式代理，出口为住宅 IP）
       sub.txt   —— base64 订阅，可直接填进 v2rayN / Shadowrocket / Clash / sing-box
       index.html —— 状态页

Fork 后必须修改的 3 处（与博客一致，均可用环境变量覆盖）：
  ① EDGE_HOSTS   —— 静态优选域名/IP（每个带端口，逗号分隔）
  ② OPTIMAL_API  —— 优选测速接口（多个逗号分隔）
  ③ NODES_URL    —— 你的 GitHub Pages nodes.txt 地址（工作流会自动拼，无需手改）

另外需要在仓库 Secrets 里设置（订阅/家宽链式编码用）：
  EDT_UUID   —— 你的 edgetunnel UUID
  EDT_DOMAIN —— 你的 edgetunnel 绑定域名（如 node.sungongqin.com）
"""

import base64
import csv
import io
import json
import os
import re
import socket
import ssl
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

# ---------------------------------------------------------------- 配置区 ----
# ① 静态优选域名（每个地址须带端口，逗号分隔）
EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        "saas.sin.fan:443,cdn.204910.best:443,cf.877774.xyz:443",
    ).split(",")
    if h.strip()
]

# ② 优选 API（支持多个，英文逗号分隔；按运营商给不同接口即可）
OPTIMAL_API = os.environ.get(
    "OPTIMAL_API",
    "https://cf.090227.xyz/ct?ips=6&port=443,"
    "https://cf.090227.xyz/cu?port=443,"
    "https://cf.090227.xyz/cmcc?ips=8&port=443",
)

# ③ nodes.txt 地址（工作流会自动按 仓库拥有者/仓库名 拼出正确地址）
NODES_URL = os.environ.get(
    "NODES_URL", "https://YOUR_GITHUB_USERNAME.github.io/gate/nodes.txt"
)

EDT_UUID = os.environ.get("EDT_UUID", "").strip()
EDT_DOMAIN = os.environ.get("EDT_DOMAIN", "").strip()

VPN_GATE_API = "https://www.vpngate.net/api/iphone/"
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")

PROBE_TIMEOUT = 4          # 单次探测超时（秒）
PROBE_WORKERS = 32         # 并发探测数
MAX_DIRECT = 24            # 直连优选节点上限
MAX_HOME = 12              # 家宽（SSTP 链式）节点上限

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")


# ---------------------------------------------------------------- 工具 ----
def log(msg):
    ts = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def http_get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")


def parse_host_line(line):
    """解析 'IP' / 'IP:port' / 'domain:port' + 可选 '#备注'。"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    remark = ""
    if "#" in line:
        line, remark = line.split("#", 1)
        remark = remark.strip()
    if ":" in line and not line.startswith("["):
        # 域名或 IPv4 带端口（IPv6 要求方括号，优选 API 不返回裸 v6）
        host, _, port = line.rpartition(":")
        port = port.strip()
        if not port.isdigit():
            return None
    else:
        host, port = line, "443"
    host = host.strip()
    if not host:
        return None
    return (host, port, remark)


def probe_tls(host, port, sni):
    """TCP 连接 + TLS 握手（SNI=edgetunnel 域名），返回延迟秒数，失败返回 None。"""
    start = time.monotonic()
    try:
        raw = socket.create_connection((host, int(port)), timeout=PROBE_TIMEOUT)
    except OSError:
        return None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw.settimeout(PROBE_TIMEOUT)
        with ctx.wrap_socket(raw, server_hostname=sni or host):
            pass
        return time.monotonic() - start
    except (OSError, ssl.SSLError):
        return None
    finally:
        try:
            raw.close()
        except OSError:
            pass


def probe_many(candidates, sni):
    """candidates: [(host, port, remark)] -> [(host, port, remark, latency)] 存活且按延迟排序。"""
    results = []
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
        fut = {ex.submit(probe_tls, h, p, sni): (h, p, r) for h, p, r in candidates}
        for f in as_completed(fut):
            h, p, r = fut[f]
            try:
                lat = f.result()
            except Exception:
                lat = None
            if lat is not None:
                results.append((h, p, r, lat))
    results.sort(key=lambda x: x[3])
    return results


# ---------------------------------------------------------------- 数据源 ----
def fetch_optimal_apis():
    """从优选 API 拉取测速后的 IP。返回 [(host, port, remark)]。"""
    cands = []
    for api in [u.strip() for u in OPTIMAL_API.split(",") if u.strip()]:
        try:
            text = http_get(api)
            n = 0
            for line in text.splitlines():
                parsed = parse_host_line(line)
                if parsed:
                    cands.append(parsed)
                    n += 1
            log(f"优选 API 取到 {n} 个候选：{api[:60]}")
        except Exception as e:
            log(f"优选 API 失败（跳过）：{api[:60]} … {e}")
    # 去重
    seen, uniq = set(), []
    for h, p, r in cands:
        if (h, p) not in seen:
            seen.add((h, p))
            uniq.append((h, p, r))
    return uniq


def fetch_edge_hosts():
    cands = []
    for h in EDGE_HOSTS:
        parsed = parse_host_line(h)
        if parsed:
            cands.append(parsed)
    return cands


def fetch_vpngate():
    """抓取 VPN Gate 公开列表，返回 [(ip, country_short)]（按分数排序）。被反爬则返回 []。"""
    try:
        text = http_get(VPN_GATE_API, timeout=30)
    except Exception as e:
        log(f"VPN Gate 抓取失败（自动降级，本次无家宽节点）：{e}")
        return []
    rows = []
    try:
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            if not row or row[0].startswith("*") or row[0].startswith("#"):
                continue
            try:
                ip = row[1].strip()
                score = int(row[2])
                ping = int(row[3])
                cc = row[6].strip()
            except (IndexError, ValueError):
                continue
            if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
                continue
            if ping > 400:
                continue
            rows.append((score, ip, cc))
    except Exception as e:
        log(f"VPN Gate 解析失败（降级）：{e}")
        return []
    rows.sort(reverse=True)
    log(f"VPN Gate 取到 {len(rows)} 个候选服务器")
    return [(ip, cc) for _, ip, cc in rows[:40]]


def check_sstp_alive(host):
    """443 端口能完成 TLS 握手即视为 SSTP 可达（SSTP 跑在 443/TLS 上）。

    返回延迟秒数；失败返回 None。注意 VPN Gate 证书多为自签名，只验证握手成功。
    """
    start = time.monotonic()
    try:
        raw = socket.create_connection((host, 443), timeout=PROBE_TIMEOUT)
    except OSError:
        return None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw.settimeout(PROBE_TIMEOUT)
        with ctx.wrap_socket(raw, server_hostname=host):
            pass
        return time.monotonic() - start
    except (OSError, ssl.SSLError):
        return None
    finally:
        try:
            raw.close()
        except OSError:
            pass


# ---------------------------------------------------------------- 编码 ----
def b64_secret_encode(plaintext, secret):
    """与 edgetunnel worker 的 base64SecretEncode 等价：XOR + base64。"""
    data = plaintext.encode("utf-8")
    key = secret.encode("utf-8")
    mixed = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return base64.b64encode(mixed).decode("ascii")


def video_path(sstp_host):
    """家宽链式代理的 WS 路径：/video/<xor(uuid) 加密的 {"type":"sstp",...}>。"""
    payload = json.dumps(
        {"type": "sstp", "username": "vpn", "password": "vpn",
         "hostname": sstp_host, "port": 443},
        separators=(",", ":"),
    )
    return "/video/" + b64_secret_encode(payload, EDT_UUID) + "?ed=2560"


def vless_link(ip, port, raw_path, remark):
    # 与 edgetunnel worker 生成订阅时的编码一致：path / 备注均做 URL 编码
    q = (f"security=tls&type=ws&host={EDT_DOMAIN}&sni={EDT_DOMAIN}"
         f"&path={quote(raw_path, safe='')}&encryption=none&fp=chrome")
    return f"vless://{EDT_UUID}@{ip}:{port}?{q}#{quote(remark, safe='')}"


# ---------------------------------------------------------------- 主流程 ----
def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    if not EDT_UUID or not EDT_DOMAIN:
        log("警告：未设置 EDT_UUID / EDT_DOMAIN，sub.txt 将无法生成，"
            "仅输出 nodes.txt。请在仓库 Secrets 中配置。")

    # 1) 优选入口 IP：API + 静态池
    entry_cands = fetch_optimal_apis() + fetch_edge_hosts()
    log(f"入口候选共 {len(entry_cands)} 个，开始 TLS 探测…")
    sni = EDT_DOMAIN or "node.sungongqin.com"
    alive = probe_many(entry_cands, sni) if entry_cands else []
    log(f"入口存活 {len(alive)} 个")
    direct = alive[:MAX_DIRECT]

    # 2) 家宽 SSTP 节点（VPN Gate）
    home_nodes = []  # [(sstp_host, cc, latency)]
    vg = fetch_vpngate()
    if vg:
        log(f"VPN Gate 候选 {len(vg)} 个，开始 443 探测…")
        with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
            fut = {ex.submit(check_sstp_alive, ip): (ip, cc) for ip, cc in vg}
            for f in as_completed(fut):
                ip, cc = fut[f]
                try:
                    lat = f.result()
                except Exception:
                    lat = None
                if lat is not None:
                    home_nodes.append((ip, cc, lat))
        home_nodes.sort(key=lambda x: x[2])
        home_nodes = home_nodes[:MAX_HOME]
        log(f"家宽 SSTP 存活 {len(home_nodes)} 个")
    else:
        log("VPN Gate 不可用，本次只输出优选直连节点")

    # 3) 组装输出
    # nodes.txt：博客版格式（可粘贴进 edgetunnel 后台「自定义优选IP」）
    node_lines = []
    sub_links = []
    for i, (h, p, r, lat) in enumerate(direct, 1):
        remark = r or "CF优选"
        remark = re.sub(r"\s+", "", remark)
        node_lines.append(f"{h}:{p}#{remark}")
        if EDT_UUID and EDT_DOMAIN:
            sub_links.append(
                vless_link(h, p, "/", f"CF优选-{i:02d} | {int(lat*1000)}ms"))

    # 家宽行：入口 IP 复用最快的几个，每个配一个 SSTP 出口（轮询）
    if home_nodes and direct:
        entries = direct[: max(4, len(home_nodes))]
        for i, (sip, cc, slat) in enumerate(home_nodes):
            eh, ep, _, elat = entries[i % len(entries)]
            tag = f"家宽-{cc}"
            node_lines.append(f"{eh}:{ep}#{tag}$sstp://vpn:vpn@{sip}")
            if EDT_UUID and EDT_DOMAIN:
                sub_links.append(vless_link(
                    eh, ep, video_path(sip), f"{tag}-{i+1:02d}"))

    update_time = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime(
        "%Y-%m-%d %H:%M:%S")

    with open(os.path.join(OUT_DIR, "nodes.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(node_lines) + "\n")

    if sub_links:
        sub_b64 = base64.b64encode(
            "\n".join(sub_links).encode("utf-8")).decode("ascii")
        with open(os.path.join(OUT_DIR, "sub.txt"), "w", encoding="utf-8") as f:
            f.write(sub_b64)

    index_html = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>家宽优选节点</title></head>
<body style="font-family:sans-serif;max-width:720px;margin:2em auto;padding:0 1em">
<h2>🏠 家宽优选节点</h2>
<p>更新时间：{update_time}（北京时间）｜ 直连优选 {len(direct)} 个 ｜ 家宽 {len(home_nodes)} 个</p>
<ul>
<li><a href="nodes.txt">nodes.txt</a> —— 粘贴进 edgetunnel 后台「自定义优选IP」</li>
{f'<li><a href="sub.txt">sub.txt</a> —— 订阅地址（base64），v2rayN / Shadowrocket / Clash / sing-box 通用</li>' if sub_links else ''}
</ul>
<p>订阅地址：<code>{NODES_URL.replace("nodes.txt", "sub.txt") if sub_links else ""}</code></p>
<p style="color:#888;font-size:12px">每 2 小时自动刷新 · 仅供学习研究使用</p>
</body></html>"""
    with open(os.path.join(OUT_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(index_html)

    log(f"完成：nodes.txt {len(node_lines)} 行，"
        f"sub.txt {len(sub_links)} 个节点，更新时间 {update_time}")


if __name__ == "__main__":
    main()
