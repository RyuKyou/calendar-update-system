#!/usr/bin/env python3
"""
Fetch Clash YAML sources, TCP probe, dedupe.
Only keep reachable nodes; hard-cap MAX_NODES (512).

Priority order:
  1) preferred regions: US, Canada, Norway, Singapore
  2) protocol: anytls > hysteria2/hysteria > vless > trojan > others > ss/vmess/ssr (last)
  3) lower TCP latency

Node names get traffic-light emoji from TCP RTT snapshot:
  🟢 <150ms  🟡 <400ms  🟠 <800ms  🔴 >=800ms
(Client UI red/green dots are separate: live HTTP health-check.)

Hong Kong / Macau nodes are fully excluded.
"""

from __future__ import annotations

import argparse
import re
import socket
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

VALID_NETWORKS = {"tcp", "udp", "ws", "http", "h2", "grpc", "raw"}
CONNECT_TIMEOUT = 6.0
MAX_WORKERS = 40
MAX_NODES = 512

PROTOCOL_RANK = {
    "anytls": 0,
    "hysteria2": 1,
    "hysteria": 1,
    "hy2": 1,
    "vless": 2,
    "trojan": 3,
    "tuic": 4,
    "wireguard": 5,
    "http": 6,
    "socks5": 6,
    "socks": 6,
    "ss": 20,
    "shadowsocks": 20,
    "ssr": 20,
    "shadowsocksr": 20,
    "vmess": 20,
}
DEFAULT_PROTOCOL_RANK = 10

HK_MO_PATTERNS = [
    r"香港",
    r"澳门",
    r"澳門",
    r"\bhk\b",
    r"\bhkg\b",
    r"hong\s*kong",
    r"\bmo\b",
    r"\bmac\b",
    r"macau",
    r"macao",
    r"🇭🇰",
    r"🇲🇴",
]
HK_MO_RE = re.compile("|".join(HK_MO_PATTERNS), re.IGNORECASE)

REGION_PATTERNS: list[tuple[int, re.Pattern[str]]] = [
    (0, re.compile(
        r"美国|美國|\busa\b|\bus\b|united\s*states|california|los\s*angeles|"
        r"san\s*francisco|new\s*york|seattle|chicago|dallas|miami|phoenix|"
        r"\bla\b|\bny\b|\bsfo\b|\bsjc\b|\biad\b|\bord\b|\bdfw\b|🇺🇸",
        re.I,
    )),
    (1, re.compile(
        r"加拿大|\bcanada\b|\bca\b|toronto|vancouver|montreal|🇨🇦",
        re.I,
    )),
    (2, re.compile(
        r"挪威|\bnorway\b|\bno\b|oslo|bergen|🇳🇴",
        re.I,
    )),
    (3, re.compile(
        r"新加坡|\bsingapore\b|\bsg\b|\bsin\b|🇸🇬",
        re.I,
    )),
]


def is_hk_or_mo(p: dict) -> bool:
    blob = " ".join(
        str(p.get(k) or "")
        for k in ("name", "server", "servername", "sni", "host")
    )
    return bool(HK_MO_RE.search(blob))


def region_priority(p: dict) -> int:
    blob = " ".join(
        str(p.get(k) or "")
        for k in ("name", "server", "servername", "sni", "host")
    )
    for rank, pat in REGION_PATTERNS:
        if pat.search(blob):
            return rank
    return 100


def type_priority(p: dict) -> int:
    t = str(p.get("type") or "").strip().lower()
    return PROTOCOL_RANK.get(t, DEFAULT_PROTOCOL_RANK)


def latency_emoji(ms: float) -> str:
    """Traffic-light style tag from TCP RTT (snapshot at build time)."""
    if ms < 150:
        return "🟢"
    if ms < 400:
        return "🟡"
    if ms < 800:
        return "🟠"
    return "🔴"


def load_urls(path: Path) -> list[tuple[str, str]]:
    entries = []
    if not path.exists():
        return entries
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "|" in line:
            url, desc = line.split("|", 1)
            entries.append((url.strip(), desc.strip()))
        else:
            entries.append((line, ""))
    return entries


def clean_proxy(p: dict, index: int) -> dict | None:
    if not isinstance(p, dict):
        return None
    name = str(p.get("name") or f"node-{index}")
    name = re.sub(r"[\x00-\x1f]", "", name).strip() or f"node-{index}"
    p = dict(p)
    p["name"] = name

    net = p.get("network")
    if isinstance(net, str):
        base = net.split("#")[0].split("@")[0].strip().lower()
        if base in VALID_NETWORKS:
            p["network"] = base
        else:
            p.pop("network", None)

    if not p.get("type") or not p.get("server"):
        return None
    try:
        port = int(p.get("port") or 0)
    except (TypeError, ValueError):
        return None
    if port <= 0 or port > 65535:
        return None
    p["port"] = port

    if is_hk_or_mo(p):
        return None
    return p


def extract_proxies(text: str) -> list[dict]:
    try:
        data = yaml.safe_load(text)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    raw = data.get("proxies") or []
    if not isinstance(raw, list):
        return []
    out = []
    for i, item in enumerate(raw):
        c = clean_proxy(item, i)
        if c:
            out.append(c)
    return out


def proxy_key(p: dict) -> str:
    t = str(p.get("type", ""))
    server = str(p.get("server", ""))
    port = str(p.get("port", ""))
    uid = str(p.get("uuid") or p.get("password") or p.get("auth") or "")
    return f"{t}|{server}|{port}|{uid}"


def tcp_latency_ms(server: str, port: int) -> float | None:
    try:
        if not server or " " in server:
            return None
        t0 = time.perf_counter()
        with socket.create_connection((server, port), timeout=CONNECT_TIMEOUT):
            pass
        return (time.perf_counter() - t0) * 1000.0
    except Exception:
        return None


def probe_alive(proxies: list[dict]) -> list[tuple[dict, float]]:
    alive: list[tuple[dict, float]] = []

    def work(p: dict):
        return p, tcp_latency_ms(str(p["server"]), int(p["port"]))

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = [ex.submit(work, p) for p in proxies]
        for fut in as_completed(futs):
            p, ms = fut.result()
            if ms is None:
                continue
            alive.append((p, ms))
    alive.sort(key=lambda x: (region_priority(x[0]), type_priority(x[0]), x[1]))
    return alive


def format_label(p: dict, ms: float) -> str:
    base = p["name"]
    t = str(p.get("type") or "").lower()
    light = latency_emoji(ms)
    tag = ""
    if t == "anytls":
        tag = "[anytls] "
    elif t in ("hysteria2", "hysteria", "hy2"):
        tag = "[hy2] "
    return f"{light} {tag}{base} | {ms:.0f}ms"


def build_config(selected: list[tuple[dict, float]], cap: int) -> str:
    seen_names: set[str] = set()
    unique: list[dict] = []
    stats = {"anytls": 0, "hy2": 0, "vless": 0, "trojan": 0, "low": 0, "preferred": 0}
    lights = Counter()
    for p, ms in selected:
        p = dict(p)
        t = str(p.get("type") or "").lower()
        if region_priority(p) < 100:
            stats["preferred"] += 1
        if t == "anytls":
            stats["anytls"] += 1
        elif t in ("hysteria2", "hysteria", "hy2"):
            stats["hy2"] += 1
        elif t == "vless":
            stats["vless"] += 1
        elif t == "trojan":
            stats["trojan"] += 1
        elif t in ("ss", "shadowsocks", "ssr", "shadowsocksr", "vmess"):
            stats["low"] += 1

        light = latency_emoji(ms)
        lights[light] += 1
        label = format_label(p, ms)
        if label in seen_names:
            k = 2
            while f"{label}-{k}" in seen_names:
                k += 1
            label = f"{label}-{k}"
        p["name"] = label
        seen_names.add(label)
        unique.append(p)

    names = [p["name"] for p in unique] or ["DIRECT"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cfg = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "proxies": unique,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["♻️ 自动选择", "DIRECT"] + names,
            },
            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "proxies": names,
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
            },
        ],
        "rules": [
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 节点选择",
        ],
    }
    n = len(unique)
    if n > cap:
        raise RuntimeError(f"BUG: {n} > hard_cap {cap}")
    header = (
        f"# Ryukyou nodes | updated {now} | count={n} | hard_cap={cap} | "
        f"lights={dict(lights)} | "
        f"anytls={stats['anytls']} hy2={stats['hy2']} vless={stats['vless']} "
        f"trojan={stats['trojan']} ss_vmess_ssr={stats['low']} | "
        f"preferred_region={stats['preferred']} | "
        f"emoji=TCP_RTT_snapshot not_client_live_check\n"
    )
    return header + yaml.dump(cfg, allow_unicode=True, sort_keys=False, default_flow_style=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default="sources/urls.txt")
    ap.add_argument("--output-dir", default="output")
    ap.add_argument("--max-nodes", type=int, default=MAX_NODES)
    args = ap.parse_args()
    cap = max(1, min(int(args.max_nodes), MAX_NODES))

    entries = load_urls(Path(args.sources))
    if not entries:
        print("No sources", file=__import__("sys").stderr)
        raise SystemExit(1)

    all_proxies: list[dict] = []
    for i, (url, desc) in enumerate(entries, 1):
        try:
            print(f"[{i}/{len(entries)}] Fetch {url}")
            r = requests.get(url, timeout=35)
            r.raise_for_status()
            found = extract_proxies(r.text)
            print(f"  -> {len(found)} proxies after HK/MO filter ({desc})")
            all_proxies.extend(found)
        except Exception as e:
            print(f"  WARN: {e}")

    deduped: list[dict] = []
    seen_keys: set[str] = set()
    for p in all_proxies:
        k = proxy_key(p)
        if k in seen_keys:
            continue
        seen_keys.add(k)
        deduped.append(p)
    print(f"After dedup: {len(deduped)} / {len(all_proxies)}")

    print(f"Probing TCP (timeout={CONNECT_TIMEOUT}s) ...")
    alive = probe_alive(deduped)
    print(f"Reachable: {len(alive)}")

    selected = alive[:cap]
    print(f"Final: {len(selected)} (hard_cap={cap})")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    text = build_config(selected, cap)
    (out_dir / "clash_clean.yaml").write_text(text, encoding="utf-8")
    print(f"Wrote output/clash_clean.yaml nodes={len(selected)}")

    type_c = Counter(str(p.get("type", "")).lower() for p, _ in selected)
    light_c = Counter(latency_emoji(ms) for _, ms in selected)
    (out_dir / "nodes_stats.txt").write_text(
        f"updated={datetime.now(timezone.utc).isoformat()}\n"
        f"sources={len(entries)}\n"
        f"raw_after_hk_mo_filter={len(all_proxies)}\n"
        f"dedup={len(deduped)}\n"
        f"reachable={len(alive)}\n"
        f"final_count={len(selected)}\n"
        f"hard_cap={cap}\n"
        f"types={dict(type_c)}\n"
        f"lights={dict(light_c)}\n"
        f"policy=region_then_hy2_vless_trojan_ss_vmess_ssr_last\n",
        encoding="utf-8",
    )
    print("Done.")


if __name__ == "__main__":
    main()
