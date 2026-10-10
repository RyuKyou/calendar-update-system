#!/usr/bin/env python3
"""
Fetch Clash YAML sources, TCP probe, dedupe.

Two-stage quality:
  A) GitHub Actions (overseas): TCP alive + drop HK/MO names
     + drop server IPs geolocated to CN / HK / MO
  B) Optional path probe file output/cn_probe_results.json (scripts/cn_probe.py)

Selection inside hard_cap=512:
  - Always reserve up to BE_RESERVED (128) path-proven [Be] nodes
    sorted by lowest path RTT (mainland probe).
  - Fill remaining slots with other overseas-alive nodes
    (region -> protocol -> overseas RTT).

Path-proven nodes are renamed with [Be] (Beyond = 跨越), never CN/HK/MO tags.
"""

from __future__ import annotations

import argparse
import json
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
BE_RESERVED = 128  # hard seats for lowest path-RTT Beyond nodes
CN_PROBE_MAX_AGE_HOURS = 36

BLOCKED_EXIT_CC = {"CN", "HK", "MO"}

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
    r"香港", r"澳门", r"澳門", r"\bhk\b", r"\bhkg\b", r"hong\s*kong",
    r"\bmo\b", r"\bmac\b", r"macau", r"macao", r"🇭🇰", r"🇲🇴",
]
HK_MO_RE = re.compile("|".join(HK_MO_PATTERNS), re.IGNORECASE)

NAME_SCRUB_RE = re.compile(
    r"(中国|大陸|大陆|內地|内地|\bcn\b|\bchina\b|香港|澳门|澳門|"
    r"\bhk\b|\bhkg\b|hong\s*kong|macau|macao|🇨🇳|🇭🇰|🇲🇴)",
    re.I,
)

REGION_PATTERNS: list[tuple[int, re.Pattern[str]]] = [
    (0, re.compile(
        r"美国|美國|\busa\b|\bus\b|united\s*states|california|los\s*angeles|"
        r"san\s*francisco|new\s*york|seattle|chicago|dallas|miami|phoenix|"
        r"\bla\b|\bny\b|\bsfo\b|\bsjc\b|\biad\b|\bord\b|\bdfw\b|🇺🇸", re.I)),
    (1, re.compile(r"加拿大|\bcanada\b|\bca\b|toronto|vancouver|montreal|🇨🇦", re.I)),
    (2, re.compile(r"挪威|\bnorway\b|\bno\b|oslo|bergen|🇳🇴", re.I)),
    (3, re.compile(r"新加坡|\bsingapore\b|\bsg\b|\bsin\b|🇸🇬", re.I)),
]


def is_hk_or_mo(p: dict) -> bool:
    blob = " ".join(str(p.get(k) or "") for k in ("name", "server", "servername", "sni", "host"))
    return bool(HK_MO_RE.search(blob))


def region_priority(p: dict) -> int:
    blob = " ".join(str(p.get(k) or "") for k in ("name", "server", "servername", "sni", "host"))
    for rank, pat in REGION_PATTERNS:
        if pat.search(blob):
            return rank
    return 100


def type_priority(p: dict) -> int:
    t = str(p.get("type") or "").strip().lower()
    return PROTOCOL_RANK.get(t, DEFAULT_PROTOCOL_RANK)


def latency_emoji(ms: float) -> str:
    if ms < 150:
        return "🟢"
    if ms < 400:
        return "🟡"
    if ms < 800:
        return "🟠"
    return "🔴"


def scrub_display_name(name: str) -> str:
    s = NAME_SCRUB_RE.sub("", name)
    s = re.sub(r"\s{2,}", " ", s).strip(" -_|/")
    return s or name


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


def resolve_ip(host: str) -> str | None:
    try:
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            return host
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        if not infos:
            return None
        return infos[0][4][0]
    except Exception:
        return None


def filter_blocked_exit_servers(proxies: list[dict]) -> list[dict]:
    """Drop nodes whose server IP is in CN / HK / MO."""
    hosts = sorted({str(p.get("server") or "") for p in proxies if p.get("server")})
    host_ip: dict[str, str] = {}
    for h in hosts:
        ip = resolve_ip(h)
        if ip:
            host_ip[h] = ip
    ips = sorted(set(host_ip.values()))
    blocked_ips: set[str] = set()
    for i in range(0, len(ips), 80):
        batch = ips[i : i + 80]
        try:
            r = requests.post(
                "http://ip-api.com/batch?fields=status,countryCode,query",
                json=[{"query": ip} for ip in batch],
                timeout=25,
            )
            if r.status_code != 200:
                continue
            for row in r.json():
                if isinstance(row, dict) and row.get("status") == "success":
                    cc = str(row.get("countryCode") or "").upper()
                    if cc in BLOCKED_EXIT_CC:
                        blocked_ips.add(str(row.get("query")))
        except Exception as e:
            print(f"  WARN geo batch: {e}")
        time.sleep(0.4)

    kept = []
    dropped = 0
    for p in proxies:
        h = str(p.get("server") or "")
        ip = host_ip.get(h)
        if ip and ip in blocked_ips:
            dropped += 1
            continue
        kept.append(p)
    print(f"CN/HK/MO server IP drop: {dropped}, kept {len(kept)}")
    return kept


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
    return alive


def load_path_probe(path: Path) -> dict[str, float]:
    """key -> path_ms for ok results; empty if missing/stale."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    updated = data.get("updated") or ""
    try:
        ts = datetime.fromisoformat(updated.replace("Z", "+00:00"))
        age_h = (datetime.now(timezone.utc) - ts.astimezone(timezone.utc)).total_seconds() / 3600.0
        if age_h > CN_PROBE_MAX_AGE_HOURS:
            print(f"Path probe stale ({age_h:.1f}h > {CN_PROBE_MAX_AGE_HOURS}h), ignore")
            return {}
    except Exception:
        print("Path probe timestamp parse fail, still using file")
    out: dict[str, float] = {}
    for row in data.get("results") or []:
        if not row.get("ok"):
            continue
        key = str(row.get("key") or "")
        ms = row.get("ms")
        if key and isinstance(ms, (int, float)):
            out[key] = float(ms)
    print(f"Path probe loaded: {len(out)} ok keys (Beyond pool)")
    return out


def overseas_sort_key(p: dict, overseas_ms: float):
    return (region_priority(p), type_priority(p), overseas_ms)


def format_label(p: dict, display_ms: float, beyond: bool) -> str:
    base = scrub_display_name(str(p["name"]))
    t = str(p.get("type") or "").lower()
    light = latency_emoji(display_ms)
    proto = ""
    if t == "anytls":
        proto = "[anytls] "
    elif t in ("hysteria2", "hysteria", "hy2"):
        proto = "[hy2] "
    be = "[Be] " if beyond else ""
    return f"{light} {be}{proto}{base} | {display_ms:.0f}ms"


def build_config(
    selected: list[tuple[dict, float, float | None]],
    cap: int,
) -> str:
    seen_names: set[str] = set()
    unique: list[dict] = []
    stats = {
        "anytls": 0, "hy2": 0, "vless": 0, "trojan": 0, "low": 0,
        "preferred": 0, "beyond": 0,
    }
    lights = Counter()
    for p, o_ms, be_ms in selected:
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
        beyond = be_ms is not None
        if beyond:
            stats["beyond"] += 1
        display = float(be_ms) if beyond else float(o_ms)
        light = latency_emoji(display)
        lights[light] += 1
        label = format_label(p, display, beyond)
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
        f"Be_reserved={BE_RESERVED} Beyond[Be]={stats['beyond']} | lights={dict(lights)} | "
        f"anytls={stats['anytls']} hy2={stats['hy2']} vless={stats['vless']} "
        f"trojan={stats['trojan']} | preferred_region={stats['preferred']}\n"
    )
    return header + yaml.dump(cfg, allow_unicode=True, sort_keys=False, default_flow_style=False)


def select_with_be_reserve(
    alive: list[tuple[dict, float]],
    path_map: dict[str, float],
    cap: int,
    be_reserved: int,
) -> list[tuple[dict, float, float | None]]:
    """
    1) Take up to be_reserved path-proven nodes with lowest path RTT.
    2) Fill remaining slots from the rest (overseas rank).
    """
    by_key: dict[str, tuple[dict, float]] = {}
    for p, o_ms in alive:
        by_key[proxy_key(p)] = (p, o_ms)

    # Beyond pool: path ok AND still overseas-alive this run
    be_pool: list[tuple[dict, float, float]] = []
    for key, be_ms in path_map.items():
        if key not in by_key:
            continue
        p, o_ms = by_key[key]
        be_pool.append((p, o_ms, float(be_ms)))
    be_pool.sort(key=lambda x: (x[2], type_priority(x[0]), x[1]))

    seats = min(be_reserved, cap, len(be_pool))
    chosen: list[tuple[dict, float, float | None]] = []
    chosen_keys: set[str] = set()
    for p, o_ms, be_ms in be_pool[:seats]:
        chosen.append((p, o_ms, be_ms))
        chosen_keys.add(proxy_key(p))

    # Fillers: everyone else not already chosen
    fillers = [(p, o) for p, o in alive if proxy_key(p) not in chosen_keys]
    fillers.sort(key=lambda x: overseas_sort_key(x[0], x[1]))
    need = cap - len(chosen)
    for p, o_ms in fillers[:need]:
        # if somehow also in path_map, keep Be tag
        k = proxy_key(p)
        be = path_map.get(k)
        chosen.append((p, o_ms, be if be is not None else None))

    print(
        f"Be reserve: pool={len(be_pool)} seats={seats}/{be_reserved} | "
        f"fillers_added={min(need, len(fillers))} | total={len(chosen)}/{cap}"
    )
    return chosen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default="sources/urls.txt")
    ap.add_argument("--output-dir", default="output")
    ap.add_argument("--max-nodes", type=int, default=MAX_NODES)
    ap.add_argument("--cn-probe", default="output/cn_probe_results.json")
    ap.add_argument("--be-reserved", type=int, default=BE_RESERVED)
    args = ap.parse_args()
    cap = max(1, min(int(args.max_nodes), MAX_NODES))
    be_reserved = max(0, min(int(args.be_reserved), cap))
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

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
            print(f"  -> {len(found)} after HK/MO name filter ({desc})")
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

    print("Geo-filter CN/HK/MO server IPs ...")
    deduped = filter_blocked_exit_servers(deduped)

    print(f"Overseas TCP probe (timeout={CONNECT_TIMEOUT}s) ...")
    alive = probe_alive(deduped)
    print(f"Overseas reachable: {len(alive)}")

    candidates = []
    for p, ms in alive:
        candidates.append(
            {
                "key": proxy_key(p),
                "server": p.get("server"),
                "port": p.get("port"),
                "type": p.get("type"),
                "name": p.get("name"),
                "overseas_ms": round(ms, 1),
            }
        )
    cand_path = out_dir / "candidates.json"
    cand_path.write_text(
        json.dumps(
            {"updated": datetime.now(timezone.utc).isoformat(), "candidates": candidates},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Wrote {cand_path} ({len(candidates)})")

    path_map = load_path_probe(Path(args.cn_probe))

    if path_map:
        selected_triples = select_with_be_reserve(alive, path_map, cap, be_reserved)
    else:
        ranked = sorted(alive, key=lambda x: overseas_sort_key(x[0], x[1]))
        selected_triples = [(p, o, None) for p, o in ranked[:cap]]
        print(f"No path probe; overseas-only select {len(selected_triples)}")

    text = build_config(selected_triples, cap)
    (out_dir / "clash_clean.yaml").write_text(text, encoding="utf-8")
    print(f"Wrote output/clash_clean.yaml nodes={len(selected_triples)}")

    type_c = Counter(str(p.get("type", "")).lower() for p, _, _ in selected_triples)
    be_n = sum(1 for _, _, c in selected_triples if c is not None)
    (out_dir / "nodes_stats.txt").write_text(
        f"updated={datetime.now(timezone.utc).isoformat()}\n"
        f"sources={len(entries)}\n"
        f"dedup={len(deduped)}\n"
        f"overseas_reachable={len(alive)}\n"
        f"path_probe_ok_keys={len(path_map)}\n"
        f"be_reserved_config={be_reserved}\n"
        f"final_count={len(selected_triples)}\n"
        f"final_beyond_Be={be_n}\n"
        f"hard_cap={cap}\n"
        f"types={dict(type_c)}\n"
        f"policy=reserve_{be_reserved}_Be_by_path_rtt_then_fill\n",
        encoding="utf-8",
    )
    print("Done.")


if __name__ == "__main__":
    main()
