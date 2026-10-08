#!/usr/bin/env python3
"""
Fetch Clash YAML sources, TCP probe, dedupe.
Only keep reachable nodes; hard-cap MAX_NODES (512).
Priority:
  1) preferred regions: US, Canada, Norway, Singapore
  2) anytls protocol
  3) lower TCP latency
Hong Kong / Macau nodes are fully excluded.
"""

from __future__ import annotations

import argparse
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

VALID_NETWORKS = {"tcp", "udp", "ws", "http", "h2", "grpc", "raw"}
CONNECT_TIMEOUT = 6.0
MAX_WORKERS = 40
MAX_NODES = 512
PRIORITY_TYPES = ("anytls",)  # lower rank = higher priority

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

# preferred regions (lower rank = higher priority)
REGION_PATTERNS: list[tuple[int, re.Pattern[str]]] = [
    # US
    (0, re.compile(
        r"美国|美國|\busa\b|\bus\b|united\s*states|california|los\s*angeles|"
        r"san\s*francisco|new\s*york|seattle|chicago|dallas|miami|phoenix|"
        r"\bla\b|\bny\b|\bsfo\b|\bsjc\b|\biad\b|\bord\b|\bdfw\b|🇺🇸",
        re.I,
    )),
    # Canada
    (1, re.compile(
        r"加拿大|\bcanada\b|\bca\b|toronto|vancouver|montreal|🇨🇦",
        re.I,
    )),
    # Norway
    (2, re.compile(
        r"挪威|\bnorway\b|\bno\b|oslo|bergen|🇳🇴",
        re.I,
    )),
    # Singapore
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
    return 100  # non-preferred regions


def type_priority(p: dict) -> int:
    t = str(p.get("type") or "").strip().lower()
    try:
        return PRIORITY_TYPES.index(t)
    except ValueError:
        return len(PRIORITY_TYPES)


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
    # region -> anytls -> latency
    alive.sort(key=lambda x: (region_priority(x[0]), type_priority(x[0]), x[1]))
    return alive


def build_config(selected: list[tuple[dict, float]], cap: int) -> str:
    seen_names: set[str] = set()
    unique: list[dict] = []
    anytls_n = 0
    preferred_n = 0
    for p, ms in selected:
        p = dict(p)
        base = p["name"]
        t = str(p.get("type") or "").lower()
        pref = region_priority(p) < 100
        if pref:
            preferred_n += 1
        if t == "anytls":
            anytls_n += 1
            label = f"[anytls] {base} | {ms:.0f}ms"
        else:
            label = f"{base} | {ms:.0f}ms"
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
        f"anytls={anytls_n} | preferred_region={preferred_n} | "
        f"only_reachable | no_HK_MO | prefer_US_CA_NO_SG+anytls\n"
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
    anytls_alive = sum(1 for p, _ in alive if str(p.get("type", "")).lower() == "anytls")
    pref_alive = sum(1 for p, _ in alive if region_priority(p) < 100)
    print(f"Reachable: {len(alive)} (anytls={anytls_alive}, preferred_region={pref_alive})")

    selected = alive[:cap]
    sel_any = sum(1 for p, _ in selected if str(p.get("type", "")).lower() == "anytls")
    sel_pref = sum(1 for p, _ in selected if region_priority(p) < 100)
    print(f"Final: {len(selected)} (anytls={sel_any}, preferred={sel_pref}, hard_cap={cap})")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    text = build_config(selected, cap)
    (out_dir / "clash_clean.yaml").write_text(text, encoding="utf-8")
    print(f"Wrote output/clash_clean.yaml nodes={len(selected)}")

    (out_dir / "nodes_stats.txt").write_text(
        f"updated={datetime.now(timezone.utc).isoformat()}\n"
        f"sources={len(entries)}\n"
        f"raw_after_hk_mo_filter={len(all_proxies)}\n"
        f"dedup={len(deduped)}\n"
        f"reachable={len(alive)}\n"
        f"reachable_anytls={anytls_alive}\n"
        f"reachable_preferred_region={pref_alive}\n"
        f"final_count={len(selected)}\n"
        f"final_anytls={sel_any}\n"
        f"final_preferred_region={sel_pref}\n"
        f"hard_cap={cap}\n"
        f"policy=prefer_US_CA_NO_SG_then_anytls_only_reachable_no_HK_MO\n",
        encoding="utf-8",
    )
    print("Done.")


if __name__ == "__main__":
    main()
