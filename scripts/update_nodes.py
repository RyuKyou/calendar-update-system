#!/usr/bin/env python3
"""
Fetch Clash YAML sources, TCP latency probe, dedupe, write one clean config.
No stego, no encryption, no email.
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
CONNECT_TIMEOUT = 3.0
MAX_WORKERS = 32
# keep nodes with latency under this (ms); 0 = keep all that connect
MAX_LATENCY_MS = 3000


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
        # skip obvious non-hostnames that need DNS special
        if not server or " " in server:
            return None
        t0 = time.perf_counter()
        with socket.create_connection((server, port), timeout=CONNECT_TIMEOUT):
            pass
        return (time.perf_counter() - t0) * 1000.0
    except Exception:
        return None


def probe_all(proxies: list[dict]) -> list[tuple[dict, float]]:
    results: list[tuple[dict, float]] = []

    def work(p: dict):
        ms = tcp_latency_ms(str(p["server"]), int(p["port"]))
        return p, ms

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = [ex.submit(work, p) for p in proxies]
        for fut in as_completed(futs):
            p, ms = fut.result()
            if ms is None:
                continue
            if MAX_LATENCY_MS and ms > MAX_LATENCY_MS:
                continue
            results.append((p, ms))
    results.sort(key=lambda x: x[1])
    return results


def build_config(alive: list[tuple[dict, float]]) -> str:
    seen_names: set[str] = set()
    unique: list[dict] = []
    for p, ms in alive:
        p = dict(p)
        base = p["name"]
        # annotate latency for readability
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
    header = f"# Ryukyou nodes | updated {now} | alive={len(unique)}\n"
    return header + yaml.dump(cfg, allow_unicode=True, sort_keys=False, default_flow_style=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default="sources/urls.txt")
    ap.add_argument("--output-dir", default="output")
    ap.add_argument("--skip-probe", action="store_true", help="skip TCP probe")
    args = ap.parse_args()

    entries = load_urls(Path(args.sources))
    if not entries:
        print("No sources", file=__import__("sys").stderr)
        raise SystemExit(1)

    all_proxies: list[dict] = []
    for i, (url, desc) in enumerate(entries, 1):
        try:
            print(f"[{i}/{len(entries)}] Fetch {url}")
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            found = extract_proxies(r.text)
            print(f"  -> {len(found)} proxies ({desc})")
            all_proxies.extend(found)
        except Exception as e:
            print(f"  WARN: {e}")

    # dedupe by identity key before probe
    deduped: list[dict] = []
    seen_keys: set[str] = set()
    for p in all_proxies:
        k = proxy_key(p)
        if k in seen_keys:
            continue
        seen_keys.add(k)
        deduped.append(p)
    print(f"After dedup: {len(deduped)} / {len(all_proxies)}")

    if args.skip_probe:
        alive = [(p, 0.0) for p in deduped]
    else:
        print(f"Probing TCP latency (timeout={CONNECT_TIMEOUT}s, workers={MAX_WORKERS}) ...")
        alive = probe_all(deduped)
        print(f"Alive: {len(alive)}")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    text = build_config(alive)
    out = out_dir / "clash_clean.yaml"
    out.write_text(text, encoding="utf-8")
    print(f"Wrote {out} ({len(text)} chars, {len(alive)} nodes)")

    # simple stats
    (out_dir / "nodes_stats.txt").write_text(
        f"updated={datetime.now(timezone.utc).isoformat()}\n"
        f"sources={len(entries)}\n"
        f"raw={len(all_proxies)}\n"
        f"dedup={len(deduped)}\n"
        f"alive={len(alive)}\n",
        encoding="utf-8",
    )
    print("Done.")


if __name__ == "__main__":
    main()
