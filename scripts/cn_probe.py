#!/usr/bin/env python3
"""
Mainland (CN-path) TCP probe agent.

Run this ON a network path similar to your real use (home broadband in CN,
or your R2S without proxy bypassing the test targets).

It reads candidates exported by update_nodes.py and writes cn_probe_results.json
for the next GitHub Actions merge pass.

Usage:
  python scripts/cn_probe.py
  python scripts/cn_probe.py --candidates output/candidates.json --out output/cn_probe_results.json

Then commit/push output/cn_probe_results.json (or upload via your own automation).
"""

from __future__ import annotations

import argparse
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

CONNECT_TIMEOUT = 5.0
MAX_WORKERS = 30


def tcp_ms(host: str, port: int) -> float | None:
    try:
        if not host or " " in host:
            return None
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            pass
        return (time.perf_counter() - t0) * 1000.0
    except Exception:
        return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", default="output/candidates.json")
    ap.add_argument("--out", default="output/cn_probe_results.json")
    ap.add_argument("--max-workers", type=int, default=MAX_WORKERS)
    args = ap.parse_args()

    path = Path(args.candidates)
    if not path.exists():
        raise SystemExit(f"missing candidates: {path} (run update_nodes on Actions first)")

    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.get("candidates") or []
    print(f"Probing {len(items)} candidates from CN-path network ...")

    results = []

    def work(it: dict):
        host = str(it.get("server") or "")
        port = int(it.get("port") or 0)
        key = str(it.get("key") or f"{host}:{port}")
        ms = tcp_ms(host, port)
        return {"key": key, "server": host, "port": port, "ok": ms is not None, "ms": ms}

    with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as ex:
        futs = [ex.submit(work, it) for it in items]
        for fut in as_completed(futs):
            results.append(fut.result())

    ok = [r for r in results if r["ok"]]
    ok.sort(key=lambda r: r["ms"] if r["ms"] is not None else 9e9)
    fail_n = len(results) - len(ok)

    out = {
        "updated": datetime.now(timezone.utc).isoformat(),
        "probe": "cn_path_tcp",
        "timeout_s": CONNECT_TIMEOUT,
        "total": len(results),
        "ok": len(ok),
        "fail": fail_n,
        "results": results,
        "ok_keys_ordered": [r["key"] for r in ok],
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"OK={len(ok)} FAIL={fail_n} -> {out_path}")


if __name__ == "__main__":
    main()
