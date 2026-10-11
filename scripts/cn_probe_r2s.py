#!/usr/bin/env python3
"""
R2S path probe + upload cn_probe_results.json.
Stdlib only. Prefer DIRECT egress (not through TUN/proxy) for GitHub HTTPS.

Skips: ss ssr shadowsocks vmess http socks5 hysteria tuic wireguard snell
Keeps: anytls hysteria2/hy2 vless trojan ...
"""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

CONNECT_TIMEOUT = 5.0
MAX_WORKERS = 20
HTTP_RETRIES = 5
HTTP_BACKOFF = 3.0

SKIP_TYPES = {
    "ss", "ssr", "shadowsocks", "shadowsocksr",
    "vmess", "http", "socks5", "socks",
    "hysteria",
    "tuic", "wireguard", "snell",
}

CONFIG_PATHS = [
    Path("/root/be-probe/config.env"),
    Path(__file__).resolve().parent / "config.env",
    Path("config.env"),
]


def load_env() -> None:
    for p in CONFIG_PATHS:
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v
        break


def _open(req: urllib.request.Request, timeout: float = 90):
    ctx = ssl.create_default_context()
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)


def http_json(
    url: str,
    method: str = "GET",
    data: dict | None = None,
    token: str | None = None,
    retries: int = HTTP_RETRIES,
) -> dict:
    body = None if data is None else json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "Ryukyou-BeProbe/1.3")
        if body is not None:
            req.add_header("Content-Type", "application/json; charset=utf-8")
            req.add_header("Content-Length", str(len(body)))
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with _open(req, timeout=90) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")
            # 409 conflict / 422 often need fresh sha — don't spin forever
            if e.code in (400, 401, 403, 404, 409, 422):
                raise RuntimeError(f"HTTP {e.code} {url}: {err[:500]}") from e
            last_err = RuntimeError(f"HTTP {e.code} {url}: {err[:300]}")
        except Exception as e:
            last_err = e
        print(f"  http retry {attempt}/{retries}: {last_err}")
        time.sleep(HTTP_BACKOFF * attempt)
    raise RuntimeError(f"http failed after {retries} tries: {last_err}")


def fetch_url_text(url: str, token: str | None = None, retries: int = HTTP_RETRIES) -> str:
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, headers={"User-Agent": "Ryukyou-BeProbe/1.3"})
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with _open(req, timeout=60) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            last_err = e
            print(f"  fetch retry {attempt}/{retries}: {e}")
            time.sleep(HTTP_BACKOFF * attempt)
    raise RuntimeError(f"fetch failed: {last_err}")


def tcp_ms(host: str, port: int) -> float | None:
    try:
        if not host or " " in host:
            return None
        t0 = time.perf_counter()
        with socket.create_connection((host, int(port)), timeout=CONNECT_TIMEOUT):
            pass
        return (time.perf_counter() - t0) * 1000.0
    except Exception:
        return None


def main() -> int:
    load_env()
    token = os.environ.get("GH_TOKEN", "").strip().replace("\n", "").replace("\r", "")
    owner = os.environ.get("GH_OWNER", "RyuKyou").strip()
    repo = os.environ.get("GH_REPO", "calendar-update-system").strip()
    branch = os.environ.get("GH_BRANCH", "main").strip()
    path = os.environ.get("GH_PATH", "output/cn_probe_results.json").strip().lstrip("/")

    if not token:
        print("ERROR: set GH_TOKEN in /root/be-probe/config.env", file=sys.stderr)
        return 1

    # Prefer API (auth) then raw — both with retries
    cand = None
    api_cand = f"https://api.github.com/repos/{owner}/{repo}/contents/output/candidates.json?ref={branch}"
    raw_cand = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/output/candidates.json"
    print(f"Fetch candidates via API ...")
    try:
        meta = http_json(api_cand, token=token)
        cand = json.loads(base64.b64decode(meta["content"]).decode("utf-8"))
        print("  API ok")
    except Exception as e:
        print(f"  API failed ({e}), try raw")
        try:
            text = fetch_url_text(raw_cand, token=token)
            cand = json.loads(text)
            print("  raw ok")
        except Exception as e2:
            print(f"FATAL: cannot get candidates: {e2}", file=sys.stderr)
            return 2

    raw_items = cand.get("candidates") or []
    items = [it for it in raw_items if str(it.get("type") or "").lower() not in SKIP_TYPES]
    print(f"Candidates {len(raw_items)} -> after protocol filter {len(items)}")
    print(f"Probing {len(items)} (workers={MAX_WORKERS}, timeout={CONNECT_TIMEOUT}s)")

    results = []

    def work(it: dict) -> dict:
        host = str(it.get("server") or "")
        port = int(it.get("port") or 0)
        key = str(it.get("key") or f"{host}:{port}")
        ms = tcp_ms(host, port)
        return {"key": key, "server": host, "port": port, "ok": ms is not None, "ms": ms}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = [ex.submit(work, it) for it in items]
        for fut in as_completed(futs):
            results.append(fut.result())

    ok = [r for r in results if r["ok"]]
    ok.sort(key=lambda r: r["ms"] if r["ms"] is not None else 9e9)
    compact_results = [
        {"key": r["key"], "ok": True, "ms": round(float(r["ms"]), 1)}
        for r in ok
        if r.get("ms") is not None
    ]
    out = {
        "updated": datetime.now(timezone.utc).isoformat(),
        "probe": "cn_path_tcp_r2s",
        "timeout_s": CONNECT_TIMEOUT,
        "total": len(results),
        "ok": len(ok),
        "fail": len(results) - len(ok),
        "skipped_protocols": sorted(SKIP_TYPES),
        "results": compact_results,
        "ok_keys_ordered": [r["key"] for r in compact_results],
    }
    text = json.dumps(out, ensure_ascii=False, separators=(",", ":")) + "\n"
    print(f"OK={out['ok']} FAIL={out['fail']} json_bytes={len(text.encode('utf-8'))}")

    local = Path("/root/be-probe/cn_probe_results.json")
    try:
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_text(text, encoding="utf-8")
        print(f"Saved {local}")
    except Exception as e:
        print(f"local save warn: {e}")

    api_path = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    sha = None
    try:
        meta = http_json(f"{api_path}?ref={branch}", token=token)
        sha = meta.get("sha")
    except Exception as e:
        print(f"get sha skip: {e}")

    b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
    payload = {
        "message": f"R2S path probe OK={out['ok']} fail={out['fail']}",
        "content": b64,
        "branch": branch,
    }
    if sha:
        payload["sha"] = sha

    print(f"Upload bytes~{len(b64)} sha={'yes' if sha else 'new'}")
    # retry upload; on 409 refresh sha once
    try:
        http_json(api_path, method="PUT", data=payload, token=token)
    except Exception as e:
        err = str(e)
        if "409" in err or "sha" in err.lower():
            print("upload conflict, refresh sha and retry")
            meta = http_json(f"{api_path}?ref={branch}", token=token)
            payload["sha"] = meta.get("sha")
            http_json(api_path, method="PUT", data=payload, token=token)
        else:
            raise
    print(f"Uploaded {owner}/{repo}:{path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        raise SystemExit(2)
