"""Mihomo deep delay/speed probe helpers."""
from __future__ import annotations
import os, time, json, subprocess, tempfile, shutil
from pathlib import Path
from urllib.parse import quote
import requests
import yaml

def _proxy_key(p: dict) -> str:
    t = str(p.get("type", ""))
    server = str(p.get("server", ""))
    port = str(p.get("port", ""))
    uid = str(p.get("uuid") or p.get("password") or p.get("auth") or "")
    return f"{t}|{server}|{port}|{uid}"


def quality_rank(p: dict) -> int:
    t = str(p.get("type") or "").strip().lower()
    blob = json.dumps(p, ensure_ascii=False).lower()
    if t == "anytls":
        return 0
    if t in ("hysteria2", "hy2"):
        return 1
    if "reality-opts" in p or "reality" in blob:
        return 2
    if t == "vless" and "vision" in str(p.get("flow") or "").lower():
        return 2
    if t == "trojan":
        return 3
    if t == "vless":
        return 4
    if t in ("ss", "shadowsocks", "ssr", "shadowsocksr", "vmess"):
        return 20
    return 10


def mihomo_deep_probe(proxies: list[dict]) -> list[tuple[dict, float, float]]:
    bin_path = shutil.which("mihomo") or os.environ.get("MIHOMO_BIN")
    if not bin_path or (not Path(str(bin_path)).is_file() and not shutil.which(str(bin_path))):
        bin_path = os.environ.get("MIHOMO_BIN", "mihomo")
        if not shutil.which(str(bin_path)) and not Path(str(bin_path)).is_file():
            print("WARN: mihomo not found; skip deep probe")
            return []
    ranked = sorted(proxies, key=lambda p: (quality_rank(p), str(p.get("server") or "")))
    batch = ranked[:500]
    print(f"Deep probe mihomo: {len(batch)}/{len(proxies)}")
    name_map = {}
    plist = []
    for i, p in enumerate(batch):
        pp = dict(p)
        nm = f"n{i:04d}"
        pp["name"] = nm
        name_map[nm] = p
        plist.append(pp)
    cfg = {
        "mixed-port": 17890, "allow-lan": False, "mode": "global",
        "log-level": "error", "ipv6": False,
        "external-controller": "127.0.0.1:19090",
        "proxies": plist,
        "proxy-groups": [{"name": "TEST", "type": "select", "proxies": list(name_map.keys()) or ["DIRECT"]}],
        "rules": ["MATCH,TEST"],
    }
    tmp = Path(tempfile.mkdtemp(prefix="mihomo-probe-"))
    conf = tmp / "config.yaml"
    conf.write_text(yaml.dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")
    exe = bin_path if Path(str(bin_path)).is_file() else (shutil.which("mihomo") or bin_path)
    proc = subprocess.Popen([str(exe), "-f", str(conf), "-d", str(tmp)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)
    out = []
    delay_url = "https://www.gstatic.com/generate_204"
    speed_url = "https://speed.cloudflare.com/__down?bytes=262144"
    try:
        for nm, original in name_map.items():
            try:
                u1 = f"http://127.0.0.1:19090/proxies/{quote(nm)}/delay?timeout=8000&url={quote(delay_url, safe='')}"
                r1 = requests.get(u1, timeout=12)
                if r1.status_code != 200:
                    continue
                delay = r1.json().get("delay")
                if not isinstance(delay, (int, float)) or delay <= 0:
                    continue
                u2 = f"http://127.0.0.1:19090/proxies/{quote(nm)}/delay?timeout=15000&url={quote(speed_url, safe='')}"
                r2 = requests.get(u2, timeout=20)
                if r2.status_code != 200:
                    continue
                speed = r2.json().get("delay")
                if not isinstance(speed, (int, float)) or speed <= 0:
                    continue
                out.append((original, float(delay), float(speed)))
            except Exception:
                continue
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        shutil.rmtree(tmp, ignore_errors=True)
    out.sort(key=lambda x: (quality_rank(x[0]), x[2], x[1]))
    print(f"Deep probe pass: {len(out)}")
    return out


def select_usable(alive, path_map, deep, cap):
    by_key = {_proxy_key(p): (p, o) for p, o in alive}
    if deep:
        selected, seen = [], set()
        # pass1: deep ∩ path_map (Be)
        for p, delay_ms, speed_ms in deep:
            k = _proxy_key(p)
            if k in seen:
                continue
            if path_map and k not in path_map:
                continue
            seen.add(k)
            be = path_map.get(k)
            selected.append((p, float(speed_ms), float(be) if be is not None else None))
            if len(selected) >= cap:
                break
        # pass2: deep-only (e.g. legacy protocols) — no Be tag
        if len(selected) < cap:
            for p, delay_ms, speed_ms in deep:
                k = _proxy_key(p)
                if k in seen:
                    continue
                seen.add(k)
                selected.append((p, float(speed_ms), None))
                if len(selected) >= cap:
                    break
        print(f"Select deep: {len(selected)} (no pad, path_ok_filter_relaxed)")
        return selected
    if path_map:
        pool = []
        for key, be_ms in path_map.items():
            if key not in by_key:
                continue
            p, o_ms = by_key[key]
            pool.append((p, o_ms, float(be_ms)))
        pool.sort(key=lambda x: (quality_rank(x[0]), x[2], x[1]))
        chosen = [(p, o, be) for p, o, be in pool[:cap]]
        print(f"Select R2S only: {len(chosen)} (no pad)")
        return chosen
    ranked = sorted(alive, key=lambda x: (quality_rank(x[0]), x[1]))
    n = min(cap, max(32, len(ranked) // 4))
    print(f"Select TCP trimmed: {n} (no pad)")
    return [(p, o, None) for p, o in ranked[:n]]
