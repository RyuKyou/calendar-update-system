#!/usr/bin/env python3
"""
Fetch Clash YAML sources, TCP probe, dedupe.

Also scans sources/tg_exports/*.html (Telegram Desktop export)
for subscription URLs and merges them into the fetch list.

Early drop: http / socks5 / socks.
Drop HK/MO names and CN/HK/MO server IPs.
Name format: 🟢 美國 [Be] [anytls] original | 120ms
Be_reserved=256 after R2S probe upload.
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
from html import unescape
from pathlib import Path

import requests
import yaml

VALID_NETWORKS = {"tcp", "udp", "ws", "http", "h2", "grpc", "raw"}
CONNECT_TIMEOUT = 6.0
MAX_WORKERS = 40
MAX_NODES = 512
BE_RESERVED = 256
CN_PROBE_MAX_AGE_HOURS = 36

DROP_TYPES = {"http", "socks5", "socks"}

SKIP_PATH_PROBE_TYPES = {
    "ss", "ssr", "shadowsocks", "shadowsocksr",
    "vmess", "http", "socks5", "socks",
    "hysteria",
    "tuic", "wireguard", "snell",
}

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
    "ss": 20,
    "shadowsocks": 20,
    "ssr": 20,
    "shadowsocksr": 20,
    "vmess": 20,
}
DEFAULT_PROTOCOL_RANK = 10

PREFERRED_CC_RANK = {"US": 0, "CA": 1, "NO": 2, "SG": 3}

CC_ZH = {
    "US": "美國", "CA": "加拿大", "NO": "挪威", "SG": "新加坡",
    "JP": "日本", "KR": "韓國", "DE": "德國", "GB": "英國",
    "FR": "法國", "NL": "荷蘭", "FI": "芬蘭", "SE": "瑞典",
    "CH": "瑞士", "AU": "澳洲", "TW": "台灣", "IN": "印度",
    "TR": "土耳其", "RU": "俄羅斯", "BR": "巴西", "IE": "愛爾蘭",
    "IT": "義大利", "ES": "西班牙", "PL": "波蘭", "VN": "越南",
    "TH": "泰國", "PH": "菲律賓", "ID": "印尼", "MY": "馬來西亞",
    "AE": "阿聯酋", "MX": "墨西哥", "AR": "阿根廷", "ZA": "南非",
    "XX": "未知",
}

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

CC_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("US", re.compile(
        r"美国|美國|\busa\b|united\s*states|california|los\s*angeles|"
        r"san\s*francisco|new\s*york|seattle|chicago|dallas|miami|phoenix|"
        r"\bla\b|\bny\b|\bsfo\b|\bsjc\b|\biad\b|\bord\b|\bdfw\b|"
        r"🇺🇸|(?<![a-z])us(?![a-z])", re.I)),
    ("CA", re.compile(r"加拿大|\bcanada\b|toronto|vancouver|montreal|🇨🇦|(?<![a-z])ca(?![a-z])", re.I)),
    ("NO", re.compile(r"挪威|\bnorway\b|oslo|bergen|🇳🇴|(?<![a-z])no(?![a-z])", re.I)),
    ("SG", re.compile(r"新加坡|\bsingapore\b|\bsin\b|🇸🇬|(?<![a-z])sg(?![a-z])", re.I)),
    ("JP", re.compile(r"日本|\bjapan\b|tokyo|osaka|\btyo\b|\bhnd\b|🇯🇵|(?<![a-z])jp(?![a-z])", re.I)),
    ("KR", re.compile(r"韩国|韓國|\bkorea\b|seoul|\bicn\b|🇰🇷|(?<![a-z])kr(?![a-z])", re.I)),
    ("DE", re.compile(r"德国|德國|\bgermany\b|frankfurt|berlin|munich|\bfra\b|🇩🇪|(?<![a-z])de(?![a-z])", re.I)),
    ("GB", re.compile(r"英国|英國|\buk\b|\bbritain\b|\bengland\b|london|\blhr\b|🇬🇧|(?<![a-z])gb(?![a-z])", re.I)),
    ("FR", re.compile(r"法国|法國|\bfrance\b|paris|\bcdg\b|🇫🇷|(?<![a-z])fr(?![a-z])", re.I)),
    ("NL", re.compile(r"荷兰|荷蘭|\bnetherlands\b|\bholland\b|amsterdam|\bams\b|🇳🇱|(?<![a-z])nl(?![a-z])", re.I)),
    ("FI", re.compile(r"芬兰|芬蘭|\bfinland\b|helsinki|🇫🇮|(?<![a-z])fi(?![a-z])", re.I)),
    ("SE", re.compile(r"瑞典|\bsweden\b|stockholm|🇸🇪|(?<![a-z])se(?![a-z])", re.I)),
    ("CH", re.compile(r"瑞士|\bswitzerland\b|zurich|geneva|🇨🇭|(?<![a-z])ch(?![a-z])", re.I)),
    ("AU", re.compile(r"澳大利亚|澳洲|\baustralia\b|sydney|melbourne|\bsyd\b|🇦🇺|(?<![a-z])au(?![a-z])", re.I)),
    ("TW", re.compile(r"台湾|台灣|\btaiwan\b|taipei|🇹🇼|(?<![a-z])tw(?![a-z])", re.I)),
    ("IN", re.compile(r"印度|\bindia\b|mumbai|\bbom\b|🇮🇳|(?<![a-z])in(?![a-z])", re.I)),
    ("TR", re.compile(r"土耳其|\bturkey\b|istanbul|🇹🇷|(?<![a-z])tr(?![a-z])", re.I)),
    ("RU", re.compile(r"俄罗斯|俄羅斯|\brussia\b|moscow|🇷🇺|(?<![a-z])ru(?![a-z])", re.I)),
    ("BR", re.compile(r"巴西|\bbrazil\b|sao\s*paulo|🇧🇷|(?<![a-z])br(?![a-z])", re.I)),
    ("IE", re.compile(r"爱尔兰|愛爾蘭|\bireland\b|dublin|🇮🇪|(?<![a-z])ie(?![a-z])", re.I)),
    ("IT", re.compile(r"意大利|義大利|\bitaly\b|milan|rome|🇮🇹|(?<![a-z])it(?![a-z])", re.I)),
    ("ES", re.compile(r"西班牙|\bspain\b|madrid|🇪🇸|(?<![a-z])es(?![a-z])", re.I)),
    ("PL", re.compile(r"波兰|波蘭|\bpoland\b|warsaw|🇵🇱|(?<![a-z])pl(?![a-z])", re.I)),
    ("VN", re.compile(r"越南|\bvietnam\b|hanoi|🇻🇳|(?<![a-z])vn(?![a-z])", re.I)),
    ("TH", re.compile(r"泰国|泰國|\bthailand\b|bangkok|🇹🇭|(?<![a-z])th(?![a-z])", re.I)),
    ("PH", re.compile(r"菲律宾|菲律賓|\bphilippines\b|manila|🇵🇭|(?<![a-z])ph(?![a-z])", re.I)),
    ("ID", re.compile(r"印尼|印度尼西亚|\bindonesia\b|jakarta|🇮🇩|(?<![a-z])id(?![a-z])", re.I)),
    ("MY", re.compile(r"马来|馬來|\bmalaysia\b|kuala\s*lumpur|🇲🇾|(?<![a-z])my(?![a-z])", re.I)),
    ("AE", re.compile(r"阿联酋|迪拜|\buae\b|\bdubai\b|🇦🇪|(?<![a-z])ae(?![a-z])", re.I)),
    ("MX", re.compile(r"墨西哥|\bmexico\b|🇲🇽|(?<![a-z])mx(?![a-z])", re.I)),
    ("AR", re.compile(r"阿根廷|\bargentina\b|🇦🇷|(?<![a-z])ar(?![a-z])", re.I)),
    ("ZA", re.compile(r"南非|\bsouth\s*africa\b|🇿🇦|(?<![a-z])za(?![a-z])", re.I)),
]

TG_SKIP_URL_RE = re.compile(
    r"(t\.me/|telegram|register\?|matcha\.su|kitty\.work|luoyun)",
    re.I,
)


def proxy_blob(p: dict) -> str:
    return " ".join(str(p.get(k) or "") for k in ("name", "server", "servername", "sni", "host"))


def detect_cc(p: dict) -> str:
    blob = proxy_blob(p)
    for cc, pat in CC_PATTERNS:
        if pat.search(blob):
            return cc
    return "XX"


def is_hk_or_mo(p: dict) -> bool:
    return bool(HK_MO_RE.search(proxy_blob(p)))


def region_priority(p: dict) -> int:
    return PREFERRED_CC_RANK.get(detect_cc(p), 100)


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


def extract_urls_from_tg_html(text: str) -> list[str]:
    found: list[str] = []
    for m in re.finditer(r"<code>(https?://[^<]+)</code>", text, re.I):
        found.append(unescape(m.group(1).strip()))
    for m in re.finditer(r'href="(https?://[^"]+)"', text, re.I):
        u = unescape(m.group(1).strip())
        if re.search(r"sub|clash|subscribe|token|link/", u, re.I):
            found.append(u)
    out: list[str] = []
    seen: set[str] = set()
    for u in found:
        u = u.strip().rstrip("#")
        if not u.startswith("http"):
            continue
        if TG_SKIP_URL_RE.search(u):
            continue
        if "#http" in u:
            u = u.split("#", 1)[0]
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


def load_tg_export_urls(dir_path: Path) -> list[tuple[str, str]]:
    if not dir_path.is_dir():
        return []
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for html_path in sorted(dir_path.glob("*.html")):
        try:
            text = html_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"  WARN tg html read {html_path.name}: {e}")
            continue
        urls = extract_urls_from_tg_html(text)
        print(f"TG export {html_path.name}: {len(urls)} urls")
        for u in urls:
            if u in seen:
                continue
            seen.add(u)
            entries.append((u, f"tg:{html_path.name}"))
    return entries


def clean_proxy(p: dict, index: int) -> dict | None:
    if not isinstance(p, dict):
        return None
    name = str(p.get("name") or f"node-{index}")
    name = re.sub(r"[\x00-\x1f]", "", name).strip() or f"node-{index}"
    p = dict(p)
    p["name"] = name
    t = str(p.get("type") or "").strip().lower()
    if t in DROP_TYPES:
        return None
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
    kept, dropped = [], 0
    for p in proxies:
        ip = host_ip.get(str(p.get("server") or ""))
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
            print(f"Path probe stale ({age_h:.1f}h), ignore")
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
    print(f"Path probe loaded: {len(out)} ok keys")
    return out


def overseas_sort_key(p: dict, overseas_ms: float):
    return (region_priority(p), type_priority(p), overseas_ms)


def format_label(p: dict, display_ms: float, beyond: bool) -> str:
    base = scrub_display_name(str(p["name"]))
    t = str(p.get("type") or "").lower()
    light = latency_emoji(display_ms)
    region = CC_ZH.get(detect_cc(p), "未知")
    proto = ""
    if t == "anytls":
        proto = "[anytls] "
    elif t in ("hysteria2", "hysteria", "hy2"):
        proto = "[hy2] "
    be = "[Be] " if beyond else ""
    return f"{light} {region} {be}{proto}{base} | {display_ms:.0f}ms"


def build_config(selected: list[tuple[dict, float, float | None]], cap: int) -> str:
    seen_names: set[str] = set()
    unique: list[dict] = []
    stats = {"anytls": 0, "hy2": 0, "vless": 0, "trojan": 0, "low": 0, "preferred": 0, "beyond": 0}
    lights = Counter()
    regions = Counter()
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
        lights[latency_emoji(display)] += 1
        regions[CC_ZH.get(detect_cc(p), "未知")] += 1
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
            {"name": "🚀 节点选择", "type": "select", "proxies": ["♻️ 自动选择", "DIRECT"] + names},
            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "proxies": names,
                "url": "https://www.gstatic.com/generate_204",
                "interval": 600,
                "tolerance": 200,
            },
        ],
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"],
    }
    if len(unique) > cap:
        raise RuntimeError(f"BUG: {len(unique)} > {cap}")
    header = (
        f"# Ryukyou nodes | updated {now} | count={len(unique)} | hard_cap={cap} | "
        f"Be_reserved={BE_RESERVED} Beyond[Be]={stats['beyond']} | lights={dict(lights)} | "
        f"regions={dict(regions)} | anytls={stats['anytls']} hy2={stats['hy2']} "
        f"vless={stats['vless']} trojan={stats['trojan']} | drop_types={sorted(DROP_TYPES)}\n"
        f"# name format: <light> <繁體地區> [Be] [proto] <base> | <ms>ms\n"
    )
    return header + yaml.dump(cfg, allow_unicode=True, sort_keys=False, default_flow_style=False)


def select_with_be_reserve(alive, path_map, cap, be_reserved):
    by_key = {proxy_key(p): (p, o) for p, o in alive}
    be_pool = []
    for key, be_ms in path_map.items():
        if key not in by_key:
            continue
        p, o_ms = by_key[key]
        be_pool.append((p, o_ms, float(be_ms)))
    be_pool.sort(key=lambda x: (x[2], type_priority(x[0]), x[1]))
    seats = min(be_reserved, cap, len(be_pool))
    chosen, chosen_keys = [], set()
    for p, o_ms, be_ms in be_pool[:seats]:
        chosen.append((p, o_ms, be_ms))
        chosen_keys.add(proxy_key(p))
    fillers = [(p, o) for p, o in alive if proxy_key(p) not in chosen_keys]
    fillers.sort(key=lambda x: overseas_sort_key(x[0], x[1]))
    need = cap - len(chosen)
    for p, o_ms in fillers[:need]:
        k = proxy_key(p)
        be = path_map.get(k)
        chosen.append((p, o_ms, be if be is not None else None))
    print(f"Be reserve: pool={len(be_pool)} seats={seats}/{be_reserved} total={len(chosen)}/{cap}")
    return chosen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default="sources/urls.txt")
    ap.add_argument("--tg-exports", default="sources/tg_exports")
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
    tg_entries = load_tg_export_urls(Path(args.tg_exports))
    if tg_entries:
        print(f"TG exports added {len(tg_entries)} subscription urls")
        entries.extend(tg_entries)
    deduped_entries: list[tuple[str, str]] = []
    seen_u: set[str] = set()
    for u, d in entries:
        if u in seen_u:
            continue
        seen_u.add(u)
        deduped_entries.append((u, d))
    entries = deduped_entries
    if not entries:
        raise SystemExit("No sources")

    all_proxies = []
    for i, (url, desc) in enumerate(entries, 1):
        try:
            print(f"[{i}/{len(entries)}] Fetch {url}")
            r = requests.get(url, timeout=35)
            r.raise_for_status()
            found = extract_proxies(r.text)
            print(f"  -> {len(found)} ({desc})")
            all_proxies.extend(found)
        except Exception as e:
            print(f"  WARN: {e}")

    deduped, seen = [], set()
    for p in all_proxies:
        k = proxy_key(p)
        if k in seen:
            continue
        seen.add(k)
        deduped.append(p)
    print(f"After dedup (http/socks dropped): {len(deduped)}")
    deduped = filter_blocked_exit_servers(deduped)

    print("Overseas TCP probe ...")
    alive = probe_alive(deduped)
    print(f"Overseas reachable: {len(alive)}")

    candidates, skipped_proto = [], 0
    for p, ms in alive:
        if str(p.get("type") or "").lower() in SKIP_PATH_PROBE_TYPES:
            skipped_proto += 1
            continue
        candidates.append({
            "key": proxy_key(p),
            "server": p.get("server"),
            "port": p.get("port"),
            "type": p.get("type"),
            "name": p.get("name"),
            "overseas_ms": round(ms, 1),
        })
    (out_dir / "candidates.json").write_text(
        json.dumps({
            "updated": datetime.now(timezone.utc).isoformat(),
            "candidates": candidates,
            "drop_types": sorted(DROP_TYPES),
            "skipped_path_probe_protocols": sorted(SKIP_PATH_PROBE_TYPES),
            "skipped_path_probe_count": skipped_proto,
            "source_url_count": len(entries),
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"candidates.json {len(candidates)} (skipped_proto={skipped_proto})")

    path_map = load_path_probe(Path(args.cn_probe))
    if path_map:
        selected = select_with_be_reserve(alive, path_map, cap, be_reserved)
    else:
        ranked = sorted(alive, key=lambda x: overseas_sort_key(x[0], x[1]))
        selected = [(p, o, None) for p, o in ranked[:cap]]
        print(f"No path probe; overseas-only {len(selected)}")

    (out_dir / "clash_clean.yaml").write_text(build_config(selected, cap), encoding="utf-8")
    be_n = sum(1 for _, _, c in selected if c is not None)
    type_c = Counter(str(p.get("type", "")).lower() for p, _, _ in selected)
    (out_dir / "nodes_stats.txt").write_text(
        f"updated={datetime.now(timezone.utc).isoformat()}\n"
        f"source_urls={len(entries)}\n"
        f"final_count={len(selected)} final_beyond_Be={be_n} hard_cap={cap}\n"
        f"drop_types={sorted(DROP_TYPES)}\n"
        f"types={dict(type_c)}\n",
        encoding="utf-8",
    )
    print("Done.")


if __name__ == "__main__":
    main()
