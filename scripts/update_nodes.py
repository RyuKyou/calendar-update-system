#!/usr/bin/env python3
"""Node aggregate: upload/tg skip deep (dedupe+geo only); web keeps deep/R2S filter."""
from __future__ import annotations
import argparse, sys, json, re, socket, time, base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

sys.path.insert(0, str(Path(__file__).resolve().parent))
from deep_probe import mihomo_deep_probe, select_usable
import requests, yaml

VALID_NETWORKS = {"tcp", "udp", "ws", "http", "h2", "grpc", "raw"}
CONNECT_TIMEOUT = 6.0
MAX_WORKERS = 40
MAX_NODES = 512
CN_PROBE_MAX_AGE_HOURS = 36
REALITY_PBK_RE = re.compile(r"^[A-Za-z0-9_-]{40,50}={0,2}$")
DROP_TYPES = {"http", "socks5", "socks"}
SKIP_PATH_PROBE_TYPES = {"http", "socks5", "socks", "wireguard", "snell"}
BLOCKED_EXIT_CC = {"CN", "HK", "MO"}
PROTOCOL_RANK = {"anytls": 0, "hysteria2": 1, "hysteria": 1, "hy2": 1, "vless": 2, "trojan": 3,
    "tuic": 4, "wireguard": 5, "ss": 20, "shadowsocks": 20, "ssr": 20, "shadowsocksr": 20, "vmess": 20}
DEFAULT_PROTOCOL_RANK = 10
PREFERRED_CC_RANK = {"US": 0, "CA": 1, "NO": 2, "SG": 3}
CC_ZH = {"US": "美國", "CA": "加拿大", "NO": "挪威", "SG": "新加坡", "JP": "日本", "KR": "韓國",
    "DE": "德國", "GB": "英國", "FR": "法國", "NL": "荷蘭", "FI": "芬蘭", "SE": "瑞典",
    "CH": "瑞士", "AU": "澳洲", "TW": "台灣", "IN": "印度", "TR": "土耳其", "RU": "俄羅斯",
    "BR": "巴西", "IE": "愛爾蘭", "IT": "義大利", "ES": "西班牙", "PL": "波蘭", "VN": "越南",
    "TH": "泰國", "PH": "菲律賓", "ID": "印尼", "MY": "馬來西亞", "AE": "阿聯酋", "MX": "墨西哥",
    "AR": "阿根廷", "ZA": "南非", "XX": "未知"}
HK_MO_RE = re.compile(r"香港|澳门|澳門|\bhk\b|\bhkg\b|hong\s*kong|\bmo\b|\bmac\b|macau|macao|🇭🇰|🇲🇴", re.I)
NAME_SCRUB_RE = re.compile(r"(中国|大陸|大陆|內地|内地|\bcn\b|\bchina\b|香港|澳门|澳門|\bhk\b|\bhkg\b|hong\s*kong|macau|macao|🇨🇳|🇭🇰|🇲🇴)", re.I)
CC_PATTERNS = [
    ("US", re.compile(r"美国|美國|\busa\b|united\s*states|🇺🇸|(?<![a-z])us(?![a-z])", re.I)),
    ("CA", re.compile(r"加拿大|\bcanada\b|🇨🇦|(?<![a-z])ca(?![a-z])", re.I)),
    ("NO", re.compile(r"挪威|\bnorway\b|🇳🇴|(?<![a-z])no(?![a-z])", re.I)),
    ("SG", re.compile(r"新加坡|\bsingapore\b|🇸🇬|(?<![a-z])sg(?![a-z])", re.I)),
    ("JP", re.compile(r"日本|\bjapan\b|🇯🇵|(?<![a-z])jp(?![a-z])", re.I)),
    ("KR", re.compile(r"韩国|韓國|\bkorea\b|🇰🇷|(?<![a-z])kr(?![a-z])", re.I)),
    ("DE", re.compile(r"德国|德國|\bgermany\b|🇩🇪|(?<![a-z])de(?![a-z])", re.I)),
    ("GB", re.compile(r"英国|英國|\buk\b|🇬🇧|(?<![a-z])gb(?![a-z])", re.I)),
    ("FR", re.compile(r"法国|法國|\bfrance\b|🇫🇷|(?<![a-z])fr(?![a-z])", re.I)),
    ("NL", re.compile(r"荷兰|荷蘭|\bnetherlands\b|🇳🇱|(?<![a-z])nl(?![a-z])", re.I)),
    ("TW", re.compile(r"台湾|台灣|\btaiwan\b|🇹🇼|(?<![a-z])tw(?![a-z])", re.I)),
    ("RU", re.compile(r"俄罗斯|俄羅斯|\brussia\b|🇷🇺|(?<![a-z])ru(?![a-z])", re.I)),
    ("TR", re.compile(r"土耳其|\bturkey\b|🇹🇷|(?<![a-z])tr(?![a-z])", re.I)),
    ("AU", re.compile(r"澳大利亚|澳洲|\baustralia\b|🇦🇺|(?<![a-z])au(?![a-z])", re.I)),
    ("IN", re.compile(r"印度|\bindia\b|🇮🇳|(?<![a-z])in(?![a-z])", re.I)),
    ("BR", re.compile(r"巴西|\bbrazil\b|🇧🇷|(?<![a-z])br(?![a-z])", re.I)),
    ("IE", re.compile(r"爱尔兰|愛爾蘭|\bireland\b|🇮🇪|(?<![a-z])ie(?![a-z])", re.I)),
    ("IT", re.compile(r"意大利|義大利|\bitaly\b|🇮🇹|(?<![a-z])it(?![a-z])", re.I)),
    ("ES", re.compile(r"西班牙|\bspain\b|🇪🇸|(?<![a-z])es(?![a-z])", re.I)),
    ("PL", re.compile(r"波兰|波蘭|\bpoland\b|🇵🇱|(?<![a-z])pl(?![a-z])", re.I)),
    ("VN", re.compile(r"越南|\bvietnam\b|🇻🇳|(?<![a-z])vn(?![a-z])", re.I)),
    ("TH", re.compile(r"泰国|泰國|\bthailand\b|🇹🇭|(?<![a-z])th(?![a-z])", re.I)),
    ("PH", re.compile(r"菲律宾|菲律賓|\bphilippines\b|🇵🇭|(?<![a-z])ph(?![a-z])", re.I)),
    ("ID", re.compile(r"印尼|\bindonesia\b|🇮🇩|(?<![a-z])id(?![a-z])", re.I)),
    ("MY", re.compile(r"马来|馬來|\bmalaysia\b|🇲🇾|(?<![a-z])my(?![a-z])", re.I)),
    ("AE", re.compile(r"阿联酋|迪拜|\buae\b|\bdubai\b|🇦🇪|(?<![a-z])ae(?![a-z])", re.I)),
    ("MX", re.compile(r"墨西哥|\bmexico\b|🇲🇽|(?<![a-z])mx(?![a-z])", re.I)),
    ("AR", re.compile(r"阿根廷|\bargentina\b|🇦🇷|(?<![a-z])ar(?![a-z])", re.I)),
    ("ZA", re.compile(r"南非|\bsouth\s*africa\b|🇿🇦|(?<![a-z])za(?![a-z])", re.I)),
    ("FI", re.compile(r"芬兰|芬蘭|\bfinland\b|🇫🇮|(?<![a-z])fi(?![a-z])", re.I)),
    ("SE", re.compile(r"瑞典|\bsweden\b|🇸🇪|(?<![a-z])se(?![a-z])", re.I)),
    ("CH", re.compile(r"瑞士|\bswitzerland\b|🇨🇭|(?<![a-z])ch(?![a-z])", re.I)),
]
TG_SKIP_URL_RE = re.compile(r"(t\.me/|telegram|register\?|matcha\.su|kitty\.work|luoyun)", re.I)

def proxy_blob(p):
    return " ".join(str(p.get(k) or "") for k in ("name", "server", "servername", "sni", "host"))
def detect_cc(p):
    blob = proxy_blob(p)
    for cc, pat in CC_PATTERNS:
        if pat.search(blob): return cc
    return "XX"
def is_hk_or_mo(p):
    return bool(HK_MO_RE.search(proxy_blob(p)))
def region_priority(p):
    return PREFERRED_CC_RANK.get(detect_cc(p), 100)
def type_priority(p):
    return PROTOCOL_RANK.get(str(p.get("type") or "").strip().lower(), DEFAULT_PROTOCOL_RANK)
def latency_emoji(ms):
    if ms < 150: return "🟢"
    if ms < 400: return "🟡"
    if ms < 800: return "🟠"
    return "🔴"
def scrub_display_name(name):
    s = str(name or "")
    s = re.sub(r"^[🟢🟡🟠🔴]\s*", "", s)
    s = re.sub(r"\[Be\]\s*", "", s, flags=re.I)
    s = re.sub(r"\[(anytls|hy2|hysteria2?|ssr?|vmess|trojan|vless)\]\s*", "", s, flags=re.I)
    s = re.sub(r"\s*\|\s*\d+\s*ms\s*$", "", s, flags=re.I)
    regions = "|".join(re.escape(v) for v in CC_ZH.values() if v and v != "未知")
    if regions: s = re.sub(rf"^({regions})\s+", "", s)
    s = NAME_SCRUB_RE.sub("", s)
    s = re.sub(r"\s{2,}", " ", s).strip(" -_|/")
    if len(s) > 36: s = s[:36].rstrip() + "…"
    return s or "node"
def load_urls(path):
    entries = []
    if not path.exists(): return entries
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        if "|" in line:
            url, desc = line.split("|", 1)
            entries.append((url.strip(), desc.strip()))
        else:
            entries.append((line, ""))
    return entries
def extract_urls_from_tg_html(text):
    found = []
    for m in re.finditer(r"<code>(https?://[^<]+)</code>", text, re.I):
        found.append(unescape(m.group(1).strip()))
    for m in re.finditer(r'href="(https?://[^"]+)"', text, re.I):
        u = unescape(m.group(1).strip())
        if re.search(r"sub|clash|subscribe|token|link/", u, re.I):
            found.append(u)
    out, seen = [], set()
    for u in found:
        u = u.strip().rstrip("#")
        if not u.startswith("http") or TG_SKIP_URL_RE.search(u): continue
        if "#http" in u: u = u.split("#", 1)[0]
        if u in seen: continue
        seen.add(u); out.append(u)
    return out
def load_tg_export_urls(dir_path):
    if not dir_path.is_dir(): return []
    entries, seen = [], set()
    for html_path in sorted(dir_path.glob("*.html")):
        try: text = html_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"  WARN tg html {html_path.name}: {e}"); continue
        urls = extract_urls_from_tg_html(text)
        print(f"TG export {html_path.name}: {len(urls)} urls")
        for u in urls:
            if u in seen: continue
            seen.add(u); entries.append((u, f"tg:{html_path.name}"))
    return entries

def load_tg_share_proxies(dir_path: Path) -> list:
    if not dir_path.is_dir():
        return []
    out = []
    for html_path in sorted(dir_path.glob("*.html")):
        try:
            text = html_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"  WARN tg share {html_path.name}: {e}")
            continue
        found = parse_share_links(text)
        if found:
            print(f"TG share-links {html_path.name}: {len(found)}")
            out.extend(found)
    return out

def clean_proxy(p, index):
    if not isinstance(p, dict): return None
    name = str(p.get("name") or f"node-{index}")
    name = re.sub(r"[\x00-\x1f]", "", name).strip() or f"node-{index}"
    p = dict(p); p["name"] = name
    t = str(p.get("type") or "").strip().lower()
    if t in DROP_TYPES: return None
    net = p.get("network")
    if isinstance(net, str):
        base = net.split("#")[0].split("@")[0].strip().lower()
        if base in VALID_NETWORKS: p["network"] = base
        else: p.pop("network", None)
    if not p.get("type") or not p.get("server"): return None
    try: port = int(p.get("port") or 0)
    except (TypeError, ValueError): return None
    if port <= 0 or port > 65535: return None
    p["port"] = port
    if is_hk_or_mo(p): return None
    ro = p.get("reality-opts")
    if isinstance(ro, dict):
        pbk = str(ro.get("public-key") or ro.get("public_key") or "").strip()
        if pbk and not REALITY_PBK_RE.fullmatch(pbk): return None
        if not pbk and ("public-key" in ro or "public_key" in ro): return None
    return p
def extract_proxies(text):
    try: data = yaml.safe_load(text)
    except Exception: return []
    if not isinstance(data, dict): return []
    raw = data.get("proxies") or []
    if not isinstance(raw, list): return []
    out = []
    for i, item in enumerate(raw):
        c = clean_proxy(item, i)
        if c: out.append(c)
    return out

def parse_share_links(text: str) -> list:
    out = []
    for i, raw in enumerate(text.splitlines()):
        line = raw.strip()
        if not line or line.startswith("#"): continue
        try:
            if line.startswith("vless://"):
                u = urlparse(line)
                uuid, host, port = unquote(u.username or ""), u.hostname, u.port
                if not uuid or not host or not port: continue
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                name = unquote(u.fragment) if u.fragment else f"vless-{i}"
                p = {"name": name, "type": "vless", "server": host, "port": int(port),
                     "uuid": uuid, "udp": True, "tls": q.get("security") in ("tls", "reality"),
                     "servername": q.get("sni") or q.get("host") or "",
                     "client-fingerprint": q.get("fp") or "", "network": q.get("type") or "tcp"}
                if q.get("flow"): p["flow"] = q["flow"]
                if q.get("security") == "reality":
                    p["reality-opts"] = {"public-key": q.get("pbk") or "", "short-id": q.get("sid") or ""}
                    p["tls"] = True
                if q.get("type") == "ws":
                    p["network"] = "ws"
                    wo = {"path": unquote(q.get("path") or "/")}
                    if q.get("host"): wo["headers"] = {"Host": q["host"]}
                    p["ws-opts"] = wo
                if q.get("type") == "grpc" and q.get("serviceName"):
                    p["grpc-opts"] = {"grpc-service-name": q["serviceName"]}
                c = clean_proxy(p, i)
                if c: out.append(c)
            elif line.startswith("trojan://"):
                u = urlparse(line)
                password, host, port = unquote(u.username or ""), u.hostname, u.port
                if not password or not host or not port: continue
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                name = unquote(u.fragment) if u.fragment else f"trojan-{i}"
                p = {"name": name, "type": "trojan", "server": host, "port": int(port),
                     "password": password, "udp": True, "sni": q.get("sni") or "",
                     "client-fingerprint": q.get("fp") or ""}
                if q.get("type") == "ws":
                    p["network"] = "ws"
                    wo = {"path": unquote(q.get("path") or "/")}
                    if q.get("host"): wo["headers"] = {"Host": q["host"]}
                    p["ws-opts"] = wo
                c = clean_proxy(p, i)
                if c: out.append(c)
            elif line.startswith("ss://"):
                body = line[5:]; name = f"ss-{i}"
                if "#" in body:
                    body, frag = body.split("#", 1); name = unquote(frag)
                host = port = method = password = None
                if "@" in body:
                    userinfo, hostport = body.rsplit("@", 1)
                    try:
                        if ":" not in userinfo:
                            pad = "=" * ((4 - len(userinfo) % 4) % 4)
                            dec = base64.urlsafe_b64decode(userinfo + pad).decode("utf-8", "replace")
                            method, password = dec.split(":", 1)
                        else:
                            method, password = userinfo.split(":", 1)
                            try:
                                pad = "=" * ((4 - len(password) % 4) % 4)
                                password = base64.urlsafe_b64decode(password + pad).decode("utf-8", "replace")
                            except Exception:
                                password = unquote(password)
                    except Exception:
                        continue
                    if ":" in hostport:
                        host, ps = hostport.rsplit(":", 1)
                        port = int(ps.split("/")[0].split("?")[0])
                else:
                    try:
                        pad = "=" * ((4 - len(body) % 4) % 4)
                        dec = base64.urlsafe_b64decode(body + pad).decode("utf-8", "replace")
                        ui, hp = dec.rsplit("@", 1)
                        method, password = ui.split(":", 1)
                        host, ps = hp.rsplit(":", 1); port = int(ps)
                    except Exception:
                        continue
                if not all([host, port, method, password]): continue
                p = {"name": name, "type": "ss", "server": host, "port": int(port),
                     "cipher": method, "password": password, "udp": True}
                c = clean_proxy(p, i)
                if c: out.append(c)
            elif line.startswith("vmess://"):
                b64 = line[8:].split("#")[0].strip()
                pad = "=" * ((4 - len(b64) % 4) % 4)
                try:
                    conf = json.loads(base64.urlsafe_b64decode(b64 + pad).decode("utf-8", "replace"))
                except Exception:
                    continue
                p = {"name": str(conf.get("ps") or f"vmess-{i}"), "type": "vmess",
                     "server": conf.get("add") or "", "port": int(conf.get("port") or 0),
                     "uuid": conf.get("id") or "", "alterId": int(conf.get("aid") or 0),
                     "cipher": conf.get("scy") or "auto", "udp": True,
                     "network": conf.get("net") or "tcp",
                     "tls": conf.get("tls") in ("tls", "true", True),
                     "servername": conf.get("sni") or ""}
                if conf.get("net") == "ws":
                    p["ws-opts"] = {"path": conf.get("path") or "/"}
                    if conf.get("host"):
                        p["ws-opts"]["headers"] = {"Host": conf["host"]}
                c = clean_proxy(p, i)
                if c: out.append(c)
        except Exception:
            continue
    print(f"Share-link parse: {len(out)} proxies")
    return out

def load_manual_subs(dir_path: Path):
    url_entries, proxies = [], []
    if not dir_path.is_dir(): return url_entries, proxies
    for path in sorted(dir_path.iterdir()):
        if not path.is_file(): continue
        name = path.name
        if name.startswith(".") or name.lower() == "readme.md": continue
        if path.suffix.lower() not in {".txt", ".yaml", ".yml", ".json"}: continue
        try: raw = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"  WARN manual {name}: {e}"); continue
        found = extract_proxies(raw)
        if found:
            print(f"Manual YAML {name}: {len(found)} proxies"); proxies.extend(found); continue
        if "://" in raw and any(x in raw for x in ("vless://", "ss://", "trojan://", "vmess://")):
            links = parse_share_links(raw)
            if links:
                print(f"Manual share-links {name}: {len(links)} proxies"); proxies.extend(links); continue
        urls = re.findall(r"https?://[^\s<>\"']+", raw)
        n = 0
        for u in urls:
            u = u.strip().rstrip(").,;'\"")
            if not u.startswith("http") or TG_SKIP_URL_RE.search(u): continue
            url_entries.append((u, f"manual:{name}")); n += 1
        if n: print(f"Manual URLs {name}: {n}")
    return url_entries, proxies

def load_previous_final(path: Path):
    if not path.is_file(): return []
    try:
        found = extract_proxies(path.read_text(encoding="utf-8", errors="replace"))
        print(f"Previous final seed {path.name}: {len(found)} nodes"); return found
    except Exception as e:
        print(f"WARN previous final seed: {e}"); return []
def proxy_key(p):
    t = str(p.get("type", "")); server = str(p.get("server", "")); port = str(p.get("port", ""))
    uid = str(p.get("uuid") or p.get("password") or p.get("auth") or "")
    return f"{t}|{server}|{port}|{uid}"
def resolve_ip(host):
    try:
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host): return host
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return infos[0][4][0] if infos else None
    except Exception: return None
def filter_blocked_exit_servers(proxies):
    hosts = sorted({str(p.get("server") or "") for p in proxies if p.get("server")})
    host_ip = {}
    for h in hosts:
        ip = resolve_ip(h)
        if ip: host_ip[h] = ip
    ips = sorted(set(host_ip.values())); blocked_ips = set()
    for i in range(0, len(ips), 80):
        batch = ips[i:i+80]
        try:
            r = requests.post("http://ip-api.com/batch?fields=status,countryCode,query",
                json=[{"query": ip} for ip in batch], timeout=25)
            if r.status_code != 200: continue
            for row in r.json():
                if isinstance(row, dict) and row.get("status") == "success":
                    if str(row.get("countryCode") or "").upper() in BLOCKED_EXIT_CC:
                        blocked_ips.add(str(row.get("query")))
        except Exception as e: print(f"  WARN geo: {e}")
        time.sleep(0.4)
    kept, dropped = [], 0
    for p in proxies:
        ip = host_ip.get(str(p.get("server") or ""))
        if ip and ip in blocked_ips: dropped += 1; continue
        kept.append(p)
    print(f"CN/HK/MO server IP drop: {dropped}, kept {len(kept)}")
    return kept
def tcp_latency_ms(server, port):
    try:
        if not server or " " in server: return None
        t0 = time.perf_counter()
        with socket.create_connection((server, port), timeout=CONNECT_TIMEOUT): pass
        return (time.perf_counter() - t0) * 1000.0
    except Exception: return None
def probe_alive(proxies):
    alive = []
    def work(p): return p, tcp_latency_ms(str(p["server"]), int(p["port"]))
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = [ex.submit(work, p) for p in proxies]
        for fut in as_completed(futs):
            p, ms = fut.result()
            if ms is not None: alive.append((p, ms))
    return alive
def load_path_probe(path):
    if not path.exists(): return {}
    try: data = json.loads(path.read_text(encoding="utf-8"))
    except Exception: return {}
    updated = data.get("updated") or ""
    try:
        ts = datetime.fromisoformat(updated.replace("Z", "+00:00"))
        age_h = (datetime.now(timezone.utc) - ts.astimezone(timezone.utc)).total_seconds() / 3600.0
        if age_h > CN_PROBE_MAX_AGE_HOURS:
            print(f"Path probe stale ({age_h:.1f}h), ignore"); return {}
    except Exception:
        print("Path probe timestamp parse fail, still using file")
    out = {}
    for row in data.get("results") or []:
        if not row.get("ok"): continue
        key = str(row.get("key") or ""); ms = row.get("ms")
        if key and isinstance(ms, (int, float)): out[key] = float(ms)
    print(f"Path probe loaded: {len(out)} ok keys")
    return out
def format_label(p, display_ms, beyond):
    base = scrub_display_name(str(p["name"]))
    light = latency_emoji(display_ms)
    region = CC_ZH.get(detect_cc(p), "未知")
    if beyond: return f"{light} {region} [Be] {base}"
    return f"{light} {region} {base}"

def format_label_upload(p):
    """No traffic-light / Be — distinguish upload/TG sources from probed ones."""
    base = scrub_display_name(str(p.get("name") or "node"))
    region = CC_ZH.get(detect_cc(p), "未知")
    return f"{region} {base}"

def build_config(selected, cap):
    """selected items: (proxy, o_ms, be_ms) or (proxy, o_ms, be_ms, is_upload)."""
    seen_names, unique = set(), []
    stats = {"anytls": 0, "hy2": 0, "vless": 0, "trojan": 0, "low": 0, "preferred": 0, "beyond": 0, "upload": 0}
    lights, regions = Counter(), Counter()
    for item in selected:
        if len(item) == 4:
            p, o_ms, be_ms, is_upload = item
        else:
            p, o_ms, be_ms = item
            is_upload = False
        p = dict(p); t = str(p.get("type") or "").lower()
        if region_priority(p) < 100: stats["preferred"] += 1
        if t == "anytls": stats["anytls"] += 1
        elif t in ("hysteria2", "hysteria", "hy2"): stats["hy2"] += 1
        elif t == "vless": stats["vless"] += 1
        elif t == "trojan": stats["trojan"] += 1
        elif t in ("ss", "shadowsocks", "ssr", "shadowsocksr", "vmess"): stats["low"] += 1
        beyond = (be_ms is not None) and (not is_upload)
        if beyond: stats["beyond"] += 1
        if is_upload: stats["upload"] += 1
        regions[CC_ZH.get(detect_cc(p), "未知")] += 1
        if is_upload:
            label = format_label_upload(p)
            lights["upload"] += 1
        else:
            display = float(be_ms) if beyond else float(o_ms or 0)
            lights[latency_emoji(display)] += 1
            label = format_label(p, display, beyond)
        if label in seen_names:
            k = 2
            while f"{label}-{k}" in seen_names: k += 1
            label = f"{label}-{k}"
        p["name"] = label; seen_names.add(label); unique.append(p)
    names = [p["name"] for p in unique] or ["DIRECT"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cfg = {"mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "info", "ipv6": False,
        "proxies": unique,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["♻️ 自动选择", "DIRECT"] + names},
            {"name": "♻️ 自动选择", "type": "url-test", "proxies": names,
             "url": "https://www.gstatic.com/generate_204", "interval": 600, "tolerance": 200}],
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"]}
    if len(unique) > cap: raise RuntimeError(f"BUG: {len(unique)} > {cap}")
    header = (f"# Ryukyou nodes | updated {now} | count={len(unique)} | hard_cap={cap} | "
        f"Beyond[Be]={stats['beyond']} | lights={dict(lights)} | regions={dict(regions)} | "
        f"anytls={stats['anytls']} hy2={stats['hy2']} vless={stats['vless']} trojan={stats['trojan']} low={stats['low']}\n"
        f"upload_direct={stats['upload']} | upload=no-light/no-Be; web=deep+R2S\n")
    return header + yaml.dump(cfg, allow_unicode=True, sort_keys=False, default_flow_style=False)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default="sources/urls.txt")
    ap.add_argument("--tg-exports", default="sources/tg_exports")
    ap.add_argument("--manual-subs", default="sources/manual_subs")
    ap.add_argument("--output-dir", default="output")
    ap.add_argument("--max-nodes", type=int, default=MAX_NODES)
    ap.add_argument("--cn-probe", default="output/cn_probe_results.json")
    args = ap.parse_args()
    cap = max(1, min(int(args.max_nodes), MAX_NODES))
    out_dir = Path(args.output_dir); out_dir.mkdir(parents=True, exist_ok=True)
    web_entries = load_urls(Path(args.sources))
    tg_entries = load_tg_export_urls(Path(args.tg_exports))
    if tg_entries:
        print(f"TG export http subs: {len(tg_entries)}")
        web_entries.extend(tg_entries)
    manual_urls, manual_proxies = load_manual_subs(Path(args.manual_subs))
    if manual_urls:
        print(f"Manual http subs: {len(manual_urls)}")
        web_entries.extend(manual_urls)
    tg_share = load_tg_share_proxies(Path(args.tg_exports))
    priority_proxies = list(manual_proxies) + list(tg_share)
    print(f"Upload/TG priority proxies: {len(priority_proxies)}")

    deduped_entries, seen_u = [], set()
    for u, d in web_entries:
        if u in seen_u:
            continue
        seen_u.add(u)
        deduped_entries.append((u, d))
    web_entries = deduped_entries
    if not web_entries and not priority_proxies:
        raise SystemExit("No sources")

    web_proxies = []
    for i, (url, desc) in enumerate(web_entries, 1):
        try:
            print(f"[{i}/{len(web_entries)}] Fetch web {url}")
            r = requests.get(url, timeout=35)
            r.raise_for_status()
            found = extract_proxies(r.text)
            print(f"  -> {len(found)} ({desc})")
            web_proxies.extend(found)
        except Exception as e:
            print(f"  WARN: {e}")

    prev_final = load_previous_final(out_dir / "clash_clean.yaml")
    prev_keys = {proxy_key(p) for p in prev_final}

    prio_dedup, seen_p = [], set()
    for p in priority_proxies:
        k = proxy_key(p)
        if k in seen_p:
            continue
        seen_p.add(k)
        prio_dedup.append(p)
    prio_geo = filter_blocked_exit_servers(prio_dedup)
    print(f"Upload/TG after geo: {len(prio_geo)}")

    web_dedup, seen_w = [], set()
    for p in web_proxies:
        k = proxy_key(p)
        if k in seen_w or k in seen_p:
            continue
        seen_w.add(k)
        web_dedup.append(p)
    for p in prev_final:
        k = proxy_key(p)
        if k in seen_w or k in seen_p:
            continue
        seen_w.add(k)
        web_dedup.append(p)
    web_geo = filter_blocked_exit_servers(web_dedup)
    print("Web overseas TCP probe ...")
    alive = probe_alive(web_geo)
    print(f"Web TCP reachable: {len(alive)}")
    candidates, skipped_proto = [], 0
    for p, ms in alive:
        if str(p.get("type") or "").lower() in SKIP_PATH_PROBE_TYPES:
            skipped_proto += 1
            continue
        candidates.append({
            "key": proxy_key(p), "server": p.get("server"), "port": p.get("port"),
            "type": p.get("type"), "name": p.get("name"), "overseas_ms": round(ms, 1),
        })
    (out_dir / "candidates.json").write_text(json.dumps({
        "updated": datetime.now(timezone.utc).isoformat(),
        "candidates": candidates,
        "drop_types": sorted(DROP_TYPES),
        "skipped_path_probe_count": skipped_proto,
        "source_url_count": len(web_entries),
        "sticky_seed": len(prev_final),
        "upload_direct": len(prio_geo),
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    path_map = load_path_probe(Path(args.cn_probe))
    LEGACY_TYPES = {"ss", "shadowsocks", "ssr", "shadowsocksr", "vmess", "hysteria", "tuic"}
    path_alive, web_extra = [], []
    for p, ms in alive:
        k = proxy_key(p)
        if path_map and k in path_map:
            path_alive.append(p)
        elif k in prev_keys or str(p.get("type") or "").lower() in LEGACY_TYPES:
            web_extra.append(p)
    seen_pool, ordered = set(), []
    for p in path_alive + web_extra:
        k = proxy_key(p)
        if k in seen_pool:
            continue
        seen_pool.add(k)
        ordered.append(p)
    pool = ordered
    pool.sort(key=lambda p: (
        0 if proxy_key(p) in prev_keys else 1,
        type_priority(p),
    ))
    print(f"Web deep pool: {len(pool)} path={len(path_alive)} extra={len(web_extra)}")
    deep = mihomo_deep_probe(pool)
    web_selected = select_usable(alive, path_map, deep, cap)
    print(f"Web deep selected: {len(web_selected)}")

    selected, seen_final = [], set()
    for p in prio_geo:
        k = proxy_key(p)
        if k in seen_final:
            continue
        seen_final.add(k)
        selected.append((p, 0.0, None, True))
        if len(selected) >= cap:
            break
    if len(selected) < cap:
        for item in web_selected:
            p = item[0]
            k = proxy_key(p)
            if k in seen_final:
                continue
            seen_final.add(k)
            o_ms, be_ms = item[1], item[2]
            selected.append((p, o_ms, be_ms, False))
            if len(selected) >= cap:
                break

    print(f"Final selected: {len(selected)} (upload={sum(1 for x in selected if x[3])} web={sum(1 for x in selected if not x[3])})")
    (out_dir / "clash_clean.yaml").write_text(build_config(selected, cap), encoding="utf-8")
    be_n = sum(1 for x in selected if (not x[3]) and x[2] is not None)
    up_n = sum(1 for x in selected if x[3])
    type_c = Counter(str(x[0].get("type", "")).lower() for x in selected)
    sticky_kept = sum(1 for x in selected if proxy_key(x[0]) in prev_keys)
    (out_dir / "nodes_stats.txt").write_text(
        f"updated={datetime.now(timezone.utc).isoformat()}\nsource_urls={len(web_entries)}\n"
        f"final_count={len(selected)} upload_direct={up_n} final_beyond_Be={be_n} hard_cap={cap}\n"
        f"deep_pass={len(deep)} path_ok={len(path_map)} sticky_seed={len(prev_final)} sticky_kept={sticky_kept}\n"
        f"types={dict(type_c)}\n", encoding="utf-8")
    print(f"Sticky kept: {sticky_kept}/{len(prev_final)}"); print("Done.")

if __name__ == "__main__":
    main()
