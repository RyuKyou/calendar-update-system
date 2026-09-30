#!/usr/bin/env python3
"""
Fetch Clash subscription YAMLs, extract & clean proxies only,
build one valid minimal Clash config, then encrypt + stego embed.
If payload still exceeds carrier capacity, skip stego and only write scrambled backup.
"""

import os
import sys
import argparse
import base64
import struct
import random
import re
from datetime import datetime
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import wave
import requests
import yaml

SALT = b"calendar-stego-v1-salt-2026"
# 2x previous capacity
IMAGE_SIZE = (3200, 2400)   # ~23M bits
AUDIO_DURATION = 180.0      # ~4M samples @ 22050 Hz
VALID_NETWORKS = {"tcp", "udp", "ws", "http", "h2", "grpc", "raw"}

def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

def encrypt_content(content: str, password: str) -> bytes:
    key = derive_key(password)
    f = Fernet(key)
    return f.encrypt(content.encode("utf-8"))

def split_payload(payload: bytes):
    mid = len(payload) // 2
    return payload[:mid], payload[mid:]

def make_scrambled_b64(ciphertext: bytes, chunk_size: int = 48) -> str:
    b64 = base64.b64encode(ciphertext).decode("ascii")
    chunks = [b64[i:i + chunk_size] for i in range(0, len(b64), chunk_size)]
    indices = list(range(len(chunks)))
    rng = random.Random(20260923)
    rng.shuffle(indices)
    lines = [f"{orig_idx:03d}:{chunks[orig_idx]}" for orig_idx in indices]
    header = f"# SCRAMBLED_B64 v1 chunks={len(chunks)} size={chunk_size}\n"
    return header + "\n".join(lines)

def embed_lsb_image(img: Image.Image, data: bytes) -> Image.Image:
    header = struct.pack(">I", len(data))
    full = header + data
    bits = np.unpackbits(np.frombuffer(full, dtype=np.uint8))
    arr = np.array(img.convert("RGB"))
    h, w, _ = arr.shape
    capacity = h * w * 3
    if len(bits) > capacity:
        raise ValueError(f"Image too small. Need {len(bits)} bits, have {capacity}")
    flat = arr.reshape(-1).copy()
    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | int(bit)
    return Image.fromarray(flat.reshape(h, w, 3).astype(np.uint8))

def create_calendar_image(year: int, month: int, size=IMAGE_SIZE) -> Image.Image:
    img = Image.new("RGB", size, color=(245, 248, 252))
    draw = ImageDraw.Draw(img)
    try:
        title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 72)
        cell_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 40)
    except Exception:
        title_font = ImageFont.load_default()
        cell_font = ImageFont.load_default()
    draw.text((size[0] // 2, 50), f"{year} 年 {month} 月", fill=(30, 60, 90), font=title_font, anchor="mt")
    weekdays = ["一", "二", "三", "四", "五", "六", "日"]
    cell_w = size[0] // 7
    for i, d in enumerate(weekdays):
        draw.text((i * cell_w + cell_w // 2, 140), d, fill=(80, 100, 120), font=cell_font, anchor="mt")
    import calendar
    cal = calendar.Calendar(firstweekday=0)
    month_days = cal.monthdayscalendar(year, month)
    start_y = 220
    cell_h = (size[1] - start_y - 40) // 6
    today = datetime.now()
    for week_idx, week in enumerate(month_days):
        for day_idx, day in enumerate(week):
            if day == 0:
                continue
            x = day_idx * cell_w + cell_w // 2
            y = start_y + week_idx * cell_h + cell_h // 2
            color = (20, 40, 70)
            if year == today.year and month == today.month and day == today.day:
                r = 36
                draw.ellipse([x - r, y - r, x + r, y + r], fill=(70, 130, 180))
                color = (255, 255, 255)
            draw.text((x, y), str(day), fill=color, font=cell_font, anchor="mm")
    draw.text((size[0] // 2, size[1] - 40), "Calendar Reminder", fill=(160, 170, 180), font=cell_font, anchor="mt")
    return img

def create_calendar_audio(duration_sec: float = AUDIO_DURATION, sample_rate: int = 22050) -> np.ndarray:
    t = np.linspace(0, duration_sec, int(sample_rate * duration_sec), endpoint=False)
    freqs = [261.63, 329.63, 392.00, 523.25, 587.33, 659.25]
    audio = np.zeros_like(t)
    segment = duration_sec / len(freqs)
    for i, f in enumerate(freqs):
        start = i * segment
        end = start + min(2.0, segment * 0.8)
        mask = (t >= start) & (t < end)
        audio[mask] += 0.2 * np.sin(2 * np.pi * f * t[mask]) * np.exp(-0.8 * (t[mask] - start))
    audio += 0.03 * np.sin(2 * np.pi * 110 * t)
    peak = np.max(np.abs(audio)) + 1e-9
    audio = audio / peak * 0.7
    return (audio * 32767).astype(np.int16)

def embed_lsb_audio(samples: np.ndarray, data: bytes) -> np.ndarray:
    header = struct.pack(">I", len(data))
    full = header + data
    bits = np.unpackbits(np.frombuffer(full, dtype=np.uint8))
    if len(bits) > len(samples):
        raise ValueError(f"Audio too short. Need {len(bits)} samples, have {len(samples)}")
    out = samples.copy()
    for i, bit in enumerate(bits):
        out[i] = (out[i] & ~1) | int(bit)
    return out

def save_wav(path: str, samples: np.ndarray, sample_rate: int = 22050):
    with wave.open(path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(samples.tobytes())

def load_urls_from_file(path: Path):
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
    return p

def extract_proxies_from_yaml_text(text: str) -> list:
    proxies = []
    try:
        data = yaml.safe_load(text)
    except Exception:
        return proxies
    if not isinstance(data, dict):
        return proxies
    raw = data.get("proxies") or []
    if not isinstance(raw, list):
        return proxies
    for i, item in enumerate(raw):
        cleaned = clean_proxy(item, i)
        if cleaned:
            proxies.append(cleaned)
    return proxies

def build_clash_config(proxies: list) -> str:
    seen = set()
    unique = []
    for p in proxies:
        n = p["name"]
        if n in seen:
            k = 2
            while f"{n}-{k}" in seen:
                k += 1
            p = dict(p)
            p["name"] = f"{n}-{k}"
            n = p["name"]
        seen.add(n)
        unique.append(p)

    names = [p["name"] for p in unique]
    if not names:
        names = ["DIRECT"]

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
    return yaml.dump(cfg, allow_unicode=True, sort_keys=False, default_flow_style=False)

def fetch_and_merge_proxies(entries) -> str:
    all_proxies = []
    for i, (url, desc) in enumerate(entries, 1):
        try:
            print(f"[{i}/{len(entries)}] Fetching {url} ...")
            resp = requests.get(url, timeout=25)
            resp.raise_for_status()
            found = extract_proxies_from_yaml_text(resp.text)
            print(f"  -> {len(found)} proxies ({desc or 'no desc'})")
            all_proxies.extend(found)
        except Exception as e:
            print(f"  Warning: failed {url}: {e}")
    print(f"Total proxies collected: {len(all_proxies)}")
    return build_clash_config(all_proxies)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--password", default=None)
    parser.add_argument("--url", help="Single URL (legacy)")
    parser.add_argument("--content", help="Direct content string")
    parser.add_argument("--sources", default="sources/urls.txt")
    parser.add_argument("--output-dir", default="output")
    parser.add_argument("--skip-stego", action="store_true", help="Only write scrambled + yaml, no image/audio")
    args = parser.parse_args()

    password = args.password or os.environ.get("STEGO_PASSWORD")
    if not password:
        print("Error: password required", file=sys.stderr)
        sys.exit(1)

    if args.content:
        content = args.content
    elif args.url:
        print(f"Fetching single URL {args.url} ...")
        resp = requests.get(args.url, timeout=30)
        resp.raise_for_status()
        proxies = extract_proxies_from_yaml_text(resp.text)
        content = build_clash_config(proxies)
    else:
        sources_path = Path(args.sources)
        entries = load_urls_from_file(sources_path)
        if entries:
            print(f"Found {len(entries)} sources in {sources_path}")
            content = fetch_and_merge_proxies(entries)
        else:
            url = os.environ.get("SUBSCRIPTION_URL")
            if url:
                resp = requests.get(url, timeout=30)
                resp.raise_for_status()
                content = build_clash_config(extract_proxies_from_yaml_text(resp.text))
            else:
                print("Error: no sources", file=sys.stderr)
                sys.exit(1)

    print(f"Final config length: {len(content)} chars")

    ciphertext = encrypt_content(content, password)
    part_a, part_b = split_payload(ciphertext)
    print(f"Ciphertext: {len(ciphertext)} bytes → A:{len(part_a)} + B:{len(part_b)}")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Always write scrambled backup + plaintext config (email body fallback)
    scrambled = make_scrambled_b64(ciphertext)
    scrambled_path = out_dir / "backup_scrambled.txt"
    scrambled_path.write_text(scrambled, encoding="utf-8")
    print(f"Wrote {scrambled_path}")

    (out_dir / "clash_clean.yaml").write_text(content, encoding="utf-8")
    print("Wrote output/clash_clean.yaml")

    stego_ok = False
    if not args.skip_stego:
        try:
            now = datetime.now()
            img = create_calendar_image(now.year, now.month)
            stego_img = embed_lsb_image(img, part_a)
            img_path = out_dir / "calendar.png"
            stego_img.save(img_path, "PNG")
            print(f"Wrote {img_path}")

            samples = create_calendar_audio()
            stego_samples = embed_lsb_audio(samples, part_b)
            wav_path = out_dir / "calendar.wav"
            save_wav(str(wav_path), stego_samples)
            print(f"Wrote {wav_path}")
            stego_ok = True
        except Exception as e:
            print(f"STEGO SKIPPED (overflow or error): {e}")
            print("Fallback: only backup_scrambled.txt + clash_clean.yaml")
            # remove partial stego files if any
            for name in ("calendar.png", "calendar.wav"):
                p = out_dir / name
                if p.exists():
                    p.unlink()
    else:
        print("--skip-stego: image/audio not generated")

    # marker for workflow
    (out_dir / "stego_status.txt").write_text(
        "ok\n" if stego_ok else "skipped\n", encoding="utf-8"
    )
    print("Done. stego=", "ok" if stego_ok else "skipped")

if __name__ == "__main__":
    main()
