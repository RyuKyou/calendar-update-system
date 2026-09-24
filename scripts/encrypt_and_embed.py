#!/usr/bin/env python3
"""
Encrypt content with a password, split the ciphertext,
and embed the two parts into a calendar PNG and a calendar WAV via LSB steganography.
"""

import os
import sys
import argparse
import base64
import struct
from datetime import datetime
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import wave
import requests

# Fixed salt (public, but password is secret). Change only if you want to invalidate all old files.
SALT = b"calendar-stego-v1-salt-2026"

def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return key

def encrypt_content(content: str, password: str) -> bytes:
    key = derive_key(password)
    f = Fernet(key)
    return f.encrypt(content.encode("utf-8"))

def split_payload(payload: bytes):
    mid = len(payload) // 2
    return payload[:mid], payload[mid:]

def embed_lsb_image(img: Image.Image, data: bytes) -> Image.Image:
    """Embed data into the least significant bit of the RGB channels."""
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
    arr = flat.reshape(h, w, 3)
    return Image.fromarray(arr.astype(np.uint8))

def create_calendar_image(year: int, month: int, size=(800, 600)) -> Image.Image:
    """Generate a simple, clean monthly calendar image."""
    img = Image.new("RGB", size, color=(245, 248, 252))
    draw = ImageDraw.Draw(img)

    try:
        title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 36)
        cell_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 20)
    except Exception:
        title_font = ImageFont.load_default()
        cell_font = ImageFont.load_default()

    title = f"{year} 年 {month} 月"
    draw.text((size[0]//2, 30), title, fill=(30, 60, 90), font=title_font, anchor="mt")

    weekdays = ["一", "二", "三", "四", "五", "六", "日"]
    cell_w = size[0] // 7
    for i, d in enumerate(weekdays):
        x = i * cell_w + cell_w // 2
        draw.text((x, 90), d, fill=(80, 100, 120), font=cell_font, anchor="mt")

    import calendar
    cal = calendar.Calendar(firstweekday=0)
    month_days = cal.monthdayscalendar(year, month)

    start_y = 130
    cell_h = (size[1] - start_y - 20) // 6
    today = datetime.now()

    for week_idx, week in enumerate(month_days):
        for day_idx, day in enumerate(week):
            if day == 0:
                continue
            x = day_idx * cell_w + cell_w // 2
            y = start_y + week_idx * cell_h + cell_h // 2
            color = (20, 40, 70)
            if year == today.year and month == today.month and day == today.day:
                r = 18
                draw.ellipse([x-r, y-r, x+r, y+r], fill=(70, 130, 180))
                color = (255, 255, 255)
            draw.text((x, y), str(day), fill=color, font=cell_font, anchor="mm")

    draw.text((size[0]//2, size[1]-25), "Calendar Reminder", fill=(160, 170, 180), font=cell_font, anchor="mt")
    return img

def create_calendar_audio(duration_sec: float = 8.0, sample_rate: int = 22050) -> np.ndarray:
    t = np.linspace(0, duration_sec, int(sample_rate * duration_sec), endpoint=False)
    freqs = [261.63, 329.63, 392.00, 523.25]
    audio = np.zeros_like(t)
    for i, f in enumerate(freqs):
        start = i * (duration_sec / len(freqs))
        end = start + 1.5
        mask = (t >= start) & (t < end)
        audio[mask] += 0.25 * np.sin(2 * np.pi * f * t[mask]) * np.exp(-1.5 * (t[mask] - start))
    audio = audio / np.max(np.abs(audio) + 1e-9) * 0.7
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--password", default=None, help="Encryption password (or use env STEGO_PASSWORD)")
    parser.add_argument("--url", help="URL to fetch content from")
    parser.add_argument("--content", help="Direct content string (alternative to --url)")
    parser.add_argument("--output-dir", default="output", help="Directory to write results")
    args = parser.parse_args()

    password = args.password or os.environ.get("STEGO_PASSWORD")
    if not password:
        print("Error: password required (pass --password or set STEGO_PASSWORD)", file=sys.stderr)
        sys.exit(1)

    if args.content:
        content = args.content
    elif args.url:
        print(f"Fetching from {args.url} ...")
        resp = requests.get(args.url, timeout=30)
        resp.raise_for_status()
        content = resp.text.strip()
    else:
        url = os.environ.get("SUBSCRIPTION_URL")
        if not url:
            print("Error: provide --url or --content or set SUBSCRIPTION_URL", file=sys.stderr)
            sys.exit(1)
        print(f"Fetching from env URL ...")
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        content = resp.text.strip()

    print(f"Content length: {len(content)} chars")

    ciphertext = encrypt_content(content, password)
    part_a, part_b = split_payload(ciphertext)
    print(f"Ciphertext: {len(ciphertext)} bytes → A:{len(part_a)} + B:{len(part_b)}")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

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

    print("Done.")

if __name__ == "__main__":
    main()
