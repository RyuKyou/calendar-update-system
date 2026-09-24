#!/usr/bin/env python3
"""
Extract hidden payload from calendar.png + calendar.wav and decrypt with password.
Also supports reconstructing from the scrambled Base64 backup text.
"""

import argparse
import base64
import struct
import sys
from pathlib import Path

import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
import wave

SALT = b"calendar-stego-v1-salt-2026"

def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

def extract_lsb_image(img: Image.Image) -> bytes:
    arr = np.array(img.convert("RGB")).reshape(-1)
    length = struct.unpack(">I", np.packbits(arr[:32] & 1).tobytes())[0]
    total_bits = 32 + length * 8
    if total_bits > len(arr):
        raise ValueError("Declared length exceeds image capacity")
    bits = arr[:total_bits] & 1
    data = np.packbits(bits[32:]).tobytes()[:length]
    return data

def extract_lsb_audio(path: str) -> bytes:
    with wave.open(path, "rb") as wf:
        frames = wf.readframes(wf.getnframes())
        samples = np.frombuffer(frames, dtype=np.int16)
    length = struct.unpack(">I", np.packbits(samples[:32] & 1).tobytes())[0]
    total_bits = 32 + length * 8
    if total_bits > len(samples):
        raise ValueError("Declared length exceeds audio capacity")
    bits = samples[:total_bits] & 1
    data = np.packbits(bits[32:]).tobytes()[:length]
    return data

def reconstruct_from_scrambled(text: str) -> bytes:
    """Parse the scrambled Base64 lines (000:chunk ...) and rebuild ciphertext."""
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        idx_str, chunk = line.split(":", 1)
        try:
            idx = int(idx_str)
            lines.append((idx, chunk))
        except ValueError:
            continue
    if not lines:
        raise ValueError("No valid scrambled chunks found")
    lines.sort(key=lambda x: x[0])
    b64 = "".join(chunk for _, chunk in lines)
    return base64.b64decode(b64)

def main():
    parser = argparse.ArgumentParser(description="Extract and decrypt hidden calendar payload")
    parser.add_argument("image", nargs="?", help="Path to calendar.png")
    parser.add_argument("audio", nargs="?", help="Path to calendar.wav")
    parser.add_argument("--scrambled", help="Path to backup_scrambled.txt (alternative to image+audio)")
    parser.add_argument("--password", required=True, help="The same password used for encryption")
    parser.add_argument("-o", "--output", help="Optional file to write recovered content")
    args = parser.parse_args()

    try:
        if args.scrambled:
            text = Path(args.scrambled).read_text(encoding="utf-8")
            ciphertext = reconstruct_from_scrambled(text)
        elif args.image and args.audio:
            part_a = extract_lsb_image(Image.open(args.image))
            part_b = extract_lsb_audio(args.audio)
            ciphertext = part_a + part_b
        else:
            print("Error: provide either image+audio or --scrambled", file=sys.stderr)
            sys.exit(1)

        key = derive_key(args.password)
        f = Fernet(key)
        plaintext = f.decrypt(ciphertext).decode("utf-8")

        if args.output:
            Path(args.output).write_text(plaintext, encoding="utf-8")
            print(f"Recovered content written to {args.output}")
        else:
            print(plaintext)

    except InvalidToken:
        print("Error: wrong password or corrupted data.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
