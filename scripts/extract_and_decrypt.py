#!/usr/bin/env python3
"""
Extract hidden payload from calendar.png + calendar.wav and decrypt with password.
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

def main():
    parser = argparse.ArgumentParser(description="Extract and decrypt hidden calendar payload")
    parser.add_argument("image", help="Path to calendar.png")
    parser.add_argument("audio", help="Path to calendar.wav")
    parser.add_argument("--password", required=True, help="The same password used for encryption")
    parser.add_argument("-o", "--output", help="Optional file to write recovered content")
    args = parser.parse_args()

    try:
        part_a = extract_lsb_image(Image.open(args.image))
        part_b = extract_lsb_audio(args.audio)
        ciphertext = part_a + part_b

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
