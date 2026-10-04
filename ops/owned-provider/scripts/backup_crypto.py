"""Streaming authenticated encryption for owned-provider backup archives."""

from __future__ import annotations

import argparse
import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


MAGIC = b"SLOPBACKUP\x00\x01"
CHUNK = 1024 * 1024


def key(path: Path) -> bytes:
    value = bytes.fromhex(path.read_text().strip())
    if len(value) != 32:
        raise RuntimeError("backup encryption key must be 32 bytes encoded as hex")
    return value


def encrypt(source: Path, destination: Path, key_path: Path):
    nonce = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key(key_path)), modes.GCM(nonce)).encryptor()
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with source.open("rb") as src, temporary.open("wb") as dst:
        dst.write(MAGIC)
        dst.write(struct.pack("!B", len(nonce)))
        dst.write(nonce)
        while chunk := src.read(CHUNK):
            dst.write(encryptor.update(chunk))
        dst.write(encryptor.finalize())
        dst.write(encryptor.tag)
        dst.flush()
        os.fsync(dst.fileno())
    temporary.replace(destination)


def decrypt(source: Path, destination: Path, key_path: Path):
    size = source.stat().st_size
    with source.open("rb") as src:
        if src.read(len(MAGIC)) != MAGIC:
            raise RuntimeError("unsupported encrypted backup format")
        nonce_size = struct.unpack("!B", src.read(1))[0]
        nonce = src.read(nonce_size)
        ciphertext_start = len(MAGIC) + 1 + nonce_size
        ciphertext_size = size - ciphertext_start - 16
        if ciphertext_size < 0:
            raise RuntimeError("truncated encrypted backup")
        src.seek(size - 16)
        tag = src.read(16)
        src.seek(ciphertext_start)
        decryptor = Cipher(
            algorithms.AES(key(key_path)), modes.GCM(nonce, tag)
        ).decryptor()
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        try:
            with temporary.open("wb") as dst:
                remaining = ciphertext_size
                while remaining:
                    chunk = src.read(min(CHUNK, remaining))
                    if not chunk:
                        raise RuntimeError("truncated encrypted backup")
                    remaining -= len(chunk)
                    dst.write(decryptor.update(chunk))
                dst.write(decryptor.finalize())
                dst.flush()
                os.fsync(dst.fileno())
            temporary.replace(destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("encrypt", "decrypt"))
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--key-file", type=Path, required=True)
    args = parser.parse_args()
    globals()[args.action](args.source, args.destination, args.key_file)


if __name__ == "__main__":
    main()
