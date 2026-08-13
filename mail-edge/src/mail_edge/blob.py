"""Encrypted local blob storage with authenticated, crash-durable writes."""

from __future__ import annotations

import hashlib
import os
import re
import struct
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import BlobIntegrityError, ConfigurationError, DuplicateConflict
from .ids import uuid7_str

_MAGIC = b"MEB1"
_NONCE_SIZE = 12
_BLOB_ID = re.compile(r"^[a-z0-9][a-z0-9/_-]{0,240}$")


@dataclass(frozen=True, slots=True)
class BlobRecord:
    blob_id: str
    sha256: str
    size: int
    key_id: str


class LocalEncryptedBlobStore:
    def __init__(
        self,
        root: Path,
        keys: Mapping[str, bytes],
        active_key_id: str,
    ) -> None:
        if active_key_id not in keys:
            raise ConfigurationError("active blob key is missing")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", active_key_id):
            raise ConfigurationError("invalid active blob key ID")
        for key_id, key in keys.items():
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", key_id):
                raise ConfigurationError("invalid blob key ID")
            if len(key) not in {16, 24, 32}:
                raise ConfigurationError("AES-GCM keys must be 16, 24, or 32 bytes")
        self.root = root.resolve()
        self.keys = dict(keys)
        self.active_key_id = active_key_id
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def _path(self, blob_id: str) -> Path:
        if not _BLOB_ID.fullmatch(blob_id) or ".." in blob_id.split("/"):
            raise ValueError("invalid blob ID")
        path = (self.root / f"{blob_id}.meb").resolve()
        if self.root not in path.parents:
            raise ValueError("blob path escapes root")
        return path

    def put(self, blob_id: str, plaintext: bytes) -> BlobRecord:
        target = self._path(blob_id)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(target.parent, 0o700)
        digest = hashlib.sha256(plaintext).hexdigest()
        if target.exists():
            existing = self.get(blob_id)
            if hashlib.sha256(existing).hexdigest() != digest:
                raise DuplicateConflict("blob ID already contains different content")
            return BlobRecord(blob_id, digest, len(existing), self._read_key_id(target))

        key_id_bytes = self.active_key_id.encode("ascii")
        nonce = os.urandom(_NONCE_SIZE)
        ciphertext = AESGCM(self.keys[self.active_key_id]).encrypt(
            nonce, plaintext, blob_id.encode("utf-8")
        )
        encoded = (
            struct.pack(">4sB", _MAGIC, len(key_id_bytes))
            + key_id_bytes
            + nonce
            + ciphertext
        )
        temporary = target.parent / f".{target.name}.{uuid7_str()}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, target)
            except FileExistsError:
                existing = self.get(blob_id)
                if hashlib.sha256(existing).hexdigest() != digest:
                    raise DuplicateConflict(
                        "concurrent blob content conflict"
                    ) from None
            self._fsync_directory(target.parent)
        finally:
            with suppress(FileNotFoundError):
                temporary.unlink()
        return BlobRecord(blob_id, digest, len(plaintext), self.active_key_id)

    def _read_key_id(self, path: Path) -> str:
        with path.open("rb") as stream:
            prefix = stream.read(5)
            if len(prefix) != 5:
                raise BlobIntegrityError("encrypted blob header is truncated")
            magic, key_length = struct.unpack(">4sB", prefix)
            if magic != _MAGIC or not 1 <= key_length <= 32:
                raise BlobIntegrityError("encrypted blob header is invalid")
            try:
                return stream.read(key_length).decode("ascii")
            except UnicodeDecodeError as exc:
                raise BlobIntegrityError("encrypted blob key ID is invalid") from exc

    def get(self, blob_id: str) -> bytes:
        path = self._path(blob_id)
        encoded = path.read_bytes()
        if len(encoded) < 5:
            raise BlobIntegrityError("encrypted blob is truncated")
        magic, key_length = struct.unpack(">4sB", encoded[:5])
        if magic != _MAGIC or not 1 <= key_length <= 32:
            raise BlobIntegrityError("encrypted blob header is invalid")
        key_end = 5 + key_length
        nonce_end = key_end + _NONCE_SIZE
        try:
            key_id = encoded[5:key_end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise BlobIntegrityError("encrypted blob key ID is invalid") from exc
        key = self.keys.get(key_id)
        if key is None:
            raise BlobIntegrityError("encrypted blob key is unavailable")
        if len(encoded) < nonce_end + 16:
            raise BlobIntegrityError("encrypted blob ciphertext is truncated")
        try:
            return AESGCM(key).decrypt(
                encoded[key_end:nonce_end],
                encoded[nonce_end:],
                blob_id.encode("utf-8"),
            )
        except Exception as exc:
            raise BlobIntegrityError("encrypted blob authentication failed") from exc

    def delete(self, blob_id: str) -> bool:
        path = self._path(blob_id)
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        self._fsync_directory(path.parent)
        return True

    def exists(self, blob_id: str) -> bool:
        return self._path(blob_id).is_file()

    def older_blob_ids(self, cutoff: datetime, *, limit: int = 500) -> list[str]:
        cutoff_timestamp = cutoff.timestamp()
        result: list[str] = []
        for path in self.root.rglob("*.meb"):
            if len(result) >= limit:
                break
            if not path.is_file() or path.stat().st_mtime > cutoff_timestamp:
                continue
            relative = path.relative_to(self.root).as_posix().removesuffix(".meb")
            if _BLOB_ID.fullmatch(relative):
                result.append(relative)
        return sorted(result)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
