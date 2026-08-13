"""RFC 9562 UUIDv7 generation for sortable, non-semantic identifiers."""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
import uuid

_lock = threading.Lock()
_last_ms = -1
_sequence = 0


def uuid7(*, now_ms: int | None = None) -> uuid.UUID:
    """Return a UUIDv7, monotonically ordered within this process per millisecond."""
    global _last_ms, _sequence
    timestamp_ms = int(time.time_ns() // 1_000_000 if now_ms is None else now_ms)
    if not 0 <= timestamp_ms < 1 << 48:
        raise ValueError("UUIDv7 timestamp is outside the 48-bit range")

    with _lock:
        if timestamp_ms < _last_ms:
            timestamp_ms = _last_ms
        if timestamp_ms == _last_ms:
            _sequence = (_sequence + 1) & 0xFFF
            if _sequence == 0:
                timestamp_ms += 1
        else:
            _sequence = secrets.randbits(12)
        _last_ms = timestamp_ms
        sequence = _sequence

    random_b = secrets.randbits(62)
    value = timestamp_ms << 80
    value |= 0x7 << 76
    value |= sequence << 64
    value |= 0b10 << 62
    value |= random_b
    return uuid.UUID(int=value)


def uuid7_str(*, now_ms: int | None = None) -> str:
    return str(uuid7(now_ms=now_ms))


def deterministic_uuid7(timestamp_ms: int, material: bytes) -> uuid.UUID:
    """Derive a stable UUIDv7 for idempotent normalization of provider events."""
    if not 0 <= timestamp_ms < 1 << 48:
        raise ValueError("UUIDv7 timestamp is outside the 48-bit range")
    random_bits = int.from_bytes(hashlib.sha256(material).digest()[:10], "big")
    value = timestamp_ms << 80
    value |= 0x7 << 76
    value |= ((random_bits >> 62) & 0xFFF) << 64
    value |= 0b10 << 62
    value |= random_bits & ((1 << 62) - 1)
    return uuid.UUID(int=value)


def require_uuid7(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError("identifier must be a UUID") from exc
    if parsed.version != 7:
        raise ValueError("identifier must be UUIDv7")
    return str(parsed)
