"""Bounded diagnostics that never retain message content or raw identifiers."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping

_EMAIL = re.compile(r"(?<![\w.+-])[^\s<>@]{1,64}@[^\s<>@]{1,253}")
_IP = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{24,}(?![A-Za-z0-9])")
_CODE = re.compile(r"[^a-z0-9_.-]+")


def _digest(value: str, salt: bytes) -> str:
    return hashlib.sha256(salt + value.lower().encode("utf-8", "replace")).hexdigest()[
        :12
    ]


def diagnostic_code(value: str) -> str:
    normalized = _CODE.sub("_", value.lower()).strip("_")[:64]
    return normalized or "unspecified"


def redact_text(
    value: object,
    *,
    salt: bytes,
    known_secrets: Iterable[str] = (),
    limit: int = 256,
) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    for secret in known_secrets:
        if secret:
            text = text.replace(secret, "<secret>")
    text = _EMAIL.sub(lambda match: f"<email:{_digest(match.group(), salt)}>", text)
    text = _IP.sub(lambda match: f"<ip:{_digest(match.group(), salt)}>", text)
    text = _LONG_TOKEN.sub("<secret>", text)
    text = " ".join(text.split())
    return text[:limit]


def bounded_diagnostics(
    values: Mapping[str, object],
    *,
    salt: bytes,
    known_secrets: Iterable[str] = (),
    maximum_fields: int = 8,
) -> dict[str, str]:
    result: dict[str, str] = {}
    for key in sorted(values)[:maximum_fields]:
        safe_key = diagnostic_code(str(key))[:32]
        result[safe_key] = redact_text(
            values[key], salt=salt, known_secrets=known_secrets
        )
    return result
