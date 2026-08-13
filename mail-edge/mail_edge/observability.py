"""Redacted, structured adapter observations."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from typing import Protocol


class Observer(Protocol):
    def emit(
        self, event: str, fields: Mapping[str, str | int | float | bool | None]
    ) -> None: ...


class NullObserver:
    def emit(
        self, event: str, fields: Mapping[str, str | int | float | bool | None]
    ) -> None:
        return None


class Redactor:
    def __init__(self, salt: bytes) -> None:
        if len(salt) < 16:
            raise ValueError("observability salt must contain at least 16 bytes")
        self._salt = salt

    def address(self, address: str) -> str:
        return hmac.new(
            self._salt, address.lower().encode(), hashlib.sha256
        ).hexdigest()[:20]

    @staticmethod
    def diagnostic(value: str | None, maximum: int = 256) -> str | None:
        if value is None:
            return None
        compact = " ".join(value.split())
        for marker in ("Authorization:", "api:", "key-"):
            if marker.lower() in compact.lower():
                return "redacted provider diagnostic"
        return compact[:maximum]
