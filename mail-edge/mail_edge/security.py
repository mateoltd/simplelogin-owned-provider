"""Mailgun HMAC verification and durable replay protection."""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path

from .config import KeyRing
from .errors import ReplayRejected, SignatureRejected


class SQLiteReplayStore:
    def __init__(self, path: str | Path) -> None:
        self._connection = sqlite3.connect(
            str(path), isolation_level=None, check_same_thread=False
        )
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS replay_tokens (
                namespace TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (namespace, token_hash)
            )
            """
        )
        self._lock = threading.Lock()

    def claim(self, namespace: str, token: str, *, now: int, expires_at: int) -> bool:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    "DELETE FROM replay_tokens WHERE expires_at < ?", (now,)
                )
                self._connection.execute(
                    "INSERT INTO replay_tokens(namespace, token_hash, expires_at) VALUES (?, ?, ?)",
                    (namespace, token_hash, expires_at),
                )
                self._connection.execute("COMMIT")
                return True
            except sqlite3.IntegrityError:
                self._connection.execute("ROLLBACK")
                return False
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def purge(self, *, now: int) -> int:
        with self._lock:
            cursor = self._connection.execute(
                "DELETE FROM replay_tokens WHERE expires_at < ?", (now,)
            )
            return cursor.rowcount

    def release(self, namespace: str, token: str) -> None:
        """Release a claim only when processing failed before durable acceptance."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self._lock:
            self._connection.execute(
                "DELETE FROM replay_tokens WHERE namespace = ? AND token_hash = ?",
                (namespace, token_hash),
            )

    def close(self) -> None:
        self._connection.close()


class MailgunSignatureVerifier:
    def __init__(
        self,
        keys: KeyRing,
        replay_store: SQLiteReplayStore,
        *,
        max_age_seconds: int = 900,
        future_skew_seconds: int = 60,
        replay_seconds: int = 86_400,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if max_age_seconds <= 0 or future_skew_seconds < 0 or replay_seconds <= 0:
            raise ValueError("invalid signature timing policy")
        self._keys = keys
        self._replay = replay_store
        self._max_age = max_age_seconds
        self._future_skew = future_skew_seconds
        self._replay_seconds = replay_seconds
        self._clock = clock

    def verify(
        self,
        *,
        timestamp: str,
        token: str,
        signature: str,
        namespace: str,
        parent_signature: str | None = None,
    ) -> str:
        try:
            timestamp_int = int(timestamp)
        except (TypeError, ValueError) as exc:
            raise SignatureRejected("invalid signature timestamp") from exc
        now = int(self._clock())
        if (
            timestamp_int < now - self._max_age
            or timestamp_int > now + self._future_skew
        ):
            raise SignatureRejected("signature timestamp is outside the replay window")
        if not token or len(token) > 256 or not signature or len(signature) != 64:
            raise SignatureRejected("malformed signature fields")

        signed = f"{timestamp}{token}".encode()
        supplied = (parent_signature or signature).lower()
        matched_key_id: str | None = None
        for key in self._keys.keys:
            expected = hmac.new(key.secret.encode(), signed, hashlib.sha256).hexdigest()
            if hmac.compare_digest(expected, supplied):
                matched_key_id = key.key_id
        if matched_key_id is None:
            raise SignatureRejected("signature mismatch")
        if not self._replay.claim(
            namespace,
            token,
            now=now,
            expires_at=now + self._replay_seconds,
        ):
            raise ReplayRejected("replayed provider request")
        return matched_key_id
