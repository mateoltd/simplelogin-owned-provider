"""Durable delivery correlation without application-owned identity state."""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .config import RetentionPolicy
from .contracts import (
    FeedbackEvent,
    FeedbackEventType,
    OutboundMessage,
    SubmissionResult,
)
from .errors import MalformedPayload

_EVENT_RANK = {
    FeedbackEventType.ACCEPTED: 10,
    FeedbackEventType.DELAYED: 20,
    FeedbackEventType.SOFT_BOUNCE: 30,
    FeedbackEventType.DELIVERED: 40,
    FeedbackEventType.REJECTED: 50,
    FeedbackEventType.HARD_BOUNCE: 50,
    FeedbackEventType.COMPLAINT: 60,
}

_TERMINAL_STATES = {
    "PERMANENT_REJECTED",
    FeedbackEventType.DELIVERED.value,
    FeedbackEventType.REJECTED.value,
    FeedbackEventType.HARD_BOUNCE.value,
    FeedbackEventType.COMPLAINT.value,
}


@dataclass(frozen=True, slots=True)
class DeliveryRecord:
    edge_delivery_id: str
    domain: str
    envelope_from: str
    envelope_recipient: str
    submitted_message_id: str
    provider_message_id: str | None
    provider_visible_message_id: str | None
    state: str
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class FeedbackApplication:
    duplicate: bool
    correlated: bool
    edge_delivery_id: str | None
    state_changed: bool


class DeliveryLedger:
    def __init__(self, path: str | Path) -> None:
        self._connection = sqlite3.connect(
            str(path), isolation_level=None, check_same_thread=False
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS deliveries (
                edge_delivery_id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                envelope_from TEXT NOT NULL,
                envelope_recipient TEXT NOT NULL,
                message_sha256 TEXT NOT NULL,
                message_bytes INTEGER NOT NULL,
                submitted_message_id TEXT NOT NULL,
                provider_message_id TEXT,
                provider_visible_message_id TEXT,
                state TEXT NOT NULL,
                diagnostic TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_event_at TEXT,
                last_event_rank INTEGER NOT NULL DEFAULT -1
            );
            CREATE INDEX IF NOT EXISTS deliveries_provider_id
                ON deliveries(provider_message_id, envelope_recipient)
                WHERE provider_message_id IS NOT NULL;
            CREATE INDEX IF NOT EXISTS deliveries_submitted_id ON deliveries(submitted_message_id);
            CREATE INDEX IF NOT EXISTS deliveries_visible_id ON deliveries(provider_visible_message_id);

            CREATE TABLE IF NOT EXISTS feedback_events (
                provider_event_id TEXT PRIMARY KEY,
                edge_delivery_id TEXT,
                provider_message_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                recipient TEXT NOT NULL,
                smtp_status TEXT,
                diagnostic TEXT,
                occurred_at TEXT NOT NULL,
                received_at TEXT NOT NULL,
                correlated INTEGER NOT NULL,
                FOREIGN KEY(edge_delivery_id) REFERENCES deliveries(edge_delivery_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS feedback_received_at ON feedback_events(received_at);
            """
        )
        self._lock = threading.RLock()

    @staticmethod
    def _iso(value: datetime) -> str:
        if value.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return value.astimezone(UTC).isoformat()

    @staticmethod
    def _from_iso(value: str) -> datetime:
        return datetime.fromisoformat(value).astimezone(UTC)

    def prepare(
        self, message: OutboundMessage, *, domain: str, message_id: str
    ) -> None:
        if len(message.envelope_recipients) != 1:
            raise MalformedPayload(
                "Mailgun deliveries require exactly one envelope recipient"
            )
        digest = hashlib.sha256(message.rfc822_bytes).hexdigest()
        created = self._iso(message.created_at)
        immutable = (
            domain,
            message.envelope_from,
            message.envelope_recipients[0],
            digest,
            len(message.rfc822_bytes),
            message_id,
        )
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM deliveries WHERE edge_delivery_id = ?",
                (message.edge_delivery_id,),
            ).fetchone()
            if row is not None:
                existing = (
                    row["domain"],
                    row["envelope_from"],
                    row["envelope_recipient"],
                    row["message_sha256"],
                    row["message_bytes"],
                    row["submitted_message_id"],
                )
                if existing != immutable:
                    raise MalformedPayload(
                        "edge delivery id was reused with different content"
                    )
                return
            self._connection.execute(
                """
                INSERT INTO deliveries(
                    edge_delivery_id, domain, envelope_from, envelope_recipient,
                    message_sha256, message_bytes, submitted_message_id, state,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PREPARED', ?, ?)
                """,
                (message.edge_delivery_id, *immutable, created, created),
            )

    def mark_submitting(self, edge_delivery_id: str, *, now: datetime) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE deliveries SET state = 'SUBMITTING', updated_at = ?
                WHERE edge_delivery_id = ? AND state IN ('PREPARED', 'RETRYABLE_REJECTED')
                """,
                (self._iso(now), edge_delivery_id),
            )
            if cursor.rowcount == 0:
                state = self._connection.execute(
                    "SELECT state FROM deliveries WHERE edge_delivery_id = ?",
                    (edge_delivery_id,),
                ).fetchone()
                if state is None:
                    raise KeyError(edge_delivery_id)
                return False
            return True

    def record_result(self, result: SubmissionResult, *, now: datetime) -> None:
        with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE deliveries
                SET state = ?, provider_message_id = COALESCE(?, provider_message_id),
                    diagnostic = ?, updated_at = ?
                WHERE edge_delivery_id = ?
                """,
                (
                    result.disposition.value,
                    result.provider_message_id,
                    result.diagnostic,
                    self._iso(now),
                    result.edge_delivery_id,
                ),
            )
            if cursor.rowcount != 1:
                raise KeyError(result.edge_delivery_id)

    def _correlate(self, event: FeedbackEvent) -> str | None:
        candidates: set[str] = set()
        if event.edge_delivery_id:
            row = self._connection.execute(
                "SELECT edge_delivery_id FROM deliveries WHERE edge_delivery_id = ?",
                (event.edge_delivery_id,),
            ).fetchone()
            if row:
                candidates.add(row["edge_delivery_id"])
        recipient_filter = (
            "" if event.recipient == "[REDACTED]" else " AND envelope_recipient = ?"
        )
        parameters: tuple[str, ...] = (
            event.provider_message_id,
            event.provider_message_id,
            event.provider_message_id,
        )
        if recipient_filter:
            parameters += (event.recipient,)
        rows = self._connection.execute(
            f"""
            SELECT edge_delivery_id FROM deliveries
            WHERE (provider_message_id = ? OR submitted_message_id = ?
               OR provider_visible_message_id = ?){recipient_filter}
            """,
            parameters,
        ).fetchall()
        candidates.update(row["edge_delivery_id"] for row in rows)
        if event.visible_message_id:
            visible_parameters: tuple[str, ...] = (
                event.visible_message_id,
                event.visible_message_id,
            )
            if recipient_filter:
                visible_parameters += (event.recipient,)
            rows = self._connection.execute(
                f"""
                SELECT edge_delivery_id FROM deliveries
                WHERE (submitted_message_id = ? OR provider_visible_message_id = ?)
                {recipient_filter}
                """,
                visible_parameters,
            ).fetchall()
            candidates.update(row["edge_delivery_id"] for row in rows)
        if len(candidates) == 1:
            return candidates.pop()
        return None

    def apply_feedback(
        self, event: FeedbackEvent, *, received_at: datetime
    ) -> FeedbackApplication:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                duplicate = self._connection.execute(
                    "SELECT edge_delivery_id, correlated FROM feedback_events WHERE provider_event_id = ?",
                    (event.provider_event_id,),
                ).fetchone()
                if duplicate is not None:
                    self._connection.execute("COMMIT")
                    return FeedbackApplication(
                        duplicate=True,
                        correlated=bool(duplicate["correlated"]),
                        edge_delivery_id=duplicate["edge_delivery_id"],
                        state_changed=False,
                    )

                edge_id = self._correlate(event)
                correlated = edge_id is not None
                self._connection.execute(
                    """
                    INSERT INTO feedback_events(
                        provider_event_id, edge_delivery_id, provider_message_id,
                        event_type, recipient, smtp_status, diagnostic, occurred_at,
                        received_at, correlated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.provider_event_id,
                        edge_id,
                        event.provider_message_id,
                        event.event_type.value,
                        event.recipient,
                        event.smtp_status,
                        event.diagnostic,
                        self._iso(event.occurred_at),
                        self._iso(received_at),
                        int(correlated),
                    ),
                )
                changed = False
                if edge_id is not None:
                    row = self._connection.execute(
                        "SELECT last_event_at, last_event_rank FROM deliveries WHERE edge_delivery_id = ?",
                        (edge_id,),
                    ).fetchone()
                    occurred = self._iso(event.occurred_at)
                    rank = _EVENT_RANK[event.event_type]
                    should_update = (
                        row["last_event_at"] is None
                        or occurred > row["last_event_at"]
                        or (
                            occurred == row["last_event_at"]
                            and rank > row["last_event_rank"]
                        )
                    )
                    if should_update:
                        self._connection.execute(
                            """
                            UPDATE deliveries
                            SET state = ?, diagnostic = ?, updated_at = ?, last_event_at = ?,
                                last_event_rank = ?,
                                provider_visible_message_id = COALESCE(
                                    provider_visible_message_id, ?
                                )
                            WHERE edge_delivery_id = ?
                            """,
                            (
                                event.event_type.value,
                                event.diagnostic,
                                self._iso(received_at),
                                occurred,
                                rank,
                                event.visible_message_id,
                                edge_id,
                            ),
                        )
                        changed = True
                self._connection.execute("COMMIT")
                return FeedbackApplication(
                    duplicate=False,
                    correlated=correlated,
                    edge_delivery_id=edge_id,
                    state_changed=changed,
                )
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def get(self, edge_delivery_id: str) -> DeliveryRecord | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM deliveries WHERE edge_delivery_id = ?",
                (edge_delivery_id,),
            ).fetchone()
        if row is None:
            return None
        return DeliveryRecord(
            edge_delivery_id=row["edge_delivery_id"],
            domain=row["domain"],
            envelope_from=row["envelope_from"],
            envelope_recipient=row["envelope_recipient"],
            submitted_message_id=row["submitted_message_id"],
            provider_message_id=row["provider_message_id"],
            provider_visible_message_id=row["provider_visible_message_id"],
            state=row["state"],
            updated_at=self._from_iso(row["updated_at"]),
        )

    def ambiguous(self) -> tuple[DeliveryRecord, ...]:
        with self._lock:
            edge_ids = [
                row["edge_delivery_id"]
                for row in self._connection.execute(
                    "SELECT edge_delivery_id FROM deliveries WHERE state = 'AMBIGUOUS' ORDER BY created_at"
                ).fetchall()
            ]
        return tuple(
            record for edge_id in edge_ids if (record := self.get(edge_id)) is not None
        )

    def translate_thread_ids(
        self, header_value: str, *, envelope_recipient: str | None = None
    ) -> str:
        """Translate only recipient-scoped or globally unambiguous visible IDs."""
        recipient_clause = ""
        parameters: tuple[str, ...] = ()
        if envelope_recipient is not None:
            recipient_clause = " AND envelope_recipient = ?"
            parameters = (envelope_recipient,)
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT provider_visible_message_id, submitted_message_id FROM deliveries
                WHERE provider_visible_message_id IS NOT NULL
                  AND provider_visible_message_id != submitted_message_id
                  {recipient_clause}
                """,
                parameters,
            ).fetchall()
        mappings: dict[str, set[str]] = {}
        for row in rows:
            mappings.setdefault(row["provider_visible_message_id"], set()).add(
                row["submitted_message_id"]
            )
        translated = header_value
        for provider_id, submitted_ids in mappings.items():
            if len(submitted_ids) == 1:
                translated = translated.replace(provider_id, next(iter(submitted_ids)))
        return translated

    def purge(self, policy: RetentionPolicy, *, now: datetime) -> dict[str, int]:
        event_cutoff = self._iso(
            now - timedelta(seconds=policy.normalized_event_seconds)
        )
        terminal_cutoff = self._iso(
            now - timedelta(seconds=policy.terminal_delivery_seconds)
        )
        ambiguous_cutoff = self._iso(
            now - timedelta(seconds=policy.ambiguous_delivery_seconds)
        )
        placeholders = ",".join("?" for _ in _TERMINAL_STATES)
        with self._lock:
            events = self._connection.execute(
                "DELETE FROM feedback_events WHERE received_at < ?", (event_cutoff,)
            ).rowcount
            terminal = self._connection.execute(
                f"DELETE FROM deliveries WHERE updated_at < ? AND state IN ({placeholders})",
                (terminal_cutoff, *_TERMINAL_STATES),
            ).rowcount
            ambiguous = self._connection.execute(
                "DELETE FROM deliveries WHERE updated_at < ? AND state = 'AMBIGUOUS'",
                (ambiguous_cutoff,),
            ).rowcount
        return {
            "events": events,
            "terminal_deliveries": terminal,
            "ambiguous": ambiguous,
        }

    def close(self) -> None:
        self._connection.close()
