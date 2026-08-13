"""Durable message handoff, scheduling, dedupe, and reconciliation repository."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .bindings import Binding, BindingStore
from .blob import LocalEncryptedBlobStore
from .contracts import (
    BindingDirection,
    BindingState,
    Envelope,
    Feedback,
    FeedbackKind,
    InboundNotice,
    InboundRawMessage,
    OutboundResult,
    OutboundSubmission,
    SubmissionOutcome,
    isoformat,
)
from .db import Connection, Database
from .errors import ContractError, DuplicateConflict, InvalidTransition
from .ids import uuid7_str
from .redaction import diagnostic_code, redact_text
from .state import (
    IngressEvent,
    IngressState,
    OutboundEvent,
    OutboundState,
    RetryPolicy,
    reduce_ingress,
    reduce_outbound,
)


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _envelope_bytes(envelope: Envelope) -> bytes:
    return _json(envelope.as_dict()).encode("utf-8")


def _envelope_from_bytes(payload: bytes) -> Envelope:
    decoded = json.loads(payload)
    return Envelope(
        sender=str(decoded["sender"]),
        recipients=tuple(str(item) for item in decoded["recipients"]),
    )


@dataclass(frozen=True, slots=True)
class ClaimedIngress:
    id: str
    notice_id: str
    domain: str
    binding_generation: int
    envelope: Envelope
    raw_mime: bytes
    raw_sha256: str
    attempt: int


@dataclass(frozen=True, slots=True)
class ClaimedOutbound:
    submission: OutboundSubmission
    binding: Binding
    attempt: int


class EdgeRepository:
    def __init__(
        self,
        database: Database,
        blobs: LocalEncryptedBlobStore,
        bindings: BindingStore,
        *,
        retry_policy: RetryPolicy | None = None,
        diagnostic_salt: bytes = b"mail-edge-diagnostics",
    ) -> None:
        self.database = database
        self.blobs = blobs
        self.bindings = bindings
        self.retry_policy = retry_policy or RetryPolicy()
        self.diagnostic_salt = diagnostic_salt

    def consume_replay_token(
        self,
        *,
        provider: str,
        purpose: str,
        token: str,
        expires_at: datetime,
        now: datetime | None = None,
    ) -> bool:
        current = now or datetime.now(UTC)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.database.transaction(immediate=True) as connection:
            connection.execute(
                "DELETE FROM replay_tokens WHERE expires_at <= ?", (isoformat(current),)
            )
            existing = connection.execute(
                "SELECT token_sha256 FROM replay_tokens WHERE token_sha256 = ?",
                (token_hash,),
            ).fetchone()
            if existing:
                return False
            connection.execute(
                """
                INSERT INTO replay_tokens(
                    token_sha256, provider, purpose, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    token_hash,
                    provider,
                    purpose,
                    isoformat(expires_at),
                    isoformat(current),
                ),
            )
        return True

    def record_inbound_notice(
        self,
        binding_id: str,
        notice: InboundNotice,
        *,
        retention_until: datetime,
    ) -> str:
        binding = self._validate_inbound_binding(binding_id, notice.domain)
        if notice.provider != binding.provider:
            raise ContractError("notice provider does not match binding generation")
        if notice.binding_generation != binding.generation:
            raise ContractError("notice generation does not match pinned binding")
        self._require_existing_if_draining(
            binding, notice.notice_id, notice.provider, notice.provider_event_id
        )
        envelope_key = f"ingress/{notice.notice_id}/envelope"
        self.blobs.put(envelope_key, _envelope_bytes(notice.envelope))
        now = datetime.now(UTC)
        notice_data = notice.as_dict()
        notice_data["envelope"] = {
            "sender_sha256": hashlib.sha256(
                notice.envelope.sender.encode()
            ).hexdigest(),
            "recipient_sha256": [
                hashlib.sha256(item.encode()).hexdigest()
                for item in notice.envelope.recipients
            ],
        }
        with self.database.transaction(immediate=True) as connection:
            existing = connection.execute(
                """
                SELECT * FROM ingress_messages
                WHERE notice_id = ? OR (provider = ? AND provider_event_id = ?)
                """,
                (notice.notice_id, notice.provider, notice.provider_event_id),
            ).fetchone()
            if existing:
                self._verify_notice_duplicate(existing, binding, notice)
                state = reduce_ingress(
                    IngressState(existing["state"]), IngressEvent.NOTICE
                )
                connection.execute(
                    """
                    UPDATE ingress_messages
                    SET state = ?, notice_json = ?, provider_message_id = ?,
                        envelope_blob_key = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        state.value,
                        _json(notice_data),
                        notice.provider_message_id,
                        envelope_key,
                        isoformat(now),
                        existing["id"],
                    ),
                )
                return str(existing["id"])
            if binding.state is BindingState.DRAINING:
                raise InvalidTransition("draining inbound binding accepts retries only")
            message_id = uuid7_str()
            state = reduce_ingress(IngressState.EMPTY, IngressEvent.NOTICE)
            connection.execute(
                """
                INSERT INTO ingress_messages(
                    id, notice_id, provider, provider_event_id, provider_message_id,
                    domain, binding_id, binding_generation, state, envelope_blob_key,
                    notice_json, retention_until, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id,
                    notice.notice_id,
                    notice.provider,
                    notice.provider_event_id,
                    notice.provider_message_id,
                    notice.domain,
                    binding.id,
                    binding.generation,
                    state.value,
                    envelope_key,
                    _json(notice_data),
                    isoformat(retention_until),
                    isoformat(now),
                    isoformat(now),
                ),
            )
            return message_id

    def record_inbound_raw(
        self,
        binding_id: str,
        *,
        provider: str,
        provider_event_id: str,
        message: InboundRawMessage,
        retention_until: datetime,
    ) -> str:
        binding = self._validate_inbound_binding(binding_id, message.domain)
        if (
            provider != binding.provider
            or message.binding_generation != binding.generation
        ):
            raise ContractError("raw ingress does not match binding generation")
        self._require_existing_if_draining(
            binding, message.notice_id, provider, provider_event_id
        )
        envelope_key = f"ingress/{message.notice_id}/envelope"
        raw_key = f"ingress/{message.notice_id}/raw"
        self.blobs.put(envelope_key, _envelope_bytes(message.envelope))
        self.blobs.put(raw_key, message.raw_mime)
        now = datetime.now(UTC)
        with self.database.transaction(immediate=True) as connection:
            existing = connection.execute(
                """
                SELECT * FROM ingress_messages
                WHERE notice_id = ? OR (provider = ? AND provider_event_id = ?)
                """,
                (message.notice_id, provider, provider_event_id),
            ).fetchone()
            if existing:
                self._verify_raw_duplicate(existing, binding, message)
                state = reduce_ingress(
                    IngressState(existing["state"]), IngressEvent.RAW
                )
                connection.execute(
                    """
                    UPDATE ingress_messages
                    SET state = ?, envelope_blob_key = ?, raw_blob_key = ?,
                        raw_sha256 = ?, raw_size = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        state.value,
                        envelope_key,
                        raw_key,
                        message.raw_sha256,
                        len(message.raw_mime),
                        isoformat(now),
                        existing["id"],
                    ),
                )
                return str(existing["id"])
            if binding.state is BindingState.DRAINING:
                raise InvalidTransition("draining inbound binding accepts retries only")
            state = reduce_ingress(IngressState.EMPTY, IngressEvent.RAW)
            connection.execute(
                """
                INSERT INTO ingress_messages(
                    id, notice_id, provider, provider_event_id, domain, binding_id,
                    binding_generation, state, envelope_blob_key, raw_blob_key,
                    raw_sha256, raw_size, retention_until, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message.message_id,
                    message.notice_id,
                    provider,
                    provider_event_id,
                    message.domain,
                    binding.id,
                    binding.generation,
                    state.value,
                    envelope_key,
                    raw_key,
                    message.raw_sha256,
                    len(message.raw_mime),
                    isoformat(retention_until),
                    isoformat(now),
                    isoformat(now),
                ),
            )
            return message.message_id

    def _validate_inbound_binding(self, binding_id: str, domain: str) -> Binding:
        binding = self.bindings.get(binding_id)
        if (
            binding.direction is not BindingDirection.INBOUND
            or binding.domain != domain
        ):
            raise ContractError("ingress does not match exact-domain inbound binding")
        if binding.state not in {BindingState.ACTIVE, BindingState.DRAINING}:
            raise InvalidTransition("inbound binding is not accepting traffic")
        return binding

    def _require_existing_if_draining(
        self,
        binding: Binding,
        notice_id: str,
        provider: str,
        provider_event_id: str,
    ) -> None:
        if binding.state is not BindingState.DRAINING:
            return
        with self.database.transaction() as connection:
            existing = connection.execute(
                """
                SELECT id FROM ingress_messages
                WHERE notice_id = ? OR (provider = ? AND provider_event_id = ?)
                """,
                (notice_id, provider, provider_event_id),
            ).fetchone()
        if existing is None:
            raise InvalidTransition("draining inbound binding accepts retries only")

    @staticmethod
    def _verify_notice_duplicate(
        row: dict[str, Any], binding: Binding, notice: InboundNotice
    ) -> None:
        expected = (
            binding.id,
            binding.generation,
            notice.domain,
            notice.provider,
            notice.provider_event_id,
        )
        actual = (
            row["binding_id"],
            int(row["binding_generation"]),
            row["domain"],
            row["provider"],
            row["provider_event_id"],
        )
        if actual != expected:
            raise DuplicateConflict("inbound notice dedupe conflict")

    def _verify_raw_duplicate(
        self, row: dict[str, Any], binding: Binding, message: InboundRawMessage
    ) -> None:
        if (
            row["binding_id"] != binding.id
            or int(row["binding_generation"]) != binding.generation
            or row["domain"] != message.domain
        ):
            raise DuplicateConflict("inbound raw dedupe conflict")
        if row["raw_sha256"] is not None and row["raw_sha256"] != message.raw_sha256:
            raise DuplicateConflict("duplicate ingress has different raw MIME")
        if row["envelope_blob_key"]:
            stored = _envelope_from_bytes(self.blobs.get(row["envelope_blob_key"]))
            if stored != message.envelope:
                raise DuplicateConflict("duplicate ingress has a different envelope")

    def claim_ingress(
        self,
        *,
        lease_seconds: int = 300,
        now: datetime | None = None,
    ) -> ClaimedIngress | None:
        current = now or datetime.now(UTC)
        lease_until = current + timedelta(seconds=lease_seconds)
        with self.database.transaction(immediate=True) as connection:
            expired = connection.execute(
                """
                SELECT id, state FROM ingress_messages
                WHERE state = 'delivering' AND lease_until <= ?
                """,
                (isoformat(current),),
            ).fetchall()
            for row in expired:
                state = reduce_ingress(
                    IngressState(row["state"]), IngressEvent.LEASE_EXPIRED
                )
                connection.execute(
                    """
                    UPDATE ingress_messages
                    SET state = ?, next_attempt_at = ?, lease_until = NULL,
                        last_diagnostic = 'handoff_lease_expired', updated_at = ?
                    WHERE id = ?
                    """,
                    (state.value, isoformat(current), isoformat(current), row["id"]),
                )
            lock = (
                " FOR UPDATE SKIP LOCKED"
                if self.database.dialect == "postgresql"
                else ""
            )
            row = connection.execute(
                """
                SELECT * FROM ingress_messages
                WHERE state = 'ready'
                   OR (state = 'retry_wait' AND next_attempt_at <= ?)
                ORDER BY created_at LIMIT 1
                """
                + lock,
                (isoformat(current),),
            ).fetchone()
            if row is None:
                return None
            next_state = reduce_ingress(IngressState(row["state"]), IngressEvent.CLAIM)
            attempt = int(row["attempts"]) + 1
            connection.execute(
                """
                UPDATE ingress_messages
                SET state = ?, attempts = ?, lease_until = ?, next_attempt_at = NULL,
                    updated_at = ? WHERE id = ?
                """,
                (
                    next_state.value,
                    attempt,
                    isoformat(lease_until),
                    isoformat(current),
                    row["id"],
                ),
            )
        raw = self.blobs.get(str(row["raw_blob_key"]))
        if hashlib.sha256(raw).hexdigest() != row["raw_sha256"]:
            self.quarantine("ingress", str(row["id"]), "raw_hash_mismatch", "")
            return None
        envelope = _envelope_from_bytes(self.blobs.get(str(row["envelope_blob_key"])))
        return ClaimedIngress(
            id=str(row["id"]),
            notice_id=str(row["notice_id"]),
            domain=str(row["domain"]),
            binding_generation=int(row["binding_generation"]),
            envelope=envelope,
            raw_mime=raw,
            raw_sha256=str(row["raw_sha256"]),
            attempt=attempt,
        )

    def complete_ingress(
        self,
        message_id: str,
        *,
        success: bool,
        retryable: bool = True,
        diagnostic: str = "",
        now: datetime | None = None,
    ) -> IngressState:
        current = now or datetime.now(UTC)
        with self.database.transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT * FROM ingress_messages WHERE id = ?", (message_id,)
            ).fetchone()
            if row is None:
                raise ContractError("ingress message does not exist")
            state = IngressState(row["state"])
            if success:
                next_state = reduce_ingress(state, IngressEvent.HANDOFF_OK)
                connection.execute(
                    """
                    UPDATE ingress_messages SET state = ?, handed_off_at = ?,
                        lease_until = NULL, last_diagnostic = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        next_state.value,
                        isoformat(current),
                        isoformat(current),
                        message_id,
                    ),
                )
                return next_state
            attempts = int(row["attempts"])
            safe_diagnostic = diagnostic_code(diagnostic)
            if retryable and attempts < self.retry_policy.maximum_attempts:
                next_state = reduce_ingress(state, IngressEvent.HANDOFF_RETRY)
                due = self.retry_policy.due_at(message_id, attempts, current)
                connection.execute(
                    """
                    UPDATE ingress_messages SET state = ?, next_attempt_at = ?,
                        lease_until = NULL, last_diagnostic = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        next_state.value,
                        isoformat(due),
                        safe_diagnostic,
                        isoformat(current),
                        message_id,
                    ),
                )
                return next_state
            next_state = reduce_ingress(state, IngressEvent.QUARANTINE)
            connection.execute(
                """
                UPDATE ingress_messages SET state = ?, lease_until = NULL,
                    last_diagnostic = ?, updated_at = ? WHERE id = ?
                """,
                (next_state.value, safe_diagnostic, isoformat(current), message_id),
            )
            self._quarantine(
                connection,
                "ingress",
                message_id,
                "handoff_failed",
                safe_diagnostic,
                current,
            )
            return next_state

    def enqueue_outbound(
        self,
        submission: OutboundSubmission,
        *,
        binding: Binding,
        retention_until: datetime,
    ) -> bool:
        if (
            binding.direction is not BindingDirection.OUTBOUND
            or binding.state is not BindingState.ACTIVE
            or binding.domain != submission.domain
            or binding.generation != submission.binding_generation
        ):
            raise ContractError("submission does not match active exact-domain binding")
        envelope_key = f"outbound/{submission.submission_id}/envelope"
        raw_key = f"outbound/{submission.submission_id}/raw"
        self.blobs.put(envelope_key, _envelope_bytes(submission.envelope))
        self.blobs.put(raw_key, submission.raw_mime)
        now = datetime.now(UTC)
        with self.database.transaction(immediate=True) as connection:
            existing = connection.execute(
                "SELECT * FROM outbound_messages WHERE id = ?",
                (submission.submission_id,),
            ).fetchone()
            if existing:
                if (
                    existing["raw_sha256"] != submission.raw_sha256
                    or existing["binding_id"] != binding.id
                    or existing["domain"] != submission.domain
                ):
                    raise DuplicateConflict(
                        "submission ID already has different content"
                    )
                stored_envelope = _envelope_from_bytes(
                    self.blobs.get(existing["envelope_blob_key"])
                )
                if stored_envelope != submission.envelope:
                    raise DuplicateConflict(
                        "submission ID already has a different envelope"
                    )
                return False
            connection.execute(
                """
                INSERT INTO outbound_messages(
                    id, domain, binding_id, binding_generation, state,
                    envelope_blob_key, raw_blob_key, raw_sha256, raw_size,
                    retention_until, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    submission.submission_id,
                    submission.domain,
                    binding.id,
                    binding.generation,
                    OutboundState.QUEUED.value,
                    envelope_key,
                    raw_key,
                    submission.raw_sha256,
                    len(submission.raw_mime),
                    isoformat(retention_until),
                    isoformat(now),
                    isoformat(now),
                ),
            )
        return True

    def claim_outbound(
        self,
        *,
        lease_seconds: int = 300,
        now: datetime | None = None,
    ) -> ClaimedOutbound | None:
        current = now or datetime.now(UTC)
        lease_until = current + timedelta(seconds=lease_seconds)
        with self.database.transaction(immediate=True) as connection:
            expired = connection.execute(
                """
                SELECT id, state FROM outbound_messages
                WHERE state = 'submitting' AND lease_until <= ?
                """,
                (isoformat(current),),
            ).fetchall()
            for expired_row in expired:
                state = reduce_outbound(
                    OutboundState(expired_row["state"]), OutboundEvent.LEASE_EXPIRED
                )
                connection.execute(
                    """
                    UPDATE outbound_messages SET state = ?, lease_until = NULL,
                        next_attempt_at = NULL,
                        last_diagnostic = 'submission_lease_expired',
                        updated_at = ? WHERE id = ?
                    """,
                    (state.value, isoformat(current), expired_row["id"]),
                )
                self._quarantine(
                    connection,
                    "outbound",
                    str(expired_row["id"]),
                    "unknown_outcome",
                    "submission_lease_expired",
                    current,
                )
            lock = (
                " FOR UPDATE SKIP LOCKED"
                if self.database.dialect == "postgresql"
                else ""
            )
            row = connection.execute(
                """
                SELECT * FROM outbound_messages
                WHERE state = 'queued'
                   OR (state = 'retry_wait' AND next_attempt_at <= ?)
                ORDER BY created_at LIMIT 1
                """
                + lock,
                (isoformat(current),),
            ).fetchone()
            if row is None:
                return None
            next_state = reduce_outbound(
                OutboundState(row["state"]), OutboundEvent.CLAIM
            )
            attempt = int(row["attempts"]) + 1
            connection.execute(
                """
                UPDATE outbound_messages SET state = ?, attempts = ?, lease_until = ?,
                    next_attempt_at = NULL, updated_at = ? WHERE id = ?
                """,
                (
                    next_state.value,
                    attempt,
                    isoformat(lease_until),
                    isoformat(current),
                    row["id"],
                ),
            )
        raw = self.blobs.get(str(row["raw_blob_key"]))
        if hashlib.sha256(raw).hexdigest() != row["raw_sha256"]:
            self.quarantine("outbound", str(row["id"]), "raw_hash_mismatch", "")
            return None
        envelope = _envelope_from_bytes(self.blobs.get(str(row["envelope_blob_key"])))
        binding = self.bindings.get(str(row["binding_id"]))
        submission = OutboundSubmission(
            submission_id=str(row["id"]),
            domain=str(row["domain"]),
            binding_generation=int(row["binding_generation"]),
            envelope=envelope,
            raw_mime=raw,
            raw_sha256=str(row["raw_sha256"]),
        )
        return ClaimedOutbound(submission=submission, binding=binding, attempt=attempt)

    def complete_outbound(
        self,
        result: OutboundResult,
        *,
        now: datetime | None = None,
    ) -> OutboundState:
        current = now or datetime.now(UTC)
        with self.database.transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT * FROM outbound_messages WHERE id = ?", (result.submission_id,)
            ).fetchone()
            if row is None:
                raise ContractError("outbound submission does not exist")
            state = OutboundState(row["state"])
            diagnostic = diagnostic_code(result.diagnostic_code)
            if result.outcome is SubmissionOutcome.ACCEPTED:
                event = OutboundEvent.ACCEPTED
            elif result.outcome is SubmissionOutcome.REJECTED:
                event = OutboundEvent.REJECTED
            elif result.outcome is SubmissionOutcome.TEMPORARY_FAILURE:
                event = OutboundEvent.DEFINITE_NOT_SUBMITTED
            else:
                event = OutboundEvent.AMBIGUOUS
            next_state = reduce_outbound(state, event)
            attempts = int(row["attempts"])
            if next_state is OutboundState.RETRY_WAIT:
                if attempts >= self.retry_policy.maximum_attempts:
                    next_state = OutboundState.QUARANTINED
                    next_attempt = None
                    self._quarantine(
                        connection,
                        "outbound",
                        result.submission_id,
                        "retry_exhausted",
                        diagnostic,
                        current,
                    )
                else:
                    if result.retry_after_seconds is not None:
                        next_attempt = current + timedelta(
                            seconds=max(1, result.retry_after_seconds)
                        )
                    else:
                        next_attempt = self.retry_policy.due_at(
                            result.submission_id, attempts, current
                        )
            else:
                next_attempt = None
            terminal_at = (
                isoformat(current)
                if next_state in {OutboundState.ACCEPTED, OutboundState.REJECTED}
                else None
            )
            connection.execute(
                """
                UPDATE outbound_messages SET state = ?, provider_receipt_id = ?,
                    next_attempt_at = ?, lease_until = NULL, last_diagnostic = ?,
                    terminal_at = ?, updated_at = ? WHERE id = ?
                """,
                (
                    next_state.value,
                    result.provider_receipt_id,
                    isoformat(next_attempt) if next_attempt else None,
                    diagnostic,
                    terminal_at,
                    isoformat(current),
                    result.submission_id,
                ),
            )
            if next_state is OutboundState.UNKNOWN:
                self._quarantine(
                    connection,
                    "outbound",
                    result.submission_id,
                    "unknown_outcome",
                    diagnostic,
                    current,
                )
            return next_state

    def record_feedback(self, feedback: Feedback) -> bool:
        now = datetime.now(UTC)
        with self.database.transaction(immediate=True) as connection:
            duplicate = connection.execute(
                """
                SELECT id FROM feedback_events
                WHERE provider = ? AND provider_event_id = ?
                """,
                (feedback.provider, feedback.provider_event_id),
            ).fetchone()
            if duplicate:
                return False
            by_id = None
            if feedback.submission_id:
                by_id = connection.execute(
                    """
                    SELECT o.* FROM outbound_messages o
                    JOIN route_generations r ON r.id = o.binding_id
                    WHERE o.id = ? AND r.provider = ?
                    """,
                    (feedback.submission_id, feedback.provider),
                ).fetchone()
            by_receipt = None
            if feedback.provider_receipt_id:
                by_receipt = connection.execute(
                    """
                    SELECT o.* FROM outbound_messages o
                    JOIN route_generations r ON r.id = o.binding_id
                    WHERE o.provider_receipt_id = ? AND r.provider = ?
                    """,
                    (feedback.provider_receipt_id, feedback.provider),
                ).fetchone()
            if by_id and by_receipt and by_id["id"] != by_receipt["id"]:
                correlated = None
                reason = "correlation_conflict"
            else:
                correlated = by_id or by_receipt
                reason = "uncorrelated_feedback"
            correlation_state = "correlated" if correlated else "quarantined"
            connection.execute(
                """
                INSERT INTO feedback_events(
                    id, provider, provider_event_id, kind, occurred_at,
                    recipient_hash, submission_id, provider_receipt_id,
                    diagnostic_code, correlation_state, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    feedback.feedback_id,
                    feedback.provider,
                    feedback.provider_event_id,
                    feedback.kind.value,
                    isoformat(feedback.occurred_at),
                    feedback.recipient_hash,
                    correlated["id"] if correlated else None,
                    feedback.provider_receipt_id,
                    diagnostic_code(feedback.diagnostic_code),
                    correlation_state,
                    isoformat(now),
                ),
            )
            if correlated is None:
                self._quarantine(
                    connection,
                    "feedback",
                    feedback.feedback_id,
                    reason,
                    feedback.diagnostic_code,
                    now,
                )
            elif correlated["state"] == OutboundState.UNKNOWN.value:
                event = (
                    OutboundEvent.RECONCILE_REJECTED
                    if feedback.kind is FeedbackKind.REJECTED
                    else OutboundEvent.RECONCILE_ACCEPTED
                )
                next_state = reduce_outbound(OutboundState.UNKNOWN, event)
                connection.execute(
                    """
                    UPDATE outbound_messages SET state = ?, provider_receipt_id = ?,
                        terminal_at = ?, updated_at = ?, last_diagnostic = ?
                    WHERE id = ?
                    """,
                    (
                        next_state.value,
                        feedback.provider_receipt_id
                        or correlated["provider_receipt_id"],
                        isoformat(now),
                        isoformat(now),
                        "reconciled_by_feedback",
                        correlated["id"],
                    ),
                )
                connection.execute(
                    """
                    UPDATE quarantine SET resolved_at = ?, resolution = ?
                    WHERE object_type = 'outbound' AND object_id = ?
                      AND reason_code = 'unknown_outcome' AND resolved_at IS NULL
                    """,
                    (isoformat(now), "provider_feedback", correlated["id"]),
                )
            return True

    def reconcile_unknown(
        self,
        submission_id: str,
        *,
        accepted: bool,
        provider_receipt_id: str | None,
        resolution: str,
    ) -> OutboundState:
        if not resolution.strip() or len(resolution) > 256:
            raise ContractError("bounded reconciliation evidence is required")
        now = datetime.now(UTC)
        with self.database.transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT state FROM outbound_messages WHERE id = ?", (submission_id,)
            ).fetchone()
            if row is None:
                raise ContractError("submission does not exist")
            event = (
                OutboundEvent.RECONCILE_ACCEPTED
                if accepted
                else OutboundEvent.RECONCILE_REJECTED
            )
            next_state = reduce_outbound(OutboundState(row["state"]), event)
            connection.execute(
                """
                UPDATE outbound_messages SET state = ?, provider_receipt_id = ?,
                    terminal_at = ?, updated_at = ?, last_diagnostic = ? WHERE id = ?
                """,
                (
                    next_state.value,
                    provider_receipt_id,
                    isoformat(now),
                    isoformat(now),
                    "manual_reconciliation",
                    submission_id,
                ),
            )
            connection.execute(
                """
                UPDATE quarantine SET resolved_at = ?, resolution = ?
                WHERE object_type = 'outbound' AND object_id = ?
                  AND reason_code = 'unknown_outcome' AND resolved_at IS NULL
                """,
                (
                    isoformat(now),
                    redact_text(resolution, salt=self.diagnostic_salt),
                    submission_id,
                ),
            )
            return next_state

    def quarantine(
        self, object_type: str, object_id: str, reason_code: str, detail: str
    ) -> str:
        now = datetime.now(UTC)
        with self.database.transaction(immediate=True) as connection:
            return self._quarantine(
                connection, object_type, object_id, reason_code, detail, now
            )

    def _quarantine(
        self,
        connection: Connection,
        object_type: str,
        object_id: str,
        reason_code: str,
        detail: str,
        now: datetime,
    ) -> str:
        quarantine_id = uuid7_str()
        safe_reason = diagnostic_code(reason_code)
        safe_detail = redact_text(detail, salt=self.diagnostic_salt)
        existing = connection.execute(
            """
            SELECT id FROM quarantine
            WHERE object_type = ? AND object_id = ? AND reason_code = ?
            """,
            (object_type, object_id, safe_reason),
        ).fetchone()
        if existing:
            return str(existing["id"])
        connection.execute(
            """
            INSERT INTO quarantine(
                id, object_type, object_id, reason_code, detail, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                quarantine_id,
                object_type,
                object_id,
                safe_reason,
                safe_detail,
                isoformat(now),
            ),
        )
        return quarantine_id

    def list_unknown(self, *, limit: int = 100) -> list[dict[str, Any]]:
        bounded = min(max(limit, 1), 1000)
        with self.database.transaction() as connection:
            return connection.execute(
                """
                SELECT id, domain, binding_id, binding_generation, attempts,
                       provider_receipt_id, last_diagnostic, created_at, updated_at
                FROM outbound_messages WHERE state = 'unknown'
                ORDER BY created_at LIMIT ?
                """,
                (bounded,),
            ).fetchall()

    def list_quarantine(self, *, limit: int = 100) -> list[dict[str, Any]]:
        bounded = min(max(limit, 1), 1000)
        with self.database.transaction() as connection:
            return connection.execute(
                """
                SELECT id, object_type, object_id, reason_code, detail, created_at
                FROM quarantine WHERE resolved_at IS NULL
                ORDER BY created_at LIMIT ?
                """,
                (bounded,),
            ).fetchall()

    def retention_sweep(self, *, now: datetime | None = None, limit: int = 500) -> int:
        current = now or datetime.now(UTC)
        cutoff = isoformat(current)
        deleted = 0
        candidates: list[tuple[str, str, str, str]] = []
        with self.database.transaction() as connection:
            ingress = connection.execute(
                """
                SELECT id, envelope_blob_key, raw_blob_key FROM ingress_messages
                WHERE state = 'handed_off' AND retention_until <= ?
                ORDER BY retention_until LIMIT ?
                """,
                (cutoff, limit),
            ).fetchall()
            for row in ingress:
                candidates.append(
                    (
                        "ingress_messages",
                        str(row["id"]),
                        row["envelope_blob_key"],
                        row["raw_blob_key"],
                    )
                )
            remaining = max(0, limit - len(candidates))
            outbound = connection.execute(
                """
                SELECT id, envelope_blob_key, raw_blob_key FROM outbound_messages
                WHERE state IN ('accepted', 'rejected') AND retention_until <= ?
                ORDER BY retention_until LIMIT ?
                """,
                (cutoff, remaining),
            ).fetchall()
            for row in outbound:
                candidates.append(
                    (
                        "outbound_messages",
                        str(row["id"]),
                        row["envelope_blob_key"],
                        row["raw_blob_key"],
                    )
                )
        for table, message_id, envelope_key, raw_key in candidates:
            if envelope_key:
                self.blobs.delete(str(envelope_key))
            if raw_key:
                self.blobs.delete(str(raw_key))
            with self.database.transaction(immediate=True) as connection:
                expected = (
                    "('handed_off')"
                    if table == "ingress_messages"
                    else "('accepted','rejected')"
                )
                changed = connection.execute(
                    f"""
                    UPDATE {table} SET state = 'deleted', deleted_at = ?, updated_at = ?
                    WHERE id = ? AND state IN {expected}
                    """,
                    (cutoff, cutoff, message_id),
                ).rowcount
                deleted += max(changed, 0)
        return deleted

    def orphan_sweep(
        self,
        *,
        now: datetime | None = None,
        grace: timedelta = timedelta(days=7),
        limit: int = 500,
    ) -> int:
        if grace < timedelta(hours=1):
            raise ValueError("orphan grace must be at least one hour")
        current = now or datetime.now(UTC)
        candidates = self.blobs.older_blob_ids(current - grace, limit=limit)
        if not candidates:
            return 0
        with self.database.transaction() as connection:
            rows = connection.execute(
                """
                SELECT envelope_blob_key, raw_blob_key FROM ingress_messages
                UNION ALL
                SELECT envelope_blob_key, raw_blob_key FROM outbound_messages
                """
            ).fetchall()
        referenced = {
            str(value)
            for row in rows
            for value in (row["envelope_blob_key"], row["raw_blob_key"])
            if value
        }
        deleted = 0
        for blob_id in candidates:
            if blob_id not in referenced and self.blobs.delete(blob_id):
                deleted += 1
        return deleted

    def state_counts(self) -> dict[str, dict[str, int]]:
        counts: dict[str, dict[str, int]] = {"ingress": {}, "outbound": {}}
        with self.database.transaction() as connection:
            for direction, table in (
                ("ingress", "ingress_messages"),
                ("outbound", "outbound_messages"),
            ):
                rows = connection.execute(
                    f"SELECT state, COUNT(*) AS count FROM {table} GROUP BY state"
                ).fetchall()
                counts[direction] = {
                    str(row["state"]): int(row["count"]) for row in rows
                }
        return counts

    def quarantine_count(self) -> int:
        with self.database.transaction() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM quarantine WHERE resolved_at IS NULL"
            ).fetchone()
        return int(row["count"])
