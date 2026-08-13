"""Deterministic edge state model used by adapter fault qualification."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Iterable

from .contracts import (
    AdapterResult,
    DeliveryRequest,
    EventType,
    FeedbackEvent,
    SubmissionAdapter,
    SubmissionDisposition,
)


class DeliveryState(str, Enum):
    QUEUED = "queued"
    SUBMITTING = "submitting"
    ACCEPTED = "accepted"
    RETRY = "retry"
    REJECTED = "rejected"
    UNKNOWN = "unknown"
    DELAYED = "delayed"
    SOFT_BOUNCED = "soft_bounced"
    HARD_BOUNCED = "hard_bounced"
    DELIVERED = "delivered"
    COMPLAINED = "complained"
    QUARANTINED = "quarantined"


TERMINAL_STATES = frozenset(
    {
        DeliveryState.REJECTED,
        DeliveryState.HARD_BOUNCED,
        DeliveryState.DELIVERED,
        DeliveryState.COMPLAINED,
        DeliveryState.QUARANTINED,
    }
)


class CoreDataCrash(RuntimeError):
    """Injected process loss after durable DATA and before provider submission."""


class SubmissionTimeout(TimeoutError):
    def __init__(self, *, accepted: bool):
        self.accepted = accepted
        phase = "after" if accepted else "before"
        super().__init__(f"timeout {phase} provider acceptance")


@dataclass
class DeliveryRecord:
    request: DeliveryRequest
    state: DeliveryState = DeliveryState.QUEUED
    provider_message_id: str | None = None
    attempts: int = 0
    diagnostics: list[str] = field(default_factory=list)
    applied_events: list[str] = field(default_factory=list)

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.request.rfc822_bytes).hexdigest()


@dataclass(frozen=True)
class SignedFeedback:
    timestamp: int
    token: str
    signature: str
    event: FeedbackEvent


class FeedbackSigner:
    def __init__(self, key: bytes):
        if not key:
            raise ValueError("feedback signing key must not be empty")
        self._key = key

    def sign(
        self, event: FeedbackEvent, *, timestamp: int, token: str
    ) -> SignedFeedback:
        signature = hmac.new(
            self._key,
            _signed_bytes(timestamp, token, event),
            hashlib.sha256,
        ).hexdigest()
        return SignedFeedback(timestamp, token, signature, event)


class MailEdge:
    """A provider-neutral, durable-state model with fail-closed ambiguity rules."""

    def __init__(
        self,
        feedback_key: bytes,
        *,
        clock: Callable[[], datetime] | None = None,
        replay_window_seconds: int = 300,
    ) -> None:
        self.records: dict[str, DeliveryRecord] = {}
        self.provider_index: dict[str, str] = {}
        self.quarantined_events: list[tuple[str, str]] = []
        self._feedback_key = feedback_key
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._replay_window_seconds = replay_window_seconds
        self._seen_tokens: set[str] = set()
        self._seen_event_ids: set[str] = set()

    def persist_data(self, request: DeliveryRequest) -> DeliveryRecord:
        existing = self.records.get(request.edge_delivery_id)
        if existing is not None:
            if existing.request != request:
                raise ValueError("edge delivery ID was reused with different DATA")
            return existing
        record = DeliveryRecord(request=request)
        self.records[request.edge_delivery_id] = record
        return record

    def submit(
        self,
        request: DeliveryRequest,
        adapter: SubmissionAdapter,
        *,
        crash_after_core_data: bool = False,
    ) -> DeliveryRecord:
        record = self.persist_data(request)
        if crash_after_core_data:
            raise CoreDataCrash(request.edge_delivery_id)
        if record.state in TERMINAL_STATES or record.state in {
            DeliveryState.ACCEPTED,
            DeliveryState.UNKNOWN,
        }:
            return record
        record.state = DeliveryState.SUBMITTING
        record.attempts += 1
        try:
            result = adapter.submit(request)
        except SubmissionTimeout as error:
            record.state = (
                DeliveryState.UNKNOWN if error.accepted else DeliveryState.RETRY
            )
            record.diagnostics.append(str(error))
            return record
        self._apply_adapter_result(record, result)
        return record

    def recover_queued(self) -> tuple[DeliveryRecord, ...]:
        return tuple(
            record
            for record in self.records.values()
            if record.state in {DeliveryState.QUEUED, DeliveryState.RETRY}
        )

    def reconcile(
        self, edge_delivery_id: str, adapter: SubmissionAdapter
    ) -> DeliveryRecord:
        record = self.records[edge_delivery_id]
        if record.state is not DeliveryState.UNKNOWN:
            return record
        result = adapter.reconcile(edge_delivery_id)
        if result is None or result.disposition is SubmissionDisposition.UNKNOWN:
            record.diagnostics.append("reconciliation remained unknown")
            return record
        self._apply_adapter_result(record, result)
        return record

    def ingest_feedback(self, signed: SignedFeedback) -> str:
        expected = hmac.new(
            self._feedback_key,
            _signed_bytes(signed.timestamp, signed.token, signed.event),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, signed.signature):
            return self._quarantine_event(signed.event, "invalid_signature")
        current = int(self._clock().timestamp())
        if abs(current - signed.timestamp) > self._replay_window_seconds:
            return self._quarantine_event(signed.event, "expired_signature")
        if signed.token in self._seen_tokens:
            return self._quarantine_event(signed.event, "signature_replay")
        self._seen_tokens.add(signed.token)
        event = signed.event
        if event.provider_event_id in self._seen_event_ids:
            return "duplicate"
        self._seen_event_ids.add(event.provider_event_id)

        mapped_edge_id = self.provider_index.get(event.provider_message_id)
        if event.edge_delivery_id and mapped_edge_id:
            if event.edge_delivery_id != mapped_edge_id:
                return self._quarantine_event(event, "conflicting_correlation")
        edge_delivery_id = event.edge_delivery_id or mapped_edge_id
        if edge_delivery_id is None or edge_delivery_id not in self.records:
            return self._quarantine_event(event, "unknown_correlation")
        record = self.records[edge_delivery_id]
        if record.provider_message_id != event.provider_message_id:
            return self._quarantine_event(event, "provider_id_mismatch")
        if event.recipient.casefold() not in {
            item.casefold() for item in record.request.envelope_recipients
        }:
            return self._quarantine_event(event, "recipient_mismatch")

        record.applied_events.append(event.provider_event_id)
        next_state = _event_state(event.event_type)
        if _may_transition(record.state, next_state):
            record.state = next_state
        return "applied"

    def _apply_adapter_result(
        self, record: DeliveryRecord, result: AdapterResult
    ) -> None:
        if result.diagnostic:
            record.diagnostics.append(result.diagnostic)
        if result.disposition is SubmissionDisposition.ACCEPTED:
            provider_id = result.provider_message_id
            if provider_id in self.provider_index:
                if self.provider_index[provider_id] != record.request.edge_delivery_id:
                    raise ValueError("provider message ID mapped to two deliveries")
            record.provider_message_id = provider_id
            self.provider_index[str(provider_id)] = record.request.edge_delivery_id
            record.state = DeliveryState.ACCEPTED
        elif result.disposition is SubmissionDisposition.RETRY:
            record.state = DeliveryState.RETRY
        elif result.disposition is SubmissionDisposition.REJECT:
            record.state = DeliveryState.REJECTED
        else:
            record.state = DeliveryState.UNKNOWN

    def _quarantine_event(self, event: FeedbackEvent, reason: str) -> str:
        self.quarantined_events.append((event.provider_event_id, reason))
        return reason


@dataclass
class ScriptedOutcome:
    result: AdapterResult | None = None
    timeout_after_acceptance: bool | None = None


class ScriptedAdapter:
    """Deterministic adapter double with observable submission and reconciliation."""

    name = "deterministic-fixture"

    def __init__(self) -> None:
        self.outcomes: list[ScriptedOutcome] = []
        self.reconciliations: dict[str, AdapterResult | None] = {}
        self.submit_calls: list[str] = []
        self.accepted: dict[str, str] = {}

    def queue(self, *outcomes: ScriptedOutcome) -> None:
        self.outcomes.extend(outcomes)

    def submit(self, request: DeliveryRequest) -> AdapterResult:
        self.submit_calls.append(request.edge_delivery_id)
        outcome = self.outcomes.pop(0) if self.outcomes else ScriptedOutcome()
        if outcome.timeout_after_acceptance is not None:
            if outcome.timeout_after_acceptance:
                provider_id = _fixture_provider_id(request)
                self.accepted[request.edge_delivery_id] = provider_id
            raise SubmissionTimeout(accepted=outcome.timeout_after_acceptance)
        result = outcome.result or AdapterResult(
            SubmissionDisposition.ACCEPTED,
            provider_message_id=_fixture_provider_id(request),
        )
        if result.disposition is SubmissionDisposition.ACCEPTED:
            self.accepted[request.edge_delivery_id] = str(result.provider_message_id)
        return result

    def reconcile(self, edge_delivery_id: str) -> AdapterResult | None:
        if edge_delivery_id in self.reconciliations:
            return self.reconciliations[edge_delivery_id]
        provider_id = self.accepted.get(edge_delivery_id)
        if provider_id:
            return AdapterResult(
                SubmissionDisposition.ACCEPTED, provider_message_id=provider_id
            )
        return None


@dataclass
class ManualCutover:
    active_adapter: str
    draining_adapter: str | None = None
    quarantined_unknown: set[str] = field(default_factory=set)
    history: list[str] = field(default_factory=list)

    def begin(
        self, target_adapter: str, records: Iterable[DeliveryRecord]
    ) -> tuple[str, ...]:
        if not target_adapter or target_adapter == self.active_adapter:
            raise ValueError("cutover target must differ from the active adapter")
        self.draining_adapter = self.active_adapter
        routeable: list[str] = []
        for record in records:
            if record.state in {DeliveryState.QUEUED, DeliveryState.RETRY}:
                routeable.append(record.request.edge_delivery_id)
            elif record.state is DeliveryState.UNKNOWN:
                self.quarantined_unknown.add(record.request.edge_delivery_id)
        self.active_adapter = target_adapter
        self.history.append(f"cutover:{self.draining_adapter}->{target_adapter}")
        return tuple(routeable)

    def drain_complete(self) -> None:
        if self.draining_adapter is None:
            raise ValueError("no adapter is draining")
        self.history.append(f"drained:{self.draining_adapter}")
        self.draining_adapter = None

    def rollback(self, previous_adapter: str) -> None:
        if self.draining_adapter is not None:
            raise ValueError("cannot roll back before the current drain is resolved")
        current = self.active_adapter
        self.active_adapter = previous_adapter
        self.history.append(f"rollback:{current}->{previous_adapter}")


def _signed_bytes(timestamp: int, token: str, event: FeedbackEvent) -> bytes:
    payload = json.dumps(
        event.as_json(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return f"{timestamp}.{token}.{payload}".encode("utf-8")


def _fixture_provider_id(request: DeliveryRequest) -> str:
    digest = hashlib.sha256(
        request.edge_delivery_id.encode("ascii") + b"\0" + request.rfc822_bytes
    ).hexdigest()[:24]
    return f"fixture-{digest}"


def _event_state(event_type: EventType) -> DeliveryState:
    return {
        EventType.DELIVERED: DeliveryState.DELIVERED,
        EventType.DELAYED: DeliveryState.DELAYED,
        EventType.SOFT_BOUNCE: DeliveryState.SOFT_BOUNCED,
        EventType.HARD_BOUNCE: DeliveryState.HARD_BOUNCED,
        EventType.COMPLAINT: DeliveryState.COMPLAINED,
        EventType.REJECTED: DeliveryState.REJECTED,
    }[event_type]


def _may_transition(current: DeliveryState, candidate: DeliveryState) -> bool:
    if current is DeliveryState.COMPLAINED:
        return False
    if candidate is DeliveryState.COMPLAINED:
        return True
    if current is DeliveryState.HARD_BOUNCED:
        return False
    if candidate is DeliveryState.HARD_BOUNCED:
        return True
    if current is DeliveryState.REJECTED:
        return False
    if current is DeliveryState.DELIVERED:
        return False
    return True
