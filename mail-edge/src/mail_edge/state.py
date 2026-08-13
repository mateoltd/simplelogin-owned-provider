"""Pure state reducers and deterministic retry scheduling."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from .errors import InvalidTransition


class IngressState(StrEnum):
    EMPTY = "empty"
    NOTICE_ONLY = "notice_only"
    RAW_ONLY = "raw_only"
    READY = "ready"
    DELIVERING = "delivering"
    RETRY_WAIT = "retry_wait"
    HANDED_OFF = "handed_off"
    QUARANTINED = "quarantined"
    DELETED = "deleted"


class IngressEvent(StrEnum):
    NOTICE = "notice"
    RAW = "raw"
    CLAIM = "claim"
    HANDOFF_OK = "handoff_ok"
    HANDOFF_RETRY = "handoff_retry"
    LEASE_EXPIRED = "lease_expired"
    QUARANTINE = "quarantine"
    DELETE = "delete"


class OutboundState(StrEnum):
    QUEUED = "queued"
    SUBMITTING = "submitting"
    RETRY_WAIT = "retry_wait"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNKNOWN = "unknown"
    QUARANTINED = "quarantined"
    DELETED = "deleted"


class OutboundEvent(StrEnum):
    CLAIM = "claim"
    DEFINITE_NOT_SUBMITTED = "definite_not_submitted"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    AMBIGUOUS = "ambiguous"
    LEASE_EXPIRED = "lease_expired"
    RETRY_DUE = "retry_due"
    RECONCILE_ACCEPTED = "reconcile_accepted"
    RECONCILE_REJECTED = "reconcile_rejected"
    QUARANTINE = "quarantine"
    DELETE = "delete"


def reduce_ingress(state: IngressState, event: IngressEvent) -> IngressState:
    if event is IngressEvent.NOTICE:
        if state is IngressState.EMPTY:
            return IngressState.NOTICE_ONLY
        if state is IngressState.RAW_ONLY:
            return IngressState.READY
        if state in {
            IngressState.NOTICE_ONLY,
            IngressState.READY,
            IngressState.DELIVERING,
            IngressState.RETRY_WAIT,
            IngressState.HANDED_OFF,
        }:
            return state
    elif event is IngressEvent.RAW:
        if state is IngressState.EMPTY:
            return IngressState.RAW_ONLY
        if state is IngressState.NOTICE_ONLY:
            return IngressState.READY
        if state in {
            IngressState.RAW_ONLY,
            IngressState.READY,
            IngressState.DELIVERING,
            IngressState.RETRY_WAIT,
            IngressState.HANDED_OFF,
        }:
            return state
    elif event is IngressEvent.CLAIM and state in {
        IngressState.READY,
        IngressState.RETRY_WAIT,
    }:
        return IngressState.DELIVERING
    elif event is IngressEvent.HANDOFF_OK and state is IngressState.DELIVERING:
        return IngressState.HANDED_OFF
    elif event in {IngressEvent.HANDOFF_RETRY, IngressEvent.LEASE_EXPIRED}:
        if state is IngressState.DELIVERING:
            return IngressState.RETRY_WAIT
    elif event is IngressEvent.QUARANTINE and state is not IngressState.DELETED:
        return IngressState.QUARANTINED
    elif event is IngressEvent.DELETE and state in {
        IngressState.HANDED_OFF,
        IngressState.QUARANTINED,
    }:
        return IngressState.DELETED
    raise InvalidTransition(f"invalid ingress transition: {state.value}/{event.value}")


def reduce_outbound(state: OutboundState, event: OutboundEvent) -> OutboundState:
    if event is OutboundEvent.CLAIM and state in {
        OutboundState.QUEUED,
        OutboundState.RETRY_WAIT,
    }:
        return OutboundState.SUBMITTING
    if (
        event is OutboundEvent.DEFINITE_NOT_SUBMITTED
        and state is OutboundState.SUBMITTING
    ):
        return OutboundState.RETRY_WAIT
    if event is OutboundEvent.ACCEPTED and state is OutboundState.SUBMITTING:
        return OutboundState.ACCEPTED
    if event is OutboundEvent.REJECTED and state is OutboundState.SUBMITTING:
        return OutboundState.REJECTED
    if (
        event in {OutboundEvent.AMBIGUOUS, OutboundEvent.LEASE_EXPIRED}
        and state is OutboundState.SUBMITTING
    ):
        return OutboundState.UNKNOWN
    if event is OutboundEvent.RETRY_DUE and state is OutboundState.RETRY_WAIT:
        return OutboundState.QUEUED
    if event is OutboundEvent.RECONCILE_ACCEPTED and state is OutboundState.UNKNOWN:
        return OutboundState.ACCEPTED
    if event is OutboundEvent.RECONCILE_REJECTED and state is OutboundState.UNKNOWN:
        return OutboundState.REJECTED
    if event is OutboundEvent.QUARANTINE and state in {
        OutboundState.UNKNOWN,
        OutboundState.REJECTED,
    }:
        return OutboundState.QUARANTINED
    if event is OutboundEvent.DELETE and state in {
        OutboundState.ACCEPTED,
        OutboundState.REJECTED,
        OutboundState.QUARANTINED,
    }:
        return OutboundState.DELETED
    raise InvalidTransition(f"invalid outbound transition: {state.value}/{event.value}")


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    initial_seconds: int = 30
    maximum_seconds: int = 3600
    maximum_attempts: int = 12
    jitter_ratio: float = 0.2

    def due_at(
        self, message_id: str, attempt: int, now: datetime | None = None
    ) -> datetime:
        if attempt < 1:
            raise ValueError("attempt must be positive")
        if attempt > self.maximum_attempts:
            raise InvalidTransition("retry attempt limit reached")
        current = now or datetime.now(UTC)
        base = min(self.initial_seconds * (2 ** (attempt - 1)), self.maximum_seconds)
        digest = hashlib.sha256(f"{message_id}:{attempt}".encode()).digest()
        sample = int.from_bytes(digest[:8], "big") / ((1 << 64) - 1)
        multiplier = 1 - self.jitter_ratio + (2 * self.jitter_ratio * sample)
        return current + timedelta(seconds=max(1, round(base * multiplier)))
