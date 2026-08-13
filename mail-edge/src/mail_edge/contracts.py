"""Provider-neutral contracts. Provider payloads are normalized outside this module."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .errors import ContractError
from .ids import require_uuid7

_DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def utcnow() -> datetime:
    return datetime.now(UTC)


def isoformat(value: datetime) -> str:
    if value.tzinfo is None:
        raise ContractError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def normalize_domain(value: str) -> str:
    candidate = value.strip().rstrip(".").lower()
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ContractError("invalid domain") from exc
    if len(candidate) > 253 or "." not in candidate:
        raise ContractError("domain must be a fully-qualified exact domain")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in candidate.split(".")):
        raise ContractError("invalid domain")
    return candidate


def address_domain(address: str) -> str:
    stripped = address.strip()
    if stripped == "":
        return ""
    if stripped.count("@") != 1:
        raise ContractError("envelope address must contain one @")
    local, domain = stripped.rsplit("@", 1)
    if not local or any(ord(char) < 33 for char in local):
        raise ContractError("invalid envelope local part")
    return normalize_domain(domain)


def validate_envelope(sender: str, recipients: tuple[str, ...]) -> None:
    if sender:
        address_domain(sender)
    if not recipients:
        raise ContractError("at least one envelope recipient is required")
    if len(recipients) > 100:
        raise ContractError("too many envelope recipients")
    for recipient in recipients:
        address_domain(recipient)


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class BindingDirection(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class BindingState(StrEnum):
    PREPARED = "prepared"
    SHADOW = "shadow"
    ACTIVE = "active"
    DRAINING = "draining"
    DISABLED = "disabled"


class SubmissionOutcome(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    TEMPORARY_FAILURE = "temporary_failure"
    UNKNOWN = "unknown"


class FeedbackKind(StrEnum):
    ACCEPTED = "accepted"
    DELIVERED = "delivered"
    DELAYED = "delayed"
    FAILED_TEMPORARY = "failed_temporary"
    FAILED_PERMANENT = "failed_permanent"
    COMPLAINED = "complained"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class Envelope:
    sender: str
    recipients: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_envelope(self.sender, self.recipients)

    def as_dict(self) -> dict[str, Any]:
        return {"sender": self.sender, "recipients": list(self.recipients)}


@dataclass(frozen=True, slots=True)
class InboundNotice:
    notice_id: str
    provider: str
    provider_event_id: str
    provider_message_id: str | None
    domain: str
    binding_generation: int
    envelope: Envelope
    occurred_at: datetime
    raw_available: bool
    diagnostics: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_uuid7(self.notice_id)
        object.__setattr__(self, "domain", normalize_domain(self.domain))
        if self.binding_generation < 1:
            raise ContractError("binding generation must be positive")
        if not self.provider or not self.provider_event_id:
            raise ContractError("provider and provider event ID are required")

    def as_dict(self) -> dict[str, Any]:
        return {
            "notice_id": self.notice_id,
            "provider": self.provider,
            "provider_event_id": self.provider_event_id,
            "provider_message_id": self.provider_message_id,
            "domain": self.domain,
            "binding_generation": self.binding_generation,
            "envelope": self.envelope.as_dict(),
            "occurred_at": isoformat(self.occurred_at),
            "raw_available": self.raw_available,
            "diagnostics": dict(self.diagnostics),
        }


@dataclass(frozen=True, slots=True)
class InboundRawMessage:
    message_id: str
    notice_id: str
    domain: str
    binding_generation: int
    envelope: Envelope
    raw_mime: bytes = field(repr=False)
    raw_sha256: str = ""

    def __post_init__(self) -> None:
        require_uuid7(self.message_id)
        require_uuid7(self.notice_id)
        object.__setattr__(self, "domain", normalize_domain(self.domain))
        actual_hash = sha256_hex(self.raw_mime)
        if self.raw_sha256 and self.raw_sha256 != actual_hash:
            raise ContractError("raw MIME hash mismatch")
        object.__setattr__(self, "raw_sha256", actual_hash)
        if not self.raw_mime:
            raise ContractError("raw MIME is empty")

    def metadata(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "notice_id": self.notice_id,
            "domain": self.domain,
            "binding_generation": self.binding_generation,
            "envelope": self.envelope.as_dict(),
            "raw_sha256": self.raw_sha256,
            "raw_size": len(self.raw_mime),
        }


@dataclass(frozen=True, slots=True)
class OutboundSubmission:
    submission_id: str
    domain: str
    binding_generation: int
    envelope: Envelope
    raw_mime: bytes = field(repr=False)
    raw_sha256: str = ""

    def __post_init__(self) -> None:
        require_uuid7(self.submission_id)
        object.__setattr__(self, "domain", normalize_domain(self.domain))
        if self.envelope.sender and address_domain(self.envelope.sender) != self.domain:
            raise ContractError("outbound domain must exactly match envelope sender")
        actual_hash = sha256_hex(self.raw_mime)
        if self.raw_sha256 and self.raw_sha256 != actual_hash:
            raise ContractError("raw MIME hash mismatch")
        object.__setattr__(self, "raw_sha256", actual_hash)
        if not self.raw_mime:
            raise ContractError("raw MIME is empty")

    def metadata(self) -> dict[str, Any]:
        return {
            "submission_id": self.submission_id,
            "domain": self.domain,
            "binding_generation": self.binding_generation,
            "envelope": self.envelope.as_dict(),
            "raw_sha256": self.raw_sha256,
            "raw_size": len(self.raw_mime),
        }


@dataclass(frozen=True, slots=True)
class OutboundResult:
    submission_id: str
    outcome: SubmissionOutcome
    provider_receipt_id: str | None
    occurred_at: datetime
    diagnostic_code: str
    retry_after_seconds: int | None = None

    def __post_init__(self) -> None:
        require_uuid7(self.submission_id)
        if self.outcome is SubmissionOutcome.ACCEPTED and not self.provider_receipt_id:
            raise ContractError("accepted outcome requires a provider receipt ID")
        if self.outcome is SubmissionOutcome.UNKNOWN and self.retry_after_seconds:
            raise ContractError("unknown outcomes cannot be scheduled for retry")

    def as_dict(self) -> dict[str, Any]:
        return {
            "submission_id": self.submission_id,
            "outcome": self.outcome.value,
            "provider_receipt_id": self.provider_receipt_id,
            "occurred_at": isoformat(self.occurred_at),
            "diagnostic_code": self.diagnostic_code,
            "retry_after_seconds": self.retry_after_seconds,
        }


@dataclass(frozen=True, slots=True)
class Feedback:
    feedback_id: str
    provider: str
    provider_event_id: str
    kind: FeedbackKind
    occurred_at: datetime
    recipient_hash: str
    submission_id: str | None = None
    provider_receipt_id: str | None = None
    diagnostic_code: str = ""

    def __post_init__(self) -> None:
        require_uuid7(self.feedback_id)
        if self.submission_id is not None:
            require_uuid7(self.submission_id)
        if not self.provider_event_id:
            raise ContractError("provider event ID is required")
        if not re.fullmatch(r"[0-9a-f]{64}", self.recipient_hash):
            raise ContractError("recipient hash must be SHA-256 hex")

    def as_dict(self) -> dict[str, Any]:
        return {
            "feedback_id": self.feedback_id,
            "provider": self.provider,
            "provider_event_id": self.provider_event_id,
            "kind": self.kind.value,
            "occurred_at": isoformat(self.occurred_at),
            "recipient_hash": self.recipient_hash,
            "submission_id": self.submission_id,
            "provider_receipt_id": self.provider_receipt_id,
            "diagnostic_code": self.diagnostic_code,
        }
