"""Provider-neutral values admitted across the adapter boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class ProviderRegion(StrEnum):
    US = "US"
    EU = "EU"


class SubmissionDisposition(StrEnum):
    ACCEPTED = "ACCEPTED"
    RETRYABLE_REJECTED = "RETRYABLE_REJECTED"
    PERMANENT_REJECTED = "PERMANENT_REJECTED"
    AMBIGUOUS = "AMBIGUOUS"


class FeedbackEventType(StrEnum):
    ACCEPTED = "accepted"
    DELIVERED = "delivered"
    DELAYED = "delayed"
    SOFT_BOUNCE = "soft_bounce"
    HARD_BOUNCE = "hard_bounce"
    COMPLAINT = "complaint"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class OutboundMessage:
    edge_delivery_id: str
    envelope_from: str
    envelope_recipients: tuple[str, ...]
    rfc822_bytes: bytes
    smtp_utf8_required: bool = False
    mail_options: tuple[str, ...] = ()
    rcpt_options: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    disposition: SubmissionDisposition
    edge_delivery_id: str
    provider_message_id: str | None = None
    visible_message_id: str | None = None
    diagnostic: str | None = None
    retry_after_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class InboundMessage:
    provider_event_id: str
    envelope_from: str
    envelope_recipients: tuple[str, ...]
    rfc822_bytes: bytes
    received_at: datetime


@dataclass(frozen=True, slots=True)
class FeedbackEvent:
    provider_event_id: str
    provider_message_id: str
    edge_delivery_id: str | None
    event_type: FeedbackEventType
    recipient: str
    smtp_status: str | None
    diagnostic: str | None
    occurred_at: datetime
    visible_message_id: str | None = None


@dataclass(frozen=True, slots=True)
class DNSRecordCapability:
    name: str
    record_type: str
    value: str
    priority: str | None
    valid: str
    active: bool


@dataclass(frozen=True, slots=True)
class DomainCapabilities:
    domain: str
    region: ProviderRegion
    state: str
    domain_type: str | None
    require_tls: bool
    message_ttl_seconds: int | None
    click_tracking: bool
    open_tracking: bool
    unsubscribe_tracking: bool
    receiving_dns: tuple[DNSRecordCapability, ...]
    sending_dns: tuple[DNSRecordCapability, ...]
