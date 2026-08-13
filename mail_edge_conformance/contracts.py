"""Small neutral data contracts shared by every qualification adapter."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Protocol


class SubmissionDisposition(str, Enum):
    ACCEPTED = "accepted"
    RETRY = "retry"
    REJECT = "reject"
    UNKNOWN = "unknown"


class EventType(str, Enum):
    DELIVERED = "delivered"
    DELAYED = "delayed"
    SOFT_BOUNCE = "soft_bounce"
    HARD_BOUNCE = "hard_bounce"
    COMPLAINT = "complaint"
    REJECTED = "rejected"


@dataclass(frozen=True)
class DeliveryRequest:
    edge_delivery_id: str
    envelope_from: str
    envelope_recipients: tuple[str, ...]
    rfc822_bytes: bytes
    smtp_utf8_required: bool = False
    mail_options: tuple[str, ...] = ()
    rcpt_options: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.edge_delivery_id or any(
            ch.isspace() for ch in self.edge_delivery_id
        ):
            raise ValueError("edge_delivery_id must be a non-empty opaque token")
        if not self.envelope_recipients:
            raise ValueError("at least one envelope recipient is required")
        if len(set(address.casefold() for address in self.envelope_recipients)) != len(
            self.envelope_recipients
        ):
            raise ValueError("duplicate envelope recipients are not neutral input")
        if not isinstance(self.rfc822_bytes, bytes) or not self.rfc822_bytes:
            raise ValueError("rfc822_bytes must contain a complete message")

    def as_json(self) -> dict[str, Any]:
        return {
            "edge_delivery_id": self.edge_delivery_id,
            "envelope_from": self.envelope_from,
            "envelope_recipients": list(self.envelope_recipients),
            "rfc822_base64": base64.b64encode(self.rfc822_bytes).decode("ascii"),
            "smtp_utf8_required": self.smtp_utf8_required,
            "mail_options": list(self.mail_options),
            "rcpt_options": list(self.rcpt_options),
        }

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "DeliveryRequest":
        return cls(
            edge_delivery_id=str(value["edge_delivery_id"]),
            envelope_from=str(value["envelope_from"]),
            envelope_recipients=tuple(
                str(item) for item in value["envelope_recipients"]
            ),
            rfc822_bytes=base64.b64decode(str(value["rfc822_base64"]), validate=True),
            smtp_utf8_required=bool(value.get("smtp_utf8_required", False)),
            mail_options=tuple(str(item) for item in value.get("mail_options", ())),
            rcpt_options=tuple(str(item) for item in value.get("rcpt_options", ())),
        )


@dataclass(frozen=True)
class AdapterResult:
    disposition: SubmissionDisposition
    provider_message_id: str | None = None
    diagnostic_code: str | None = None
    diagnostic: str | None = None

    def __post_init__(self) -> None:
        if self.disposition is SubmissionDisposition.ACCEPTED:
            if not self.provider_message_id:
                raise ValueError("accepted submissions require a provider message ID")
        elif self.provider_message_id is not None:
            raise ValueError(
                "only accepted submissions may expose a provider message ID"
            )

    def as_json(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition.value,
            "provider_message_id": self.provider_message_id,
            "diagnostic_code": self.diagnostic_code,
            "diagnostic": self.diagnostic,
        }

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "AdapterResult":
        return cls(
            disposition=SubmissionDisposition(str(value["disposition"])),
            provider_message_id=_optional_string(value.get("provider_message_id")),
            diagnostic_code=_optional_string(value.get("diagnostic_code")),
            diagnostic=_optional_string(value.get("diagnostic")),
        )


@dataclass(frozen=True)
class FeedbackEvent:
    provider_event_id: str
    provider_message_id: str
    event_type: EventType
    recipient: str
    occurred_at: datetime
    edge_delivery_id: str | None = None
    smtp_status: str | None = None
    diagnostic: str | None = None

    def __post_init__(self) -> None:
        if not self.provider_event_id or not self.provider_message_id:
            raise ValueError("provider event and message IDs are required")
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")

    def as_json(self) -> dict[str, Any]:
        return {
            "provider_event_id": self.provider_event_id,
            "provider_message_id": self.provider_message_id,
            "edge_delivery_id": self.edge_delivery_id,
            "event_type": self.event_type.value,
            "recipient": self.recipient,
            "smtp_status": self.smtp_status,
            "diagnostic": self.diagnostic,
            "occurred_at": self.occurred_at.astimezone(timezone.utc).isoformat(),
        }

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "FeedbackEvent":
        return cls(
            provider_event_id=str(value["provider_event_id"]),
            provider_message_id=str(value["provider_message_id"]),
            edge_delivery_id=_optional_string(value.get("edge_delivery_id")),
            event_type=EventType(str(value["event_type"])),
            recipient=str(value["recipient"]),
            smtp_status=_optional_string(value.get("smtp_status")),
            diagnostic=_optional_string(value.get("diagnostic")),
            occurred_at=datetime.fromisoformat(str(value["occurred_at"])),
        )


class SubmissionAdapter(Protocol):
    name: str

    def submit(self, request: DeliveryRequest) -> AdapterResult:
        """Submit one neutral request without changing its contract."""

    def reconcile(self, edge_delivery_id: str) -> AdapterResult | None:
        """Return definitive knowledge for an ambiguous attempt, if available."""


def _optional_string(value: Any) -> str | None:
    return None if value is None else str(value)
