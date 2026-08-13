"""Authenticated Mailgun feedback normalization and durable application."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from collections.abc import Callable
from datetime import UTC, datetime

from ..config import DomainRegistry
from ..contracts import FeedbackEvent, FeedbackEventType
from ..errors import ConfigurationError, MalformedPayload, SignatureRejected
from ..ledger import DeliveryLedger, FeedbackApplication
from ..observability import NullObserver, Observer, Redactor
from ..security import MailgunSignatureVerifier, SQLiteReplayStore
from ..validation import bounded_text, validate_delivery_id, validate_mailbox


class MailgunFeedbackAdapter:
    def __init__(
        self,
        registry: DomainRegistry,
        replay_store: SQLiteReplayStore,
        ledger: DeliveryLedger,
        *,
        max_payload_bytes: int = 1_000_000,
        observer: Observer | None = None,
        redactor: Redactor | None = None,
        signature_clock: Callable[[], float] = time.time,
    ) -> None:
        if observer is not None and redactor is None:
            raise ConfigurationError(
                "an explicit redactor is required when observability is enabled"
            )
        self._registry = registry
        self._replay = replay_store
        self._ledger = ledger
        self._max_payload = max_payload_bytes
        self._observer = observer or NullObserver()
        self._redactor = redactor or Redactor(b"mail-edge-default-redaction-salt")
        self._signature_clock = signature_clock

    def consume(
        self, payload_bytes: bytes, *, received_at: datetime | None = None
    ) -> FeedbackApplication:
        event, replay_namespace, replay_token = self._normalize_signed(payload_bytes)
        try:
            applied = self._ledger.apply_feedback(
                event, received_at=received_at or datetime.now(UTC)
            )
        except Exception:
            self._replay.release(replay_namespace, replay_token)
            raise
        self._observer.emit(
            "mailgun_feedback",
            {
                "provider_event_id": event.provider_event_id,
                "event_type": event.event_type.value,
                "recipient_hash": self._redactor.address(event.recipient),
                "correlated": applied.correlated,
                "duplicate": applied.duplicate,
                "diagnostic": self._redactor.diagnostic(event.diagnostic),
            },
        )
        return applied

    def normalize_signed(self, payload_bytes: bytes) -> FeedbackEvent:
        event, _, _ = self._normalize_signed(payload_bytes)
        return event

    def _normalize_signed(self, payload_bytes: bytes) -> tuple[FeedbackEvent, str, str]:
        if (
            not isinstance(payload_bytes, bytes)
            or len(payload_bytes) > self._max_payload
        ):
            raise MalformedPayload("feedback payload exceeds its boundary limit")
        try:
            payload = json.loads(payload_bytes)
            signature = payload["signature"]
            event_data = payload["event-data"]
            if not isinstance(signature, dict) or not isinstance(event_data, dict):
                raise TypeError
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise MalformedPayload("invalid Mailgun feedback payload") from exc

        domain = self._event_domain(event_data)
        config = self._registry.exact(domain)
        try:
            replay_namespace = f"mailgun:feedback:{config.domain}"
            replay_token = str(signature["token"])
            MailgunSignatureVerifier(
                config.webhook_keys, self._replay, clock=self._signature_clock
            ).verify(
                timestamp=str(signature["timestamp"]),
                token=replay_token,
                signature=str(signature["signature"]),
                parent_signature=(
                    str(signature["parent-signature"])
                    if signature.get("parent-signature")
                    else None
                ),
                namespace=replay_namespace,
            )
        except KeyError as exc:
            raise SignatureRejected("feedback signature fields are incomplete") from exc
        return self.normalize_event_data(event_data), replay_namespace, replay_token

    @staticmethod
    def _event_domain(event_data: Mapping[str, object]) -> str:
        domain = event_data.get("domain")
        if isinstance(domain, dict) and isinstance(domain.get("name"), str):
            return domain["name"].rstrip(".").lower()
        raise MalformedPayload("feedback omitted the Mailgun domain")

    @staticmethod
    def normalize_event_data(event_data: Mapping[str, object]) -> FeedbackEvent:
        try:
            event_name = str(event_data["event"]).lower()
            event_id = event_data["id"]
            timestamp = float(event_data["timestamp"])
            message = event_data["message"]
            headers = message["headers"]
            provider_message_id = headers["message-id"]
            recipient = event_data["recipient"]
            if not all(
                isinstance(value, str) and value
                for value in (event_id, provider_message_id, recipient)
            ):
                raise TypeError
            if len(event_id) > 256 or len(provider_message_id) > 998:
                raise ValueError
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise MalformedPayload("feedback event lacks correlation fields") from exc

        if recipient != "[REDACTED]":
            validate_mailbox(recipient, smtp_utf8=True)
        try:
            occurred_at = datetime.fromtimestamp(timestamp, tz=UTC)
        except (ValueError, OverflowError, OSError) as exc:
            raise MalformedPayload("feedback timestamp is invalid") from exc

        delivery_status = event_data.get("delivery-status")
        if not isinstance(delivery_status, dict):
            delivery_status = {}
        severity = str(event_data.get("severity", "")).lower()
        smtp_status = bounded_text(delivery_status.get("code"), maximum=32)
        diagnostic = bounded_text(
            delivery_status.get("message")
            or delivery_status.get("description")
            or event_data.get("reason"),
            maximum=512,
        )
        event_type = MailgunFeedbackAdapter._event_type(
            event_name, severity=severity, smtp_status=smtp_status
        )
        edge_id = MailgunFeedbackAdapter._edge_id(event_data.get("user-variables"))
        visible_message_id = provider_message_id
        scoped_event_id = (
            f"{MailgunFeedbackAdapter._event_domain(event_data)}:"
            f"{occurred_at:%Y%m%d}:{event_id}"
        )
        return FeedbackEvent(
            provider_event_id=scoped_event_id,
            provider_message_id=provider_message_id,
            edge_delivery_id=edge_id,
            event_type=event_type,
            recipient=recipient,
            smtp_status=smtp_status,
            diagnostic=diagnostic,
            occurred_at=occurred_at,
            visible_message_id=visible_message_id,
        )

    @staticmethod
    def _event_type(
        name: str, *, severity: str, smtp_status: str | None
    ) -> FeedbackEventType:
        if name == "accepted":
            return FeedbackEventType.ACCEPTED
        if name == "delivered":
            return FeedbackEventType.DELIVERED
        if name in {"delayed", "temporary_fail"}:
            return FeedbackEventType.DELAYED
        if name in {"complained", "complaint"}:
            return FeedbackEventType.COMPLAINT
        if name == "rejected":
            return FeedbackEventType.REJECTED
        if name in {"failed", "permanent_fail"}:
            if severity == "temporary":
                return FeedbackEventType.DELAYED
            if smtp_status and smtp_status.startswith("4"):
                return FeedbackEventType.SOFT_BOUNCE
            return FeedbackEventType.HARD_BOUNCE
        raise MalformedPayload("unsupported Mailgun feedback event")

    @staticmethod
    def _edge_id(value: object) -> str | None:
        if not isinstance(value, dict):
            return None
        edge_id = value.get("edge_delivery_id")
        if edge_id is None:
            return None
        if not isinstance(edge_id, str):
            raise MalformedPayload("edge correlation variable is invalid")
        validate_delivery_id(edge_id)
        return edge_id
