from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime

import pytest

from mail_edge.config import DomainRegistry, KeyRing, MailgunDomainConfig, SecretKey
from mail_edge.contracts import OutboundMessage, ProviderRegion
from mail_edge.ledger import DeliveryLedger
from mail_edge.security import SQLiteReplayStore

NOW = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
NOW_EPOCH = int(NOW.timestamp())
DOMAIN = "edge.example.test"
API_KEY = "api-current-secret"
OLD_API_KEY = "api-old-secret"
WEBHOOK_KEY = "webhook-current-secret"
OLD_WEBHOOK_KEY = "webhook-old-secret"


def keyring(*pairs: tuple[str, str]) -> KeyRing:
    return KeyRing(tuple(SecretKey(key_id, secret) for key_id, secret in pairs))


def domain_config(
    *,
    domain: str = DOMAIN,
    region: ProviderRegion = ProviderRegion.US,
    api_keys: KeyRing | None = None,
    webhook_keys: KeyRing | None = None,
    **kwargs,
) -> MailgunDomainConfig:
    return MailgunDomainConfig(
        domain=domain,
        region=region,
        api_keys=api_keys or keyring(("current", API_KEY)),
        webhook_keys=webhook_keys or keyring(("current", WEBHOOK_KEY)),
        **kwargs,
    )


@pytest.fixture
def registry() -> DomainRegistry:
    return DomainRegistry((domain_config(),))


@pytest.fixture
def ledger(tmp_path) -> DeliveryLedger:
    value = DeliveryLedger(tmp_path / "deliveries.sqlite3")
    yield value
    value.close()


@pytest.fixture
def replay_store(tmp_path) -> SQLiteReplayStore:
    value = SQLiteReplayStore(tmp_path / "replay.sqlite3")
    yield value
    value.close()


def raw_message(
    *,
    message_id: str = "<submitted-1@edge.example.test>",
    sender: str = "Alias <alias@edge.example.test>",
    recipient: str = "Contact <contact@recipient.example>",
    body: bytes = b"hello\r\n",
    extra_headers: bytes = b"",
) -> bytes:
    return (
        (
            f"From: {sender}\r\n"
            f"To: {recipient}\r\n"
            "Subject: adapter conformance\r\n"
            f"Message-ID: {message_id}\r\n"
        ).encode()
        + extra_headers
        + b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        + body
    )


def outbound(
    *,
    edge_id: str = "edge-delivery-1",
    envelope_from: str = "bounce+opaque@edge.example.test",
    recipient: str = "contact@recipient.example",
    raw: bytes | None = None,
    **kwargs,
) -> OutboundMessage:
    return OutboundMessage(
        edge_delivery_id=edge_id,
        envelope_from=envelope_from,
        envelope_recipients=(recipient,),
        rfc822_bytes=raw or raw_message(),
        created_at=NOW,
        **kwargs,
    )


def signature_fields(
    *,
    key: str = WEBHOOK_KEY,
    token: str = "t" * 50,
    timestamp: int = NOW_EPOCH,
) -> dict[str, str]:
    signature = hmac.new(
        key.encode(), f"{timestamp}{token}".encode(), hashlib.sha256
    ).hexdigest()
    return {"timestamp": str(timestamp), "token": token, "signature": signature}


def webhook_payload(
    event_data: dict[str, object],
    *,
    key: str = WEBHOOK_KEY,
    token: str = "w" * 50,
    timestamp: int = NOW_EPOCH,
) -> bytes:
    return json.dumps(
        {
            "signature": signature_fields(key=key, token=token, timestamp=timestamp),
            "event-data": event_data,
        }
    ).encode()


def event_data(
    *,
    event: str = "accepted",
    event_id: str = "provider-event-1",
    message_id: str = "<submitted-1@edge.example.test>",
    recipient: str = "contact@recipient.example",
    timestamp: float = NOW_EPOCH,
    severity: str | None = None,
    smtp_status: str | None = None,
    diagnostic: str | None = None,
    edge_id: str | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "domain": {"name": DOMAIN},
        "event": event,
        "id": event_id,
        "timestamp": timestamp,
        "message": {"headers": {"message-id": message_id}},
        "recipient": recipient,
        "user-variables": ({"edge_delivery_id": edge_id} if edge_id else {}),
    }
    if severity is not None:
        value["severity"] = severity
    if smtp_status is not None or diagnostic is not None:
        value["delivery-status"] = {"code": smtp_status, "message": diagnostic}
    return value
