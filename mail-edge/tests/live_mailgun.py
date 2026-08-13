"""Opt-in, nondestructive Mailgun qualification harness.

This module performs only read-only discovery and a `o:testmode=yes` MIME
submission. Mailgun documents test mode as processing without recipient delivery.
"""

from __future__ import annotations

import os
import tempfile
import uuid
from datetime import UTC, datetime

from mail_edge.config import DomainRegistry, KeyRing, MailgunDomainConfig, SecretKey
from mail_edge.contracts import OutboundMessage, ProviderRegion, SubmissionDisposition
from mail_edge.ledger import DeliveryLedger
from mail_edge.mailgun.discovery import MailgunDiscoveryAdapter
from mail_edge.mailgun.outbound import MailgunOutboundAdapter
from mail_edge.transport import StdlibHTTPTransport


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def main() -> int:
    if os.environ.get("MAIL_EDGE_LIVE") != "1":
        raise SystemExit("refusing live access without MAIL_EDGE_LIVE=1")
    domain = required("MAILGUN_DOMAIN").rstrip(".").lower()
    region = ProviderRegion(required("MAILGUN_REGION").upper())
    api_key = required("MAILGUN_API_KEY")
    envelope_from = required("MAILGUN_ENVELOPE_FROM")
    envelope_to = required("MAILGUN_ENVELOPE_TO")
    config = MailgunDomainConfig(
        domain=domain,
        region=region,
        api_keys=KeyRing((SecretKey("live", api_key),)),
        # No webhook is exercised; this non-secret placeholder satisfies the
        # immutable domain contract without reusing API credentials.
        webhook_keys=KeyRing((SecretKey("unused", "unused-live-harness-key"),)),
        test_mode=True,
    )
    registry = DomainRegistry((config,))
    transport = StdlibHTTPTransport()
    capabilities = MailgunDiscoveryAdapter(registry, transport).discover(domain)
    if capabilities.domain != domain or capabilities.state != "active":
        raise SystemExit("configured Mailgun domain is not active")

    marker = uuid.uuid4().hex
    raw = (
        f"From: Mail edge qualification <{envelope_from}>\r\n"
        f"To: Qualification sink <{envelope_to}>\r\n"
        "Subject: nondestructive mail-edge qualification\r\n"
        f"Message-ID: <{marker}@{domain}>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Mailgun test mode: this message must not be delivered.\r\n"
    ).encode()
    with tempfile.TemporaryDirectory(prefix="mail-edge-live-") as directory:
        ledger = DeliveryLedger(f"{directory}/ledger.sqlite3")
        try:
            result = MailgunOutboundAdapter(registry, transport, ledger).submit(
                OutboundMessage(
                    edge_delivery_id=f"live-{marker}",
                    envelope_from=envelope_from,
                    envelope_recipients=(envelope_to,),
                    rfc822_bytes=raw,
                    created_at=datetime.now(UTC),
                )
            )
        finally:
            ledger.close()
    if result.disposition is not SubmissionDisposition.ACCEPTED:
        raise SystemExit(f"test-mode submission failed: {result.disposition.value}")
    print(
        f"Mailgun {region.value} domain active; test-mode MIME accepted; "
        f"tracking click={capabilities.click_tracking} open={capabilities.open_tracking}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
