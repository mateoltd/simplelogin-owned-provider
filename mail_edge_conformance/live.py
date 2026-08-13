"""Opt-in, nondestructive live qualification utilities."""

from __future__ import annotations

import imaplib
import os
import time
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses

from .contracts import EventType
from .corpus import CorpusCase
from .evidence import QualificationResult
from .mime import TransportHeaderPolicy
from .providers.mailgun import MailgunAdapter
from .qualification import qualify_corpus, qualify_size_boundary


@dataclass(frozen=True)
class MailgunLiveConfiguration:
    api_key: str
    sending_domain: str
    recipient: str
    isolated_domains: tuple[str, ...]
    imap_host: str
    imap_port: int
    imap_user: str
    imap_password: str
    imap_folder: str
    api_base: str
    size_limit_bytes: int
    allowed_transport_headers: tuple[str, ...]

    @classmethod
    def from_environment(cls) -> "MailgunLiveConfiguration":
        required = (
            "MAIL_EDGE_LIVE_MAILGUN_API_KEY",
            "MAIL_EDGE_LIVE_SENDING_DOMAIN",
            "MAIL_EDGE_LIVE_RECIPIENT",
            "MAIL_EDGE_LIVE_ISOLATED_DOMAINS",
            "MAIL_EDGE_LIVE_IMAP_HOST",
            "MAIL_EDGE_LIVE_IMAP_USER",
            "MAIL_EDGE_LIVE_IMAP_PASSWORD",
            "MAIL_EDGE_LIVE_SIZE_LIMIT_BYTES",
        )
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise ValueError("missing explicit live settings: " + ", ".join(missing))
        if os.environ.get("MAIL_EDGE_LIVE_CONFIRM") != "isolated-staging-only":
            raise ValueError(
                "set MAIL_EDGE_LIVE_CONFIRM=isolated-staging-only after verifying both domains"
            )
        isolated = tuple(
            sorted(
                {
                    item.strip().lower()
                    for item in os.environ["MAIL_EDGE_LIVE_ISOLATED_DOMAINS"].split(",")
                    if item.strip()
                }
            )
        )
        sending_domain = os.environ["MAIL_EDGE_LIVE_SENDING_DOMAIN"].lower()
        recipient = os.environ["MAIL_EDGE_LIVE_RECIPIENT"]
        recipient_domain = recipient.rsplit("@", 1)[-1].lower()
        if sending_domain not in isolated or recipient_domain not in isolated:
            raise ValueError(
                "sending and recipient domains must both be named in "
                "MAIL_EDGE_LIVE_ISOLATED_DOMAINS"
            )
        if any(
            domain.endswith((".example", ".test", ".invalid", ".localhost"))
            or domain in {"example.com", "example.net", "example.org"}
            for domain in isolated
        ):
            raise ValueError("reserved example domains cannot be live staging domains")
        size_limit = int(os.environ["MAIL_EDGE_LIVE_SIZE_LIMIT_BYTES"])
        if size_limit < 1024:
            raise ValueError("live size boundary must be at least 1024 bytes")
        allowed = tuple(
            item.strip().lower()
            for item in os.environ.get(
                "MAIL_EDGE_LIVE_ALLOWED_TRANSPORT_HEADERS", ""
            ).split(",")
            if item.strip()
        )
        return cls(
            api_key=os.environ["MAIL_EDGE_LIVE_MAILGUN_API_KEY"],
            sending_domain=sending_domain,
            recipient=recipient,
            isolated_domains=isolated,
            imap_host=os.environ["MAIL_EDGE_LIVE_IMAP_HOST"],
            imap_port=int(os.environ.get("MAIL_EDGE_LIVE_IMAP_PORT", "993")),
            imap_user=os.environ["MAIL_EDGE_LIVE_IMAP_USER"],
            imap_password=os.environ["MAIL_EDGE_LIVE_IMAP_PASSWORD"],
            imap_folder=os.environ.get("MAIL_EDGE_LIVE_IMAP_FOLDER", "INBOX"),
            api_base=os.environ.get(
                "MAIL_EDGE_LIVE_MAILGUN_API_BASE", "https://api.mailgun.net"
            ),
            size_limit_bytes=size_limit,
            allowed_transport_headers=allowed,
        )


class ImapQualificationMailbox:
    def __init__(
        self,
        config: MailgunLiveConfiguration,
        *,
        timeout: float = 180.0,
    ) -> None:
        self.config = config
        self.timeout = timeout

    def get(self, edge_delivery_id: str, provider_message_id: str) -> bytes:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            with imaplib.IMAP4_SSL(
                self.config.imap_host, self.config.imap_port
            ) as client:
                client.login(self.config.imap_user, self.config.imap_password)
                status, _ = client.select(self.config.imap_folder, readonly=True)
                if status != "OK":
                    raise RuntimeError("cannot select the qualification IMAP folder")
                status, data = client.search(
                    None, "HEADER", "X-Mail-Edge-Test-ID", edge_delivery_id
                )
                if status == "OK" and data and data[0]:
                    message_number = data[0].split()[-1]
                    status, fetched = client.fetch(message_number, "(BODY.PEEK[])")
                    if status == "OK":
                        for item in fetched:
                            if isinstance(item, tuple) and isinstance(item[1], bytes):
                                return item[1]
            time.sleep(2)
        raise TimeoutError(f"staging mailbox did not receive {edge_delivery_id}")


def run_live_mailgun(
    config: MailgunLiveConfiguration,
) -> tuple[QualificationResult, ...]:
    adapter = MailgunAdapter(
        domain=config.sending_domain,
        api_key=config.api_key,
        api_base=config.api_base,
    )
    mailbox = ImapQualificationMailbox(config)
    transport_policy = TransportHeaderPolicy.with_additional(
        config.allowed_transport_headers
    )

    def render(case: CorpusCase, edge_id: str) -> bytes:
        sending = config.sending_domain.encode("idna")
        recipient_domain = config.recipient.rsplit("@", 1)[-1].encode("idna")
        encoded = case.rfc822_bytes.replace(b"sender.test", sending).replace(
            b"receiver.test", recipient_domain
        )
        separator = b"\r\n\r\n" if b"\r\n\r\n" in encoded else b"\n\n"
        line_ending = b"\r\n" if separator.startswith(b"\r") else b"\n"
        head, body = encoded.split(separator, 1)
        return (
            head
            + line_ending
            + b"X-Mail-Edge-Test-ID: "
            + edge_id.encode("ascii")
            + separator
            + body
        )

    def envelope(case: CorpusCase, encoded: bytes):
        message = BytesParser(policy=policy.default).parsebytes(encoded)
        addresses = [
            address
            for _, address in getaddresses(message.get_all("From", ()))
            if address
        ]
        if len(addresses) != 1:
            raise ValueError(
                f"{case.case_id} must expose exactly one live envelope sender"
            )
        from_address = addresses[0]
        return from_address, (config.recipient,)

    corpus_results = qualify_corpus(
        adapter,
        mailbox,
        transport_policy=transport_policy,
        message_renderer=render,
        envelope_resolver=envelope,
    )
    size_results = qualify_size_boundary(
        adapter,
        mailbox,
        limit=config.size_limit_bytes,
        transport_policy=transport_policy,
        sender="qualification@" + config.sending_domain,
        recipient=config.recipient,
    )
    accepted_corpus = next(
        (
            result
            for result in corpus_results
            if result.result_id.startswith("corpus:") and result.status == "passed"
        ),
        None,
    )
    event_result: QualificationResult
    try:
        if accepted_corpus is None:
            raise AssertionError("no live corpus message was accepted")
        edge_id = "corpus-" + accepted_corpus.result_id.split(":", 1)[1]
        provider_id = adapter.accepted_provider_id(edge_id)
        if provider_id is None:
            raise AssertionError("accepted corpus message lost its provider ID mapping")
        event = adapter.wait_for_event(
            provider_message_id=provider_id,
            edge_delivery_id=edge_id,
            event_type=EventType.DELIVERED,
            timeout=180,
        )
        event_result = QualificationResult(
            "live:event-correlation",
            "feedback",
            "passed",
            "executed",
            {
                "event_type": event.event_type.value,
                "edge_delivery_id_matched": True,
                "provider_message_id_matched": event.provider_message_id == provider_id,
            },
        )
    except Exception as error:
        event_result = QualificationResult(
            "live:event-correlation",
            "feedback",
            "failed",
            "executed",
            {"error": f"{type(error).__name__}: {error}"},
        )
    boundary_passed = all(item.status == "passed" for item in size_results)
    return (
        QualificationResult(
            "live:credentials-explicit",
            "live-safety",
            "passed",
            "executed",
            {"credential_sources": ["environment", "imap-environment"]},
        ),
        QualificationResult(
            "live:isolated-staging-domains",
            "live-safety",
            "passed",
            "executed",
            {"domains": list(config.isolated_domains)},
        ),
        *corpus_results,
        *size_results,
        QualificationResult(
            "live:delivery-correlation",
            "envelope-correlation",
            "passed" if accepted_corpus is not None else "failed",
            "executed",
            {"observed_corpus_delivery": accepted_corpus is not None},
        ),
        event_result,
        QualificationResult(
            "live:size-boundary",
            "size-boundary",
            "passed" if boundary_passed else "failed",
            "executed",
            {
                "declared_test_limit_bytes": config.size_limit_bytes,
                "all_three_observations_passed": boundary_passed,
            },
        ),
    )
