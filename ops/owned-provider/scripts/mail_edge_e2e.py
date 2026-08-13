"""Exercise SimpleLogin through the deterministic edge, mailbox, and reverse alias."""

from __future__ import annotations

import base64
import json
import os
import smtplib
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path

from e2e import (
    ADMIN_EMAIL,
    CUSTOM_DOMAIN,
    SMTP_HOST,
    SMTP_PORT,
    authenticate,
    http_request,
)
from mail_edge_conformance.corpus import load_corpus
from mail_edge_conformance.evidence import CapabilityEvidence, QualificationResult
from mail_edge_conformance.mime import TransportHeaderPolicy, compare_messages
from mail_edge_conformance.providers.mailgun import MailgunAdapter


MAILPIT_URL = os.environ["OWNED_PROVIDER_MAILPIT_URL"].rstrip("/")
FIXTURE_URL = os.environ["OWNED_PROVIDER_MAIL_EDGE_FIXTURE_URL"].rstrip("/")
EVIDENCE_OUTPUT = Path(os.environ["MAIL_EDGE_EVIDENCE_OUTPUT"])
SOURCE_REVISION = os.environ["MAIL_EDGE_SOURCE_REVISION"]
ADAPTER_NAME = os.environ.get("MAIL_EDGE_ADAPTER_NAME", "mailgun")
ADAPTER_VERSION = os.environ.get(
    "MAIL_EDGE_ADAPTER_VERSION", MailgunAdapter.adapter_version
)
MAILPIT_TRANSPORT_POLICY = TransportHeaderPolicy.with_additional(("bcc",))


def _request_json(url: str) -> dict[str, object]:
    with urllib.request.urlopen(url, timeout=10) as response:
        encoded = response.read(40 * 1024 * 1024 + 1)
    if len(encoded) > 40 * 1024 * 1024:
        raise AssertionError("local qualification response exceeded 40 MiB")
    return json.loads(encoded)


def _messages() -> list[dict[str, object]]:
    return list(_request_json(MAILPIT_URL + "/api/v1/messages?limit=500")["messages"])


def _raw_message(message_id: object) -> bytes:
    encoded_id = urllib.parse.quote(str(message_id), safe="")
    with urllib.request.urlopen(
        MAILPIT_URL + f"/api/v1/message/{encoded_id}/raw", timeout=10
    ) as response:
        return response.read(40 * 1024 * 1024 + 1)


def _wait_raw(
    subject: str, *, body_marker: str | None = None, timeout: float = 60
) -> bytes:
    deadline = time.monotonic() + timeout
    observed: list[dict[str, object]] = []
    while time.monotonic() < deadline:
        observed = _messages()
        for message in observed:
            if message.get("Subject") != subject:
                continue
            encoded = _raw_message(message["ID"])
            if body_marker is None or body_marker.encode("utf-8") in encoded:
                return encoded
        time.sleep(0.5)
    summaries = [
        {
            "ID": item.get("ID"),
            "Subject": item.get("Subject"),
            "To": item.get("To"),
        }
        for item in observed[-10:]
    ]
    raise AssertionError(
        f"mailbox did not receive subject {subject!r}, body {body_marker!r}; "
        f"observed={summaries!r}"
    )


def _edge_submission(test_id: str, subject: str, recipient: str) -> bytes:
    payload = _request_json(
        FIXTURE_URL
        + "/v1/deliveries?"
        + urllib.parse.urlencode({"test_id": test_id, "subject": subject})
    )
    delivery = payload["delivery"]
    recipients = tuple(
        str(value).casefold() for value in delivery["envelope_recipients"]
    )
    if recipients != (recipient.casefold(),):
        raise AssertionError(
            f"edge envelope recipients {recipients!r} did not match {recipient!r}"
        )
    return base64.b64decode(delivery["rfc822_base64"], validate=True)


def _send_raw(sender: str, recipient: str, encoded: bytes) -> None:
    options = (
        ["SMTPUTF8"]
        if any(byte >= 128 for byte in encoded.split(b"\n\n", 1)[0])
        else []
    )
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
        smtp.sendmail(sender, [recipient], encoded, mail_options=options)


def _annotate(encoded: bytes, test_id: str) -> bytes:
    separator = b"\r\n\r\n" if b"\r\n\r\n" in encoded else b"\n\n"
    line_ending = b"\r\n" if separator.startswith(b"\r") else b"\n"
    head, body = encoded.split(separator, 1)
    return (
        head
        + line_ending
        + b"X-Mail-Edge-Test-ID: "
        + test_id.encode("ascii")
        + separator
        + body
    )


def _thread_message(
    *,
    sender: str,
    recipient: str,
    subject: str,
    message_id: str,
    test_id: str,
    body: str,
    predecessor: str | None = None,
    references: tuple[str, ...] = (),
) -> bytes:
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message["Date"] = "Thu, 13 Aug 2026 14:00:00 +0000"
    message["Message-ID"] = message_id
    message["X-Mail-Edge-Test-ID"] = test_id
    if predecessor:
        message["In-Reply-To"] = predecessor
    if references:
        message["References"] = " ".join(references)
    message.set_content(body)
    return message.as_bytes()


def _message_id(encoded: bytes) -> str:
    message = BytesParser(policy=policy.default).parsebytes(encoded)
    value = message.get("Message-ID")
    if not value:
        raise AssertionError("delivered thread message has no Message-ID")
    return str(value)


def _reverse_alias_identity(encoded: bytes) -> str:
    message = BytesParser(policy=policy.default).parsebytes(encoded)
    source = message.get_all("Reply-To", []) or message.get_all("From", [])
    addresses = getaddresses(source)
    if len(addresses) != 1 or not addresses[0][1]:
        raise AssertionError("forwarded message did not expose one reply identity")
    return addresses[0][1]


def main() -> None:
    started = datetime.now(timezone.utc)
    nonce = str(time.time_ns())
    api_key = authenticate()
    alias_id: int | None = None
    comparisons = 0
    try:
        _, mailboxes = http_request("GET", "/api/v2/mailboxes", api_key=api_key)
        default_mailbox = next(
            item for item in mailboxes["mailboxes"] if item["default"]
        )
        _, options = http_request("GET", "/api/v5/alias/options", api_key=api_key)
        domain_option = next(
            item
            for item in options["suffixes"]
            if item["suffix"] == f"@{CUSTOM_DOMAIN}"
        )
        prefix = f"mail-edge-{nonce}"
        _, alias = http_request(
            "POST",
            "/api/v3/alias/custom/new?hostname=qualification.invalid",
            {
                "alias_prefix": prefix,
                "signed_suffix": domain_option["signed_suffix"],
                "mailbox_ids": [default_mailbox["id"]],
                "name": "Mail edge qualification",
                "note": "contained local conformance fixture",
            },
            api_key,
            expected=(201,),
        )
        alias_id = alias["id"]
        contact_address = f"contact-{nonce}@example.com"
        _, contact = http_request(
            "POST",
            f"/api/aliases/{alias_id}/contacts",
            {"contact": contact_address},
            api_key,
            expected=(201,),
        )
        reverse_alias = contact["reverse_alias_address"]

        rich_case = next(
            case
            for case in load_corpus()
            if case.case_id == "nested-alternative-related"
        )
        rich_subject = f"Mail edge rich MIME {nonce}"
        rich_test_id = f"e2e-rich-{nonce}"
        rich = rich_case.rfc822_bytes.replace(
            b"mira@sender.test", contact_address.encode("ascii")
        ).replace(b"rowan@receiver.test", alias["alias"].encode("ascii"))
        rich = rich.replace(
            b"Nested alternative and related fixture", rich_subject.encode("ascii")
        )
        rich = _annotate(rich, rich_test_id)
        _send_raw(contact_address, alias["alias"], rich)
        rich_delivered = _wait_raw(rich_subject)
        compare_messages(
            _edge_submission(rich_test_id, rich_subject, ADMIN_EMAIL),
            rich_delivered,
            MAILPIT_TRANSPORT_POLICY,
        ).require_equivalent()
        comparisons += 1

        thread_subject = f"Re: Mail edge thread {nonce}"
        references: list[str] = []
        first_id = f"<contact-1-{nonce}@sender.invalid>"
        first_test = f"e2e-thread-1-{nonce}"
        first = _thread_message(
            sender=contact_address,
            recipient=alias["alias"],
            subject=thread_subject,
            message_id=first_id,
            test_id=first_test,
            body="contact to alias, first message",
        )
        _send_raw(contact_address, alias["alias"], first)
        first_delivered = _wait_raw(
            thread_subject, body_marker="contact to alias, first message"
        )
        observed_reverse_alias = _reverse_alias_identity(first_delivered)
        if observed_reverse_alias.casefold() != reverse_alias.casefold():
            raise AssertionError("SimpleLogin changed the authorized reverse alias")
        compare_messages(
            _edge_submission(first_test, thread_subject, ADMIN_EMAIL),
            first_delivered,
            MAILPIT_TRANSPORT_POLICY,
        ).require_equivalent()
        comparisons += 1
        references.append(_message_id(first_delivered))

        second_test = f"e2e-thread-2-{nonce}"
        second = _thread_message(
            sender=ADMIN_EMAIL,
            recipient=reverse_alias,
            subject=thread_subject,
            message_id=f"<mailbox-1-{nonce}@receiver.invalid>",
            test_id=second_test,
            body="mailbox to reverse alias, first reply",
            predecessor=references[-1],
            references=tuple(references),
        )
        _send_raw(ADMIN_EMAIL, reverse_alias, second)
        second_delivered = _wait_raw(
            thread_subject, body_marker="mailbox to reverse alias, first reply"
        )
        compare_messages(
            _edge_submission(second_test, thread_subject, contact_address),
            second_delivered,
            MAILPIT_TRANSPORT_POLICY,
        ).require_equivalent()
        comparisons += 1
        references.append(_message_id(second_delivered))

        third_test = f"e2e-thread-3-{nonce}"
        third = _thread_message(
            sender=contact_address,
            recipient=alias["alias"],
            subject=thread_subject,
            message_id=f"<contact-2-{nonce}@sender.invalid>",
            test_id=third_test,
            body="contact to alias, second reply",
            predecessor=references[-1],
            references=tuple(references),
        )
        _send_raw(contact_address, alias["alias"], third)
        third_delivered = _wait_raw(
            thread_subject, body_marker="contact to alias, second reply"
        )
        compare_messages(
            _edge_submission(third_test, thread_subject, ADMIN_EMAIL),
            third_delivered,
            MAILPIT_TRANSPORT_POLICY,
        ).require_equivalent()
        comparisons += 1
        references.append(_message_id(third_delivered))

        fourth_test = f"e2e-thread-4-{nonce}"
        fourth = _thread_message(
            sender=ADMIN_EMAIL,
            recipient=reverse_alias,
            subject=thread_subject,
            message_id=f"<mailbox-2-{nonce}@receiver.invalid>",
            test_id=fourth_test,
            body="mailbox to reverse alias, second reply",
            predecessor=references[-1],
            references=tuple(references),
        )
        _send_raw(ADMIN_EMAIL, reverse_alias, fourth)
        fourth_delivered = _wait_raw(
            thread_subject, body_marker="mailbox to reverse alias, second reply"
        )
        compare_messages(
            _edge_submission(fourth_test, thread_subject, contact_address),
            fourth_delivered,
            MAILPIT_TRANSPORT_POLICY,
        ).require_equivalent()
        comparisons += 1
        references.append(_message_id(fourth_delivered))

        results = (
            QualificationResult(
                "e2e:simplelogin-edge-mailbox",
                "end-to-end",
                "passed",
                "executed",
                {
                    "flow": ["simplelogin", "edge", "provider-fixture", "mailbox"],
                    "rich_mime_delivered": True,
                    "mailbox_transport_headers": ["bcc"],
                },
            ),
            QualificationResult(
                "e2e:reverse-alias-thread",
                "threading",
                "passed",
                "executed",
                {
                    "messages": 4,
                    "references_retained": len(references),
                    "reverse_alias_matched": True,
                },
            ),
            QualificationResult(
                "e2e:semantic-fidelity",
                "mime-fidelity",
                "passed",
                "executed",
                {"edge_to_mailbox_comparisons": comparisons},
            ),
        )
        evidence = CapabilityEvidence(
            adapter=ADAPTER_NAME,
            adapter_version=ADAPTER_VERSION,
            mode="local-e2e",
            source_revision=SOURCE_REVISION,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            results=results,
        )
        evidence.write(EVIDENCE_OUTPUT)
        print(json.dumps(evidence.as_json(), sort_keys=True))
    finally:
        if alias_id is not None:
            http_request("DELETE", f"/api/aliases/{alias_id}", api_key=api_key)


if __name__ == "__main__":
    main()
