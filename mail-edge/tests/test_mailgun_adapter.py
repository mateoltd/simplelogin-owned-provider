from __future__ import annotations

import hashlib
import hmac
import json
import smtplib
from datetime import UTC, datetime
from urllib.parse import quote_from_bytes

import pytest

from mail_edge.adapters.mailgun import (
    MailgunAdapter,
    MailgunCredentials,
    parse_urlencoded_bytes,
    verify_mailgun_signature,
)
from mail_edge.contracts import (
    Envelope,
    FeedbackKind,
    OutboundSubmission,
    SubmissionOutcome,
)
from mail_edge.errors import ContractError
from mail_edge.ids import uuid7_str


def _adapter():
    return MailgunAdapter(
        credentials=MailgunCredentials("smtp-user", "smtp-password", "webhook-key"),
        smtp_host="smtp.mailgun.test",
        diagnostic_salt=b"test-salt-for-mailgun-adapter",
    )


def _signed_form(values: dict[str, bytes], timestamp: int, token: str) -> bytes:
    values = dict(values)
    values["timestamp"] = str(timestamp).encode()
    values["token"] = token.encode()
    values["signature"] = (
        hmac.new(b"webhook-key", f"{timestamp}{token}".encode(), hashlib.sha256)
        .hexdigest()
        .encode()
    )
    return b"&".join(
        quote_from_bytes(key.encode()).encode()
        + b"="
        + quote_from_bytes(value).encode()
        for key, value in values.items()
    )


def test_raw_mime_form_parser_preserves_arbitrary_percent_encoded_bytes():
    raw = bytes(range(256))
    parsed = parse_urlencoded_bytes(
        b"body-mime=" + quote_from_bytes(raw).encode() + b"&token=abc"
    )
    assert parsed["body-mime"] == [raw]


def test_inbound_normalization_preserves_mime_envelope_and_stable_ids():
    now = datetime.now(UTC)
    raw = (
        b"Message-ID: <original@outside.example>\r\n"
        b"From: Sender <sender@outside.example>\r\n"
        b"Content-Type: application/octet-stream\r\n\r\n\x00\xff\r\n"
    )
    form = _signed_form(
        {
            "sender": b"bounce@outside.example",
            "recipient": b"alias@aliases.example",
            "message-headers": json.dumps(
                [["Message-ID", "<original@outside.example>"]]
            ).encode(),
            "body-mime": raw,
        },
        int(now.timestamp()),
        "t" * 50,
    )
    first = _adapter().normalize_inbound(
        form, domain="aliases.example", binding_generation=3, now=now
    )
    second = _adapter().normalize_inbound(
        form, domain="aliases.example", binding_generation=3, now=now
    )
    notice, message, token = first
    assert notice.notice_id == second[0].notice_id
    assert message.message_id == second[1].message_id
    assert message.raw_mime == raw
    assert notice.envelope.sender == "bounce@outside.example"
    assert notice.envelope.recipients == ("alias@aliases.example",)
    assert notice.provider_message_id == "<original@outside.example>"
    assert token == "t" * 50


def test_inbound_normalization_rejects_wrong_domain_and_bad_signature():
    now = datetime.now(UTC)
    form = _signed_form(
        {
            "sender": b"sender@outside.example",
            "recipient": b"alias@other.example",
            "message-headers": b"[]",
            "body-mime": b"From: sender@outside.example\r\n\r\nbody",
        },
        int(now.timestamp()),
        "u" * 50,
    )
    with pytest.raises(ContractError, match="exact inbound domain"):
        _adapter().normalize_inbound(
            form, domain="aliases.example", binding_generation=1, now=now
        )
    with pytest.raises(ContractError, match="invalid webhook signature"):
        verify_mailgun_signature(
            timestamp=str(int(now.timestamp())),
            token="token",
            signature="bad",
            signing_key="webhook-key",
            now=now,
        )


def test_feedback_normalization_is_neutral_and_correlation_safe():
    now = datetime.now(UTC)
    token = "v" * 50
    timestamp = str(int(now.timestamp()))
    signature = hmac.new(
        b"webhook-key", f"{timestamp}{token}".encode(), hashlib.sha256
    ).hexdigest()
    submission_id = uuid7_str()
    payload = json.dumps(
        {
            "signature": {
                "timestamp": timestamp,
                "token": token,
                "signature": signature,
            },
            "event-data": {
                "id": "provider-event",
                "event": "failed",
                "severity": "temporary",
                "timestamp": now.timestamp(),
                "domain": {"name": "aliases.example"},
                "recipient": "private@recipient.example",
                "user-variables": {"mail_edge_submission_id": submission_id},
                "delivery-status": {"code": 451},
            },
        }
    ).encode()
    feedback, replay = _adapter().normalize_feedback(
        payload, expected_domain="aliases.example", now=now
    )
    assert feedback.kind is FeedbackKind.FAILED_TEMPORARY
    assert feedback.submission_id == submission_id
    assert (
        feedback.recipient_hash
        != hashlib.sha256(b"private@recipient.example").hexdigest()
    )
    assert replay == token


def _submission():
    identifier = uuid7_str()
    return OutboundSubmission(
        submission_id=identifier,
        domain="aliases.example",
        binding_generation=1,
        envelope=Envelope("bounce@aliases.example", ("recipient@outside.example",)),
        raw_mime=(
            f"X-Mail-Edge-Submission-ID: {identifier}\r\n"
            "From: alias@aliases.example\r\n\r\nbody\r\n"
        ).encode(),
    )


def test_provider_control_headers_are_adapter_local_and_suppressed():
    submission = _submission()
    wire = MailgunAdapter._wire_message(submission)
    assert wire.endswith(submission.raw_mime)
    assert b"X-Mailgun-Suppress-Headers: all\r\n" in wire
    assert submission.submission_id.encode() in wire
    assert b"X-Mailgun" not in submission.raw_mime


class _SMTP:
    def __init__(
        self, failure=None, data_result=(250, b"Queued id=provider123"), **kwargs
    ):
        self.failure = failure
        self.data_result = data_result
        self.wire = None

    def connect(self, host, port):
        if self.failure == "connect":
            raise OSError("offline")
        return 220, b"ready"

    def ehlo(self):
        return 250, b"ok"

    def starttls(self, context):
        return 220, b"tls"

    def login(self, username, password):
        if self.failure == "auth":
            raise smtplib.SMTPAuthenticationError(535, b"bad")

    def mail(self, sender):
        return 250, b"ok"

    def rcpt(self, recipient):
        return 250, b"ok"

    def data(self, wire):
        self.wire = wire
        if self.failure == "post-data":
            raise smtplib.SMTPServerDisconnected("lost acknowledgement")
        return self.data_result

    def close(self):
        return None


@pytest.mark.parametrize("failure", ["connect", "auth"])
def test_mailgun_failure_before_data_is_safe_to_retry(monkeypatch, failure):
    monkeypatch.setattr(
        "mail_edge.adapters.mailgun.smtplib.SMTP",
        lambda **kwargs: _SMTP(failure=failure),
    )
    result = _adapter().submit(_submission())
    assert result.outcome is SubmissionOutcome.TEMPORARY_FAILURE


def test_mailgun_disconnect_after_data_is_unknown(monkeypatch):
    monkeypatch.setattr(
        "mail_edge.adapters.mailgun.smtplib.SMTP",
        lambda **kwargs: _SMTP(failure="post-data"),
    )
    result = _adapter().submit(_submission())
    assert result.outcome is SubmissionOutcome.UNKNOWN
    assert result.retry_after_seconds is None


@pytest.mark.parametrize(
    ("data_result", "outcome"),
    [
        ((250, b"Queued id=provider123"), SubmissionOutcome.ACCEPTED),
        ((451, b"try later"), SubmissionOutcome.TEMPORARY_FAILURE),
        ((550, b"rejected"), SubmissionOutcome.REJECTED),
    ],
)
def test_mailgun_post_data_responses_are_classified(monkeypatch, data_result, outcome):
    monkeypatch.setattr(
        "mail_edge.adapters.mailgun.smtplib.SMTP",
        lambda **kwargs: _SMTP(data_result=data_result),
    )
    assert _adapter().submit(_submission()).outcome is outcome
