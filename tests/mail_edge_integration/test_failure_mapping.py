import hashlib
from email.message import EmailMessage

import pytest
from aiosmtpd.smtp import Envelope

import email_handler
from app.email import status
from app.mail_edge.errors import MailEdgeContractError, MailEdgeUnavailableError
from app.models import Alias
from tests.utils import create_new_user


def test_mail_edge_submission_identity_survives_retry_serialization():
    envelope = Envelope()
    envelope.original_content = b"From: sender@example.net\r\n\r\nbody"
    message = EmailMessage()
    message.set_content("body")
    first = email_handler.mail_edge_idempotency_subject(envelope, message, None)
    message["Date"] = "Thu, 13 Aug 2026 12:00:00 +0000"
    assert email_handler.mail_edge_idempotency_subject(envelope, message, None) == first

    message["Message-ID"] = "<stable@example.net>"
    subject = email_handler.mail_edge_idempotency_subject(
        envelope, message, message["Message-ID"]
    )
    assert subject == (
        "message-id-sha256:"
        + hashlib.sha256(b"<stable@example.net>").hexdigest()
        + ":raw-sha256:"
        + hashlib.sha256(envelope.original_content).hexdigest()
    )

    envelope.mail_edge_delivery_id = "01890f31-7b4a-7cc8-8d32-2f6e9a401119"
    assert email_handler.mail_edge_idempotency_subject(
        envelope, message, message["Message-ID"]
    ).startswith("delivery:")


def test_application_delivery_requires_every_active_handoff():
    partial = [(True, status.E200), (False, status.E407)]
    assert email_handler.select_delivery_status(partial, False) == status.E200
    assert email_handler.select_delivery_status(partial, True) == status.E407


@pytest.mark.parametrize(
    ("failure", "expected"),
    (
        (MailEdgeUnavailableError("MAIL_EDGE_CONNECT_TIMEOUT"), status.E407),
        (
            MailEdgeUnavailableError(
                "MAIL_EDGE_RESPONSE_TIMEOUT", delivery_certainty="unknown"
            ),
            status.E523,
        ),
        (MailEdgeContractError("INTENT_RESPONSE_INVALID"), status.E523),
    ),
)
def test_inbound_smtp_retries_only_proven_not_sent_failures(
    flask_client, monkeypatch, failure, expected
):
    user = create_new_user()
    alias = Alias.create_new_random(user)
    envelope = Envelope()
    envelope.mail_from = "sender@example.net"
    envelope.rcpt_tos = [alias.email]
    message = EmailMessage()
    message["From"] = envelope.mail_from
    message["To"] = alias.email
    message["Subject"] = "failure boundary"
    message.set_content("body")

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(email_handler, "sl_sendmail", fail)
    assert email_handler.handle(envelope, message) == expected
