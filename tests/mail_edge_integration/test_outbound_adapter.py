from email.message import EmailMessage
from types import SimpleNamespace

import pytest

from app.mail_edge.errors import MailEdgeAmbiguousDeliveryError, MailEdgeContractError
from app.mail_edge.outbound import (
    MailEdgeOutboundTransport,
    OutboundStatusProjectionService,
)
from app.mail_sender import SendRequest


TENANT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401111"
DELIVERY_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401119"


class Client:
    tenant_id = TENANT_ID

    def __init__(self):
        self.calls = []

    def submit_message(self, envelope, raw, idempotency_key):
        self.calls.append((envelope, raw, idempotency_key))
        return SimpleNamespace(
            intent_id="01890f31-7b4a-7cc8-8d32-2f6e9a401112",
            fingerprint="f" * 64,
            state="accepted",
            version=0,
        )

    def get_outbound_intent(self, intent_id):
        return SimpleNamespace(
            intent_id=intent_id,
            fingerprint="f" * 64,
            state="quarantined_unknown",
            version=1,
        )


class Projections:
    def __init__(self):
        self.calls = []

    def record_accepted(self, tenant_id, intent, context):
        self.calls.append((tenant_id, intent, context))

    def project_status(self, tenant_id, intent):
        self.calls.append((tenant_id, intent))


class FailingProjections(Projections):
    def record_accepted(self, tenant_id, intent, context):
        raise RuntimeError("database unavailable")


def request():
    message = EmailMessage()
    message["From"] = "alias@example.com"
    message["To"] = "sender@example.net"
    message["Message-ID"] = "<message@example.com>"
    message["In-Reply-To"] = "<parent@example.net>"
    message["References"] = "<root@example.net> <parent@example.net>"
    message.set_content("reply")
    return SendRequest(
        envelope_from="bounce@example.com",
        envelope_to="sender@example.net",
        msg=message,
        is_forward=False,
        use_mail_edge=True,
        mail_edge_context={
            "user_id": 1,
            "alias_id": 2,
            "contact_id": 3,
            "mailbox_id": 4,
            "email_log_id": 5,
            "idempotency_subject": DELIVERY_ID,
        },
    )


def test_outbound_adapter_preserves_thread_headers_and_projects_only_after_acceptance(
    flask_client,
):
    client = Client()
    projections = Projections()
    transport = MailEdgeOutboundTransport(client, projections)
    send_request = request()
    assert transport.send(send_request)
    envelope, raw, key = client.calls[0]
    assert envelope.mail_from == "bounce@example.com"
    assert envelope.rcpt_to[0].address == "sender@example.net"
    assert b"Message-ID: <message@example.com>" in raw
    assert b"In-Reply-To: <parent@example.net>" in raw
    assert b"References: <root@example.net> <parent@example.net>" in raw
    assert key.startswith("sl-") and len(key) == 67
    assert projections.calls[0][0] == TENANT_ID


def test_outbound_adapter_preserves_esmtp_and_dsn_semantics(flask_client):
    client = Client()
    send_request = request()
    send_request.mail_options = (
        "BODY=8BITMIME",
        "SMTPUTF8",
        "REQUIRETLS",
        "RET=HDRS",
        "ENVID=message+2Bid",
    )
    send_request.rcpt_options = (
        "NOTIFY=SUCCESS,FAILURE,DELAY",
        "ORCPT=rfc822;sender@example.net",
    )

    MailEdgeOutboundTransport(client, Projections()).send(send_request)

    envelope = client.calls[0][0]
    assert envelope.body == "8bitmime"
    assert envelope.smtp_utf8
    assert envelope.require_tls
    assert envelope.dsn == {"ret": "headers", "envelopeId": "message+2Bid"}
    assert envelope.rcpt_to[0].dsn == {
        "notify": ["success", "failure", "delay"],
        "originalRecipient": "rfc822;sender@example.net",
    }


def test_idempotency_key_is_stable_across_retry_serialization_changes(flask_client):
    client = Client()
    transport = MailEdgeOutboundTransport(client, Projections())
    first = request()
    second = request()
    second.envelope_from = "changed-retry-token@example.com"
    second.msg.set_payload("different retry serialization")
    assert transport.send(first)
    assert transport.send(second)
    assert client.calls[0][1] != client.calls[1][1]
    assert client.calls[0][0] != client.calls[1][0]
    assert client.calls[0][2] == client.calls[1][2]


def test_status_refresh_projects_tenant_scoped_quarantine(flask_client):
    client = Client()
    projections = Projections()
    intent = OutboundStatusProjectionService(client, projections).refresh(
        "01890f31-7b4a-7cc8-8d32-2f6e9a401112"
    )
    assert intent.state == "quarantined_unknown"
    assert projections.calls == [(TENANT_ID, intent)]


def test_projection_failure_after_edge_acceptance_is_terminal_unknown(flask_client):
    client = Client()
    with pytest.raises(MailEdgeAmbiguousDeliveryError) as raised:
        MailEdgeOutboundTransport(client, FailingProjections()).send(request())
    assert raised.value.delivery_certainty == "unknown"
    assert not raised.value.retryable
    assert len(client.calls) == 1


def test_invalid_local_context_fails_before_any_edge_handoff(flask_client):
    client = Client()
    send_request = request()
    del send_request.mail_edge_context["alias_id"]
    with pytest.raises(MailEdgeContractError):
        MailEdgeOutboundTransport(client, Projections()).send(send_request)
    assert client.calls == []
