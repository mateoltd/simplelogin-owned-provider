import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from app.mail_edge.contracts import (
    ApplicationDelivery,
    ApplicationFeedback,
    RawMessageRef,
    RouteBindingSnapshot,
    SmtpEnvelope,
    SmtpRecipient,
)
from app.mail_edge.errors import MailEdgeAmbiguousDeliveryError, MailEdgeContractError
from app.mail_edge.host_services import (
    ApplicationDeliveryService,
    ApplicationFeedbackService,
)


TENANT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401111"
DELIVERY_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401112"


@dataclass
class Claim:
    receipt_id: int
    completed_acknowledgement: object = None


class Callbacks:
    def __init__(self):
        self.claims = []
        self.completed = []

    def claim(self, tenant_id, operation, subject_id, body_sha256):
        self.claims.append((tenant_id, operation, subject_id, body_sha256))
        return Claim(1)

    def complete(self, receipt_id, acknowledgement):
        self.completed.append((receipt_id, acknowledgement))


class Bindings:
    def __init__(self, authorized=True):
        self.authorized = authorized

    def authorize_delivery(self, binding):
        return self.authorized


def application_delivery(raw, recipients=("alias@example.com",)):
    binding = RouteBindingSnapshot(
        binding_id="01890f31-7b4a-7cc8-8d32-2f6e9a401113",
        binding_version=1,
        tenant_id=TENANT_ID,
        domain_a_label="example.com",
        direction="inbound",
        provider_id="provider-neutral",
        adapter_version="v1",
        provider_instance_id="01890f31-7b4a-7cc8-8d32-2f6e9a401114",
        provider_resource_ids={},
        capability_digest="c" * 64,
        config_revision="revision-1",
        created_at="2026-08-13T12:00:00Z",
    )
    return ApplicationDelivery(
        delivery_id=DELIVERY_ID,
        receipt_id="01890f31-7b4a-7cc8-8d32-2f6e9a401115",
        tenant_id=TENANT_ID,
        envelope=SmtpEnvelope(
            "sender@example.net",
            tuple(SmtpRecipient(recipient) for recipient in recipients),
            False,
        ),
        raw=RawMessageRef(
            "01890f31-7b4a-7cc8-8d32-2f6e9a401116",
            hashlib.sha256(raw).hexdigest(),
            len(raw),
        ),
        binding=binding,
        attempt=1,
        occurred_at="2026-08-13T12:00:00Z",
    )


def test_application_delivery_verifies_raw_and_acks_only_after_host_acceptance():
    raw = b"From: sender@example.net\r\nTo: alias@example.com\r\nMessage-ID: <m@example.net>\r\n\r\nbody"
    callbacks = Callbacks()
    delivered = []
    service = ApplicationDeliveryService(
        TENANT_ID,
        callbacks,
        Bindings(),
        lambda envelope, message: delivered.append((envelope, message))
        or "250 accepted",
        clock=lambda: datetime(2026, 8, 13, 12, 1, tzinfo=timezone.utc),
    )
    callback_body = b'{"schemaVersion":"v1","deliveryId":"fixture"}'
    acknowledgement = service.deliver(application_delivery(raw), raw, callback_body)
    assert acknowledgement == {
        "deliveryId": DELIVERY_ID,
        "acceptedAt": "2026-08-13T12:01:00Z",
    }
    assert delivered[0][0].rcpt_tos == ["alias@example.com"]
    assert delivered[0][1]["Message-ID"] == "<m@example.net>"
    assert callbacks.completed == [(1, acknowledgement)]
    assert callbacks.claims[0][3] == hashlib.sha256(callback_body).hexdigest()


def test_application_delivery_fails_closed_on_ambiguous_recipient_raw_or_binding():
    raw = b"From: sender@example.net\r\n\r\nbody"
    for delivery, supplied, bindings, error in (
        (
            application_delivery(raw, ("one@example.com", "two@example.com")),
            raw,
            Bindings(),
            MailEdgeAmbiguousDeliveryError,
        ),
        (
            application_delivery(raw, ("alias@another.example",)),
            raw,
            Bindings(),
            MailEdgeContractError,
        ),
        (application_delivery(raw), raw + b"tamper", Bindings(), MailEdgeContractError),
        (application_delivery(raw), raw, Bindings(False), MailEdgeContractError),
    ):
        service = ApplicationDeliveryService(
            TENANT_ID, Callbacks(), bindings, lambda envelope, message: "250 accepted"
        )
        with pytest.raises(error):
            service.deliver(delivery, supplied, b"callback")


def test_application_delivery_does_not_ack_rejected_local_handoff():
    raw = b"From: sender@example.net\r\n\r\nbody"
    callbacks = Callbacks()
    service = ApplicationDeliveryService(
        TENANT_ID, callbacks, Bindings(), lambda envelope, message: "451 retry"
    )
    with pytest.raises(MailEdgeContractError):
        service.deliver(application_delivery(raw), raw, b"callback")
    assert callbacks.completed == []


def test_feedback_projects_only_after_tenant_and_exact_body_are_claimed():
    callbacks = Callbacks()
    projected = []
    feedback = ApplicationFeedback(
        feedback_event_id="01890f31-7b4a-7cc8-8d32-2f6e9a401117",
        tenant_id=TENANT_ID,
        intent_id="01890f31-7b4a-7cc8-8d32-2f6e9a401118",
        kind="bounced",
        occurred_at="2026-08-13T12:00:00Z",
        normalized_evidence={},
    )
    callback_body = b'{"schemaVersion":"v1","kind":"bounced"}'
    service = ApplicationFeedbackService(
        TENANT_ID,
        callbacks,
        projected.append,
        clock=lambda: datetime(2026, 8, 13, 12, 1, tzinfo=timezone.utc),
    )
    acknowledgement = service.deliver(feedback, callback_body)
    assert projected == [feedback]
    assert callbacks.claims[0][3] == hashlib.sha256(callback_body).hexdigest()
    assert callbacks.completed == [(1, acknowledgement)]
