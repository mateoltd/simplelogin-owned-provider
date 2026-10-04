import hashlib
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from app.mail_edge.contracts import (
    ApplicationDestination,
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
from app.mail_edge.configuration import MimeParserLimits
from app.mail_edge.mime import BoundedMimeParserService
from app.mail_edge.resources import RawMessageResource


TENANT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401111"
DELIVERY_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401112"


def parser():
    return BoundedMimeParserService(
        MimeParserLimits(64, 8, 256, 256 * 1024, 256 * 1024, 4 * 1024 * 1024, 5)
    )


def deliver_raw(service, delivery, raw, callback_body):
    with RawMessageResource(4 * 1024 * 1024, tempfile.gettempdir()) as resource:
        resource.write(raw)
        return service.deliver(delivery, resource, callback_body)


@dataclass
class Claim:
    receipt_id: int
    fence: int = 1
    completed_acknowledgement: object = None


class Callbacks:
    def __init__(self):
        self.claims = []
        self.completed = []

    def claim(self, tenant_id, operation, subject_id, body_sha256, lease_seconds):
        self.claims.append(
            (tenant_id, operation, subject_id, body_sha256, lease_seconds)
        )
        return Claim(1)

    def start_business_effect(self, receipt_id, fence):
        self.started = (receipt_id, fence)

    def complete(self, receipt_id, fence, acknowledgement):
        self.completed.append((receipt_id, fence, acknowledgement))


class Bindings:
    def __init__(self, authorized=True):
        self.authorized = authorized

    def authorize_delivery(self, binding):
        return self.authorized


class Destinations:
    def __init__(self, address="alias@example.com"):
        self.address = address

    def resolve_destination(self, destination, envelope):
        from app.mail_edge.routing import AliasRoute

        return AliasRoute(1, self.address, self.address.rsplit("@", 1)[1])


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
        destination=ApplicationDestination("destination-1", "push", "opaque"),
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
        Destinations(),
        lambda envelope, message: (
            delivered.append((envelope, message)) or "250 accepted"
        ),
        parser(),
        clock=lambda: datetime(2026, 8, 13, 12, 1, tzinfo=timezone.utc),
    )
    callback_body = b'{"schemaVersion":"v1","deliveryId":"fixture"}'
    acknowledgement = deliver_raw(
        service, application_delivery(raw), raw, callback_body
    )
    assert acknowledgement == {
        "deliveryId": DELIVERY_ID,
        "acceptedAt": "2026-08-13T12:01:00Z",
    }
    assert delivered[0][0].rcpt_tos == ["alias@example.com"]
    assert delivered[0][1]["Message-ID"] == "<m@example.net>"
    assert callbacks.started == (1, 1)
    assert callbacks.completed == [(1, 1, acknowledgement)]
    assert callbacks.claims[0][3] != hashlib.sha256(callback_body).hexdigest()


def test_application_delivery_fails_closed_on_ambiguous_recipient_raw_or_binding():
    raw = b"From: sender@example.net\r\n\r\nbody"
    for delivery, supplied, bindings, destinations in (
        (
            application_delivery(raw, ("one@example.com", "two@example.com")),
            raw,
            Bindings(),
            Destinations("missing@example.com"),
        ),
        (
            application_delivery(raw, ("alias@another.example",)),
            raw,
            Bindings(),
            Destinations(),
        ),
        (application_delivery(raw), raw + b"tamper", Bindings(), Destinations()),
        (application_delivery(raw), raw, Bindings(False), Destinations()),
    ):
        service = ApplicationDeliveryService(
            TENANT_ID,
            Callbacks(),
            bindings,
            destinations,
            lambda envelope, message: "250 accepted",
            parser(),
        )
        with pytest.raises(MailEdgeContractError):
            deliver_raw(service, delivery, supplied, b"callback")


def test_application_delivery_does_not_ack_rejected_local_handoff():
    raw = b"From: sender@example.net\r\n\r\nbody"
    callbacks = Callbacks()
    service = ApplicationDeliveryService(
        TENANT_ID,
        callbacks,
        Bindings(),
        Destinations(),
        lambda envelope, message: "451 retry",
        parser(),
    )
    with pytest.raises(MailEdgeAmbiguousDeliveryError):
        deliver_raw(service, application_delivery(raw), raw, b"callback")
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
    assert callbacks.completed == [(1, 1, acknowledgement)]
