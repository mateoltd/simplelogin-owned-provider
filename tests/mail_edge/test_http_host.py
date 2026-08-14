import base64
import hashlib
import hmac
import json
import threading
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

from flask import Flask

from app.mail_edge.configuration import (
    HostAuthentication,
    HttpLimits,
    MailEdgeConfiguration,
)
from app.mail_edge.contracts import canonical_json
from app.mail_edge.errors import MailEdgeAuthenticationError
from app.mail_edge.host_services import (
    ApplicationDeliveryService,
    AuthenticatedHostOperations,
)
from app.mail_edge.http_host import create_mail_edge_host_blueprint
from app.mail_edge.routing import AliasRoute, ReverseRoute
from app.mail_edge.security import HOST_SIGNATURE_HEADERS, HostSignature, _signing_input


TENANT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401111"
RECEIPT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401112"
DELIVERY_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401113"
BLOB_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401114"
BINDING_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401115"
INSTANCE_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401116"
KEY = b"Z" * 32
NOW = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)


class Nonces:
    def __init__(self):
        self.seen = set()

    def consume(self, key_id, nonce, expires_at):
        identity = (key_id, nonce)
        if identity in self.seen:
            raise MailEdgeAuthenticationError("HOST_SIGNATURE_REPLAYED")
        self.seen.add(identity)


class Callbacks:
    def __init__(self):
        self.fingerprint = None
        self.acknowledgement = None

    def claim(self, tenant_id, operation, subject_id, body_sha256, lease_seconds):
        if self.fingerprint is None:
            self.fingerprint = body_sha256
        assert self.fingerprint == body_sha256
        return SimpleNamespace(
            receipt_id=1,
            fence=1,
            completed_acknowledgement=self.acknowledgement,
        )

    def start_business_effect(self, receipt_id, fence):
        assert (receipt_id, fence) == (1, 1)

    def complete(self, receipt_id, fence, acknowledgement):
        assert (receipt_id, fence) == (1, 1)
        self.acknowledgement = dict(acknowledgement)


class Destinations:
    def resolve_destination(self, destination, envelope):
        assert destination.delivery_mode == "push"
        return AliasRoute(1, "alias@example.com", "example.com")


class Bindings:
    def authorize_delivery(self, binding):
        return binding.binding_id == BINDING_ID


class RawClient:
    def __init__(self, raw):
        self.raw = raw
        self.downloads = 0

    def download_raw_to(self, grant, target):
        self.downloads += 1
        assert grant.subject_id == DELIVERY_ID
        target.write(self.raw)


class Router:
    def resolve_recipients(self, tenant_id, envelope, receipt_id):
        assert tenant_id == TENANT_ID
        assert receipt_id == RECEIPT_ID
        return (
            {
                "destinationId": "destination-1",
                "deliveryMode": "push",
                "opaqueToken": "opaque",
            },
        )


class ReverseResolver:
    def resolve_reverse_route(self, tenant_id, envelope, raw, opaque_reply_token):
        assert tenant_id == TENANT_ID
        assert opaque_reply_token == "reply@example.com"
        return ReverseRoute(envelope, ("From: alias@example.com",))


class Feedback:
    def deliver(self, feedback, callback_body):
        return {
            "deliveryId": feedback.feedback_event_id,
            "acceptedAt": "2026-08-14T12:00:00Z",
        }


def configuration():
    return MailEdgeConfiguration(
        tenant_id=TENANT_ID,
        base_url="http://edge.internal",
        bearer_token="b" * 32,
        opaque_token_key=b"o" * 32,
        maximum_raw_bytes=1024 * 1024,
        http=HttpLimits(1, 5, 2, 3, 10, 0),
        host_authentication=HostAuthentication(
            "simplelogin-host", 300, 30, {"host-key": KEY}
        ),
    )


def signed_headers(body, operation, subject_id, nonce):
    signature = HostSignature(
        key_id="host-key",
        audience="simplelogin-host",
        subject_id=subject_id,
        nonce=nonce,
        body_sha256=hashlib.sha256(body).hexdigest(),
        operation=operation,
        timestamp="2026-08-14T12:00:00Z",
        signature="",
    )
    encoded = (
        base64.urlsafe_b64encode(
            hmac.new(KEY, _signing_input(signature), hashlib.sha256).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    values = {**signature.claims, "signature": encoded}
    return {
        header_name: values[claim]
        for claim, header_name in HOST_SIGNATURE_HEADERS.items()
    }


def callback_app(
    raw_message=b"From: sender@example.net\r\n\r\nbody",
    *,
    concurrency=2,
    router=None,
):
    selected = configuration()
    selected = replace(
        selected, http=replace(selected.http, concurrency=concurrency)
    )
    raw_client = RawClient(raw_message)
    callbacks = Callbacks()
    bridge = SimpleNamespace(
        configuration=selected,
        authenticated_host_operations=AuthenticatedHostOperations(
            selected.host_authentication, Nonces()
        ),
        recipient_router=router or Router(),
        reverse_route_resolver=ReverseResolver(),
        feedback_service=Feedback(),
        client=raw_client,
    )
    deliveries = []
    delivery_service = ApplicationDeliveryService(
        TENANT_ID,
        callbacks,
        Bindings(),
        Destinations(),
        lambda envelope, message: deliveries.append((envelope, message))
        or "250 accepted",
        clock=lambda: NOW,
    )
    app = Flask(__name__)
    app.register_blueprint(
        create_mail_edge_host_blueprint(bridge, delivery_service, clock=lambda: NOW)
    )
    return app, raw_client, deliveries


def envelope():
    return {
        "schemaVersion": "v1",
        "mailFrom": "sender@example.net",
        "rcptTo": [{"address": "alias@example.com"}],
        "smtpUtf8": False,
    }


def raw_reference(raw_message):
    return {
        "schemaVersion": "v1",
        "blobId": BLOB_ID,
        "sha256": hashlib.sha256(raw_message).hexdigest(),
        "size": len(raw_message),
        "mediaType": "message/rfc822",
    }


def delivery_callback(
    raw_message,
    *,
    issued_at="2026-08-14T11:59:30Z",
    expires_at="2026-08-14T12:04:30Z",
):
    raw = raw_reference(raw_message)
    grant_id = "01890f31-7b4a-7cc8-8d32-2f6e9a401117"
    return {
        "schemaVersion": "v1",
        "delivery": {
            "schemaVersion": "v1",
            "deliveryId": DELIVERY_ID,
            "receiptId": RECEIPT_ID,
            "tenantId": TENANT_ID,
            "envelope": envelope(),
            "raw": raw,
            "destination": {
                "destinationId": "destination-1",
                "deliveryMode": "push",
                "opaqueToken": "opaque",
            },
            "binding": {
                "schemaVersion": "v1",
                "bindingId": BINDING_ID,
                "bindingVersion": 1,
                "tenantId": TENANT_ID,
                "domainALabel": "example.com",
                "direction": "inbound",
                "providerId": "provider-neutral",
                "adapterVersion": "v1",
                "providerInstanceId": INSTANCE_ID,
                "providerResourceIds": {},
                "capabilityDigest": "c" * 64,
                "configRevision": "revision-1",
                "createdAt": "2026-08-14T11:55:00Z",
            },
            "attempt": 1,
            "occurredAt": "2026-08-14T11:59:00Z",
        },
        "rawAccessGrant": {
            "schemaVersion": "v1",
            "grantId": grant_id,
            "tenantId": TENANT_ID,
            "raw": raw,
            "audience": "simplelogin-host",
            "operation": "raw_download",
            "subjectId": DELIVERY_ID,
            "purpose": "application_delivery",
            "singleUse": True,
            "opaqueToken": "t" * 43,
            "downloadPath": f"/v1/raw-access-grants/{grant_id}/raw",
            "issuedAt": issued_at,
            "expiresAt": expires_at,
        },
    }


def post_signed(client, path, value, operation, subject_id, nonce):
    body = json.dumps(value, separators=(",", ":")).encode()
    return client.post(
        path,
        data=body,
        content_type="application/json",
        headers=signed_headers(body, operation, subject_id, nonce),
    )


def test_recipient_callback_echoes_subject_and_replay_fails_closed():
    app, _, _ = callback_app()
    client = app.test_client()
    value = {
        "schemaVersion": "v1",
        "tenantId": TENANT_ID,
        "envelope": envelope(),
        "receiptId": RECEIPT_ID,
    }
    response = post_signed(
        client,
        "/mail-edge/recipients",
        value,
        "recipient_route",
        RECEIPT_ID,
        "abcdefghijklmnop",
    )
    assert response.status_code == 200
    assert response.headers["X-Mail-Edge-Subject-Id"] == RECEIPT_ID
    assert response.json == {
        "destinations": [
            {
                "deliveryMode": "push",
                "destinationId": "destination-1",
                "opaqueToken": "opaque",
            }
        ]
    }
    replay = post_signed(
        client,
        "/mail-edge/recipients",
        value,
        "recipient_route",
        RECEIPT_ID,
        "abcdefghijklmnop",
    )
    assert replay.status_code == 401
    assert replay.json["code"] == "authentication-failed"
    assert "destination-1" not in replay.get_data(as_text=True)


def test_delivery_streams_granted_raw_once_and_reuses_durable_ack():
    raw_message = b"From: sender@example.net\r\nTo: alias@example.com\r\n\r\nbody"
    app, raw_client, deliveries = callback_app(raw_message)
    client = app.test_client()
    value = delivery_callback(raw_message)
    first = post_signed(
        client,
        "/mail-edge/delivery",
        value,
        "application_delivery",
        DELIVERY_ID,
        "delivery_nonce_01",
    )
    duplicate = post_signed(
        client,
        "/mail-edge/delivery",
        value,
        "application_delivery",
        DELIVERY_ID,
        "delivery_nonce_02",
    )
    assert first.status_code == duplicate.status_code == 200
    assert first.json == duplicate.json
    assert first.json["deliveryId"] == DELIVERY_ID
    assert raw_client.downloads == 1
    assert len(deliveries) == 1
    assert deliveries[0][0].original_content == raw_message


def test_reverse_and_feedback_callbacks_use_contract_subjects():
    raw_message = b"message"
    app, _, _ = callback_app(raw_message)
    client = app.test_client()
    reverse = post_signed(
        client,
        "/mail-edge/reverse-route",
        {
            "tenantId": TENANT_ID,
            "envelope": envelope(),
            "raw": raw_reference(raw_message),
            "opaqueReplyToken": "reply@example.com",
        },
        "reverse_route",
        BLOB_ID,
        "reverse_nonce_001",
    )
    assert reverse.status_code == 200
    assert reverse.headers["X-Mail-Edge-Subject-Id"] == BLOB_ID
    assert reverse.json["policyCode"] == "reverse_alias"

    feedback_id = "01890f31-7b4a-7cc8-8d32-2f6e9a401118"
    feedback = post_signed(
        client,
        "/mail-edge/feedback",
        {
            "schemaVersion": "v1",
            "feedbackEventId": feedback_id,
            "tenantId": TENANT_ID,
            "intentId": "01890f31-7b4a-7cc8-8d32-2f6e9a401119",
            "kind": "bounced",
            "occurredAt": "2026-08-14T11:59:00Z",
            "normalizedEvidence": {},
        },
        "application_feedback",
        feedback_id,
        "feedback_nonce_1",
    )
    assert feedback.status_code == 200
    assert feedback.headers["X-Mail-Edge-Subject-Id"] == feedback_id
    assert feedback.json["deliveryId"] == feedback_id


def test_callback_rejects_limits_encoding_and_expired_grants_with_exact_problem():
    raw_message = b"message"
    app, raw_client, _ = callback_app(raw_message)
    client = app.test_client()
    oversized = client.post(
        "/mail-edge/recipients",
        data=b"{" + b"x" * (1024 * 1024),
        content_type="application/json",
    )
    assert oversized.status_code == 413
    assert oversized.json["code"] == "ingress-limit-exceeded"
    assert oversized.content_type.startswith("application/problem+json")

    encoded = client.post(
        "/mail-edge/recipients",
        data=canonical_json({"invalid": True}),
        content_type="application/json",
        headers={"Content-Encoding": "gzip"},
    )
    assert encoded.status_code == 400
    assert encoded.json["code"] == "validation-failed"

    expired = post_signed(
        client,
        "/mail-edge/delivery",
        delivery_callback(
            raw_message,
            issued_at="2026-08-14T11:54:00Z",
            expires_at="2026-08-14T11:59:00Z",
        ),
        "application_delivery",
        DELIVERY_ID,
        "expired_grant_01",
    )
    assert expired.status_code == 403
    assert expired.json["code"] == "authorization-failed"
    assert raw_client.downloads == 0


def test_callback_admission_backpressures_and_releases_capacity():
    entered = threading.Event()
    release = threading.Event()

    class BlockingRouter(Router):
        def resolve_recipients(self, tenant_id, envelope, receipt_id):
            entered.set()
            assert release.wait(timeout=2)
            return super().resolve_recipients(tenant_id, envelope, receipt_id)

    app, _, _ = callback_app(concurrency=1, router=BlockingRouter())
    value = {
        "schemaVersion": "v1",
        "tenantId": TENANT_ID,
        "envelope": envelope(),
        "receiptId": RECEIPT_ID,
    }
    first_response = []

    def run_first_request():
        first_response.append(
            post_signed(
                app.test_client(),
                "/mail-edge/recipients",
                value,
                "recipient_route",
                RECEIPT_ID,
                "admission_nonce_01",
            )
        )

    worker = threading.Thread(target=run_first_request)
    worker.start()
    assert entered.wait(timeout=2)
    rejected = post_signed(
        app.test_client(),
        "/mail-edge/recipients",
        value,
        "recipient_route",
        RECEIPT_ID,
        "admission_nonce_02",
    )
    assert rejected.status_code == 429
    assert rejected.json["code"] == "rate-limited"
    assert rejected.json["retryable"] is True

    release.set()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert first_response[0].status_code == 200

    recovered = post_signed(
        app.test_client(),
        "/mail-edge/recipients",
        value,
        "recipient_route",
        RECEIPT_ID,
        "admission_nonce_03",
    )
    assert recovered.status_code == 200
