import base64
import hashlib
import hmac
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from flask import Flask, Response, request
from werkzeug.serving import make_server

import email_handler
import psutil
from app.db import Session
from app.mail_edge.client import MailEdgeClient
from app.mail_edge.composition import MailEdgeBridge
from app.mail_edge.configuration import (
    HostAuthentication,
    HostDeliveryLimits,
    HttpLimits,
    MailEdgeConfiguration,
    MimeParserLimits,
)
from app.mail_edge.contracts import (
    RouteBindingSnapshot,
    SmtpEnvelope,
    SmtpRecipient,
    canonical_json,
)
from app.mail_edge.control import MailEdgeControlService
from app.mail_edge.host_services import (
    ApplicationFeedbackService,
    AuthenticatedHostOperations,
)
from app.mail_edge.http_host import create_mail_edge_host_blueprint
from app.mail_edge.mime import BoundedMimeParserService
from app.mail_edge.outbound import (
    MailEdgeOutboundTransport,
    OutboundStatusProjectionService,
)
from app.mail_edge.repository import (
    CallbackReceiptRepository,
    OutboundProjectionRepository,
    ReplayNonceRepository,
    RouteBindingProjectionRepository,
)
from app.mail_edge.resources import HostResourceAdmissionService
from app.mail_edge.routing import (
    OpaqueAliasTokenCodec,
    RecipientRouter,
    ReverseRouteResolver,
)
from app.mail_edge.security import HOST_SIGNATURE_HEADERS, HostSignature, _signing_input
from app.mail_edge.simplelogin_repository import SimpleLoginAliasRoutingRepository
from app.models import (
    Alias,
    Contact,
    EmailLog,
    MailEdgeCallbackReceipt,
    MailEdgeOutboundProjection,
    MailEdgeReplayNonce,
    MailEdgeRouteBindingProjection,
)
from app.mail_sender import MailSender
from tests.utils import create_new_user


TENANT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401111"
RECEIPT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401131"
DELIVERY_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401132"
BLOB_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401133"
GRANT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401134"
BINDING_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401135"
INSTANCE_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401136"
INTENT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401137"
FEEDBACK_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401138"
HOST_KEY = b"host-integration-key-material-32b"


def signed_headers(
    body,
    now,
    nonce,
    *,
    operation="application_delivery",
    subject_id=DELIVERY_ID,
):
    signature = HostSignature(
        key_id="host-key",
        audience="simplelogin-host",
        subject_id=subject_id,
        nonce=nonce,
        body_sha256=hashlib.sha256(body).hexdigest(),
        operation=operation,
        timestamp=now.isoformat().replace("+00:00", "Z"),
        signature="",
    )
    encoded = (
        base64.urlsafe_b64encode(
            hmac.new(HOST_KEY, _signing_input(signature), hashlib.sha256).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    claims = {**signature.claims, "signature": encoded}
    return {header: claims[claim] for claim, header in HOST_SIGNATURE_HEADERS.items()}


def test_real_route_client_parser_handler_and_postgres_are_idempotent(
    flask_client, tmp_path
):
    MailEdgeReplayNonce.filter_by(key_id="host-key").delete()
    MailEdgeCallbackReceipt.query().filter(
        MailEdgeCallbackReceipt.tenant_id == TENANT_ID,
        MailEdgeCallbackReceipt.subject_id.in_((DELIVERY_ID, FEEDBACK_ID)),
    ).delete(synchronize_session=False)
    MailEdgeOutboundProjection.filter_by(
        tenant_id=TENANT_ID, intent_id=INTENT_ID
    ).delete()
    MailEdgeRouteBindingProjection.filter_by(
        tenant_id=TENANT_ID, binding_id=BINDING_ID
    ).delete()
    Session.commit()
    user = create_new_user()
    alias = Alias.create_new_random(user)
    body_line = b"x" * 76 + b"\r\n"
    large_body = body_line * ((20 * 1024 * 1024) // len(body_line))
    raw = (
        b"From: sender@example.net\r\n"
        + f"To: {alias.email}\r\n".encode()
        + b"Subject: real host delivery\r\n"
        + b"Message-ID: <real-host-delivery@example.net>\r\n"
        + b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        + large_body
    )
    raw_requests = []
    raw_application = Flask("mail_edge_raw_origin")

    @raw_application.route(f"/v1/raw-access-grants/{GRANT_ID}/raw")
    def download_raw():
        raw_requests.append(dict(request.headers))
        return Response(
            raw,
            content_type="message/rfc822",
            headers={
                "Accept-Ranges": "none",
                "Content-Length": str(len(raw)),
            },
        )

    raw_server = make_server("127.0.0.1", 0, raw_application, threaded=True)
    raw_thread = threading.Thread(target=raw_server.serve_forever)
    raw_thread.start()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    configuration = MailEdgeConfiguration(
        tenant_id=TENANT_ID,
        base_url=f"http://127.0.0.1:{raw_server.server_port}",
        bearer_token="b" * 32,
        opaque_token_key=b"o" * 32,
        maximum_raw_bytes=25 * 1024 * 1024,
        http=HttpLimits(1, 5, 4, 3, 10, 0, shutdown_seconds=2),
        host_authentication=HostAuthentication(
            "simplelogin-host", 300, 30, {"host-key": HOST_KEY}
        ),
        host_delivery=HostDeliveryLimits(
            4,
            2,
            50 * 1024 * 1024,
            300 * 1024 * 1024,
            64 * 1024 * 1024 * 1024,
            0,
            8,
            8 * 1024 * 1024,
            str(tmp_path),
            MimeParserLimits(
                256,
                16,
                1024,
                1024 * 1024,
                1024 * 1024,
                100 * 1024 * 1024,
                10,
            ),
        ),
    )
    client = MailEdgeClient(configuration)
    routing_repository = SimpleLoginAliasRoutingRepository()
    router = RecipientRouter(
        TENANT_ID,
        routing_repository,
        OpaqueAliasTokenCodec(TENANT_ID, configuration.opaque_token_key),
    )
    smtp_envelope = SmtpEnvelope(
        "sender@example.net", (SmtpRecipient(alias.email),), False
    )
    destination = router.resolve_recipients(TENANT_ID, smtp_envelope, RECEIPT_ID)[0]
    binding = RouteBindingSnapshot(
        binding_id=BINDING_ID,
        binding_version=1,
        tenant_id=TENANT_ID,
        domain_a_label=alias.email.rsplit("@", 1)[1],
        direction="inbound",
        provider_id="provider-neutral",
        adapter_version="v1",
        provider_instance_id=INSTANCE_ID,
        provider_resource_ids={},
        capability_digest="c" * 64,
        config_revision="qualification-1",
        created_at=now.isoformat().replace("+00:00", "Z"),
    )
    bindings = RouteBindingProjectionRepository(TENANT_ID)
    bindings.activate(binding)
    callbacks = CallbackReceiptRepository()
    authentication = AuthenticatedHostOperations(
        configuration.host_authentication, ReplayNonceRepository()
    )
    parser = BoundedMimeParserService(configuration.host_delivery.mime)
    outbound_projections = OutboundProjectionRepository()
    outbound_transport = MailEdgeOutboundTransport(client, outbound_projections)
    bridge = MailEdgeBridge(
        configuration,
        client,
        outbound_transport,
        OutboundStatusProjectionService(client, outbound_projections),
        router,
        ReverseRouteResolver(TENANT_ID, routing_repository),
        authentication,
        ApplicationFeedbackService(
            TENANT_ID,
            callbacks,
            outbound_projections.stage_feedback,
        ),
        callbacks,
        bindings,
        MailEdgeControlService(client, bindings),
        HostResourceAdmissionService(
            configuration.host_delivery, configuration.maximum_raw_bytes
        ),
        parser,
        MailSender(),
    )
    delivery_service = bridge.application_delivery_service(email_handler.handle)
    callback_application = Flask("simplelogin_mail_edge_host")
    callback_application.register_blueprint(
        create_mail_edge_host_blueprint(bridge, delivery_service, clock=lambda: now)
    )
    raw_reference = {
        "schemaVersion": "v1",
        "blobId": BLOB_ID,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "mediaType": "message/rfc822",
    }
    callback = {
        "schemaVersion": "v1",
        "delivery": {
            "schemaVersion": "v1",
            "deliveryId": DELIVERY_ID,
            "receiptId": RECEIPT_ID,
            "tenantId": TENANT_ID,
            "envelope": dict(smtp_envelope.to_wire()),
            "raw": raw_reference,
            "destination": destination,
            "binding": dict(binding.to_wire()),
            "attempt": 1,
            "occurredAt": now.isoformat().replace("+00:00", "Z"),
        },
        "rawAccessGrant": {
            "schemaVersion": "v1",
            "grantId": GRANT_ID,
            "tenantId": TENANT_ID,
            "raw": raw_reference,
            "audience": "simplelogin-host",
            "operation": "raw_download",
            "subjectId": DELIVERY_ID,
            "purpose": "application_delivery",
            "singleUse": True,
            "opaqueToken": "t" * 43,
            "downloadPath": f"/v1/raw-access-grants/{GRANT_ID}/raw",
            "issuedAt": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
            "expiresAt": (now + timedelta(minutes=2))
            .isoformat()
            .replace("+00:00", "Z"),
        },
    }
    body = canonical_json(callback)
    process = psutil.Process()
    baseline_rss = process.memory_info().rss
    peak_rss = [baseline_rss]
    stop_sampling = threading.Event()

    def sample_rss():
        while not stop_sampling.is_set():
            peak_rss[0] = max(peak_rss[0], process.memory_info().rss)
            time.sleep(0.002)

    sampler = threading.Thread(target=sample_rss)
    sampler.start()
    try:
        first = callback_application.test_client().post(
            "/mail-edge/delivery",
            data=body,
            content_type="application/json",
            headers=signed_headers(body, now, "real_route_nonce_01"),
        )
        duplicate = callback_application.test_client().post(
            "/mail-edge/delivery",
            data=body,
            content_type="application/json",
            headers=signed_headers(body, now, "real_route_nonce_02"),
        )

        contact = Contact.filter_by(alias_id=alias.id).one()
        reverse_envelope = SmtpEnvelope(
            user.default_mailbox.email,
            (SmtpRecipient(contact.reply_email),),
            False,
        )
        reverse_body = canonical_json(
            {
                "tenantId": TENANT_ID,
                "envelope": dict(reverse_envelope.to_wire()),
                "raw": raw_reference,
                "opaqueReplyToken": contact.reply_email,
            }
        )
        reverse = callback_application.test_client().post(
            "/mail-edge/reverse-route",
            data=reverse_body,
            content_type="application/json",
            headers=signed_headers(
                reverse_body,
                now,
                "real_reverse_nonce_01",
                operation="reverse_route",
                subject_id=BLOB_ID,
            ),
        )

        outbound_projections.record_accepted(
            TENANT_ID,
            SimpleNamespace(
                intent_id=INTENT_ID,
                fingerprint="f" * 64,
                state="accepted",
                version=0,
            ),
            {
                "user_id": user.id,
                "alias_id": alias.id,
                "contact_id": contact.id,
                "mailbox_id": user.default_mailbox_id,
                "email_log_id": None,
                "idempotency_subject": "delivery:" + DELIVERY_ID,
            },
        )
        feedback_body = canonical_json(
            {
                "schemaVersion": "v1",
                "feedbackEventId": FEEDBACK_ID,
                "tenantId": TENANT_ID,
                "intentId": INTENT_ID,
                "kind": "bounced",
                "occurredAt": now.isoformat().replace("+00:00", "Z"),
                "normalizedEvidence": {},
            }
        )
        feedback = callback_application.test_client().post(
            "/mail-edge/feedback",
            data=feedback_body,
            content_type="application/json",
            headers=signed_headers(
                feedback_body,
                now,
                "real_feedback_nonce_01",
                operation="application_feedback",
                subject_id=FEEDBACK_ID,
            ),
        )
    finally:
        stop_sampling.set()
        sampler.join(timeout=2)
        assert bridge.close(2)
        raw_server.shutdown()
        raw_thread.join(timeout=2)

    assert first.status_code == duplicate.status_code == 200, (
        first.json,
        duplicate.json,
    )
    assert first.json == duplicate.json
    assert reverse.status_code == 200
    assert reverse.json["envelope"]["rcptTo"] == [{"address": "sender@example.net"}]
    assert feedback.status_code == 200
    assert feedback.json["deliveryId"] == FEEDBACK_ID
    assert len(raw_requests) == 1
    assert raw_requests[0]["Authorization"] == "MailEdgeRaw " + "t" * 43
    assert EmailLog.filter_by(alias_id=alias.id).count() == 1
    receipt = MailEdgeCallbackReceipt.filter_by(
        tenant_id=TENANT_ID,
        operation="application_delivery",
        subject_id=DELIVERY_ID,
    ).one()
    assert receipt.status == "completed"
    assert receipt.business_started_at is not None
    projection = MailEdgeOutboundProjection.filter_by(
        tenant_id=TENANT_ID, intent_id=INTENT_ID
    ).one()
    assert projection.feedback_kind == "bounced"
    assert list(tmp_path.iterdir()) == []
    reserved_memory = (
        len(raw) * configuration.host_delivery.estimated_memory_multiplier
        + configuration.host_delivery.estimated_memory_fixed_bytes
    )
    peak_delta = peak_rss[0] - baseline_rss
    print(
        "mail_edge_rss_qualification "
        f"raw_bytes={len(raw)} peak_delta_bytes={peak_delta} "
        f"reserved_bytes={reserved_memory}"
    )
    assert peak_delta <= reserved_memory
    MailEdgeReplayNonce.filter_by(key_id="host-key").delete()
    MailEdgeCallbackReceipt.query().filter(
        MailEdgeCallbackReceipt.tenant_id == TENANT_ID,
        MailEdgeCallbackReceipt.subject_id.in_((DELIVERY_ID, FEEDBACK_ID)),
    ).delete(synchronize_session=False)
    MailEdgeOutboundProjection.filter_by(
        tenant_id=TENANT_ID, intent_id=INTENT_ID
    ).delete()
    MailEdgeRouteBindingProjection.filter_by(
        tenant_id=TENANT_ID, binding_id=BINDING_ID
    ).delete()
    Session.commit()
    Session.rollback()
