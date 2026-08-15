"""Exercise and verify Mail Edge host state during the contained restore drill."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import os
import re
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Mapping

from werkzeug.serving import make_server

from app.db import Session
from app.mail_edge.configuration import configuration_from_environment
from app.mail_edge.contracts import RouteBindingSnapshot, canonical_json
from app.mail_edge.repository import (
    CallbackReceiptRepository,
    OutboundProjectionRepository,
    ReplayNonceRepository,
    RouteBindingProjectionRepository,
)
from app.mail_edge.security import HOST_SIGNATURE_HEADERS
from app.models import (
    Alias,
    Contact,
    MailEdgeCallbackReceipt,
    MailEdgeOutboundProjection,
    MailEdgeReplayNonce,
    MailEdgeRouteBindingProjection,
)
from server import create_app, create_light_app


STATE_FIELDS = frozenset(
    {
        "tenant_id",
        "callback_subject_id",
        "intent_id",
        "binding_id",
        "binding_version",
        "domain_a_label",
        "nonce",
        "key_id",
        "alias_id",
        "mailbox_id",
        "user_id",
        "fingerprint",
    }
)
TENANT_PATH = re.compile(
    r"^/v1/tenants/([0-9a-f-]{36})/(raw-messages|outbound-intents)$"
)


class EdgeContractFixture:
    """Bounded test-only edge peer for the destructive host restore probe."""

    def __init__(self, tenant_id: str, bearer_token: str, inbound_raw: bytes):
        self.tenant_id = tenant_id
        self.bearer_token = bearer_token
        self.inbound_raw = inbound_raw
        self.raw_token = "r" * 43
        self.raw_downloads = 0
        self.stored_raw_count = 0
        self.outbound_intents: list[Mapping[str, object]] = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                owner.handle_get(self)

            def do_POST(self) -> None:
                owner.handle_post(self)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="mail-edge-contract-fixture"
        )

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._thread.join(timeout=10)
        self._server.server_close()
        if self._thread.is_alive():
            raise RuntimeError("Mail Edge contract fixture did not stop")

    @staticmethod
    def _respond(
        handler: http.server.BaseHTTPRequestHandler,
        status: int,
        body: bytes,
        content_type: str,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or {}).items():
            handler.send_header(name, value)
        handler.end_headers()
        handler.wfile.write(body)

    def _read(self, handler: http.server.BaseHTTPRequestHandler) -> bytes:
        try:
            length = int(handler.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if not 0 <= length <= 26_214_400:
            raise RuntimeError("Mail Edge contract fixture request is unbounded")
        body = handler.rfile.read(length)
        if len(body) != length:
            raise RuntimeError("Mail Edge contract fixture request was truncated")
        return body

    def handle_get(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        if (
            not re.fullmatch(r"/v1/raw-access-grants/[0-9a-f-]{36}/raw", handler.path)
            or handler.headers.get("Authorization") != "MailEdgeRaw " + self.raw_token
        ):
            self._respond(handler, 404, b"{}", "application/problem+json")
            return
        self.raw_downloads += 1
        self._respond(
            handler,
            200,
            self.inbound_raw,
            "message/rfc822",
            {"Accept-Ranges": "none"},
        )

    def handle_post(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        match = TENANT_PATH.fullmatch(handler.path)
        if (
            match is None
            or match.group(1) != self.tenant_id
            or handler.headers.get("Authorization") != "Bearer " + self.bearer_token
        ):
            self._respond(handler, 404, b"{}", "application/problem+json")
            return
        body = self._read(handler)
        if match.group(2) == "raw-messages":
            self.stored_raw_count += 1
            response = canonical_json(
                {
                    "schemaVersion": "v1",
                    "blobId": uuid7(),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "size": len(body),
                    "mediaType": "message/rfc822",
                }
            )
            self._respond(handler, 201, response, "application/json")
            return
        value = json.loads(body)
        if not isinstance(value, dict) or set(value) != {"envelope", "raw"}:
            raise RuntimeError("Mail Edge outbound fixture request is malformed")
        envelope = value["envelope"]
        raw = value["raw"]
        if not isinstance(envelope, dict) or not isinstance(raw, dict):
            raise RuntimeError("Mail Edge outbound fixture request is malformed")
        intent_id = uuid7()
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        binding = {
            "schemaVersion": "v1",
            "bindingId": uuid7(),
            "bindingVersion": 1,
            "tenantId": self.tenant_id,
            "domainALabel": "example.net",
            "direction": "outbound",
            "providerId": "restore-probe",
            "adapterVersion": "1",
            "providerInstanceId": uuid7(),
            "providerResourceIds": {"probe": intent_id},
            "capabilityDigest": hashlib.sha256(b"restore-probe").hexdigest(),
            "configRevision": "restore-probe-v1",
            "createdAt": now,
        }
        response_value = {
            "schemaVersion": "v1",
            "intentId": intent_id,
            "tenantId": self.tenant_id,
            "raw": raw,
            "envelope": envelope,
            "primaryBinding": binding,
            "fallbackBindings": [],
            "transmissionRaw": raw,
            "fingerprint": hashlib.sha256(body).hexdigest(),
            "state": "accepted",
            "createdAt": now,
            "version": 0,
        }
        self.outbound_intents.append(response_value)
        self._respond(handler, 202, canonical_json(response_value), "application/json")


def uuid7() -> str:
    """Return a UUIDv7 without depending on Python 3.14's uuid.uuid7."""

    timestamp_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    value = (timestamp_ms << 80) | int.from_bytes(os.urandom(10), "big")
    value = (value & ~(0xF << 76)) | (0x7 << 76)
    value = (value & ~(0x3 << 62)) | (0x2 << 62)
    return str(uuid.UUID(int=value))


def configuration():
    selected = configuration_from_environment()
    if selected is None:
        raise RuntimeError("Mail Edge restore probe requires MAIL_EDGE_CONFIG_PATH")
    return selected


def seed() -> Mapping[str, object]:
    selected = configuration()
    alias = (
        Session.query(Alias)
        .filter(Alias.enabled.is_(True), Alias.delete_on.is_(None))
        .order_by(Alias.id)
        .first()
    )
    if alias is None or not alias.mailboxes:
        raise RuntimeError("Mail Edge restore probe requires one enabled alias mailbox")
    mailbox = sorted(alias.mailboxes, key=lambda item: item.id)[0]
    now = datetime.now(timezone.utc)
    callback_subject_id = uuid7()
    intent_id = uuid7()
    binding_id = uuid7()
    binding_version = 1
    nonce = "restore_" + uuid.uuid4().hex
    key_id = sorted(selected.host_authentication.verification_keys)[0]
    fingerprint = hashlib.sha256(intent_id.encode("ascii")).hexdigest()
    domain = alias.email.rsplit("@", 1)[1].lower()

    ReplayNonceRepository().consume(key_id, nonce, now + timedelta(days=1))
    callbacks = CallbackReceiptRepository()
    body_sha256 = hashlib.sha256(callback_subject_id.encode("ascii")).hexdigest()
    claim = callbacks.claim(
        selected.tenant_id,
        "application_delivery",
        callback_subject_id,
        body_sha256,
        selected.host_authentication.callback_lease_seconds,
    )
    callbacks.start_business_effect(claim.receipt_id, claim.fence)
    callbacks.complete(
        claim.receipt_id,
        claim.fence,
        {"deliveryId": callback_subject_id, "status": "accepted"},
    )
    OutboundProjectionRepository().record_accepted(
        selected.tenant_id,
        SimpleNamespace(
            intent_id=intent_id,
            fingerprint=fingerprint,
            state="accepted",
            version=0,
        ),
        {
            "user_id": alias.user_id,
            "alias_id": alias.id,
            "contact_id": None,
            "mailbox_id": mailbox.id,
            "email_log_id": None,
            "idempotency_subject": "restore:" + intent_id,
        },
    )
    RouteBindingProjectionRepository(selected.tenant_id).activate(
        RouteBindingSnapshot(
            binding_id=binding_id,
            binding_version=binding_version,
            tenant_id=selected.tenant_id,
            domain_a_label=domain,
            direction="outbound",
            provider_id="restore-probe",
            adapter_version="1",
            provider_instance_id=uuid7(),
            provider_resource_ids={"probe": binding_id},
            capability_digest=hashlib.sha256(b"restore-probe").hexdigest(),
            config_revision="restore-probe-v1",
            created_at=now.isoformat().replace("+00:00", "Z"),
        )
    )
    return {
        "tenant_id": selected.tenant_id,
        "callback_subject_id": callback_subject_id,
        "intent_id": intent_id,
        "binding_id": binding_id,
        "binding_version": binding_version,
        "domain_a_label": domain,
        "nonce": nonce,
        "key_id": key_id,
        "alias_id": alias.id,
        "mailbox_id": mailbox.id,
        "user_id": alias.user_id,
        "fingerprint": fingerprint,
    }


def parse_state(raw: str) -> Mapping[str, object]:
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != STATE_FIELDS:
        raise ValueError("Mail Edge restore state is malformed")
    for field in STATE_FIELDS - {
        "binding_version",
        "alias_id",
        "mailbox_id",
        "user_id",
    }:
        if not isinstance(value[field], str) or not value[field]:
            raise ValueError("Mail Edge restore state is malformed")
    for field in ("binding_version", "alias_id", "mailbox_id", "user_id"):
        if isinstance(value[field], bool) or not isinstance(value[field], int):
            raise ValueError("Mail Edge restore state is malformed")
    return value


def verify(raw_state: str) -> Mapping[str, object]:
    state = parse_state(raw_state)
    nonce_digest = hashlib.sha256(str(state["nonce"]).encode("ascii")).hexdigest()
    replay = MailEdgeReplayNonce.filter_by(
        key_id=state["key_id"], nonce_digest=nonce_digest
    ).one()
    callback = MailEdgeCallbackReceipt.filter_by(
        tenant_id=state["tenant_id"],
        operation="application_delivery",
        subject_id=state["callback_subject_id"],
    ).one()
    outbound = MailEdgeOutboundProjection.filter_by(
        tenant_id=state["tenant_id"], intent_id=state["intent_id"]
    ).one()
    binding = MailEdgeRouteBindingProjection.filter_by(
        tenant_id=state["tenant_id"],
        binding_id=state["binding_id"],
        binding_version=state["binding_version"],
    ).one()
    if replay.expires_at.datetime <= datetime.now(timezone.utc):
        raise RuntimeError("restored Mail Edge replay nonce expired unexpectedly")
    if callback.status != "completed" or callback.acknowledgement != {
        "deliveryId": state["callback_subject_id"],
        "status": "accepted",
    }:
        raise RuntimeError("restored Mail Edge callback receipt differs")
    if (
        outbound.state != "accepted"
        or outbound.request_fingerprint != state["fingerprint"]
        or outbound.user_id != state["user_id"]
        or outbound.alias_id != state["alias_id"]
        or outbound.mailbox_id != state["mailbox_id"]
    ):
        raise RuntimeError("restored Mail Edge outbound projection differs")
    if (
        binding.domain_a_label != state["domain_a_label"]
        or binding.direction != "outbound"
        or binding.state != "active"
    ):
        raise RuntimeError("restored Mail Edge binding projection differs")
    return {
        "mail_edge_replay_nonce": "restored",
        "mail_edge_callback_receipt": "restored",
        "mail_edge_outbound_projection": "restored",
        "mail_edge_route_binding_projection": "restored",
    }


def signed_headers(
    body: bytes,
    *,
    key_id: str,
    key: bytes,
    audience: str,
    operation: str,
    subject_id: str,
    nonce: str,
) -> Mapping[str, str]:
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    claims = {
        "schemaVersion": "v1",
        "algorithm": "hmac-sha256",
        "keyId": key_id,
        "audience": audience,
        "subjectId": subject_id,
        "nonce": nonce,
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "operation": operation,
        "timestamp": timestamp,
    }
    signing_input = canonical_json({**claims, "context": "mail-edge-host-signature-v1"})
    claims["signature"] = (
        base64.urlsafe_b64encode(hmac.new(key, signing_input, hashlib.sha256).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return {HOST_SIGNATURE_HEADERS[name]: value for name, value in claims.items()}


def post(
    url: str, body: bytes, headers: Mapping[str, str]
) -> tuple[int, Mapping[str, object], Mapping[str, str]]:
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        response = urllib.request.urlopen(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        payload = response.read(1_048_577)
        if len(payload) > 1_048_576:
            raise RuntimeError("Mail Edge callback response exceeded the proof limit")
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise RuntimeError("Mail Edge callback response is not an object")
        return response.status, value, dict(response.headers.items())


def callback() -> Mapping[str, object]:
    original_config_path = os.environ["MAIL_EDGE_CONFIG_PATH"]
    selected = configuration()
    inbound_raw = (
        b"From: sender@example.net\r\n"
        b"To: restore-probe@example.invalid\r\n"
        b"Subject: Mail Edge restore callback\r\n"
        b"Message-ID: <mail-edge-restore-probe@example.net>\r\n"
        b"\r\n"
        b"restored callback body\r\n"
    )
    edge = EdgeContractFixture(selected.tenant_id, selected.bearer_token, inbound_raw)
    edge.start()
    application = None
    bridge = None
    server = None
    thread = None
    try:
        with tempfile.TemporaryDirectory(prefix="mail-edge-restore-") as temporary:
            raw_config = Path(original_config_path).read_bytes()
            if len(raw_config) > 64 * 1024:
                raise RuntimeError("Mail Edge restore configuration is oversized")
            config_document = json.loads(raw_config)
            if not isinstance(config_document, dict):
                raise RuntimeError("Mail Edge restore configuration is malformed")
            config_document["baseUrl"] = edge.base_url
            probe_config = Path(temporary) / "config.json"
            probe_config.write_bytes(canonical_json(config_document))
            probe_config.chmod(0o600)
            os.environ["MAIL_EDGE_CONFIG_PATH"] = str(probe_config)

            application = create_app()
            bridge = application.extensions.get("mail_edge_bridge")
            if bridge is None:
                raise RuntimeError("Mail Edge host callback blueprint is not active")
            with application.app_context():
                alias = (
                    Session.query(Alias)
                    .filter(Alias.enabled.is_(True), Alias.delete_on.is_(None))
                    .order_by(Alias.id)
                    .first()
                )
                if alias is None:
                    raise RuntimeError(
                        "Mail Edge callback proof requires one enabled alias"
                    )
                alias_id = alias.id
                alias_address = alias.email
                alias_domain = alias.email.rsplit("@", 1)[1].lower()
                inbound_raw = inbound_raw.replace(
                    b"restore-probe@example.invalid", alias_address.encode("ascii")
                )
                edge.inbound_raw = inbound_raw
                callback_before = Session.query(MailEdgeCallbackReceipt).count()
                outbound_before = Session.query(MailEdgeOutboundProjection).count()

            now = datetime.now(timezone.utc)
            inbound_binding = RouteBindingSnapshot(
                binding_id=uuid7(),
                binding_version=1,
                tenant_id=selected.tenant_id,
                domain_a_label=alias_domain,
                direction="inbound",
                provider_id="restore-probe",
                adapter_version="1",
                provider_instance_id=uuid7(),
                provider_resource_ids={},
                capability_digest=hashlib.sha256(b"restore-probe").hexdigest(),
                config_revision="restore-probe-v1",
                created_at=now.isoformat().replace("+00:00", "Z"),
            )
            with application.app_context():
                bridge.binding_projections.activate(inbound_binding)

            key_id = sorted(selected.host_authentication.verification_keys)[0]
            key = selected.host_authentication.verification_keys[key_id]
            server = make_server("127.0.0.1", 0, application)
            thread = threading.Thread(
                target=server.serve_forever, name="mail-edge-restore-probe"
            )
            thread.start()
            base_url = f"http://127.0.0.1:{server.server_port}"

            receipt_id = uuid7()
            envelope = {
                "schemaVersion": "v1",
                "mailFrom": "sender@example.net",
                "rcptTo": [{"address": alias_address}],
                "smtpUtf8": False,
            }
            recipient_body = canonical_json(
                {
                    "schemaVersion": "v1",
                    "tenantId": selected.tenant_id,
                    "envelope": envelope,
                    "receiptId": receipt_id,
                }
            )
            recipient_nonce = "recipient_" + uuid.uuid4().hex
            recipient_headers = signed_headers(
                recipient_body,
                key_id=key_id,
                key=key,
                audience=selected.host_authentication.audience,
                operation="recipient_route",
                subject_id=receipt_id,
                nonce=recipient_nonce,
            )
            recipient_status, recipient_response, recipient_response_headers = post(
                base_url + "/mail-edge/recipients",
                recipient_body,
                recipient_headers,
            )
            replay_status, replay_response, _ = post(
                base_url + "/mail-edge/recipients",
                recipient_body,
                recipient_headers,
            )
            destinations = recipient_response.get("destinations")
            if (
                recipient_status != 200
                or not isinstance(destinations, list)
                or len(destinations) != 1
                or recipient_response_headers.get("X-Mail-Edge-Subject-Id")
                != receipt_id
            ):
                raise RuntimeError(
                    "Mail Edge signed recipient callback did not resolve exactly"
                )
            if (
                replay_status != 401
                or replay_response.get("code") != "authentication-failed"
            ):
                raise RuntimeError("Mail Edge callback replay did not fail closed")

            delivery_id = uuid7()
            grant_id = uuid7()
            raw_reference = {
                "schemaVersion": "v1",
                "blobId": uuid7(),
                "sha256": hashlib.sha256(inbound_raw).hexdigest(),
                "size": len(inbound_raw),
                "mediaType": "message/rfc822",
            }
            delivery_value = {
                "schemaVersion": "v1",
                "delivery": {
                    "schemaVersion": "v1",
                    "deliveryId": delivery_id,
                    "receiptId": receipt_id,
                    "tenantId": selected.tenant_id,
                    "envelope": envelope,
                    "raw": raw_reference,
                    "destination": destinations[0],
                    "binding": dict(inbound_binding.to_wire()),
                    "attempt": 1,
                    "occurredAt": now.isoformat().replace("+00:00", "Z"),
                },
                "rawAccessGrant": {
                    "schemaVersion": "v1",
                    "grantId": grant_id,
                    "tenantId": selected.tenant_id,
                    "raw": raw_reference,
                    "audience": selected.host_authentication.audience,
                    "operation": "raw_download",
                    "subjectId": delivery_id,
                    "purpose": "application_delivery",
                    "singleUse": True,
                    "opaqueToken": edge.raw_token,
                    "downloadPath": f"/v1/raw-access-grants/{grant_id}/raw",
                    "issuedAt": (now - timedelta(seconds=1))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "expiresAt": (now + timedelta(minutes=2))
                    .isoformat()
                    .replace("+00:00", "Z"),
                },
            }
            delivery_body = canonical_json(delivery_value)
            delivery_nonce = "delivery_" + uuid.uuid4().hex
            delivery_status, delivery_response, _ = post(
                base_url + "/mail-edge/delivery",
                delivery_body,
                signed_headers(
                    delivery_body,
                    key_id=key_id,
                    key=key,
                    audience=selected.host_authentication.audience,
                    operation="application_delivery",
                    subject_id=delivery_id,
                    nonce=delivery_nonce,
                ),
            )
            duplicate_nonce = "duplicate_" + uuid.uuid4().hex
            duplicate_status, duplicate_response, _ = post(
                base_url + "/mail-edge/delivery",
                delivery_body,
                signed_headers(
                    delivery_body,
                    key_id=key_id,
                    key=key,
                    audience=selected.host_authentication.audience,
                    operation="application_delivery",
                    subject_id=delivery_id,
                    nonce=duplicate_nonce,
                ),
            )
            if (
                delivery_status != 200
                or duplicate_status != 200
                or delivery_response != duplicate_response
                or delivery_response.get("deliveryId") != delivery_id
                or edge.raw_downloads != 1
            ):
                raise RuntimeError(
                    "Mail Edge delivery callback was not durably idempotent: "
                    f"first={delivery_status}:{delivery_response!r}, "
                    f"duplicate={duplicate_status}:{duplicate_response!r}, "
                    f"raw_downloads={edge.raw_downloads}, "
                    f"stored_raw={edge.stored_raw_count}, "
                    f"outbound_intents={len(edge.outbound_intents)}"
                )
            if len(edge.outbound_intents) != 1 or edge.stored_raw_count != 1:
                raise RuntimeError(
                    "Mail Edge callback did not create one durable outbound intent"
                )

            with application.app_context():
                contact = Contact.filter_by(
                    alias_id=alias_id, website_email="sender@example.net"
                ).one()
                mailbox_address = contact.user.default_mailbox.email
                reply_address = contact.reply_email
            reverse_body = canonical_json(
                {
                    "tenantId": selected.tenant_id,
                    "envelope": {
                        "schemaVersion": "v1",
                        "mailFrom": mailbox_address,
                        "rcptTo": [{"address": reply_address}],
                        "smtpUtf8": False,
                    },
                    "raw": raw_reference,
                    "opaqueReplyToken": reply_address,
                }
            )
            reverse_nonce = "reverse_" + uuid.uuid4().hex
            reverse_status, reverse_response, _ = post(
                base_url + "/mail-edge/reverse-route",
                reverse_body,
                signed_headers(
                    reverse_body,
                    key_id=key_id,
                    key=key,
                    audience=selected.host_authentication.audience,
                    operation="reverse_route",
                    subject_id=raw_reference["blobId"],
                    nonce=reverse_nonce,
                ),
            )
            if reverse_status != 200 or reverse_response.get("envelope", {}).get(
                "rcptTo"
            ) != [{"address": "sender@example.net"}]:
                raise RuntimeError("Mail Edge reverse-route callback differed")

            intent_id = str(edge.outbound_intents[0]["intentId"])
            feedback_id = uuid7()
            feedback_body = canonical_json(
                {
                    "schemaVersion": "v1",
                    "feedbackEventId": feedback_id,
                    "tenantId": selected.tenant_id,
                    "intentId": intent_id,
                    "kind": "bounced",
                    "occurredAt": datetime.now(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "normalizedEvidence": {},
                }
            )
            feedback_nonce = "feedback_" + uuid.uuid4().hex
            feedback_status, feedback_response, _ = post(
                base_url + "/mail-edge/feedback",
                feedback_body,
                signed_headers(
                    feedback_body,
                    key_id=key_id,
                    key=key,
                    audience=selected.host_authentication.audience,
                    operation="application_feedback",
                    subject_id=feedback_id,
                    nonce=feedback_nonce,
                ),
            )
            expected_nonce_digests = {
                hashlib.sha256(value.encode("ascii")).hexdigest()
                for value in (
                    recipient_nonce,
                    delivery_nonce,
                    duplicate_nonce,
                    reverse_nonce,
                    feedback_nonce,
                )
            }
            with application.app_context():
                projection = MailEdgeOutboundProjection.filter_by(
                    tenant_id=selected.tenant_id, intent_id=intent_id
                ).one()
                durable_nonces = (
                    Session.query(MailEdgeReplayNonce)
                    .filter(MailEdgeReplayNonce.key_id == key_id)
                    .filter(
                        MailEdgeReplayNonce.nonce_digest.in_(expected_nonce_digests)
                    )
                    .count()
                )
                callback_after = Session.query(MailEdgeCallbackReceipt).count()
                outbound_after = Session.query(MailEdgeOutboundProjection).count()
            if (
                feedback_status != 200
                or feedback_response.get("deliveryId") != feedback_id
                or projection.feedback_kind != "bounced"
            ):
                raise RuntimeError("Mail Edge feedback callback was not projected")
            if durable_nonces != len(expected_nonce_digests):
                raise RuntimeError("Mail Edge callback nonces were not durable")
            if callback_after != callback_before + 2:
                raise RuntimeError("Mail Edge callback receipts were not durable")
            if outbound_after != outbound_before + 1:
                raise RuntimeError("Mail Edge outbound projection was not durable")
            if any(Path(selected.host_delivery.spool_directory).iterdir()):
                raise RuntimeError("Mail Edge raw spool leaked after callbacks")
            result = {
                "signed_callbacks": [
                    "recipient",
                    "delivery",
                    "reverse_route",
                    "feedback",
                ],
                "same_delivery_id_recovery": "passed",
                "raw_grant_downloads": edge.raw_downloads,
                "outbound_intents": len(edge.outbound_intents),
                "replay_rejection": "passed",
                "durable_nonces": durable_nonces,
                "spool_cleanup": "passed",
            }
    finally:
        if server is not None:
            server.shutdown()
            if thread is not None:
                thread.join(timeout=10)
                if thread.is_alive():
                    raise RuntimeError("Mail Edge callback proof server did not stop")
            server.server_close()
        if bridge is not None and not bridge.close(10):
            raise RuntimeError("Mail Edge callback proof bridge did not close")
        edge.close()
        os.environ["MAIL_EDGE_CONFIG_PATH"] = original_config_path
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("seed")
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("state_json")
    commands.add_parser("callback")
    arguments = parser.parse_args()
    with create_light_app().app_context():
        if arguments.command == "seed":
            result = seed()
        elif arguments.command == "verify":
            result = verify(arguments.state_json)
        else:
            result = None
    if arguments.command == "callback":
        result = callback()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
