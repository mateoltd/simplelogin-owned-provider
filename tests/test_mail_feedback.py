import asyncio
import hashlib
import json
import uuid
from types import SimpleNamespace

import arrow
from aiosmtpd.smtp import Envelope
from email.message import EmailMessage

import email_handler
from app.email import headers, status
from app.email_utils import generate_verp_email
from app.mail_feedback import (
    INGRESS_ID_HEADER,
    IngressConflict,
    auth_headers,
    claim_ingress_receipt,
    create_app,
    finish_ingress_receipt,
    mark_ingress_unknown,
    replace_transport_message_ids,
)
from app.models import (
    Alias,
    Bounce,
    Contact,
    EmailLog,
    MailFeedbackReceipt,
    MailFeedbackReceiptState,
    MailIngressReceipt,
    MailIngressReceiptState,
    MessageIDMatching,
    ProviderComplaint,
    TransportMessageIDMatching,
    VerpType,
)
from tests.utils import create_new_user, random_email


NOW = arrow.get("2026-08-13T08:00:00Z")
KEYS = {
    "edge-current": bytes.fromhex("11" * 32),
    "edge-next": bytes.fromhex("22" * 32),
}
RUN_ID = uuid.uuid4().hex


def _body(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _signed_request(
    client,
    method,
    path,
    payload=None,
    key_id="edge-current",
    nonce="nonce-0000000000000001",
    timestamp=None,
    key=None,
):
    body = b"" if payload is None else _body(payload)
    request_nonce = f"{nonce or 'nonce'}-{RUN_ID}"
    request_headers = auth_headers(
        key_id,
        key or KEYS[key_id],
        method,
        path,
        body=body,
        timestamp=timestamp if timestamp is not None else int(NOW.timestamp),
        nonce=request_nonce,
    )
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    return client.open(path, method=method, data=body, headers=request_headers)


def _feedback_client(flask_client):
    app = create_app(KEYS, now=lambda: NOW)
    app.config["TESTING"] = True
    return app.test_client()


def _unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex}"


def _email_log(is_reply=False):
    user = create_new_user()
    alias = Alias.create_new_random(user)
    contact = Contact.create(
        user_id=user.id,
        alias_id=alias.id,
        website_email=random_email(),
        reply_email=random_email(),
        commit=True,
    )
    email_log = EmailLog.create(
        user_id=user.id,
        alias_id=alias.id,
        contact_id=contact.id,
        mailbox_id=user.default_mailbox_id,
        is_reply=is_reply,
        message_id="<original@example.net>",
        commit=True,
    )
    return user, alias, contact, email_log


def _mapping_payload(email_log, recipient, suffix="one"):
    verp_type = VerpType.bounce_reply if email_log.is_reply else VerpType.bounce_forward
    return {
        "edge_delivery_id": f"delivery-{suffix}",
        "provider_message_id": f"transport-{suffix}",
        "submitted_message_id": f"<submitted-{suffix}@example.net>",
        "provider_visible_message_id": f"<visible-{suffix}@example.net>",
        "original_envelope_from": generate_verp_email(verp_type, email_log.id),
        "recipient": recipient,
    }


def _feedback_payload(mapping, event_type, suffix="one", occurred_at=None):
    return {
        "provider_event_id": f"event-{event_type}-{suffix}",
        "provider_message_id": mapping["provider_message_id"],
        "edge_delivery_id": mapping["edge_delivery_id"],
        "event_type": event_type,
        "recipient": mapping["recipient"],
        "smtp_status": "550 5.1.1",
        "diagnostic": "recipient rejected",
        "occurred_at": occurred_at or NOW.isoformat(),
    }


def test_hmac_replay_expiry_forgery_and_key_rotation(flask_client):
    client = _feedback_client(flask_client)
    path = f"/v1/ingress/{_unique('not-found')}"
    replay_nonce = _unique("nonce")

    current = _signed_request(client, "GET", path, nonce=replay_nonce)
    assert current.status_code == 404
    replay = _signed_request(client, "GET", path, nonce=replay_nonce)
    assert replay.status_code == 409

    next_key = _signed_request(
        client,
        "GET",
        path,
        key_id="edge-next",
        nonce=_unique("nonce"),
    )
    assert next_key.status_code == 404

    expired = _signed_request(
        client,
        "GET",
        path,
        nonce=_unique("nonce"),
        timestamp=int(NOW.timestamp) - 301,
    )
    assert expired.status_code == 401

    forged = _signed_request(
        client,
        "GET",
        path,
        nonce=_unique("nonce"),
        key=bytes.fromhex("33" * 32),
    )
    assert forged.status_code == 401


def test_feedback_before_mapping_applies_once_after_correlation(flask_client):
    client = _feedback_client(flask_client)
    user, alias, contact, email_log = _email_log(is_reply=True)
    suffix = _unique("bounce")
    mapping = _mapping_payload(email_log, contact.website_email, suffix=suffix)
    feedback = _feedback_payload(mapping, "hard_bounce", suffix=suffix)
    email_log_id = email_log.id
    contact_email = contact.website_email

    pending = _signed_request(
        client,
        "POST",
        "/v1/feedback",
        feedback,
        nonce="nonce-0000000000000010",
    )
    assert pending.status_code == 202
    assert pending.get_json()["state"] == "pending"
    assert not EmailLog.get(email_log_id).bounced

    mapped = _signed_request(
        client,
        "POST",
        "/v1/message-id-map",
        mapping,
        nonce="nonce-0000000000000011",
    )
    assert mapped.status_code == 201
    assert mapped.get_json()["original_message_id"] == mapping["submitted_message_id"]
    assert EmailLog.get(email_log_id).bounced
    assert Bounce.filter_by(email=contact_email).count() == 1
    receipt = MailFeedbackReceipt.get_by(
        provider_event_id=feedback["provider_event_id"]
    )
    assert receipt.state == MailFeedbackReceiptState.applied.value

    duplicate_map = _signed_request(
        client,
        "POST",
        "/v1/message-id-map",
        mapping,
        nonce="nonce-0000000000000012",
    )
    assert duplicate_map.status_code == 200

    duplicate = _signed_request(
        client,
        "POST",
        "/v1/feedback",
        feedback,
        nonce="nonce-0000000000000014",
    )
    assert duplicate.status_code == 200
    assert Bounce.filter_by(email=contact_email).count() == 1

    older_delivery = _feedback_payload(
        mapping,
        "delivered",
        suffix=suffix,
        occurred_at=NOW.shift(minutes=-10).isoformat(),
    )
    delivered = _signed_request(
        client,
        "POST",
        "/v1/feedback",
        older_delivery,
        nonce="nonce-0000000000000016",
    )
    assert delivered.status_code == 201
    assert EmailLog.get(email_log_id).bounced

    conflicting_feedback = {**feedback, "diagnostic": "different outcome"}
    conflict = _signed_request(
        client,
        "POST",
        "/v1/feedback",
        conflicting_feedback,
        nonce="nonce-0000000000000015",
    )
    assert conflict.status_code == 409


def test_message_mapping_rejects_a_conflicting_reuse(flask_client):
    client = _feedback_client(flask_client)
    user, alias, contact, email_log = _email_log(is_reply=True)
    suffix = _unique("map-conflict")
    mapping = _mapping_payload(email_log, contact.website_email, suffix=suffix)
    created = _signed_request(
        client,
        "POST",
        "/v1/message-id-map",
        mapping,
        nonce="nonce-0000000000000017",
    )
    assert created.status_code == 201

    conflicting_map = {**mapping, "recipient": random_email()}
    conflict = _signed_request(
        client,
        "POST",
        "/v1/message-id-map",
        conflicting_map,
        nonce="nonce-0000000000000018",
    )
    assert conflict.status_code == 409


def test_complaint_is_idempotent_and_recipient_is_bound(flask_client):
    client = _feedback_client(flask_client)
    user, alias, contact, email_log = _email_log(is_reply=True)
    suffix = _unique("complaint")
    mapping = _mapping_payload(email_log, contact.website_email, suffix=suffix)
    user_id = user.id
    created = _signed_request(
        client,
        "POST",
        "/v1/message-id-map",
        mapping,
        nonce="nonce-0000000000000020",
    )
    assert created.status_code == 201

    forged_feedback = _feedback_payload(mapping, "complaint", suffix=f"forged-{suffix}")
    forged_feedback["recipient"] = random_email()
    rejected = _signed_request(
        client,
        "POST",
        "/v1/feedback",
        forged_feedback,
        nonce="nonce-0000000000000021",
    )
    assert rejected.status_code == 422
    assert ProviderComplaint.filter_by(user_id=user_id).count() == 0

    complaint = _feedback_payload(mapping, "complaint", suffix=f"real-{suffix}")
    accepted = _signed_request(
        client,
        "POST",
        "/v1/feedback",
        complaint,
        nonce="nonce-0000000000000022",
    )
    assert accepted.status_code == 201
    assert ProviderComplaint.filter_by(user_id=user_id).count() == 1

    duplicate = _signed_request(
        client,
        "POST",
        "/v1/feedback",
        complaint,
        nonce="nonce-0000000000000023",
    )
    assert duplicate.status_code == 200
    assert ProviderComplaint.filter_by(user_id=user_id).count() == 1


def test_provider_native_payload_is_rejected(flask_client):
    client = _feedback_client(flask_client)
    suffix = _unique("native")
    payload = {
        "provider_event_id": f"event-{suffix}",
        "edge_delivery_id": f"delivery-{suffix}",
        "event_type": "delivered",
        "recipient": random_email(),
        "occurred_at": NOW.isoformat(),
        "native_event": {"type": "vendor-specific"},
    }
    response = _signed_request(
        client,
        "POST",
        "/v1/feedback",
        payload,
        nonce="nonce-0000000000000030",
    )
    assert response.status_code == 422
    assert MailFeedbackReceipt.get_by(provider_event_id=f"event-{suffix}") is None


def test_transport_ids_feed_existing_thread_resolution(flask_client):
    user, alias, contact, email_log = _email_log(is_reply=True)
    suffix = uuid.uuid4().hex
    submitted = f"<submitted-{suffix}@example.net>"
    original = f"<original-{suffix}@example.net>"
    visible = f"<visible-{suffix}@example.net>"
    MessageIDMatching.create(
        sl_message_id=submitted,
        original_message_id=original,
        email_log_id=email_log.id,
        commit=True,
    )
    TransportMessageIDMatching.create(
        edge_delivery_id=f"delivery-{suffix}",
        provider_message_id=f"transport-{suffix}",
        provider_visible_message_id=visible,
        submitted_message_id=submitted,
        original_message_id=original,
        original_envelope_from=generate_verp_email(VerpType.bounce_reply, email_log.id),
        recipient=contact.website_email,
        email_log_id=email_log.id,
        commit=True,
    )
    message = EmailMessage()
    message[headers.IN_REPLY_TO] = visible
    message[headers.REFERENCES] = f"<older@example.net> {visible}"

    replace_transport_message_ids(message)
    email_handler.replace_sl_message_id_by_original_message_id(message)

    assert message[headers.IN_REPLY_TO] == original
    assert message[headers.REFERENCES] == f"<older@example.net> {original}"


def test_ingress_receipt_lease_recovery_and_conflict(flask_client):
    digest = hashlib.sha256(b"message").hexdigest()
    ingress_id = _unique("ingress-lease")
    first = claim_ingress_receipt(ingress_id, digest, now=NOW, lease_seconds=30)
    assert first.should_process
    duplicate = claim_ingress_receipt(
        ingress_id, digest, now=NOW.shift(seconds=1), lease_seconds=30
    )
    assert not duplicate.should_process
    assert duplicate.smtp_status == status.E408

    recovered = claim_ingress_receipt(
        ingress_id, digest, now=NOW.shift(seconds=31), lease_seconds=30
    )
    assert recovered.should_process
    assert recovered.lease_token != first.lease_token
    assert finish_ingress_receipt(
        ingress_id, recovered.lease_token, status.E200, now=NOW.shift(seconds=32)
    )
    completed = claim_ingress_receipt(
        ingress_id, digest, now=NOW.shift(seconds=40), lease_seconds=30
    )
    assert not completed.should_process
    assert completed.state == "completed"
    assert completed.smtp_status == status.E200
    assert MailIngressReceipt.get_by(ingress_id=ingress_id).attempt_count == 2

    try:
        claim_ingress_receipt(ingress_id, hashlib.sha256(b"other").hexdigest(), now=NOW)
    except IngressConflict:
        pass
    else:
        raise AssertionError("reusing ingress_id with different content must fail")

    unknown_id = _unique("ingress-unknown")
    unknown = claim_ingress_receipt(unknown_id, digest, now=NOW)
    assert mark_ingress_unknown(unknown_id, unknown.lease_token)
    retried = claim_ingress_receipt(unknown_id, digest, now=NOW.shift(seconds=1))
    assert not retried.should_process
    assert retried.state == "unknown"

    rejected_id = _unique("ingress-rejected")
    rejected = claim_ingress_receipt(rejected_id, digest, now=NOW)
    assert finish_ingress_receipt(rejected_id, rejected.lease_token, status.E510)
    duplicate_rejection = claim_ingress_receipt(
        rejected_id, digest, now=NOW.shift(seconds=1)
    )
    assert not duplicate_rejection.should_process
    assert duplicate_rejection.state == "rejected"
    assert duplicate_rejection.smtp_status == status.E510


def _envelope(ingress_id, extra_headers=None):
    message = EmailMessage()
    message["From"] = "sender@example.net"
    message["To"] = "alias@example.net"
    message[INGRESS_ID_HEADER] = ingress_id
    for name, value in extra_headers or []:
        message[name] = value
    message.set_content("mail edge ingress")
    envelope = Envelope()
    envelope.mail_from = "sender@example.net"
    envelope.rcpt_tos = ["alias@example.net"]
    envelope.original_content = message.as_bytes()
    return envelope


def test_mail_handler_deduplicates_and_recovers_unknown_data(flask_client, monkeypatch):
    handler = email_handler.MailHandler()
    session = SimpleNamespace(peer=("10.10.0.4", 25000))
    calls = []

    def successful_handle(envelope, message):
        calls.append(message)
        assert message.get(INGRESS_ID_HEADER) is None
        return status.E200

    monkeypatch.setattr(handler, "_handle", successful_handle)
    duplicate_id = _unique("ingress-handler-duplicate")
    envelope = _envelope(duplicate_id)
    assert asyncio.run(handler.handle_DATA(None, session, envelope)) == status.E200
    assert asyncio.run(handler.handle_DATA(None, session, envelope)) == status.E200
    assert len(calls) == 1
    conflicting_envelope = _envelope(duplicate_id)
    conflicting_envelope.original_content += b"\r\ndifferent"
    assert (
        asyncio.run(handler.handle_DATA(None, session, conflicting_envelope))
        == status.E527
    )
    assert len(calls) == 1

    ambiguous_headers = _envelope(
        _unique("ingress-ambiguous"),
        [(INGRESS_ID_HEADER, _unique("second-ingress"))],
    )
    assert (
        asyncio.run(handler.handle_DATA(None, session, ambiguous_headers))
        == status.E527
    )
    assert len(calls) == 1

    crashing = email_handler.MailHandler()

    def crash(envelope, message):
        raise RuntimeError("simulated DATA acknowledgement loss")

    monkeypatch.setattr(crashing, "_handle", crash)
    crash_id = _unique("ingress-handler-crash")
    crash_envelope = _envelope(crash_id)
    assert (
        asyncio.run(crashing.handle_DATA(None, session, crash_envelope)) == status.E404
    )
    receipt = MailIngressReceipt.get_by(ingress_id=crash_id)
    assert receipt.state == MailIngressReceiptState.unknown.value

    monkeypatch.setattr(crashing, "_handle", successful_handle)
    assert (
        asyncio.run(crashing.handle_DATA(None, session, crash_envelope)) == status.E404
    )
    receipt = MailIngressReceipt.get_by(ingress_id=crash_id)
    assert receipt.state == MailIngressReceiptState.unknown.value
    assert receipt.attempt_count == 1


def test_forged_internal_headers_are_stripped_from_untrusted_smtp(
    flask_client, monkeypatch
):
    handler = email_handler.MailHandler()
    captured = []

    def capture(envelope, message):
        captured.append(message)
        return status.E200

    forged_ingress_id = _unique("ingress-forged")
    monkeypatch.setattr(handler, "_handle", capture)
    envelope = _envelope(
        forged_ingress_id,
        [
            (headers.SL_EMAIL_LOG_ID, "123"),
            (headers.SPAMD_RESULT, "spf=pass"),
            (headers.AUTHENTICATION_RESULTS, "forged.example; dkim=pass"),
        ],
    )
    untrusted = SimpleNamespace(peer=("203.0.113.8", 25000))
    assert asyncio.run(handler.handle_DATA(None, untrusted, envelope)) == status.E200
    assert len(captured) == 1
    message = captured[0]
    assert message.get(INGRESS_ID_HEADER) is None
    assert message.get(headers.SL_EMAIL_LOG_ID) is None
    assert message.get(headers.SPAMD_RESULT) is None
    assert message.get(headers.AUTHENTICATION_RESULTS) is None
    assert MailIngressReceipt.get_by(ingress_id=forged_ingress_id) is None
