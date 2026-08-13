"""Provider-neutral mail-edge receipts, correlation, and feedback service."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass
from email.message import Message
from typing import Callable, Dict, Mapping, Optional, Tuple

import arrow
from arrow import Arrow
from flask import Flask, jsonify, request
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from app import config
from app.db import Session
from app.email import headers, status
from app.email_utils import get_verp_info_from_email
from app.models import (
    Bounce,
    EmailLog,
    MailEdgeReplayNonce,
    MailFeedbackReceipt,
    MailFeedbackReceiptState,
    MailIngressReceipt,
    MailIngressReceiptState,
    Mailbox,
    MessageIDMatching,
    Phase,
    ProviderComplaint,
    ProviderComplaintState,
    TransactionalEmail,
    TransportMessageIDMatching,
    User,
    VerpType,
)
from server import create_light_app


AUTH_KEY_ID_HEADER = "X-Mail-Edge-Key-Id"
AUTH_TIMESTAMP_HEADER = "X-Mail-Edge-Timestamp"
AUTH_NONCE_HEADER = "X-Mail-Edge-Nonce"
AUTH_SIGNATURE_HEADER = "X-Mail-Edge-Signature"

INGRESS_ID_HEADER = "X-SimpleLogin-Edge-Ingress-ID"
RESERVED_EDGE_HEADER_PREFIX = "x-simplelogin-edge-"

EVENT_TYPES = {
    "delivered",
    "delayed",
    "soft_bounce",
    "hard_bounce",
    "complaint",
    "rejected",
}
FEEDBACK_FIELDS = {
    "provider_event_id",
    "provider_message_id",
    "edge_delivery_id",
    "event_type",
    "recipient",
    "smtp_status",
    "diagnostic",
    "occurred_at",
}
MESSAGE_ID_MAP_FIELDS = {
    "edge_delivery_id",
    "provider_message_id",
    "submitted_message_id",
    "provider_visible_message_id",
    "original_envelope_from",
    "recipient",
}
KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
INGRESS_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class MailEdgeError(Exception):
    status_code = 400


class AuthenticationError(MailEdgeError):
    status_code = 401


class ReplayError(MailEdgeError):
    status_code = 409


class ConflictError(MailEdgeError):
    status_code = 409


class ValidationError(MailEdgeError):
    status_code = 422


class IngressConflict(ConflictError):
    pass


@dataclass(frozen=True)
class IngressClaim:
    should_process: bool
    state: str
    lease_token: Optional[str] = None
    smtp_status: Optional[str] = None


def _bounded_text(value, name: str, maximum: int, required: bool = False):
    if value is None:
        if required:
            raise ValidationError(f"{name} is required")
        return None
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValidationError(f"{name} is invalid")
    if any(ord(character) < 32 for character in value):
        raise ValidationError(f"{name} contains control characters")
    return value


def _parse_occurred_at(value: str) -> Arrow:
    _bounded_text(value, "occurred_at", 64, required=True)
    try:
        parsed = arrow.get(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError("occurred_at is invalid") from exc
    if parsed.tzinfo is None:
        raise ValidationError("occurred_at must include a timezone")
    return parsed.to("utc")


def _canonical_json(payload: Mapping) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _payload_digest(payload: Mapping) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _canonical_auth_request(
    key_id: str, method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    body_digest = hashlib.sha256(body).hexdigest()
    return "\n".join(
        (key_id, method.upper(), path, timestamp, nonce, body_digest)
    ).encode("utf-8")


def sign_request(
    key: bytes,
    key_id: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes = b"",
) -> str:
    """Create the lowercase hex signature used by the private core API."""

    return hmac.new(
        key,
        _canonical_auth_request(key_id, method, path, timestamp, nonce, body),
        hashlib.sha256,
    ).hexdigest()


def auth_headers(
    key_id: str,
    key: bytes,
    method: str,
    path: str,
    body: bytes = b"",
    timestamp: Optional[int] = None,
    nonce: Optional[str] = None,
) -> Dict[str, str]:
    """Build request headers for tests and neutral edge clients."""

    timestamp_value = str(timestamp if timestamp is not None else int(time.time()))
    nonce_value = nonce or secrets.token_urlsafe(24)
    return {
        AUTH_KEY_ID_HEADER: key_id,
        AUTH_TIMESTAMP_HEADER: timestamp_value,
        AUTH_NONCE_HEADER: nonce_value,
        AUTH_SIGNATURE_HEADER: sign_request(
            key, key_id, method, path, timestamp_value, nonce_value, body
        ),
    }


def _normalize_hmac_keys(keys: Mapping[str, object]) -> Dict[str, bytes]:
    normalized = {}
    for key_id, value in keys.items():
        if not isinstance(key_id, str) or not KEY_ID_RE.fullmatch(key_id):
            raise RuntimeError("MAIL_EDGE_HMAC_KEYS contains an invalid key ID")
        if isinstance(value, bytes):
            key = value
        elif isinstance(value, str):
            try:
                key = bytes.fromhex(value)
            except ValueError as exc:
                raise RuntimeError(
                    "MAIL_EDGE_HMAC_KEYS values must be hex-encoded"
                ) from exc
        else:
            raise RuntimeError("MAIL_EDGE_HMAC_KEYS values must be strings")
        if len(key) < 32:
            raise RuntimeError("MAIL_EDGE_HMAC_KEYS values must contain 32 bytes")
        normalized[key_id] = key
    if not normalized:
        raise RuntimeError("MAIL_EDGE_HMAC_KEYS must contain at least one key")
    return normalized


def _claim_replay_nonce(key_id: str, nonce: str, expires_at: Arrow, now: Arrow):
    MailEdgeReplayNonce.filter(MailEdgeReplayNonce.expires_at < now).delete(
        synchronize_session=False
    )
    MailEdgeReplayNonce.create(key_id=key_id, nonce=nonce, expires_at=expires_at)
    try:
        Session.commit()
    except IntegrityError as exc:
        Session.rollback()
        raise ReplayError("request nonce was already used") from exc


def authenticate_http_request(
    flask_request,
    keys: Mapping[str, bytes],
    now: Arrow,
    max_age_seconds: int,
    future_skew_seconds: int,
):
    key_id = flask_request.headers.get(AUTH_KEY_ID_HEADER, "")
    timestamp = flask_request.headers.get(AUTH_TIMESTAMP_HEADER, "")
    nonce = flask_request.headers.get(AUTH_NONCE_HEADER, "")
    signature = flask_request.headers.get(AUTH_SIGNATURE_HEADER, "")
    if not KEY_ID_RE.fullmatch(key_id) or key_id not in keys:
        raise AuthenticationError("request authentication failed")
    if not NONCE_RE.fullmatch(nonce):
        raise AuthenticationError("request authentication failed")
    try:
        timestamp_int = int(timestamp)
    except ValueError as exc:
        raise AuthenticationError("request authentication failed") from exc
    now_timestamp = int(now.timestamp)
    if timestamp_int < now_timestamp - max_age_seconds:
        raise AuthenticationError("request timestamp expired")
    if timestamp_int > now_timestamp + future_skew_seconds:
        raise AuthenticationError("request timestamp is in the future")
    supplied = signature.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", supplied):
        raise AuthenticationError("request authentication failed")
    body = flask_request.get_data(cache=True)
    expected = sign_request(
        keys[key_id],
        key_id,
        flask_request.method,
        flask_request.path,
        timestamp,
        nonce,
        body,
    )
    if not hmac.compare_digest(supplied, expected):
        raise AuthenticationError("request authentication failed")
    expires_at = now.shift(seconds=max_age_seconds + future_skew_seconds)
    _claim_replay_nonce(key_id, nonce, expires_at, now)


def strip_reserved_edge_headers(message: Message) -> None:
    """Remove every edge-reserved message header before domain processing."""

    for index in reversed(range(len(message._headers))):
        if message._headers[index][0].lower().startswith(RESERVED_EDGE_HEADER_PREFIX):
            del message._headers[index]


def strip_untrusted_internal_headers(message: Message) -> None:
    """Remove correlation and authentication claims from an untrusted SMTP hop."""

    reserved_exact = {
        headers.SL_QUEUE_ID.lower(),
        headers.AUTHENTICATION_RESULTS.lower(),
    }
    reserved_prefixes = (
        "x-simplelogin-",
        "x-rspamd-",
        "x-spamd-",
        "arc-authentication-results",
        "arc-message-signature",
        "arc-seal",
    )
    for index in reversed(range(len(message._headers))):
        name = message._headers[index][0].lower()
        if name in reserved_exact or name.startswith(reserved_prefixes):
            del message._headers[index]


def extract_ingress_id(message: Message, trusted_edge: bool) -> Optional[str]:
    values = message.get_all(INGRESS_ID_HEADER, [])
    strip_reserved_edge_headers(message)
    if not trusted_edge:
        strip_untrusted_internal_headers(message)
        return None
    if not values:
        return None
    if len(values) != 1:
        raise IngressConflict("trusted delivery has multiple ingress identifiers")
    value = str(values[0]).strip()
    if not INGRESS_ID_RE.fullmatch(value):
        raise IngressConflict("trusted delivery has an invalid ingress identifier")
    return value


def claim_ingress_receipt(
    ingress_id: str,
    message_digest: str,
    now: Optional[Arrow] = None,
    lease_seconds: Optional[int] = None,
) -> IngressClaim:
    """Acquire or recover the processing lease for an ingress delivery."""

    if not INGRESS_ID_RE.fullmatch(ingress_id):
        raise ValidationError("ingress_id is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", message_digest):
        raise ValidationError("message_digest is invalid")
    now = now or arrow.utcnow()
    lease_seconds = lease_seconds or config.MAIL_INGRESS_LEASE_SECONDS
    receipt = (
        MailIngressReceipt.query()
        .filter_by(ingress_id=ingress_id)
        .with_for_update()
        .first()
    )
    if receipt is None:
        token = secrets.token_hex(24)
        receipt = MailIngressReceipt.create(
            ingress_id=ingress_id,
            message_digest=message_digest,
            state=MailIngressReceiptState.processing.value,
            lease_token=token,
            lease_expires_at=now.shift(seconds=lease_seconds),
        )
        try:
            Session.commit()
            return IngressClaim(True, "processing", token)
        except IntegrityError:
            Session.rollback()
            return claim_ingress_receipt(
                ingress_id, message_digest, now=now, lease_seconds=lease_seconds
            )
    if receipt.message_digest != message_digest:
        Session.rollback()
        raise IngressConflict("ingress_id was already used for different content")
    state = MailIngressReceiptState(receipt.state)
    if state in (
        MailIngressReceiptState.completed,
        MailIngressReceiptState.rejected,
        MailIngressReceiptState.unknown,
    ):
        smtp_status = receipt.smtp_status
        Session.commit()
        return IngressClaim(False, state.name, smtp_status=smtp_status)
    if (
        state == MailIngressReceiptState.processing
        and receipt.lease_expires_at
        and receipt.lease_expires_at > now
    ):
        Session.commit()
        return IngressClaim(False, "processing", smtp_status=status.E408)

    token = secrets.token_hex(24)
    receipt.state = MailIngressReceiptState.processing.value
    receipt.lease_token = token
    receipt.lease_expires_at = now.shift(seconds=lease_seconds)
    receipt.smtp_status = None
    receipt.attempt_count += 1
    Session.commit()
    return IngressClaim(True, "processing", token)


def finish_ingress_receipt(
    ingress_id: str,
    lease_token: str,
    smtp_status: str,
    now: Optional[Arrow] = None,
) -> bool:
    now = now or arrow.utcnow()
    receipt = (
        MailIngressReceipt.query()
        .filter_by(ingress_id=ingress_id)
        .with_for_update()
        .first()
    )
    if (
        receipt is None
        or receipt.state != MailIngressReceiptState.processing.value
        or not lease_token
        or not hmac.compare_digest(receipt.lease_token or "", lease_token)
    ):
        Session.rollback()
        return False
    if smtp_status.startswith("2"):
        receipt.state = MailIngressReceiptState.completed.value
    elif smtp_status.startswith("5"):
        receipt.state = MailIngressReceiptState.rejected.value
    else:
        receipt.state = MailIngressReceiptState.unknown.value
    receipt.smtp_status = smtp_status[:512]
    receipt.lease_token = None
    receipt.lease_expires_at = None
    receipt.completed_at = now
    Session.commit()
    return True


def mark_ingress_unknown(
    ingress_id: str, lease_token: str, smtp_status: str = status.E404
) -> bool:
    return finish_ingress_receipt(ingress_id, lease_token, smtp_status)


def ingress_receipt_payload(receipt: MailIngressReceipt) -> Dict[str, object]:
    return {
        "ingress_id": receipt.ingress_id,
        "state": receipt.state_name,
        "smtp_status": receipt.smtp_status,
        "attempt_count": receipt.attempt_count,
        "lease_expires_at": (
            receipt.lease_expires_at.to("utc").isoformat()
            if receipt.lease_expires_at
            else None
        ),
        "completed_at": (
            receipt.completed_at.to("utc").isoformat() if receipt.completed_at else None
        ),
    }


def resolve_transport_message_id(message_id: str) -> str:
    """Translate a recipient-visible ID back to the ID submitted by SimpleLogin."""

    matching = TransportMessageIDMatching.get_by(provider_visible_message_id=message_id)
    return matching.submitted_message_id if matching else message_id


def replace_transport_message_ids(message: Message) -> None:
    """Translate known transport IDs in reply-thread headers in place."""

    for header_name in (headers.IN_REPLY_TO, headers.REFERENCES):
        values = message.get_all(header_name, [])
        if not values:
            continue
        translated_values = []
        for value in values:
            translated_values.append(
                " ".join(
                    resolve_transport_message_id(message_id)
                    for message_id in str(value).split()
                )
            )
        del message[header_name]
        for value in translated_values:
            message[header_name] = value


def _transport_context(envelope_from: str) -> Tuple[Optional[int], Optional[int]]:
    verp = get_verp_info_from_email(envelope_from)
    if not verp:
        raise ValidationError("original_envelope_from is not a valid signed VERP")
    verp_type, object_id = verp
    if verp_type in (VerpType.bounce_forward, VerpType.bounce_reply):
        email_log = EmailLog.get_by(id=object_id)
        if not email_log:
            raise ValidationError("original_envelope_from references no email log")
        return email_log.id, None
    if verp_type == VerpType.transactional:
        transactional = TransactionalEmail.get_by(id=object_id)
        return None, transactional.id if transactional else None
    raise ValidationError("original_envelope_from has an unsupported VERP type")


def _validate_message_id_map(payload: Mapping) -> Dict[str, object]:
    if not isinstance(payload, dict) or set(payload) - MESSAGE_ID_MAP_FIELDS:
        raise ValidationError("message-id-map contains unsupported fields")
    result = {
        "edge_delivery_id": _bounded_text(
            payload.get("edge_delivery_id"), "edge_delivery_id", 128, required=True
        ),
        "provider_message_id": _bounded_text(
            payload.get("provider_message_id"), "provider_message_id", 512
        ),
        "submitted_message_id": _bounded_text(
            payload.get("submitted_message_id"),
            "submitted_message_id",
            1024,
            required=True,
        ),
        "provider_visible_message_id": _bounded_text(
            payload.get("provider_visible_message_id"),
            "provider_visible_message_id",
            1024,
        ),
        "original_envelope_from": _bounded_text(
            payload.get("original_envelope_from"),
            "original_envelope_from",
            512,
            required=True,
        ),
        "recipient": _bounded_text(
            payload.get("recipient"), "recipient", 512, required=True
        ).lower(),
    }
    if not result["provider_message_id"] and not result["provider_visible_message_id"]:
        raise ValidationError(
            "provider_message_id or provider_visible_message_id is required"
        )
    return result


def _message_map_equal(
    matching: TransportMessageIDMatching, values: Mapping[str, object]
) -> bool:
    return all(getattr(matching, key) == value for key, value in values.items())


def register_message_id_mapping(
    payload: Mapping,
) -> Tuple[TransportMessageIDMatching, bool]:
    values = _validate_message_id_map(payload)
    matching = TransportMessageIDMatching.get_by(
        edge_delivery_id=values["edge_delivery_id"]
    )
    if matching:
        if not _message_map_equal(matching, values):
            raise ConflictError("edge_delivery_id already has a different mapping")
        apply_pending_feedback(matching)
        return matching, False

    email_log_id, transactional_email_id = _transport_context(
        values["original_envelope_from"]
    )
    existing_message_match = MessageIDMatching.get_by(
        sl_message_id=values["submitted_message_id"]
    )
    original_message_id = (
        existing_message_match.original_message_id
        if existing_message_match
        else values["submitted_message_id"]
    )
    persisted_values = {
        **values,
        "original_message_id": original_message_id,
        "email_log_id": email_log_id,
        "transactional_email_id": transactional_email_id,
    }
    matching = TransportMessageIDMatching.create(**persisted_values)
    try:
        Session.commit()
    except IntegrityError as exc:
        Session.rollback()
        matching = TransportMessageIDMatching.get_by(
            edge_delivery_id=values["edge_delivery_id"]
        )
        if matching and _message_map_equal(matching, values):
            apply_pending_feedback(matching)
            return matching, False
        raise ConflictError("message ID is already mapped") from exc
    apply_pending_feedback(matching)
    return matching, True


def _validate_feedback(payload: Mapping) -> Dict[str, object]:
    if not isinstance(payload, dict) or set(payload) - FEEDBACK_FIELDS:
        raise ValidationError("feedback contains unsupported fields")
    event_type = payload.get("event_type")
    if event_type not in EVENT_TYPES:
        raise ValidationError("event_type is invalid")
    edge_delivery_id = _bounded_text(
        payload.get("edge_delivery_id"), "edge_delivery_id", 128
    )
    provider_message_id = _bounded_text(
        payload.get("provider_message_id"), "provider_message_id", 512
    )
    if not edge_delivery_id and not provider_message_id:
        raise ValidationError("edge_delivery_id or provider_message_id is required")
    return {
        "provider_event_id": _bounded_text(
            payload.get("provider_event_id"),
            "provider_event_id",
            256,
            required=True,
        ),
        "provider_message_id": provider_message_id,
        "edge_delivery_id": edge_delivery_id,
        "event_type": event_type,
        "recipient": _bounded_text(
            payload.get("recipient"), "recipient", 512, required=True
        ).lower(),
        "smtp_status": _bounded_text(payload.get("smtp_status"), "smtp_status", 512),
        "diagnostic": _bounded_text(payload.get("diagnostic"), "diagnostic", 2048),
        "occurred_at": _parse_occurred_at(payload.get("occurred_at")),
    }


def _find_transport_matching(receipt: MailFeedbackReceipt):
    clauses = []
    if receipt.edge_delivery_id:
        clauses.append(
            TransportMessageIDMatching.edge_delivery_id == receipt.edge_delivery_id
        )
    if receipt.provider_message_id:
        clauses.append(
            TransportMessageIDMatching.provider_message_id
            == receipt.provider_message_id
        )
    if not clauses:
        return None
    matches = TransportMessageIDMatching.filter(or_(*clauses)).all()
    if len(matches) != 1:
        return None
    matching = matches[0]
    if (
        receipt.edge_delivery_id
        and matching.edge_delivery_id != receipt.edge_delivery_id
    ) or (
        receipt.provider_message_id
        and matching.provider_message_id != receipt.provider_message_id
    ):
        return None
    return matching


def _bounce_address(matching: TransportMessageIDMatching) -> str:
    if matching.email_log:
        email_log = matching.email_log
        if email_log.is_reply:
            return email_log.contact.website_email
        mailbox = email_log.mailbox or email_log.alias.mailbox
        return mailbox.email
    if matching.transactional_email:
        return matching.transactional_email.email
    return matching.recipient


def _apply_hard_bounce(
    matching: TransportMessageIDMatching, receipt: MailFeedbackReceipt, now: Arrow
):
    if matching.hard_bounce_applied_at:
        return
    bounce_info = "\n".join(
        value for value in (receipt.smtp_status, receipt.diagnostic) if value
    )
    Bounce.create(email=_bounce_address(matching), info=bounce_info or None)
    if matching.email_log:
        matching.email_log.bounced = True
        if not matching.email_log.is_reply:
            mailbox = matching.email_log.mailbox or matching.email_log.alias.mailbox
            matching.email_log.bounced_mailbox_id = mailbox.id
    matching.hard_bounce_applied_at = now


def _feedback_user(matching: TransportMessageIDMatching) -> Optional[User]:
    if matching.email_log:
        return matching.email_log.user
    recipient = matching.recipient
    user = User.get_by(email=recipient)
    if user:
        return user
    mailbox = Mailbox.get_by(email=recipient)
    return mailbox.user if mailbox else None


def _apply_complaint(matching: TransportMessageIDMatching, now: Arrow):
    if matching.complaint_applied_at:
        return
    user = _feedback_user(matching)
    if not user:
        raise ValidationError("complaint cannot be correlated to a user")
    phase = Phase.unknown
    if matching.email_log:
        phase = Phase.reply if matching.email_log.is_reply else Phase.forward
    ProviderComplaint.create(
        user_id=user.id,
        state=ProviderComplaintState.new.value,
        phase=phase.value,
    )
    matching.complaint_applied_at = now


def apply_feedback_receipt(receipt: MailFeedbackReceipt) -> bool:
    if receipt.state != MailFeedbackReceiptState.pending.value:
        return receipt.state == MailFeedbackReceiptState.applied.value
    matching = _find_transport_matching(receipt)
    if not matching:
        return False
    if receipt.recipient.lower() != matching.recipient.lower():
        receipt.state = MailFeedbackReceiptState.rejected.value
        receipt.rejection_reason = "recipient does not match transport mapping"
        receipt.applied_at = arrow.utcnow()
        Session.commit()
        return False

    matching = (
        TransportMessageIDMatching.query()
        .filter_by(id=matching.id)
        .with_for_update()
        .one()
    )
    now = arrow.utcnow()
    if receipt.event_type in ("hard_bounce", "rejected"):
        _apply_hard_bounce(matching, receipt, now)
    elif receipt.event_type == "complaint":
        _apply_complaint(matching, now)
    receipt.transport_matching_id = matching.id
    receipt.state = MailFeedbackReceiptState.applied.value
    receipt.applied_at = now
    Session.commit()
    return True


def apply_pending_feedback(matching: TransportMessageIDMatching) -> int:
    clauses = [
        MailFeedbackReceipt.edge_delivery_id == matching.edge_delivery_id,
    ]
    if matching.provider_message_id:
        clauses.append(
            MailFeedbackReceipt.provider_message_id == matching.provider_message_id
        )
    pending = MailFeedbackReceipt.filter(
        MailFeedbackReceipt.state == MailFeedbackReceiptState.pending.value,
        or_(*clauses),
    ).all()
    return sum(1 for receipt in pending if apply_feedback_receipt(receipt))


def record_feedback(payload: Mapping) -> Tuple[MailFeedbackReceipt, bool]:
    values = _validate_feedback(payload)
    digest = _payload_digest(payload)
    receipt = MailFeedbackReceipt.get_by(provider_event_id=values["provider_event_id"])
    created = False
    if receipt:
        if receipt.payload_digest != digest:
            raise ConflictError("provider_event_id already has different feedback")
    else:
        receipt = MailFeedbackReceipt.create(payload_digest=digest, **values)
        try:
            Session.commit()
            created = True
        except IntegrityError:
            Session.rollback()
            receipt = MailFeedbackReceipt.get_by(
                provider_event_id=values["provider_event_id"]
            )
            if not receipt or receipt.payload_digest != digest:
                raise ConflictError("provider_event_id already has different feedback")
    apply_feedback_receipt(receipt)
    return receipt, created


def feedback_receipt_payload(receipt: MailFeedbackReceipt) -> Dict[str, object]:
    return {
        "provider_event_id": receipt.provider_event_id,
        "state": receipt.state_name,
        "event_type": receipt.event_type,
        "edge_delivery_id": receipt.edge_delivery_id,
        "applied_at": (
            receipt.applied_at.to("utc").isoformat() if receipt.applied_at else None
        ),
        "rejection_reason": receipt.rejection_reason,
    }


def message_id_map_payload(
    matching: TransportMessageIDMatching,
) -> Dict[str, object]:
    return {
        "edge_delivery_id": matching.edge_delivery_id,
        "provider_message_id": matching.provider_message_id,
        "provider_visible_message_id": matching.provider_visible_message_id,
        "submitted_message_id": matching.submitted_message_id,
        "original_message_id": matching.original_message_id,
    }


def _json_body() -> Mapping:
    if not request.is_json:
        raise ValidationError("application/json is required")
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise ValidationError("JSON object is required")
    return payload


def create_app(
    hmac_keys: Optional[Mapping[str, object]] = None,
    now: Callable[[], Arrow] = arrow.utcnow,
) -> Flask:
    app = create_light_app()
    app.config["MAX_CONTENT_LENGTH"] = config.MAIL_EDGE_MAX_REQUEST_BYTES
    keys = _normalize_hmac_keys(hmac_keys or config.MAIL_EDGE_HMAC_KEYS)

    @app.before_request
    def authenticate_mail_edge():
        if request.path == "/health":
            return None
        try:
            authenticate_http_request(
                request,
                keys,
                now(),
                config.MAIL_EDGE_AUTH_MAX_AGE_SECONDS,
                config.MAIL_EDGE_AUTH_FUTURE_SKEW_SECONDS,
            )
        except MailEdgeError as exc:
            return jsonify(error=str(exc)), exc.status_code
        return None

    @app.errorhandler(MailEdgeError)
    def handle_mail_edge_error(exc):
        Session.rollback()
        return jsonify(error=str(exc)), exc.status_code

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify(ok=True)

    @app.route("/v1/feedback", methods=["POST"])
    def feedback():
        receipt, created = record_feedback(_json_body())
        response_status = 201 if created else 200
        if receipt.state == MailFeedbackReceiptState.pending.value:
            response_status = 202
        elif receipt.state == MailFeedbackReceiptState.rejected.value:
            response_status = 422
        return jsonify(feedback_receipt_payload(receipt)), response_status

    @app.route("/v1/message-id-map", methods=["POST"])
    def message_id_map():
        matching, created = register_message_id_mapping(_json_body())
        return jsonify(message_id_map_payload(matching)), 201 if created else 200

    @app.route("/v1/ingress/<ingress_id>", methods=["GET"])
    def ingress(ingress_id: str):
        if not INGRESS_ID_RE.fullmatch(ingress_id):
            raise ValidationError("ingress_id is invalid")
        receipt = MailIngressReceipt.get_by(ingress_id=ingress_id)
        if not receipt:
            return jsonify(error="ingress receipt not found"), 404
        return jsonify(ingress_receipt_payload(receipt))

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=7781)
