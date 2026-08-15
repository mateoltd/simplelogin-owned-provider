from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from .contracts import TOKEN_RE, canonical_json, parse_rfc3339
from .errors import MailEdgeAuthenticationError


NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
OPERATIONS = frozenset(
    {"application_delivery", "application_feedback", "recipient_route", "reverse_route"}
)
HOST_SIGNATURE_HEADERS = {
    "schemaVersion": "x-mail-edge-signature-version",
    "algorithm": "x-mail-edge-signature-algorithm",
    "keyId": "x-mail-edge-key-id",
    "audience": "x-mail-edge-signature-audience",
    "subjectId": "x-mail-edge-subject-id",
    "nonce": "x-mail-edge-nonce",
    "bodySha256": "x-mail-edge-body-sha256",
    "operation": "x-mail-edge-operation",
    "timestamp": "x-mail-edge-timestamp",
    "signature": "x-mail-edge-signature",
}


@dataclass(frozen=True)
class HostSignature:
    key_id: str
    audience: str
    subject_id: str
    nonce: str
    body_sha256: str
    operation: str
    timestamp: str
    signature: str

    @property
    def claims(self) -> Mapping[str, Any]:
        return {
            "schemaVersion": "v1",
            "algorithm": "hmac-sha256",
            "keyId": self.key_id,
            "audience": self.audience,
            "subjectId": self.subject_id,
            "nonce": self.nonce,
            "bodySha256": self.body_sha256,
            "operation": self.operation,
            "timestamp": self.timestamp,
        }


def _reject() -> None:
    raise MailEdgeAuthenticationError("HOST_AUTHENTICATION_FAILED")


def parse_host_signature(value: Any) -> HostSignature:
    if isinstance(value, HostSignature):
        value = {**value.claims, "signature": value.signature}
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "algorithm",
        "keyId",
        "audience",
        "subjectId",
        "nonce",
        "bodySha256",
        "operation",
        "timestamp",
        "signature",
    }:
        _reject()
    if value["schemaVersion"] != "v1" or value["algorithm"] != "hmac-sha256":
        _reject()
    if not all(
        isinstance(value[field], str) and TOKEN_RE.fullmatch(value[field])
        for field in ("keyId", "audience", "subjectId")
    ):
        _reject()
    if not isinstance(value["nonce"], str) or not NONCE_RE.fullmatch(value["nonce"]):
        _reject()
    if not isinstance(value["bodySha256"], str) or not SHA256_RE.fullmatch(
        value["bodySha256"]
    ):
        _reject()
    if not isinstance(value["operation"], str) or value["operation"] not in OPERATIONS:
        _reject()
    try:
        parse_rfc3339(value["timestamp"], "HOST_TIMESTAMP_INVALID")
    except Exception:
        _reject()
    if not isinstance(value["signature"], str) or not SIGNATURE_RE.fullmatch(
        value["signature"]
    ):
        _reject()
    return HostSignature(
        key_id=value["keyId"],
        audience=value["audience"],
        subject_id=value["subjectId"],
        nonce=value["nonce"],
        body_sha256=value["bodySha256"],
        operation=value["operation"],
        timestamp=value["timestamp"],
        signature=value["signature"],
    )


def parse_host_signature_headers(headers: Mapping[str, Any]) -> HostSignature:
    if not callable(getattr(headers, "get", None)):
        _reject()
    value: dict[str, str] = {}
    for claim, header_name in HOST_SIGNATURE_HEADERS.items():
        getlist = getattr(headers, "getlist", None)
        if callable(getlist):
            observed = getlist(header_name)
            if len(observed) != 1:
                _reject()
            header_value = observed[0]
        else:
            header_value = headers.get(header_name)
        if not isinstance(header_value, str):
            _reject()
        value[claim] = header_value
    return parse_host_signature(value)


def _signing_input(signature: HostSignature) -> bytes:
    claims = dict(signature.claims)
    claims["context"] = "mail-edge-host-signature-v1"
    return canonical_json(claims)


def verify_host_signature(
    value: Any,
    *,
    keys: Mapping[str, bytes],
    audience: str,
    operation: str,
    subject_id: str,
    body: bytes,
    now: datetime,
    maximum_age_seconds: int,
    maximum_future_skew_seconds: int,
) -> HostSignature:
    if (
        not isinstance(audience, str)
        or not TOKEN_RE.fullmatch(audience)
        or not isinstance(operation, str)
        or operation not in OPERATIONS
        or not isinstance(subject_id, str)
        or not TOKEN_RE.fullmatch(subject_id)
        or not isinstance(body, bytes)
        or not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() is None
        or isinstance(maximum_age_seconds, bool)
        or not isinstance(maximum_age_seconds, int)
        or maximum_age_seconds < 1
        or isinstance(maximum_future_skew_seconds, bool)
        or not isinstance(maximum_future_skew_seconds, int)
        or maximum_future_skew_seconds < 0
    ):
        _reject()
    signed = parse_host_signature(value)
    key = keys.get(signed.key_id)
    if key is None or not 32 <= len(key) <= 1024:
        _reject()
    body_sha256 = hashlib.sha256(body).hexdigest()
    if not (
        hmac.compare_digest(signed.audience, audience)
        and hmac.compare_digest(signed.operation, operation)
        and hmac.compare_digest(signed.subject_id, subject_id)
        and hmac.compare_digest(signed.body_sha256, body_sha256)
    ):
        _reject()
    timestamp = datetime.fromisoformat(signed.timestamp.replace("Z", "+00:00"))
    current = now.astimezone(timezone.utc)
    delta = (timestamp.astimezone(timezone.utc) - current).total_seconds()
    if delta > maximum_future_skew_seconds or delta < -maximum_age_seconds:
        _reject()
    try:
        supplied = base64.urlsafe_b64decode(signed.signature + "=")
    except (binascii.Error, ValueError):
        _reject()
    canonical_signature = (
        base64.urlsafe_b64encode(supplied).rstrip(b"=").decode("ascii")
    )
    if not hmac.compare_digest(canonical_signature, signed.signature):
        _reject()
    expected = hmac.new(key, _signing_input(signed), hashlib.sha256).digest()
    if len(supplied) != len(expected) or not hmac.compare_digest(supplied, expected):
        _reject()
    return signed
