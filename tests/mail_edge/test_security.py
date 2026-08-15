import base64
import hashlib
import hmac
from datetime import datetime, timezone

import pytest

from app.mail_edge.configuration import HostAuthentication
from app.mail_edge.errors import MailEdgeAuthenticationError
from app.mail_edge.host_services import AuthenticatedHostOperations
from app.mail_edge.security import (
    _signing_input,
    parse_host_signature,
    verify_host_signature,
)


def test_exact_mail_edge_node_signature_fixture():
    signed = parse_host_signature(
        {
            "schemaVersion": "v1",
            "algorithm": "hmac-sha256",
            "audience": "host-callback",
            "bodySha256": "a" * 64,
            "keyId": "key-2026-08",
            "nonce": "abcdefghijklmnop",
            "operation": "application_delivery",
            "subjectId": "delivery-01890f31",
            "timestamp": "2026-08-13T12:00:00Z",
            "signature": "usqapbv5pm6HJnKiovdyHqUf-D8dieWBk4kAxgX0QEw",
        }
    )
    calculated = (
        base64.urlsafe_b64encode(
            hmac.new(
                bytes([0x5A]) * 32, _signing_input(signed), hashlib.sha256
            ).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    assert calculated == signed.signature


def _signed(body: bytes):
    value = {
        "schemaVersion": "v1",
        "algorithm": "hmac-sha256",
        "audience": "host-callback",
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "keyId": "key-2026-08",
        "nonce": "abcdefghijklmnop",
        "operation": "application_delivery",
        "subjectId": "delivery-01890f31",
        "timestamp": "2026-08-13T12:00:00Z",
        "signature": "A" * 43,
    }
    parsed = parse_host_signature(value)
    value["signature"] = (
        base64.urlsafe_b64encode(
            hmac.new(b"Z" * 32, _signing_input(parsed), hashlib.sha256).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    return value


def test_signature_verifies_body_context_and_timestamp_and_rejects_replay_inputs():
    body = b'{"schemaVersion":"v1"}'
    signed = _signed(body)
    verified = verify_host_signature(
        signed,
        keys={"key-2026-08": b"Z" * 32},
        audience="host-callback",
        operation="application_delivery",
        subject_id="delivery-01890f31",
        body=body,
        now=datetime(2026, 8, 13, 12, 1, tzinfo=timezone.utc),
        maximum_age_seconds=300,
        maximum_future_skew_seconds=30,
    )
    assert verified.nonce == "abcdefghijklmnop"
    for changed in (
        {**signed, "audience": "another-host"},
        {**signed, "bodySha256": "b" * 64},
        {**signed, "signature": signed["signature"][:-1] + "A"},
    ):
        with pytest.raises(MailEdgeAuthenticationError):
            verify_host_signature(
                changed,
                keys={"key-2026-08": b"Z" * 32},
                audience="host-callback",
                operation="application_delivery",
                subject_id="delivery-01890f31",
                body=body,
                now=datetime(2026, 8, 13, 12, 1, tzinfo=timezone.utc),
                maximum_age_seconds=300,
                maximum_future_skew_seconds=30,
            )
    with pytest.raises(MailEdgeAuthenticationError):
        verify_host_signature(
            signed,
            keys={"key-2026-08": b"Z" * 32},
            audience="host-callback",
            operation="application_delivery",
            subject_id="delivery-01890f31",
            body=body,
            now=datetime(2026, 8, 13, 13, 0, tzinfo=timezone.utc),
            maximum_age_seconds=300,
            maximum_future_skew_seconds=30,
        )


def test_malformed_signature_values_always_fail_as_authentication_errors():
    with pytest.raises(MailEdgeAuthenticationError):
        parse_host_signature({**_signed(b"body"), "operation": {}})


def test_replay_nonce_lifetime_covers_the_signed_timestamp_window():
    consumed = []

    class Nonces:
        def consume(self, key_id, nonce, expires_at):
            consumed.append((key_id, nonce, expires_at))

    body = b"body"
    AuthenticatedHostOperations(
        HostAuthentication("host-callback", 300, 30, {"key-2026-08": b"Z" * 32}),
        Nonces(),
    ).verify(
        _signed(body),
        operation="application_delivery",
        subject_id="delivery-01890f31",
        body=body,
        now=datetime(2026, 8, 13, 11, 59, 45, tzinfo=timezone.utc),
    )
    assert consumed[0][2] == datetime(2026, 8, 13, 12, 5, tzinfo=timezone.utc)
