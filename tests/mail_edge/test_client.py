import hashlib
import io
import json

import pytest
import requests

from app.mail_edge.client import CircuitBreaker, MailEdgeClient
from app.mail_edge.configuration import (
    HostAuthentication,
    HttpLimits,
    MailEdgeConfiguration,
)
from app.mail_edge.contracts import SmtpEnvelope, SmtpRecipient
from app.mail_edge.errors import (
    MailEdgeAmbiguousDeliveryError,
    MailEdgeContractError,
    MailEdgeUnavailableError,
)


TENANT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401111"
BINDING_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401112"
INSTANCE_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401113"
INTENT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401114"
REPLAY_BLOB_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401115"


class Response:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class StreamingResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body
        self.closed = False

    def iter_content(self, chunk_size):
        yield self._body

    def close(self):
        self.closed = True


class Session:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def configuration(retries=1):
    return MailEdgeConfiguration(
        tenant_id=TENANT_ID,
        base_url="http://edge.internal",
        bearer_token="b" * 32,
        opaque_token_key=b"o" * 32,
        maximum_raw_bytes=26214400,
        http=HttpLimits(1, 5, 2, 3, 10, retries),
        host_authentication=HostAuthentication("host", 300, 30, {"key": b"k" * 32}),
    )


def raw_ref(raw):
    return {
        "schemaVersion": "v1",
        "blobId": BINDING_ID,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "mediaType": "message/rfc822",
    }


def binding():
    return {
        "schemaVersion": "v1",
        "bindingId": BINDING_ID,
        "bindingVersion": 1,
        "tenantId": TENANT_ID,
        "domainALabel": "example.com",
        "direction": "outbound",
        "providerId": "provider-neutral",
        "adapterVersion": "v1",
        "providerInstanceId": INSTANCE_ID,
        "providerResourceIds": {},
        "capabilityDigest": "c" * 64,
        "configRevision": "revision-1",
        "createdAt": "2026-08-13T12:00:00Z",
    }


def intent(raw, envelope):
    reference = raw_ref(raw)
    return {
        "schemaVersion": "v1",
        "intentId": INTENT_ID,
        "tenantId": TENANT_ID,
        "raw": reference,
        "envelope": dict(envelope.to_wire()),
        "primaryBinding": binding(),
        "fallbackBindings": [],
        "transmissionRaw": reference,
        "fingerprint": "f" * 64,
        "state": "accepted",
        "createdAt": "2026-08-13T12:00:00Z",
        "version": 0,
    }


def test_stream_contract_and_durable_intent_use_same_bounded_idempotency_key():
    raw = b"From: sender@example.net\r\nTo: Alias@example.com\r\n\r\nhello"
    envelope = SmtpEnvelope(
        "bounce@example.com", (SmtpRecipient("target@example.net"),), False
    )
    session = Session(
        [Response(201, raw_ref(raw)), Response(202, intent(raw, envelope))]
    )
    client = MailEdgeClient(configuration(), session=session)
    result = client.submit_message(envelope, raw, idempotency_key="stable-key")
    assert result.intent_id == INTENT_ID
    assert session.calls[0][2]["headers"]["Content-Type"] == "message/rfc822"
    assert session.calls[0][2]["allow_redirects"] is False
    assert session.calls[1][2]["headers"]["Idempotency-Key"] == "stable-key"
    assert json.loads(session.calls[1][2]["data"])["raw"] == raw_ref(raw)


def test_intent_replay_accepts_a_new_blob_identity_for_identical_raw_content():
    raw = b"message"
    envelope = SmtpEnvelope(
        "bounce@example.com", (SmtpRecipient("target@example.net"),), False
    )
    uploaded = {**raw_ref(raw), "blobId": REPLAY_BLOB_ID}
    session = Session([Response(201, uploaded), Response(200, intent(raw, envelope))])
    result = MailEdgeClient(configuration(), session=session).submit_message(
        envelope, raw, idempotency_key="stable-key"
    )
    assert result.raw.blob_id == BINDING_ID


def test_tenant_scoped_status_read_uses_exact_intent_contract():
    raw = b"message"
    envelope = SmtpEnvelope(
        "bounce@example.com", (SmtpRecipient("target@example.net"),), False
    )
    session = Session([Response(200, intent(raw, envelope))])
    result = MailEdgeClient(configuration(), session=session).get_outbound_intent(
        INTENT_ID
    )
    assert result.state == "accepted"
    assert session.calls[0][1].endswith(
        f"/v1/tenants/{TENANT_ID}/outbound-intents/{INTENT_ID}"
    )


def test_raw_reference_mismatch_fails_closed():
    raw = b"message"
    mismatched = {**raw_ref(raw), "sha256": "0" * 64}
    client = MailEdgeClient(
        configuration(), session=Session([Response(201, mismatched)])
    )
    with pytest.raises(MailEdgeContractError):
        client.store_raw_message(raw)


def test_successful_intent_response_with_invalid_contract_is_unknown():
    raw = b"message"
    envelope = SmtpEnvelope(
        "bounce@example.com", (SmtpRecipient("target@example.net"),), False
    )
    client = MailEdgeClient(
        configuration(),
        session=Session([Response(201, raw_ref(raw)), Response(202, {})]),
    )
    with pytest.raises(MailEdgeAmbiguousDeliveryError) as raised:
        client.submit_message(envelope, raw, idempotency_key="stable-key")
    assert raised.value.delivery_certainty == "unknown"
    assert not raised.value.retryable


def test_response_body_is_bounded_and_closed():
    response = StreamingResponse(201, b"x" * (64 * 1024 + 1))
    client = MailEdgeClient(configuration(), session=Session([response]))
    with pytest.raises(MailEdgeContractError) as raised:
        client.store_raw_message(b"message")
    assert raised.value.code == "MAIL_EDGE_RAW_RESPONSE_INVALID"
    assert response.closed


def test_large_message_uses_seekable_stream_and_content_length_without_buffer_copy():
    raw = b"x" * (25 * 1024 * 1024)
    stream = io.BytesIO(raw)
    session = Session([Response(201, raw_ref(raw))])
    reference = MailEdgeClient(configuration(), session=session).store_raw_stream(
        stream
    )
    assert reference.size == len(raw)
    assert session.calls[0][2]["data"] is stream
    assert session.calls[0][2]["headers"]["Content-Length"] == str(len(raw))


def test_safe_request_retries_boundedly_but_unknown_response_never_loops():
    raw = b"message"
    session = Session([requests.ConnectTimeout(), Response(201, raw_ref(raw))])
    assert MailEdgeClient(configuration(retries=1), session=session).store_raw_message(
        raw
    ).size == len(raw)
    assert len(session.calls) == 2

    failed = Session([requests.ReadTimeout()])
    with pytest.raises(MailEdgeUnavailableError) as raised:
        MailEdgeClient(configuration(retries=0), session=failed).store_raw_message(raw)
    assert raised.value.delivery_certainty == "not_sent"
    assert raised.value.retryable
    assert len(failed.calls) == 1

    unknown = Session([Response(201, raw_ref(raw)), requests.ReadTimeout()])
    envelope = SmtpEnvelope(
        "bounce@example.com", (SmtpRecipient("target@example.net"),), False
    )
    with pytest.raises(MailEdgeUnavailableError) as raised:
        MailEdgeClient(configuration(retries=0), session=unknown).submit_message(
            envelope, raw, idempotency_key="stable-key"
        )
    assert raised.value.delivery_certainty == "unknown"
    assert not raised.value.retryable


def test_circuit_breaker_opens_and_allows_only_one_bounded_probe():
    now = [100.0]
    breaker = CircuitBreaker(2, 10, clock=lambda: now[0])
    breaker.failure()
    breaker.failure()
    with pytest.raises(MailEdgeUnavailableError):
        breaker.enter()
    now[0] = 111.0
    breaker.enter()
    with pytest.raises(MailEdgeUnavailableError):
        breaker.enter()
    breaker.success()
    breaker.enter()


def test_remote_problem_retryability_is_explicit_and_only_not_sent_is_safe():
    for certainty, remote_retryable, expected_retryable in (
        ("not_sent", True, True),
        ("not_sent", False, False),
        ("accepted", True, False),
        ("unknown", True, False),
    ):
        response = Response(
            503,
            {
                "code": "HOST_UNAVAILABLE",
                "deliveryCertainty": certainty,
                "retryable": remote_retryable,
            },
        )
        problem = MailEdgeClient._problem(response)
        assert problem.retryable is expected_retryable
        assert problem.delivery_certainty == certainty
    malformed = MailEdgeClient._problem(
        Response(
            500,
            {
                "code": "unsafe\naddress@example.com",
                "deliveryCertainty": "not_sent",
                "retryable": True,
            },
        )
    )
    assert malformed.code == "MAIL_EDGE_REQUEST_FAILED"
