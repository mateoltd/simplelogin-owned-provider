from __future__ import annotations

import base64
import json

import pytest

from mail_edge.config import DomainRegistry, RetryPolicy
from mail_edge.contracts import ProviderRegion, SubmissionDisposition
from mail_edge.errors import TransportFailure
from mail_edge.mailgun.outbound import MailgunOutboundAdapter

from .conftest import (
    API_KEY,
    DOMAIN,
    NOW,
    OLD_API_KEY,
    domain_config,
    keyring,
    outbound,
    raw_message,
)
from .fakes import FakeTransport, response


def multipart_parts(request) -> dict[str, list[bytes]]:
    content_type = request.headers["Content-Type"]
    boundary = content_type.split("boundary=", 1)[1].encode()
    parts: dict[str, list[bytes]] = {}
    for raw_part in request.body.split(b"--" + boundary)[1:-1]:
        raw_part = raw_part.removeprefix(b"\r\n").removesuffix(b"\r\n")
        headers, payload = raw_part.split(b"\r\n\r\n", 1)
        disposition = next(
            line
            for line in headers.split(b"\r\n")
            if line.lower().startswith(b"content-disposition")
        )
        name = disposition.split(b'name="', 1)[1].split(b'"', 1)[0].decode()
        parts.setdefault(name, []).append(payload)
    return parts


def adapter(registry, transport, ledger, **kwargs):
    return MailgunOutboundAdapter(
        registry,
        transport,
        ledger,
        clock=lambda: NOW,
        sleeper=lambda _delay: None,
        **kwargs,
    )


def test_messages_mime_preserves_raw_bytes_and_exact_envelope(registry, ledger):
    raw = raw_message(body="Grüße\r\n".encode())
    transport = FakeTransport(
        response(200, json.dumps({"id": "<mailgun-id@mg>"}).encode())
    )
    result = adapter(registry, transport, ledger).submit(outbound(raw=raw))

    assert result.disposition is SubmissionDisposition.ACCEPTED
    assert result.provider_message_id == "<mailgun-id@mg>"
    request = transport.requests[0]
    assert request.method == "POST"
    assert request.url == f"https://api.mailgun.net/v3/{DOMAIN}/messages.mime"
    assert request.headers["Authorization"] == (
        "Basic " + base64.b64encode(f"api:{API_KEY}".encode()).decode()
    )
    parts = multipart_parts(request)
    assert parts["from"] == [b"bounce+opaque@edge.example.test"]
    assert parts["to"] == [b"contact@recipient.example"]
    assert parts["o:native-send"] == [b"yes"]
    assert parts["o:tracking"] == [b"no"]
    assert parts["o:tracking-clicks"] == [b"no"]
    assert parts["o:tracking-opens"] == [b"no"]
    assert parts["message"] == [raw]
    record = ledger.get("edge-delivery-1")
    assert record is not None
    assert record.state == "ACCEPTED"
    assert record.envelope_from == "bounce+opaque@edge.example.test"
    assert record.envelope_recipient == "contact@recipient.example"


def test_eu_region_and_api_key_rotation(ledger):
    config = domain_config(
        region=ProviderRegion.EU,
        api_keys=keyring(("old", OLD_API_KEY), ("current", API_KEY)),
    )
    transport = FakeTransport(
        response(401, b'{"message":"expired"}'),
        response(200, b'{"id":"<eu-id@mg>"}'),
    )
    result = adapter(DomainRegistry((config,)), transport, ledger).submit(outbound())

    assert result.disposition is SubmissionDisposition.ACCEPTED
    assert len(transport.requests) == 2
    assert all(
        request.url.startswith("https://api.eu.mailgun.net/")
        for request in transport.requests
    )
    assert (
        transport.requests[0].headers["Authorization"]
        != transport.requests[1].headers["Authorization"]
    )


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (400, SubmissionDisposition.PERMANENT_REJECTED),
        (413, SubmissionDisposition.PERMANENT_REJECTED),
        (422, SubmissionDisposition.PERMANENT_REJECTED),
    ],
)
def test_permanent_http_rejections(registry, ledger, status, expected):
    transport = FakeTransport(response(status, b'{"message":"request rejected"}'))
    result = adapter(registry, transport, ledger).submit(outbound())
    assert result.disposition is expected
    assert len(transport.requests) == 1


def test_quota_retries_are_bounded_and_semantic(registry, ledger):
    transport = FakeTransport(
        response(429, b'{"message":"quota"}', {"retry-after": "0"}),
        response(429, b'{"message":"quota"}', {"retry-after": "7"}),
    )
    result = adapter(
        registry,
        transport,
        ledger,
        retry=RetryPolicy(max_attempts=2, base_delay_seconds=0, max_delay_seconds=0),
    ).submit(outbound())
    assert result.disposition is SubmissionDisposition.RETRYABLE_REJECTED
    assert result.retry_after_seconds == 7
    assert len(transport.requests) == 2


def test_explicit_service_unavailable_is_retryable(registry, ledger):
    transport = FakeTransport(
        response(503, b'{"message":"unavailable"}', {"retry-after": "0"}),
        response(503, b'{"message":"unavailable"}', {"retry-after": "1"}),
    )
    result = adapter(
        registry,
        transport,
        ledger,
        retry=RetryPolicy(max_attempts=2, base_delay_seconds=0, max_delay_seconds=0),
    ).submit(outbound())
    assert result.disposition is SubmissionDisposition.RETRYABLE_REJECTED
    assert len(transport.requests) == 2


@pytest.mark.parametrize("status", [500, 502, 504])
def test_gateway_errors_are_ambiguous_and_not_retried(registry, ledger, status):
    transport = FakeTransport(
        response(status, b'{"message":"gateway failed"}'),
        response(200, b'{"id":"<duplicate@mg>"}'),
    )
    result = adapter(registry, transport, ledger).submit(outbound())
    assert result.disposition is SubmissionDisposition.AMBIGUOUS
    assert len(transport.requests) == 1


def test_connect_failure_can_retry_before_any_submission(registry, ledger):
    transport = FakeTransport(
        TransportFailure("connection refused", request_sent=False),
        response(200, b'{"id":"<accepted-after-connect@mg>"}'),
    )
    result = adapter(registry, transport, ledger).submit(outbound())
    assert result.disposition is SubmissionDisposition.ACCEPTED
    assert len(transport.requests) == 2


def test_timeout_after_request_is_ambiguous_and_never_retried(registry, ledger):
    transport = FakeTransport(
        TransportFailure("read timed out", request_sent=True),
        response(200, b'{"id":"<must-not-be-used@mg>"}'),
    )
    result = adapter(registry, transport, ledger).submit(outbound())
    assert result.disposition is SubmissionDisposition.AMBIGUOUS
    assert len(transport.requests) == 1
    assert ledger.get("edge-delivery-1").state == "AMBIGUOUS"

    second_transport = FakeTransport(response(200, b'{"id":"<duplicate@mg>"}'))
    repeated = adapter(registry, second_transport, ledger).submit(outbound())
    assert repeated.disposition is SubmissionDisposition.AMBIGUOUS
    assert second_transport.requests == []


def test_repeated_accepted_delivery_is_idempotent(registry, ledger):
    first_transport = FakeTransport(response(200, b'{"id":"<accepted-once@mg>"}'))
    first = adapter(registry, first_transport, ledger).submit(outbound())
    assert first.disposition is SubmissionDisposition.ACCEPTED

    second_transport = FakeTransport(response(200, b'{"id":"<duplicate@mg>"}'))
    second = adapter(registry, second_transport, ledger).submit(outbound())
    assert second.disposition is SubmissionDisposition.ACCEPTED
    assert second.provider_message_id == "<accepted-once@mg>"
    assert second_transport.requests == []
    assert ledger.get("edge-delivery-1").state == "ACCEPTED"

    conflicting_transport = FakeTransport(response(200, b'{"id":"<must-not-send@mg>"}'))
    conflict = adapter(registry, conflicting_transport, ledger).submit(
        outbound(raw=raw_message(body=b"different body\r\n"))
    )
    assert conflict.disposition is SubmissionDisposition.PERMANENT_REJECTED
    assert conflicting_transport.requests == []
    assert ledger.get("edge-delivery-1").state == "ACCEPTED"


def test_malformed_success_is_ambiguous(registry, ledger):
    transport = FakeTransport(response(200, b'{"message":"queued"}'))
    result = adapter(registry, transport, ledger).submit(outbound())
    assert result.disposition is SubmissionDisposition.AMBIGUOUS


def test_oversized_and_malformed_messages_never_reach_provider(registry, ledger):
    transport = FakeTransport()
    oversized = raw_message(body=b"x" * 24_000_000)
    too_large = adapter(registry, transport, ledger).submit(
        outbound(edge_id="oversized", raw=oversized)
    )
    malformed = adapter(registry, transport, ledger).submit(
        outbound(edge_id="malformed", raw=b"From: invalid\r\n")
    )
    assert too_large.disposition is SubmissionDisposition.PERMANENT_REJECTED
    assert malformed.disposition is SubmissionDisposition.PERMANENT_REJECTED
    assert transport.requests == []


def test_arbitrary_quoted_alias_local_part_is_not_provisioned(registry, ledger):
    transport = FakeTransport(response(200, b'{"id":"<quoted@mg>"}'))
    message = outbound(envelope_from='"odd local"@edge.example.test')
    result = adapter(registry, transport, ledger).submit(message)
    assert result.disposition is SubmissionDisposition.ACCEPTED
    assert multipart_parts(transport.requests[0])["from"] == [
        b'"odd local"@edge.example.test'
    ]


def test_unconfigured_domain_does_not_fail_over(ledger):
    registry = DomainRegistry(
        (
            domain_config(domain="first.example.test"),
            domain_config(domain="second.example.test", region=ProviderRegion.EU),
        )
    )
    transport = FakeTransport()
    result = adapter(registry, transport, ledger).submit(
        outbound(envelope_from="bounce@unknown.example.test")
    )
    assert result.disposition is SubmissionDisposition.PERMANENT_REJECTED
    assert transport.requests == []


def test_smtp_options_are_rejected_instead_of_silently_dropped(registry, ledger):
    transport = FakeTransport()
    result = adapter(registry, transport, ledger).submit(
        outbound(mail_options=("BODY=8BITMIME",))
    )
    assert result.disposition is SubmissionDisposition.PERMANENT_REJECTED
    assert transport.requests == []
