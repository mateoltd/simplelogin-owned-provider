import hashlib
import hmac

from mail_edge_conformance.contracts import EventType
from mail_edge_conformance.providers.mailgun import (
    HttpResponse,
    MailgunAdapter,
    MailgunContractTransport,
    MailgunWebhookVerifier,
    normalize_mailgun_event,
)
from mail_edge_conformance.qualification import qualify_corpus, qualify_size_boundary


def test_mailgun_adapter_passes_neutral_suite_through_mime_upload():
    transport = MailgunContractTransport(size_limit=8192)
    adapter = MailgunAdapter(
        domain="qualification.invalid",
        api_key="offline-fixture-not-a-secret",
        api_base="http://contract.invalid",
        transport=transport,
        allow_test_endpoint=True,
    )
    results = (
        *qualify_corpus(adapter, transport),
        *qualify_size_boundary(adapter, transport, limit=8192),
    )
    assert len(results) == 18
    assert all(item.status == "passed" for item in results)
    assert transport.fields["o:tracking"] == ["no"]
    assert transport.fields["o:suppress-headers"] == ["all"]


def test_mailgun_response_statuses_normalize_without_provider_leakage():
    class StatusTransport:
        def __init__(self, status):
            self.status = status

        def request(self, method, url, headers, body, timeout):
            return HttpResponse(self.status, b'{"message":"injected"}', {})

    request = next(iter(_one_request()))
    expected = {400: "reject", 401: "retry", 403: "retry", 429: "retry", 503: "retry"}
    for status, disposition in expected.items():
        adapter = MailgunAdapter(
            domain="qualification.invalid",
            api_key="offline-fixture-not-a-secret",
            api_base="http://contract.invalid",
            transport=StatusTransport(status),
            allow_test_endpoint=True,
        )
        assert adapter.submit(request).disposition.value == disposition


def test_mailgun_webhook_signature_replay_and_event_normalization():
    key = "offline-signing-fixture"
    timestamp = "1786622400"
    token = "token-123"
    signature = hmac.new(
        key.encode(), (timestamp + token).encode(), hashlib.sha256
    ).hexdigest()
    payload = {
        "signature": {
            "timestamp": timestamp,
            "token": token,
            "signature": signature,
        },
        "event-data": {
            "id": "event-1",
            "event": "failed",
            "severity": "permanent",
            "reason": "bounce",
            "timestamp": 1786622400.5,
            "recipient": "recipient@receiver.test",
            "user-variables": {"edge_delivery_id": "edge-1"},
            "message": {"headers": {"message-id": "<provider-1>"}},
            "delivery-status": {
                "enhanced-code": "5.1.1",
                "message": "mailbox unavailable",
            },
        },
    }
    verifier = MailgunWebhookVerifier(key)
    assert verifier.verify(payload, now=1786622400) == "verified"
    assert verifier.verify(payload, now=1786622400) == "signature_replay"
    event = normalize_mailgun_event(payload)
    assert event.event_type is EventType.HARD_BOUNCE
    assert event.edge_delivery_id == "edge-1"
    assert event.provider_message_id == "<provider-1>"
    assert event.smtp_status == "5.1.1"


def _one_request():
    from mail_edge_conformance.contracts import DeliveryRequest

    yield DeliveryRequest(
        edge_delivery_id="mailgun-status",
        envelope_from="sender@sender.test",
        envelope_recipients=("receiver@receiver.test",),
        rfc822_bytes=b"From: sender@sender.test\r\nTo: receiver@receiver.test\r\n\r\nbody",
    )
