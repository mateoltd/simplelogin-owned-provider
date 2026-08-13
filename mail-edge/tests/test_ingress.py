from __future__ import annotations

import json

import pytest

from mail_edge.config import DomainRegistry, IngressContentPolicy
from mail_edge.errors import (
    MalformedPayload,
    ReplayRejected,
    SignatureRejected,
    TemporaryIngressFailure,
    TransportFailure,
)
from mail_edge.mailgun.inbound import MailgunIngressAdapter

from .conftest import (
    DOMAIN,
    NOW_EPOCH,
    OLD_WEBHOOK_KEY,
    WEBHOOK_KEY,
    domain_config,
    keyring,
    raw_message,
    signature_fields,
)
from .fakes import FakeTransport, response


def ingress_fields(*, raw: bytes | None = None, **overrides):
    fields: dict[str, str | bytes] = {
        "domain": DOMAIN,
        "sender": "smtp-return@external.example",
        "recipient": "never-provisioned+anything@edge.example.test",
        "body-mime": raw
        or raw_message(
            sender="Visible Person <visible@header.example>",
            recipient="Different Header <header-to@edge.example.test>",
        ),
        **signature_fields(),
    }
    fields.update(overrides)
    return fields


def adapter(registry, transport, replay_store):
    return MailgunIngressAdapter(
        registry,
        transport,
        replay_store,
        signature_clock=lambda: NOW_EPOCH,
    )


def test_signed_raw_mime_uses_separate_smtp_envelope(registry, replay_store):
    transport = FakeTransport()
    message = adapter(registry, transport, replay_store).receive(ingress_fields())
    assert message.envelope_from == "smtp-return@external.example"
    assert message.envelope_recipients == (
        "never-provisioned+anything@edge.example.test",
    )
    assert b"From: Visible Person <visible@header.example>" in message.rfc822_bytes
    assert b"To: Different Header <header-to@edge.example.test>" in message.rfc822_bytes
    assert transport.requests == []


def test_signed_ingress_cannot_cross_configured_domain(registry, replay_store):
    fields = ingress_fields(recipient="outside@other.example.test", token="c" * 50)
    fields.update(signature_fields(token="c" * 50))
    with pytest.raises(MalformedPayload):
        adapter(registry, FakeTransport(), replay_store).receive(fields)


def test_ingress_accepts_null_envelope_sender_for_dsn(registry, replay_store):
    fields = ingress_fields(sender="<>", token="n" * 50)
    signature = signature_fields(token="n" * 50)
    fields.update(signature)
    message = adapter(registry, FakeTransport(), replay_store).receive(fields)
    assert message.envelope_from == "<>"


def test_replay_is_rejected_after_one_success(registry, replay_store):
    target = adapter(registry, FakeTransport(), replay_store)
    fields = ingress_fields()
    target.receive(fields)
    with pytest.raises(ReplayRejected):
        target.receive(fields)


def test_rotated_webhook_key_is_accepted(replay_store):
    config = domain_config(
        webhook_keys=keyring(("current", WEBHOOK_KEY), ("old", OLD_WEBHOOK_KEY))
    )
    fields = ingress_fields(token="o" * 50)
    fields.update(signature_fields(key=OLD_WEBHOOK_KEY, token="o" * 50))
    message = adapter(DomainRegistry((config,)), FakeTransport(), replay_store).receive(
        fields
    )
    assert message.provider_event_id.endswith("o" * 50)


def test_forged_and_expired_signatures_are_rejected(registry, replay_store):
    target = adapter(registry, FakeTransport(), replay_store)
    forged = ingress_fields(signature="0" * 64)
    with pytest.raises(SignatureRejected):
        target.receive(forged)

    expired = ingress_fields(token="e" * 50, timestamp=str(NOW_EPOCH - 901))
    expired.update(signature_fields(token="e" * 50, timestamp=NOW_EPOCH - 901))
    with pytest.raises(SignatureRejected):
        target.receive(expired)


def test_malformed_and_oversized_mime_are_rejected(registry, replay_store):
    target = adapter(registry, FakeTransport(), replay_store)
    malformed = ingress_fields(raw=b"From: missing-body-separator\r\n", token="m" * 50)
    malformed.update(signature_fields(token="m" * 50))
    with pytest.raises(MalformedPayload):
        target.receive(malformed)

    oversized_raw = raw_message(body=b"x" * 24_000_000)
    oversized = ingress_fields(raw=oversized_raw, token="z" * 50)
    oversized.update(signature_fields(token="z" * 50))
    with pytest.raises(MalformedPayload):
        target.receive(oversized)


def test_direct_policy_never_fetches_implicitly(registry, replay_store):
    fields = ingress_fields(token="d" * 50)
    fields.update(signature_fields(token="d" * 50))
    fields.pop("body-mime")
    fields["message-url"] = (
        f"https://storage-us-east4.api.mailgun.net/v3/domains/{DOMAIN}/messages/key"
    )
    transport = FakeTransport()
    with pytest.raises(MalformedPayload):
        adapter(registry, transport, replay_store).receive(fields)
    assert transport.requests == []


def test_explicit_store_and_fetch_preserves_outer_envelope(replay_store):
    config = domain_config(ingress_policy=IngressContentPolicy.STORE_AND_FETCH)
    raw = raw_message(body=b"stored body\r\n")
    transport = FakeTransport(
        response(200, json.dumps({"body-mime": raw.decode()}).encode())
    )
    fields = ingress_fields(token="s" * 50)
    fields.update(signature_fields(token="s" * 50))
    fields.pop("body-mime")
    fields["message-url"] = (
        f"https://storage-us-east4.api.mailgun.net/v3/domains/{DOMAIN}/messages/storage-key"
    )
    message = adapter(DomainRegistry((config,)), transport, replay_store).receive(
        fields
    )
    assert message.rfc822_bytes == raw
    assert message.envelope_from == "smtp-return@external.example"
    assert message.envelope_recipients[0].startswith("never-provisioned")
    assert transport.requests[0].method == "GET"


def test_store_fetch_rejects_ssrf_and_treats_outage_as_temporary(replay_store):
    config = domain_config(ingress_policy=IngressContentPolicy.STORE_AND_FETCH)
    registry = DomainRegistry((config,))
    unsafe = ingress_fields(token="u" * 50)
    unsafe.update(signature_fields(token="u" * 50))
    unsafe.pop("body-mime")
    unsafe["message-url"] = f"https://attacker.invalid/v3/domains/{DOMAIN}/messages/key"
    transport = FakeTransport()
    with pytest.raises(MalformedPayload):
        adapter(registry, transport, replay_store).receive(unsafe)
    assert transport.requests == []

    outage = ingress_fields(token="q" * 50)
    outage.update(signature_fields(token="q" * 50))
    outage.pop("body-mime")
    outage["message-url"] = (
        f"https://storage-us-east4.api.mailgun.net/v3/domains/{DOMAIN}/messages/key"
    )
    failing = FakeTransport(
        TransportFailure("timeout", request_sent=True),
        TransportFailure("timeout", request_sent=True),
        TransportFailure("timeout", request_sent=True),
    )
    with pytest.raises(TemporaryIngressFailure):
        adapter(registry, failing, replay_store).receive(outage)
    failing.outcomes.append(
        response(200, json.dumps({"body-mime": raw_message().decode()}).encode())
    )
    recovered = adapter(registry, failing, replay_store).receive(outage)
    assert recovered.rfc822_bytes == raw_message()
