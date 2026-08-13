from __future__ import annotations

from datetime import timedelta

import pytest

from mail_edge.contracts import (
    FeedbackEvent,
    FeedbackEventType,
    SubmissionDisposition,
    SubmissionResult,
)
from mail_edge.errors import ReplayRejected, SignatureRejected
from mail_edge.mailgun.feedback import MailgunFeedbackAdapter

from .conftest import (
    NOW,
    NOW_EPOCH,
    event_data,
    outbound,
    webhook_payload,
)


def prepare_accepted(ledger):
    message = outbound()
    ledger.prepare(
        message,
        domain="edge.example.test",
        message_id="<submitted-1@edge.example.test>",
    )
    ledger.mark_submitting(message.edge_delivery_id, now=NOW)
    ledger.record_result(
        SubmissionResult(
            disposition=SubmissionDisposition.ACCEPTED,
            edge_delivery_id=message.edge_delivery_id,
            provider_message_id="<mailgun-id@mg>",
            visible_message_id="<submitted-1@edge.example.test>",
        ),
        now=NOW,
    )


def adapter(registry, replay_store, ledger, **kwargs):
    return MailgunFeedbackAdapter(
        registry,
        replay_store,
        ledger,
        signature_clock=lambda: NOW_EPOCH,
        **kwargs,
    )


@pytest.mark.parametrize(
    ("event", "severity", "smtp_status", "expected"),
    [
        ("accepted", None, None, FeedbackEventType.ACCEPTED),
        ("delivered", None, "250", FeedbackEventType.DELIVERED),
        ("delayed", None, "421", FeedbackEventType.DELAYED),
        ("failed", "temporary", "421", FeedbackEventType.DELAYED),
        ("failed", "permanent", "450", FeedbackEventType.SOFT_BOUNCE),
        ("failed", "permanent", "550", FeedbackEventType.HARD_BOUNCE),
        ("rejected", None, "550", FeedbackEventType.REJECTED),
        ("complained", None, None, FeedbackEventType.COMPLAINT),
    ],
)
def test_signed_event_normalization(
    registry, replay_store, ledger, event, severity, smtp_status, expected
):
    payload = webhook_payload(
        event_data(
            event=event,
            event_id=f"event-{event}-{expected.value}",
            message_id="<mailgun-id@mg>",
            severity=severity,
            smtp_status=smtp_status,
            diagnostic="  bounded   diagnostic  ",
        ),
        token=(event + expected.value).ljust(50, "x")[:50],
    )
    normalized = adapter(registry, replay_store, ledger).normalize_signed(payload)
    assert normalized.event_type is expected
    assert normalized.provider_message_id == "<mailgun-id@mg>"
    assert normalized.diagnostic == "bounded diagnostic"


def test_duplicate_and_out_of_order_events_are_idempotent(
    registry, replay_store, ledger
):
    prepare_accepted(ledger)
    target = adapter(registry, replay_store, ledger)
    delivered_data = event_data(
        event="delivered",
        event_id="delivered-once",
        message_id="<mailgun-id@mg>",
        timestamp=NOW_EPOCH + 100,
        smtp_status="250",
    )
    first = target.consume(
        webhook_payload(delivered_data, token="1" * 50), received_at=NOW
    )
    duplicate = target.consume(
        webhook_payload(delivered_data, token="2" * 50), received_at=NOW
    )
    late_accepted = target.consume(
        webhook_payload(
            event_data(
                event="accepted",
                event_id="accepted-arrived-late",
                message_id="<mailgun-id@mg>",
                timestamp=NOW_EPOCH,
            ),
            token="3" * 50,
        ),
        received_at=NOW,
    )

    assert first.correlated and first.state_changed
    assert duplicate.duplicate and not duplicate.state_changed
    assert late_accepted.correlated and not late_accepted.state_changed
    assert ledger.get("edge-delivery-1").state == "delivered"


def test_complaint_after_delivery_advances_state(registry, replay_store, ledger):
    prepare_accepted(ledger)
    target = adapter(registry, replay_store, ledger)
    target.consume(
        webhook_payload(
            event_data(
                event="delivered",
                event_id="delivered",
                message_id="<mailgun-id@mg>",
                timestamp=NOW_EPOCH + 1,
            ),
            token="4" * 50,
        ),
        received_at=NOW,
    )
    target.consume(
        webhook_payload(
            event_data(
                event="complained",
                event_id="complaint",
                message_id="<mailgun-id@mg>",
                timestamp=NOW_EPOCH + 2,
            ),
            token="5" * 50,
        ),
        received_at=NOW,
    )
    assert ledger.get("edge-delivery-1").state == "complaint"


def test_replay_forgery_and_uncorrelated_feedback_have_no_delivery_effect(
    registry, replay_store, ledger
):
    prepare_accepted(ledger)
    target = adapter(registry, replay_store, ledger)
    payload = webhook_payload(
        event_data(event_id="replay", message_id="<mailgun-id@mg>"), token="6" * 50
    )
    target.consume(payload, received_at=NOW)
    with pytest.raises(ReplayRejected):
        target.consume(payload, received_at=NOW)

    forged = bytearray(
        webhook_payload(
            event_data(event_id="forged", message_id="<mailgun-id@mg>"), token="7" * 50
        )
    )
    signature_offset = forged.find(b'"signature": "') + len(b'"signature": "')
    forged[signature_offset] = (
        ord("0") if forged[signature_offset] != ord("0") else ord("1")
    )
    with pytest.raises(SignatureRejected):
        target.consume(bytes(forged), received_at=NOW)

    unknown = target.consume(
        webhook_payload(
            event_data(event_id="unknown", message_id="<unknown@mg>"), token="8" * 50
        ),
        received_at=NOW,
    )
    assert not unknown.correlated
    assert ledger.get("edge-delivery-1").state == "accepted"


def test_provider_visible_message_id_supports_reverse_thread_translation(ledger):
    prepare_accepted(ledger)
    event = FeedbackEvent(
        provider_event_id="visible-id-learned",
        provider_message_id="<mailgun-id@mg>",
        edge_delivery_id="edge-delivery-1",
        event_type=FeedbackEventType.DELIVERED,
        recipient="contact@recipient.example",
        smtp_status="250",
        diagnostic=None,
        occurred_at=NOW + timedelta(seconds=1),
        visible_message_id="<provider-visible@recipient>",
    )
    ledger.apply_feedback(event, received_at=NOW + timedelta(seconds=2))
    assert (
        ledger.translate_thread_ids("<older@thread> <provider-visible@recipient>")
        == "<older@thread> <submitted-1@edge.example.test>"
    )


def test_message_id_correlation_is_scoped_to_exact_envelope_recipient(ledger):
    first = outbound(edge_id="first", recipient="first@recipient.example")
    second = outbound(edge_id="second", recipient="second@recipient.example")
    for message in (first, second):
        ledger.prepare(
            message,
            domain="edge.example.test",
            message_id="<submitted-1@edge.example.test>",
        )
        ledger.mark_submitting(message.edge_delivery_id, now=NOW)
        ledger.record_result(
            SubmissionResult(
                disposition=SubmissionDisposition.ACCEPTED,
                edge_delivery_id=message.edge_delivery_id,
                provider_message_id="<shared-provider-id@mg>",
            ),
            now=NOW,
        )
    application = ledger.apply_feedback(
        FeedbackEvent(
            provider_event_id="recipient-scoped",
            provider_message_id="<shared-provider-id@mg>",
            edge_delivery_id=None,
            event_type=FeedbackEventType.DELIVERED,
            recipient="second@recipient.example",
            smtp_status="250",
            diagnostic=None,
            occurred_at=NOW,
        ),
        received_at=NOW,
    )
    assert application.edge_delivery_id == "second"
    assert ledger.get("first").state == "ACCEPTED"
    assert ledger.get("second").state == "delivered"


def test_redacted_mailgun_recipient_is_accepted(registry, replay_store, ledger):
    payload = webhook_payload(
        event_data(event_id="pii-redacted", recipient="[REDACTED]"), token="9" * 50
    )
    normalized = adapter(registry, replay_store, ledger).normalize_signed(payload)
    assert normalized.recipient == "[REDACTED]"
