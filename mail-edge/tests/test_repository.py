from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from conftest import active_binding

from mail_edge.bindings import BindingStore
from mail_edge.contracts import (
    BindingDirection,
    BindingState,
    Envelope,
    Feedback,
    FeedbackKind,
    InboundNotice,
    InboundRawMessage,
    OutboundResult,
    OutboundSubmission,
    SubmissionOutcome,
)
from mail_edge.errors import DuplicateConflict, InvalidTransition
from mail_edge.ids import uuid7_str
from mail_edge.repository import EdgeRepository
from mail_edge.state import OutboundState


def _inbound(
    binding, *, token="provider-event-1", raw=b"From: x@y.example\r\n\r\nbody"
):
    notice_id = uuid7_str()
    envelope = Envelope("sender@outside.example", ("alias@aliases.example",))
    notice = InboundNotice(
        notice_id=notice_id,
        provider="mailgun",
        provider_event_id=token,
        provider_message_id="<message@outside.example>",
        domain=binding.domain,
        binding_generation=binding.generation,
        envelope=envelope,
        occurred_at=datetime.now(UTC),
        raw_available=True,
    )
    message = InboundRawMessage(
        message_id=uuid7_str(),
        notice_id=notice_id,
        domain=binding.domain,
        binding_generation=binding.generation,
        envelope=envelope,
        raw_mime=raw,
    )
    return notice, message


def _outbound(binding, *, submission_id=None, raw=None):
    identifier = submission_id or uuid7_str()
    payload = (
        raw
        or (
            f"X-Mail-Edge-Submission-ID: {identifier}\r\n"
            "From: alias@aliases.example\r\n\r\nbody\r\n"
        ).encode()
    )
    return OutboundSubmission(
        submission_id=identifier,
        domain=binding.domain,
        binding_generation=binding.generation,
        envelope=Envelope("bounce@aliases.example", ("recipient@outside.example",)),
        raw_mime=payload,
    )


@pytest.mark.parametrize("raw_first", [True, False])
def test_ingress_notice_and_raw_are_durable_in_either_order(edge, raw_first):
    binding = active_binding(edge, BindingDirection.INBOUND)
    notice, message = _inbound(binding)
    retention = datetime.now(UTC) + timedelta(hours=1)
    repository = edge["repository"]
    operations = (
        [
            lambda: repository.record_inbound_raw(
                binding.id,
                provider="mailgun",
                provider_event_id=notice.provider_event_id,
                message=message,
                retention_until=retention,
            ),
            lambda: repository.record_inbound_notice(
                binding.id, notice, retention_until=retention
            ),
        ]
        if raw_first
        else [
            lambda: repository.record_inbound_notice(
                binding.id, notice, retention_until=retention
            ),
            lambda: repository.record_inbound_raw(
                binding.id,
                provider="mailgun",
                provider_event_id=notice.provider_event_id,
                message=message,
                retention_until=retention,
            ),
        ]
    )
    ids = [operation() for operation in operations]
    assert ids[0] == ids[1]
    claimed = repository.claim_ingress()
    assert claimed.id == ids[0]
    assert claimed.raw_mime == message.raw_mime
    assert claimed.envelope == message.envelope
    repository.complete_ingress(claimed.id, success=True)
    assert repository.claim_ingress() is None


def test_duplicate_ingress_is_idempotent_but_conflicting_bytes_fail(edge):
    binding = active_binding(edge, BindingDirection.INBOUND)
    notice, message = _inbound(binding)
    retention = datetime.now(UTC) + timedelta(hours=1)
    repository = edge["repository"]
    first = repository.record_inbound_raw(
        binding.id,
        provider="mailgun",
        provider_event_id=notice.provider_event_id,
        message=message,
        retention_until=retention,
    )
    assert (
        repository.record_inbound_raw(
            binding.id,
            provider="mailgun",
            provider_event_id=notice.provider_event_id,
            message=message,
            retention_until=retention,
        )
        == first
    )
    conflicting = InboundRawMessage(
        message_id=message.message_id,
        notice_id=message.notice_id,
        domain=message.domain,
        binding_generation=message.binding_generation,
        envelope=message.envelope,
        raw_mime=b"different",
    )
    with pytest.raises(DuplicateConflict):
        repository.record_inbound_raw(
            binding.id,
            provider="mailgun",
            provider_event_id=notice.provider_event_id,
            message=conflicting,
            retention_until=retention,
        )


def test_draining_inbound_accepts_only_pinned_retries_without_orphan_write(edge):
    binding = active_binding(edge, BindingDirection.INBOUND)
    notice, message = _inbound(binding)
    retention = datetime.now(UTC) + timedelta(hours=1)
    edge["repository"].record_inbound_raw(
        binding.id,
        provider="mailgun",
        provider_event_id=notice.provider_event_id,
        message=message,
        retention_until=retention,
    )
    edge["bindings"].transition(binding.id, BindingState.DRAINING)
    assert edge["repository"].record_inbound_notice(
        binding.id, notice, retention_until=retention
    )
    new_notice, new_message = _inbound(binding, token="provider-event-new")
    with pytest.raises(InvalidTransition, match="retries only"):
        edge["repository"].record_inbound_raw(
            binding.id,
            provider="mailgun",
            provider_event_id=new_notice.provider_event_id,
            message=new_message,
            retention_until=retention,
        )
    assert not edge["blobs"].exists(f"ingress/{new_notice.notice_id}/raw")


def test_ingress_expired_lease_is_safely_retried_with_same_id(edge):
    binding = active_binding(edge, BindingDirection.INBOUND)
    notice, message = _inbound(binding)
    retention = datetime.now(UTC) + timedelta(hours=1)
    edge["repository"].record_inbound_notice(
        binding.id, notice, retention_until=retention
    )
    edge["repository"].record_inbound_raw(
        binding.id,
        provider="mailgun",
        provider_event_id=notice.provider_event_id,
        message=message,
        retention_until=retention,
    )
    now = datetime.now(UTC)
    first = edge["repository"].claim_ingress(lease_seconds=1, now=now)
    restarted = EdgeRepository(
        edge["database"],
        edge["blobs"],
        BindingStore(edge["database"], edge["registry"]),
        diagnostic_salt=b"test-diagnostic-salt-32-bytes!!",
    )
    second = restarted.claim_ingress(now=now + timedelta(seconds=2))
    assert second.id == first.id
    assert second.attempt == 2


def test_submission_enqueue_is_idempotent_and_generation_pinned(edge):
    binding = active_binding(edge, BindingDirection.OUTBOUND)
    submission = _outbound(binding)
    retention = datetime.now(UTC) + timedelta(hours=1)
    assert edge["repository"].enqueue_outbound(
        submission, binding=binding, retention_until=retention
    )
    assert not edge["repository"].enqueue_outbound(
        submission, binding=binding, retention_until=retention
    )
    claimed = edge["repository"].claim_outbound()
    assert claimed.binding.id == binding.id
    assert claimed.submission.raw_mime == submission.raw_mime


def test_expired_submission_lease_becomes_unknown_and_never_retries(edge):
    binding = active_binding(edge, BindingDirection.OUTBOUND)
    submission = _outbound(binding)
    now = datetime.now(UTC)
    edge["repository"].enqueue_outbound(
        submission,
        binding=binding,
        retention_until=now + timedelta(hours=1),
    )
    assert edge["repository"].claim_outbound(lease_seconds=1, now=now)
    restarted = EdgeRepository(
        edge["database"],
        edge["blobs"],
        BindingStore(edge["database"], edge["registry"]),
        diagnostic_salt=b"test-diagnostic-salt-32-bytes!!",
    )
    assert restarted.claim_outbound(now=now + timedelta(seconds=2)) is None
    unknown = restarted.list_unknown()
    assert [row["id"] for row in unknown] == [submission.submission_id]
    assert edge["repository"].list_quarantine()[0]["reason_code"] == "unknown_outcome"
    assert edge["repository"].claim_outbound(now=now + timedelta(days=30)) is None


def test_ambiguous_result_never_auto_retries_or_fails_over(edge):
    binding = active_binding(edge, BindingDirection.OUTBOUND)
    submission = _outbound(binding)
    edge["repository"].enqueue_outbound(
        submission,
        binding=binding,
        retention_until=datetime.now(UTC) + timedelta(hours=1),
    )
    edge["repository"].claim_outbound()
    state = edge["repository"].complete_outbound(
        OutboundResult(
            submission_id=submission.submission_id,
            outcome=SubmissionOutcome.UNKNOWN,
            provider_receipt_id=None,
            occurred_at=datetime.now(UTC),
            diagnostic_code="post_data_disconnect",
        )
    )
    assert state is OutboundState.UNKNOWN
    assert (
        edge["repository"].claim_outbound(now=datetime.now(UTC) + timedelta(days=1))
        is None
    )


def test_feedback_is_deduplicated_and_can_reconcile_unknown(edge):
    binding = active_binding(edge, BindingDirection.OUTBOUND)
    submission = _outbound(binding)
    edge["repository"].enqueue_outbound(
        submission,
        binding=binding,
        retention_until=datetime.now(UTC) + timedelta(hours=1),
    )
    edge["repository"].claim_outbound()
    edge["repository"].complete_outbound(
        OutboundResult(
            submission.submission_id,
            SubmissionOutcome.UNKNOWN,
            None,
            datetime.now(UTC),
            "lost_ack",
        )
    )
    feedback = Feedback(
        feedback_id=uuid7_str(),
        provider="mailgun",
        provider_event_id="feedback-1",
        kind=FeedbackKind.DELIVERED,
        occurred_at=datetime.now(UTC),
        recipient_hash="b" * 64,
        submission_id=submission.submission_id,
        provider_receipt_id="provider-receipt",
    )
    assert edge["repository"].record_feedback(feedback)
    assert not edge["repository"].record_feedback(feedback)
    assert edge["repository"].list_unknown() == []
    assert edge["repository"].list_quarantine() == []


def test_uncorrelated_feedback_is_quarantined_without_message_state_change(edge):
    feedback = Feedback(
        feedback_id=uuid7_str(),
        provider="mailgun",
        provider_event_id="feedback-unmatched",
        kind=FeedbackKind.COMPLAINED,
        occurred_at=datetime.now(UTC),
        recipient_hash="c" * 64,
    )
    assert edge["repository"].record_feedback(feedback)
    assert edge["repository"].list_quarantine()[0]["reason_code"] == (
        "uncorrelated_feedback"
    )


def test_forged_unknown_submission_correlation_is_quarantined_without_fk_failure(edge):
    feedback = Feedback(
        feedback_id=uuid7_str(),
        provider="mailgun",
        provider_event_id="feedback-forged-correlation",
        kind=FeedbackKind.DELIVERED,
        occurred_at=datetime.now(UTC),
        recipient_hash="d" * 64,
        submission_id=uuid7_str(),
    )
    assert edge["repository"].record_feedback(feedback)
    assert edge["repository"].list_quarantine()[0]["reason_code"] == (
        "uncorrelated_feedback"
    )


def test_binding_switch_drains_old_generation_without_repinning_mail(edge):
    first = active_binding(edge, BindingDirection.OUTBOUND)
    first_submission = _outbound(first)
    edge["repository"].enqueue_outbound(
        first_submission,
        binding=first,
        retention_until=datetime.now(UTC) + timedelta(hours=1),
    )
    second = edge["bindings"].create(
        domain=first.domain,
        direction=BindingDirection.OUTBOUND,
        provider="mailgun",
        provider_config={"credential_ref": "mailgun-second"},
    )
    edge["bindings"].transition(second.id, BindingState.SHADOW)
    edge["bindings"].switch(second.id)
    with pytest.raises(InvalidTransition, match="pinned messages"):
        edge["bindings"].transition(first.id, BindingState.DISABLED)
    claimed = edge["repository"].claim_outbound()
    assert claimed.binding.id == first.id
    assert claimed.binding.state is BindingState.DRAINING
    edge["repository"].complete_outbound(
        OutboundResult(
            first_submission.submission_id,
            SubmissionOutcome.ACCEPTED,
            "receipt-first",
            datetime.now(UTC),
            "accepted",
        )
    )
    assert (
        edge["bindings"].transition(first.id, BindingState.DISABLED).state
        is BindingState.DISABLED
    )
    active = edge["bindings"].resolve_active(first.domain, BindingDirection.OUTBOUND)
    second_submission = _outbound(active)
    assert second_submission.binding_generation == 2


def test_retention_deletes_only_definitive_terminal_content(edge):
    binding = active_binding(edge, BindingDirection.OUTBOUND)
    accepted = _outbound(binding)
    unknown = _outbound(binding)
    expired = datetime.now(UTC) - timedelta(seconds=1)
    for submission in (accepted, unknown):
        edge["repository"].enqueue_outbound(
            submission, binding=binding, retention_until=expired
        )
        edge["repository"].claim_outbound()
        edge["repository"].complete_outbound(
            OutboundResult(
                submission.submission_id,
                (
                    SubmissionOutcome.ACCEPTED
                    if submission is accepted
                    else SubmissionOutcome.UNKNOWN
                ),
                "receipt" if submission is accepted else None,
                datetime.now(UTC),
                "result",
            )
        )
    assert edge["repository"].retention_sweep() == 1
    assert not edge["blobs"].exists(f"outbound/{accepted.submission_id}/raw")
    assert edge["blobs"].exists(f"outbound/{unknown.submission_id}/raw")
    assert edge["repository"].list_unknown()[0]["id"] == unknown.submission_id


def test_orphan_sweep_uses_grace_and_never_deletes_referenced_blobs(edge):
    binding = active_binding(edge, BindingDirection.OUTBOUND)
    submission = _outbound(binding)
    edge["repository"].enqueue_outbound(
        submission,
        binding=binding,
        retention_until=datetime.now(UTC) + timedelta(days=30),
    )
    edge["blobs"].put("orphan/old/raw", b"orphan")
    edge["blobs"].put("orphan/recent/raw", b"recent")
    old = datetime.now(UTC) - timedelta(days=2)
    old_timestamp = old.timestamp()
    for blob_id in (
        f"outbound/{submission.submission_id}/raw",
        f"outbound/{submission.submission_id}/envelope",
        "orphan/old/raw",
    ):
        path = edge["blobs"]._path(blob_id)
        os.utime(path, (old_timestamp, old_timestamp))
    deleted = edge["repository"].orphan_sweep(
        now=datetime.now(UTC), grace=timedelta(days=1)
    )
    assert deleted == 1
    assert not edge["blobs"].exists("orphan/old/raw")
    assert edge["blobs"].exists("orphan/recent/raw")
    assert edge["blobs"].exists(f"outbound/{submission.submission_id}/raw")
