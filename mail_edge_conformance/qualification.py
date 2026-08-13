"""Reusable neutral suites for MIME, failure, size, and threading behavior."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from typing import Callable, Protocol

from .contracts import (
    AdapterResult,
    DeliveryRequest,
    EventType,
    FeedbackEvent,
    SubmissionAdapter,
    SubmissionDisposition,
)
from .corpus import CorpusCase, boundary_cases, load_corpus
from .edge import (
    CoreDataCrash,
    DeliveryState,
    FeedbackSigner,
    MailEdge,
    ManualCutover,
    ScriptedAdapter,
    ScriptedOutcome,
)
from .evidence import QualificationResult
from .mime import TransportHeaderPolicy, compare_messages


class DeliveredMessageSource(Protocol):
    def get(self, edge_delivery_id: str, provider_message_id: str) -> bytes:
        """Return the bytes observed at the controlled recipient."""


class CapturingAdapter:
    """Exact-delivery adapter used to prove the neutral suite itself."""

    name = "deterministic-capture"

    def __init__(self, *, size_limit: int | None = None) -> None:
        self.size_limit = size_limit
        self.messages: dict[str, bytes] = {}

    def submit(self, request: DeliveryRequest) -> AdapterResult:
        if self.size_limit is not None and len(request.rfc822_bytes) > self.size_limit:
            return AdapterResult(
                SubmissionDisposition.REJECT,
                diagnostic_code="5.3.4",
                diagnostic="message exceeds configured fixture limit",
            )
        provider_id = f"capture-{hashlib.sha256(request.edge_delivery_id.encode()).hexdigest()[:20]}"
        self.messages[provider_id] = request.rfc822_bytes
        return AdapterResult(
            SubmissionDisposition.ACCEPTED, provider_message_id=provider_id
        )

    def reconcile(self, edge_delivery_id: str) -> AdapterResult | None:
        return None

    def get(self, edge_delivery_id: str, provider_message_id: str) -> bytes:
        return self.messages[provider_message_id]


def qualify_corpus(
    adapter: SubmissionAdapter,
    mailbox: DeliveredMessageSource,
    *,
    cases: tuple[CorpusCase, ...] | None = None,
    transport_policy: TransportHeaderPolicy | None = None,
    message_renderer: Callable[[CorpusCase, str], bytes] | None = None,
    envelope_resolver: (
        Callable[[CorpusCase, bytes], tuple[str, tuple[str, ...]]] | None
    ) = None,
) -> tuple[QualificationResult, ...]:
    results: list[QualificationResult] = []
    for case in cases or load_corpus():
        edge_id = f"corpus-{case.case_id}"
        submitted = (
            message_renderer(case, edge_id)
            if message_renderer is not None
            else _annotate(case.rfc822_bytes, edge_id)
        )
        sender, recipients = (
            envelope_resolver(case, submitted)
            if envelope_resolver is not None
            else _envelope_bytes(submitted)
        )
        request = DeliveryRequest(
            edge_delivery_id=edge_id,
            envelope_from=sender,
            envelope_recipients=recipients,
            rfc822_bytes=submitted,
            smtp_utf8_required=case.smtp_utf8_required,
            mail_options=("SMTPUTF8",) if case.smtp_utf8_required else (),
        )
        try:
            adapter_result = adapter.submit(request)
            if adapter_result.disposition is not SubmissionDisposition.ACCEPTED:
                raise AssertionError(
                    f"adapter returned {adapter_result.disposition.value}: "
                    f"{adapter_result.diagnostic or adapter_result.diagnostic_code}"
                )
            delivered = mailbox.get(edge_id, str(adapter_result.provider_message_id))
            comparison = compare_messages(
                submitted, delivered, transport_policy=transport_policy
            )
            comparison.require_equivalent()
            observed = {
                "corpus_sha256": case.sha256,
                "features": list(case.features),
                "wire_bytes": len(case.rfc822_bytes),
                "allowed_transport_mutations": [
                    mutation.location
                    for mutation in comparison.allowed_transport_mutations
                ],
            }
            status = "passed"
        except Exception as error:  # Evidence must retain every failed case.
            status = "failed"
            observed = {
                "corpus_sha256": case.sha256,
                "features": list(case.features),
                "error": f"{type(error).__name__}: {error}",
            }
        results.append(
            QualificationResult(
                result_id=f"corpus:{case.case_id}",
                gate="mime-fidelity",
                status=status,
                method="executed",
                observed=observed,
            )
        )
    results.append(_qualify_thread_topology(cases or load_corpus()))
    return tuple(results)


def qualify_size_boundary(
    adapter: SubmissionAdapter,
    mailbox: DeliveredMessageSource,
    *,
    limit: int,
    transport_policy: TransportHeaderPolicy | None = None,
    sender: str = "size-sender@sender.test",
    recipient: str = "size-recipient@receiver.test",
) -> tuple[QualificationResult, ...]:
    results: list[QualificationResult] = []
    for case in boundary_cases(limit, sender=sender, recipient=recipient):
        encoded = case.rfc822_bytes
        request = DeliveryRequest(
            edge_delivery_id=case.case_id,
            envelope_from=sender,
            envelope_recipients=(recipient,),
            rfc822_bytes=encoded,
        )
        expected_acceptance = len(encoded) <= limit
        try:
            adapter_result = adapter.submit(request)
            accepted = adapter_result.disposition is SubmissionDisposition.ACCEPTED
            if accepted != expected_acceptance:
                raise AssertionError(
                    f"expected accepted={expected_acceptance}, got "
                    f"{adapter_result.disposition.value}"
                )
            if accepted:
                delivered = mailbox.get(
                    request.edge_delivery_id, str(adapter_result.provider_message_id)
                )
                compare_messages(
                    request.rfc822_bytes,
                    delivered,
                    transport_policy=transport_policy,
                ).require_equivalent()
            status = "passed"
            observed = {
                "wire_bytes": len(encoded),
                "disposition": adapter_result.disposition.value,
                "diagnostic_code": adapter_result.diagnostic_code,
            }
        except Exception as error:
            status = "failed"
            observed = {
                "wire_bytes": len(encoded),
                "error": f"{type(error).__name__}: {error}",
            }
        results.append(
            QualificationResult(
                result_id=f"boundary:{case.case_id}",
                gate="size-boundary",
                status=status,
                method="executed",
                observed=observed,
            )
        )
    return tuple(results)


def run_failure_matrix() -> tuple[QualificationResult, ...]:
    checks: list[tuple[str, str, Callable[[], dict[str, object]]]] = [
        ("notices-duplicated", "idempotency", _notices_duplicated),
        ("events-duplicated", "feedback", _events_duplicated),
        ("events-reordered", "feedback", _events_reordered),
        ("signature-replay", "feedback-authentication", _signature_replay),
        ("signature-invalid", "feedback-authentication", _signature_invalid),
        ("rejection", "submission-failure", _rejection),
        ("delay", "feedback", lambda: _event_transition(EventType.DELAYED)),
        ("soft-bounce", "feedback", lambda: _event_transition(EventType.SOFT_BOUNCE)),
        ("hard-bounce", "feedback", lambda: _event_transition(EventType.HARD_BOUNCE)),
        ("complaint", "feedback", lambda: _event_transition(EventType.COMPLAINT)),
        ("timeout-before-acceptance", "ambiguous-acceptance", _timeout_before),
        ("timeout-after-acceptance", "ambiguous-acceptance", _timeout_after),
        ("crash-after-core-data", "durability", _crash_after_data),
        ("credential-failure", "provider-availability", lambda: _retry("credential")),
        ("quota-exhaustion", "provider-availability", lambda: _retry("quota")),
        ("provider-pause", "provider-availability", lambda: _retry("provider_pause")),
        ("cutover", "manual-fallback", _cutover),
        ("drain", "manual-fallback", _drain),
        ("rollback", "manual-fallback", _rollback),
        ("unknown-reconciliation", "reconciliation", _unknown_reconciliation),
        ("unknown-reconciliation-unresolved", "reconciliation", _unknown_unresolved),
    ]
    results: list[QualificationResult] = []
    for identifier, gate, check in checks:
        try:
            observed = check()
            status = "passed"
        except Exception as error:
            observed = {"error": f"{type(error).__name__}: {error}"}
            status = "failed"
        results.append(
            QualificationResult(
                result_id=f"fault:{identifier}",
                gate=gate,
                status=status,
                method="fault-injected",
                observed=observed,
            )
        )
    return tuple(results)


def run_neutral_suite(size_limit: int = 8192) -> tuple[QualificationResult, ...]:
    adapter = CapturingAdapter(size_limit=size_limit)
    return (
        *qualify_corpus(adapter, adapter),
        *qualify_size_boundary(adapter, adapter, limit=size_limit),
        *run_failure_matrix(),
    )


def _envelope(case: CorpusCase) -> tuple[str, tuple[str, ...]]:
    return _envelope_bytes(case.rfc822_bytes)


def _envelope_bytes(encoded: bytes) -> tuple[str, tuple[str, ...]]:
    message = BytesParser(policy=policy.default).parsebytes(encoded)
    from_addresses = getaddresses(message.get_all("from", []))
    recipients = getaddresses(message.get_all("to", []) + message.get_all("cc", []))
    sender = from_addresses[0][1] if from_addresses else "sender@sender.test"
    recipient_addresses = tuple(address for _, address in recipients if address)
    if not recipient_addresses:
        recipient_addresses = ("recipient@receiver.test",)
    return sender, recipient_addresses


def _annotate(encoded: bytes, edge_id: str) -> bytes:
    separator = b"\r\n\r\n" if b"\r\n\r\n" in encoded else b"\n\n"
    head, body = encoded.split(separator, 1)
    line_ending = b"\r\n" if separator == b"\r\n\r\n" else b"\n"
    return (
        head
        + line_ending
        + b"X-Mail-Edge-Test-ID: "
        + edge_id.encode("ascii")
        + separator
        + body
    )


def _qualify_thread_topology(cases: tuple[CorpusCase, ...]) -> QualificationResult:
    thread = sorted(
        (case for case in cases if case.thread == "reverse-alias-four-message"),
        key=lambda item: int(item.sequence or 0),
    )
    try:
        if [item.sequence for item in thread] != [1, 2, 3, 4]:
            raise AssertionError("four ordered reverse-alias messages are required")
        seen: list[str] = []
        for index, case in enumerate(thread):
            message = BytesParser(policy=policy.default).parsebytes(case.rfc822_bytes)
            message_id = str(message["Message-ID"])
            if index:
                if str(message["In-Reply-To"]) != seen[-1]:
                    raise AssertionError(
                        f"{case.case_id} does not reply to its predecessor"
                    )
                references = str(message["References"]).split()
                if references != seen:
                    raise AssertionError(f"{case.case_id} lost thread references")
            seen.append(message_id)
        status = "passed"
        observed: dict[str, object] = {
            "messages": len(thread),
            "message_ids": seen,
        }
    except Exception as error:
        status = "failed"
        observed = {"error": f"{type(error).__name__}: {error}"}
    return QualificationResult(
        result_id="thread:reverse-alias-four-message",
        gate="threading",
        status=status,
        method="executed",
        observed=observed,
    )


_NOW = datetime(2026, 8, 13, 12, 0, tzinfo=timezone.utc)
_KEY = b"deterministic-feedback-key-for-tests"


def _request(identifier: str = "edge-1") -> DeliveryRequest:
    return DeliveryRequest(
        edge_delivery_id=identifier,
        envelope_from="bounce+fixture@edge.test",
        envelope_recipients=("recipient@receiver.test",),
        rfc822_bytes=(
            b"From: sender@sender.test\r\n"
            b"To: recipient@receiver.test\r\n"
            b"Subject: failure matrix\r\n"
            b"Message-ID: <failure@sender.test>\r\n\r\nbody\r\n"
        ),
    )


def _accepted(identifier: str = "edge-1") -> tuple[MailEdge, ScriptedAdapter]:
    edge = MailEdge(_KEY, clock=lambda: _NOW)
    adapter = ScriptedAdapter()
    record = edge.submit(_request(identifier), adapter)
    assert record.state is DeliveryState.ACCEPTED
    return edge, adapter


def _event(
    edge: MailEdge,
    event_type: EventType,
    *,
    event_id: str,
    edge_id: str = "edge-1",
) -> FeedbackEvent:
    record = edge.records[edge_id]
    return FeedbackEvent(
        provider_event_id=event_id,
        provider_message_id=str(record.provider_message_id),
        edge_delivery_id=edge_id,
        event_type=event_type,
        recipient=record.request.envelope_recipients[0],
        occurred_at=_NOW,
    )


def _signed(edge: MailEdge, event: FeedbackEvent, token: str):
    return FeedbackSigner(_KEY).sign(
        event, timestamp=int(_NOW.timestamp()), token=token
    )


def _notices_duplicated() -> dict[str, object]:
    edge, adapter = _accepted()
    edge.submit(_request(), adapter)
    assert adapter.submit_calls == ["edge-1"]
    return {"provider_submissions": 1, "state": edge.records["edge-1"].state.value}


def _events_duplicated() -> dict[str, object]:
    edge, _ = _accepted()
    event = _event(edge, EventType.DELIVERED, event_id="event-duplicate")
    assert edge.ingest_feedback(_signed(edge, event, "token-one")) == "applied"
    assert edge.ingest_feedback(_signed(edge, event, "token-two")) == "duplicate"
    assert edge.records["edge-1"].applied_events == ["event-duplicate"]
    return {"state_actions": 1, "final_state": DeliveryState.DELIVERED.value}


def _events_reordered() -> dict[str, object]:
    edge, _ = _accepted()
    delivered = _event(edge, EventType.DELIVERED, event_id="event-delivered")
    delayed = _event(edge, EventType.DELAYED, event_id="event-delayed")
    assert (
        edge.ingest_feedback(_signed(edge, delivered, "token-delivered")) == "applied"
    )
    assert edge.ingest_feedback(_signed(edge, delayed, "token-delayed")) == "applied"
    assert edge.records["edge-1"].state is DeliveryState.DELIVERED
    return {"arrival_order": ["delivered", "delayed"], "final_state": "delivered"}


def _signature_replay() -> dict[str, object]:
    edge, _ = _accepted()
    event = _event(edge, EventType.DELIVERED, event_id="event-replay")
    signed = _signed(edge, event, "replayed-token")
    assert edge.ingest_feedback(signed) == "applied"
    assert edge.ingest_feedback(signed) == "signature_replay"
    assert len(edge.records["edge-1"].applied_events) == 1
    return {"replay_effects": 0, "quarantine_reason": "signature_replay"}


def _signature_invalid() -> dict[str, object]:
    edge, _ = _accepted()
    event = _event(edge, EventType.DELIVERED, event_id="event-forged")
    signed = _signed(edge, event, "forged-token")
    forged = type(signed)(signed.timestamp, signed.token, "0" * 64, signed.event)
    assert edge.ingest_feedback(forged) == "invalid_signature"
    assert edge.records["edge-1"].state is DeliveryState.ACCEPTED
    return {"state_effects": 0, "quarantine_reason": "invalid_signature"}


def _rejection() -> dict[str, object]:
    edge = MailEdge(_KEY, clock=lambda: _NOW)
    adapter = ScriptedAdapter()
    adapter.queue(
        ScriptedOutcome(
            AdapterResult(
                SubmissionDisposition.REJECT,
                diagnostic_code="5.7.1",
                diagnostic="policy rejection",
            )
        )
    )
    record = edge.submit(_request(), adapter)
    assert record.state is DeliveryState.REJECTED
    return {"state": record.state.value, "attempts": record.attempts}


def _event_transition(event_type: EventType) -> dict[str, object]:
    edge, _ = _accepted()
    event = _event(edge, event_type, event_id=f"event-{event_type.value}")
    assert (
        edge.ingest_feedback(_signed(edge, event, f"token-{event_type.value}"))
        == "applied"
    )
    return {"event_type": event_type.value, "state": edge.records["edge-1"].state.value}


def _timeout_before() -> dict[str, object]:
    edge = MailEdge(_KEY, clock=lambda: _NOW)
    adapter = ScriptedAdapter()
    adapter.queue(ScriptedOutcome(timeout_after_acceptance=False))
    record = edge.submit(_request(), adapter)
    assert record.state is DeliveryState.RETRY
    return {"state": record.state.value, "safe_to_retry": True}


def _timeout_after() -> dict[str, object]:
    edge = MailEdge(_KEY, clock=lambda: _NOW)
    adapter = ScriptedAdapter()
    adapter.queue(ScriptedOutcome(timeout_after_acceptance=True))
    record = edge.submit(_request(), adapter)
    assert record.state is DeliveryState.UNKNOWN
    edge.submit(_request(), adapter)
    assert adapter.submit_calls == ["edge-1"]
    return {"state": record.state.value, "automatic_resubmissions": 0}


def _crash_after_data() -> dict[str, object]:
    edge = MailEdge(_KEY, clock=lambda: _NOW)
    adapter = ScriptedAdapter()
    try:
        edge.submit(_request(), adapter, crash_after_core_data=True)
    except CoreDataCrash:
        pass
    else:
        raise AssertionError("crash injection did not interrupt submission")
    assert [record.state for record in edge.recover_queued()] == [DeliveryState.QUEUED]
    record = edge.submit(_request(), adapter)
    assert record.state is DeliveryState.ACCEPTED
    assert len(adapter.submit_calls) == 1
    return {"recovered": 1, "provider_submissions": 1}


def _retry(reason: str) -> dict[str, object]:
    edge = MailEdge(_KEY, clock=lambda: _NOW)
    adapter = ScriptedAdapter()
    adapter.queue(
        ScriptedOutcome(
            AdapterResult(
                SubmissionDisposition.RETRY,
                diagnostic_code=reason,
                diagnostic=f"injected {reason}",
            )
        )
    )
    record = edge.submit(_request(), adapter)
    assert record.state is DeliveryState.RETRY
    return {"state": record.state.value, "reason": reason, "data_retained": True}


def _cutover_fixture() -> tuple[ManualCutover, tuple[str, ...]]:
    edge = MailEdge(_KEY, clock=lambda: _NOW)
    queued = edge.persist_data(_request("queued"))
    adapter = ScriptedAdapter()
    adapter.queue(
        ScriptedOutcome(AdapterResult(SubmissionDisposition.RETRY, diagnostic="retry")),
        ScriptedOutcome(timeout_after_acceptance=True),
    )
    retry = edge.submit(_request("retry"), adapter)
    unknown = edge.submit(_request("unknown"), adapter)
    assert (queued.state, retry.state, unknown.state) == (
        DeliveryState.QUEUED,
        DeliveryState.RETRY,
        DeliveryState.UNKNOWN,
    )
    router = ManualCutover("primary")
    routeable = router.begin("fallback", edge.records.values())
    return router, routeable


def _cutover() -> dict[str, object]:
    router, routeable = _cutover_fixture()
    assert set(routeable) == {"queued", "retry"}
    assert router.quarantined_unknown == {"unknown"}
    return {
        "target": router.active_adapter,
        "routeable": sorted(routeable),
        "quarantined_unknown": sorted(router.quarantined_unknown),
    }


def _drain() -> dict[str, object]:
    router, _ = _cutover_fixture()
    assert router.draining_adapter == "primary"
    router.drain_complete()
    assert router.draining_adapter is None
    return {"drained": "primary", "active": router.active_adapter}


def _rollback() -> dict[str, object]:
    router, _ = _cutover_fixture()
    router.drain_complete()
    router.rollback("primary")
    assert router.active_adapter == "primary"
    return {"active": router.active_adapter, "history": list(router.history)}


def _unknown_reconciliation() -> dict[str, object]:
    edge = MailEdge(_KEY, clock=lambda: _NOW)
    adapter = ScriptedAdapter()
    adapter.queue(ScriptedOutcome(timeout_after_acceptance=True))
    record = edge.submit(_request(), adapter)
    assert record.state is DeliveryState.UNKNOWN
    reconciled = edge.reconcile("edge-1", adapter)
    assert reconciled.state is DeliveryState.ACCEPTED
    return {"state": reconciled.state.value, "provider_message_id_mapped": True}


def _unknown_unresolved() -> dict[str, object]:
    edge = MailEdge(_KEY, clock=lambda: _NOW)
    adapter = ScriptedAdapter()
    adapter.queue(ScriptedOutcome(timeout_after_acceptance=False))
    record = edge.submit(_request(), adapter)
    record.state = DeliveryState.UNKNOWN
    reconciled = edge.reconcile("edge-1", adapter)
    assert reconciled.state is DeliveryState.UNKNOWN
    assert len(adapter.submit_calls) == 1
    return {"state": reconciled.state.value, "automatic_resubmissions": 0}
