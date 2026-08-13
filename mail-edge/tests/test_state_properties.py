from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mail_edge.errors import InvalidTransition
from mail_edge.state import (
    IngressEvent,
    IngressState,
    OutboundEvent,
    OutboundState,
    RetryPolicy,
    reduce_ingress,
    reduce_outbound,
)


@given(st.lists(st.sampled_from(list(OutboundEvent)), max_size=100))
def test_unknown_outcome_never_reenters_automatic_scheduler(events):
    state = OutboundState.QUEUED
    reached_unknown = False
    for event in events:
        try:
            state = reduce_outbound(state, event)
        except InvalidTransition:
            continue
        if reached_unknown:
            assert state in {
                OutboundState.UNKNOWN,
                OutboundState.ACCEPTED,
                OutboundState.REJECTED,
                OutboundState.QUARANTINED,
                OutboundState.DELETED,
            }
            assert state not in {
                OutboundState.QUEUED,
                OutboundState.SUBMITTING,
                OutboundState.RETRY_WAIT,
            }
        reached_unknown = reached_unknown or state is OutboundState.UNKNOWN


@given(st.permutations([IngressEvent.NOTICE, IngressEvent.RAW]))
def test_notice_and_raw_are_order_independent(events):
    state = IngressState.EMPTY
    for event in events:
        state = reduce_ingress(state, event)
    assert state is IngressState.READY
    assert reduce_ingress(state, IngressEvent.NOTICE) is IngressState.READY
    assert reduce_ingress(state, IngressEvent.RAW) is IngressState.READY


def test_retry_schedule_is_deterministic_bounded_and_exponential():
    policy = RetryPolicy(initial_seconds=10, maximum_seconds=100, jitter_ratio=0)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    delays = [
        (policy.due_at("message", attempt, now) - now).total_seconds()
        for attempt in range(1, 7)
    ]
    assert delays == [10, 20, 40, 80, 100, 100]
    assert policy.due_at("message", 3, now) == policy.due_at("message", 3, now)


def test_unknown_rejects_retry_event():
    with pytest.raises(InvalidTransition):
        reduce_outbound(OutboundState.UNKNOWN, OutboundEvent.RETRY_DUE)
