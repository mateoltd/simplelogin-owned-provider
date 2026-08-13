from __future__ import annotations

import sqlite3
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest
from conftest import active_binding

from mail_edge.contracts import BindingDirection, BindingState
from mail_edge.errors import (
    ConfigurationError,
    InvalidTransition,
    QualificationError,
    UnknownDomain,
)


def test_activation_requires_current_product_evidence_not_provider_status(edge):
    binding = edge["bindings"].create(
        domain="aliases.example",
        direction=BindingDirection.INBOUND,
        provider="mailgun",
        provider_config={"credential_ref": "mailgun-test"},
    )
    edge["bindings"].transition(binding.id, BindingState.SHADOW)
    with pytest.raises(QualificationError, match="activation lacks policy evidence"):
        edge["bindings"].transition(binding.id, BindingState.ACTIVE)
    missing = edge["registry"].missing_evidence(
        "mailgun", "aliases.example", BindingDirection.INBOUND
    )
    assert missing


def test_expired_failed_and_other_domain_evidence_do_not_activate(edge):
    registry = edge["registry"]
    now = datetime.now(UTC)
    for requirement in registry.policy.requirements(BindingDirection.INBOUND):
        registry.record_evidence(
            provider="mailgun",
            domain_scope="other.example" if requirement.exact_domain else "*",
            capability=requirement.capability,
            passed=False,
            artifact_sha256="b" * 64,
            evidence_uri="artifact:test/failed",
            observed_at=now - timedelta(days=2),
            expires_at=now - timedelta(days=1),
            reviewer="test-suite",
        )
    assert registry.missing_evidence(
        "mailgun", "aliases.example", BindingDirection.INBOUND
    )


def test_inbound_and_outbound_bindings_are_independent_and_exact(edge):
    inbound = active_binding(edge, BindingDirection.INBOUND)
    outbound = active_binding(edge, BindingDirection.OUTBOUND)
    assert inbound.generation == 1
    assert outbound.generation == 1
    assert (
        edge["bindings"].resolve_active("ALIASES.EXAMPLE.", BindingDirection.INBOUND).id
        == inbound.id
    )
    assert (
        edge["bindings"].resolve_active("aliases.example", BindingDirection.OUTBOUND).id
        == outbound.id
    )
    with pytest.raises(UnknownDomain):
        edge["bindings"].resolve_active("sub.aliases.example", BindingDirection.INBOUND)
    with pytest.raises(UnknownDomain):
        edge["bindings"].resolve_active("unknown.example", BindingDirection.OUTBOUND)


def test_switch_is_atomic_generation_pinned_and_old_route_drains(edge):
    first = active_binding(edge, BindingDirection.OUTBOUND)
    second = edge["bindings"].create(
        domain="aliases.example",
        direction=BindingDirection.OUTBOUND,
        provider="mailgun",
        provider_config={"credential_ref": "mailgun-second"},
    )
    edge["bindings"].transition(second.id, BindingState.SHADOW)
    previous, active = edge["bindings"].switch(second.id)
    assert previous.id == first.id
    assert edge["bindings"].get(first.id).state is BindingState.DRAINING
    assert active.state is BindingState.ACTIVE
    assert active.generation == 2
    assert (
        edge["bindings"].resolve_active("aliases.example", BindingDirection.OUTBOUND).id
        == second.id
    )


def test_route_generation_is_immutable_in_code_and_database(edge):
    binding = active_binding(edge, BindingDirection.INBOUND)
    with pytest.raises(FrozenInstanceError):
        binding.domain = "changed.example"
    with (
        edge["database"].transaction(immediate=True) as connection,
        pytest.raises(sqlite3.IntegrityError, match="immutable"),
    ):
        connection.execute(
            "UPDATE route_generations SET provider_config = ? WHERE id = ?",
            ('{"credential_ref":"changed"}', binding.id),
        )


def test_binding_config_rejects_embedded_credentials(edge):
    with pytest.raises(ConfigurationError, match="credentials"):
        edge["bindings"].create(
            domain="aliases.example",
            direction=BindingDirection.OUTBOUND,
            provider="mailgun",
            provider_config={
                "credential_ref": "mailgun-test",
                "api_key": "must-not-be-here",
            },
        )


def test_draining_cannot_skip_to_active_or_disable_with_pending(edge):
    binding = active_binding(edge, BindingDirection.OUTBOUND)
    edge["bindings"].transition(binding.id, BindingState.DRAINING)
    with pytest.raises(InvalidTransition):
        edge["bindings"].transition(binding.id, BindingState.ACTIVE)
