from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mail_edge.bindings import BindingStore
from mail_edge.blob import LocalEncryptedBlobStore
from mail_edge.contracts import BindingDirection, BindingState
from mail_edge.db import Database, migrate, sqlite_url
from mail_edge.registry import CapabilityRegistry
from mail_edge.repository import EdgeRepository


@pytest.fixture
def edge(tmp_path):
    database = Database(sqlite_url(tmp_path / "mail-edge.sqlite"))
    migrate(database)
    blobs = LocalEncryptedBlobStore(tmp_path / "blobs", {"key-1": b"k" * 32}, "key-1")
    registry = CapabilityRegistry(database)
    bindings = BindingStore(database, registry)
    repository = EdgeRepository(
        database,
        blobs,
        bindings,
        diagnostic_salt=b"test-diagnostic-salt-32-bytes!!",
    )
    return {
        "database": database,
        "blobs": blobs,
        "registry": registry,
        "bindings": bindings,
        "repository": repository,
    }


def qualify(registry, provider: str, domain: str, direction: BindingDirection) -> None:
    now = datetime.now(UTC)
    for requirement in registry.policy.requirements(direction):
        scope = domain if requirement.exact_domain else "*"
        registry.record_evidence(
            provider=provider,
            domain_scope=scope,
            capability=requirement.capability,
            passed=True,
            artifact_sha256="a" * 64,
            evidence_uri=f"artifact:test/{direction.value}/{requirement.capability.value}",
            observed_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(days=1),
            reviewer="test-suite",
        )


def active_binding(edge, direction: BindingDirection, domain: str = "aliases.example"):
    qualify(edge["registry"], "mailgun", domain, direction)
    binding = edge["bindings"].create(
        domain=domain,
        direction=direction,
        provider="mailgun",
        provider_config={
            "credential_ref": "mailgun-test",
            "smtp_host": "smtp.mailgun.test",
            "smtp_port": 587,
        },
    )
    edge["bindings"].transition(binding.id, BindingState.SHADOW)
    return edge["bindings"].transition(binding.id, BindingState.ACTIVE)
