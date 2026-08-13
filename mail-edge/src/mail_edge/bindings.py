"""Exact-domain, immutable-generation provider bindings."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .contracts import (
    BindingDirection,
    BindingState,
    isoformat,
    normalize_domain,
)
from .db import Database
from .errors import ConfigurationError, InvalidTransition, UnknownDomain
from .ids import uuid7_str
from .registry import PROVIDER_CAPABILITIES, CapabilityRegistry

_ALLOWED_TRANSITIONS = {
    BindingState.PREPARED: {BindingState.SHADOW, BindingState.DISABLED},
    BindingState.SHADOW: {BindingState.ACTIVE, BindingState.DISABLED},
    BindingState.ACTIVE: {BindingState.DRAINING},
    BindingState.DRAINING: {BindingState.DISABLED},
    BindingState.DISABLED: set(),
}
_MAILGUN_CONFIG_KEYS = frozenset({"credential_ref", "smtp_host", "smtp_port"})


@dataclass(frozen=True, slots=True)
class Binding:
    id: str
    domain: str
    direction: BindingDirection
    generation: int
    provider: str
    state: BindingState
    provider_config: dict[str, Any]
    qualified_policy_version: str


def _binding(row: dict[str, Any]) -> Binding:
    return Binding(
        id=str(row["id"]),
        domain=str(row["domain"]),
        direction=BindingDirection(row["direction"]),
        generation=int(row["generation"]),
        provider=str(row["provider"]),
        state=BindingState(row["state"]),
        provider_config=json.loads(row["provider_config"]),
        qualified_policy_version=str(row["qualified_policy_version"]),
    )


class BindingStore:
    def __init__(self, database: Database, registry: CapabilityRegistry):
        self.database = database
        self.registry = registry

    def create(
        self,
        *,
        domain: str,
        direction: BindingDirection,
        provider: str,
        provider_config: dict[str, Any],
    ) -> Binding:
        normalized = normalize_domain(domain)
        if provider not in PROVIDER_CAPABILITIES:
            raise ConfigurationError("provider adapter is not installed")
        self._validate_provider_config(provider, provider_config)
        encoded_config = json.dumps(
            provider_config, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        now = isoformat(datetime.now(UTC))
        binding_id = uuid7_str()
        with self.database.transaction(immediate=True) as connection:
            row = connection.execute(
                """
                SELECT COALESCE(MAX(generation), 0) AS maximum
                FROM route_generations WHERE domain = ? AND direction = ?
                """,
                (normalized, direction.value),
            ).fetchone()
            generation = int(row["maximum"]) + 1
            connection.execute(
                """
                INSERT INTO route_generations(
                    id, domain, direction, generation, provider, state,
                    provider_config, qualified_policy_version, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    binding_id,
                    normalized,
                    direction.value,
                    generation,
                    provider,
                    BindingState.PREPARED.value,
                    encoded_config,
                    self.registry.policy.version,
                    now,
                    now,
                ),
            )
        return self.get(binding_id)

    @staticmethod
    def _validate_provider_config(provider: str, config: dict[str, Any]) -> None:
        encoded = json.dumps(config, sort_keys=True)
        if len(encoded.encode()) > 8192:
            raise ConfigurationError("provider configuration is too large")
        allowed = _MAILGUN_CONFIG_KEYS if provider == "mailgun" else frozenset()
        if set(config) - allowed:
            raise ConfigurationError(
                "provider credentials and unsupported fields cannot be embedded"
            )
        credential_ref = config.get("credential_ref")
        if not isinstance(credential_ref, str) or not credential_ref.strip():
            raise ConfigurationError("provider config requires a credential_ref")

    def get(self, binding_id: str) -> Binding:
        with self.database.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM route_generations WHERE id = ?", (binding_id,)
            ).fetchone()
        if row is None:
            raise UnknownDomain("binding generation does not exist")
        return _binding(row)

    def resolve_active(self, domain: str, direction: BindingDirection) -> Binding:
        normalized = normalize_domain(domain)
        with self.database.transaction() as connection:
            row = connection.execute(
                """
                SELECT * FROM route_generations
                WHERE domain = ? AND direction = ? AND state = 'active'
                """,
                (normalized, direction.value),
            ).fetchone()
        if row is None:
            raise UnknownDomain(f"no active {direction.value} binding for exact domain")
        return _binding(row)

    def transition(self, binding_id: str, target: BindingState) -> Binding:
        binding = self.get(binding_id)
        if target not in _ALLOWED_TRANSITIONS[binding.state]:
            raise InvalidTransition(
                f"invalid binding transition: {binding.state.value}/{target.value}"
            )
        if target is BindingState.ACTIVE:
            self.registry.assert_activation(
                binding.provider, binding.domain, binding.direction
            )
        if target is BindingState.DISABLED and binding.state is BindingState.DRAINING:
            pending = self.pending_for_binding(binding)
            if pending:
                raise InvalidTransition(f"binding still has {pending} pinned messages")
        now = isoformat(datetime.now(UTC))
        with self.database.transaction(immediate=True) as connection:
            current = connection.execute(
                "SELECT state FROM route_generations WHERE id = ?", (binding_id,)
            ).fetchone()
            if current is None or current["state"] != binding.state.value:
                raise InvalidTransition("binding state changed concurrently")
            connection.execute(
                "UPDATE route_generations SET state = ?, updated_at = ? WHERE id = ?",
                (target.value, now, binding_id),
            )
        return self.get(binding_id)

    def switch(self, candidate_id: str) -> tuple[Binding | None, Binding]:
        candidate = self.get(candidate_id)
        if candidate.state is not BindingState.SHADOW:
            raise InvalidTransition(
                "candidate binding must be shadow before activation"
            )
        self.registry.assert_activation(
            candidate.provider, candidate.domain, candidate.direction
        )
        now = isoformat(datetime.now(UTC))
        previous: Binding | None = None
        with self.database.transaction(immediate=True) as connection:
            current_row = connection.execute(
                """
                SELECT * FROM route_generations
                WHERE domain = ? AND direction = ? AND state = 'active'
                """,
                (candidate.domain, candidate.direction.value),
            ).fetchone()
            if current_row is not None:
                previous = _binding(current_row)
                connection.execute(
                    """
                    UPDATE route_generations
                    SET state = 'draining', updated_at = ? WHERE id = ?
                    """,
                    (now, previous.id),
                )
            changed = connection.execute(
                """
                UPDATE route_generations SET state = 'active', updated_at = ?
                WHERE id = ? AND state = 'shadow'
                """,
                (now, candidate.id),
            ).rowcount
            if changed != 1:
                raise InvalidTransition("candidate state changed concurrently")
        return previous, self.get(candidate.id)

    def pending_for_binding(self, binding: Binding) -> int:
        table = (
            "ingress_messages"
            if binding.direction is BindingDirection.INBOUND
            else "outbound_messages"
        )
        terminal = (
            "('handed_off','quarantined','deleted')"
            if binding.direction is BindingDirection.INBOUND
            else "('accepted','rejected','quarantined','deleted')"
        )
        with self.database.transaction() as connection:
            row = connection.execute(
                f"SELECT COUNT(*) AS count FROM {table} "
                f"WHERE binding_id = ? AND state NOT IN {terminal}",
                (binding.id,),
            ).fetchone()
        return int(row["count"])
