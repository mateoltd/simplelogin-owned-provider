"""Administrative CLI for migrations, bindings, evidence, and reconciliation."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .contracts import BindingDirection, BindingState
from .db import migrate, migration_status
from .registry import Capability
from .runtime import build_runtime


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("timestamp must include a timezone")
    return parsed


def _output(value: Any) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _binding_document(binding: Any) -> dict[str, Any]:
    return {
        "id": binding.id,
        "domain": binding.domain,
        "direction": binding.direction.value,
        "generation": binding.generation,
        "provider": binding.provider,
        "state": binding.state.value,
        "provider_config": binding.provider_config,
        "policy_version": binding.qualified_policy_version,
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate")
    commands.add_parser("status")

    binding = commands.add_parser("binding")
    binding_commands = binding.add_subparsers(dest="binding_command", required=True)
    create = binding_commands.add_parser("create")
    create.add_argument("--domain", required=True)
    create.add_argument(
        "--direction", choices=[item.value for item in BindingDirection], required=True
    )
    create.add_argument("--provider", choices=("mailgun",), required=True)
    create.add_argument("--config", type=Path, required=True)
    transition = binding_commands.add_parser("transition")
    transition.add_argument("binding_id")
    transition.add_argument("state", choices=[item.value for item in BindingState])
    switch = binding_commands.add_parser("switch")
    switch.add_argument("candidate_id")
    show = binding_commands.add_parser("show")
    show.add_argument("binding_id")

    evidence = commands.add_parser("evidence")
    evidence.add_argument("--provider", choices=("mailgun",), required=True)
    evidence.add_argument("--domain-scope", required=True)
    evidence.add_argument(
        "--capability", choices=[item.value for item in Capability], required=True
    )
    evidence.add_argument("--passed", action="store_true")
    evidence.add_argument("--artifact-sha256", required=True)
    evidence.add_argument("--evidence-uri", required=True)
    evidence.add_argument("--observed-at", type=_time, required=True)
    evidence.add_argument("--expires-at", type=_time, required=True)
    evidence.add_argument("--reviewer", required=True)

    unknown = commands.add_parser("unknown")
    unknown_commands = unknown.add_subparsers(dest="unknown_command", required=True)
    unknown_list = unknown_commands.add_parser("list")
    unknown_list.add_argument("--limit", type=int, default=100)
    resolve = unknown_commands.add_parser("resolve")
    resolve.add_argument("submission_id")
    outcome = resolve.add_mutually_exclusive_group(required=True)
    outcome.add_argument("--accepted", action="store_true")
    outcome.add_argument("--rejected", action="store_true")
    resolve.add_argument("--provider-receipt-id")
    resolve.add_argument("--evidence", required=True)

    quarantine = commands.add_parser("quarantine")
    quarantine.add_argument("--limit", type=int, default=100)
    return root


def main() -> None:
    arguments = parser().parse_args()
    runtime = build_runtime()
    if arguments.command == "migrate":
        _output({"applied": migrate(runtime.database)})
    elif arguments.command == "status":
        expected, applied = migration_status(runtime.database)
        _output(
            {
                "database": runtime.database.ping(),
                "expected_migrations": expected,
                "applied_migrations": applied,
                "state_counts": runtime.repository.state_counts(),
                "unknown": len(runtime.repository.list_unknown(limit=1000)),
                "quarantine": len(runtime.repository.list_quarantine(limit=1000)),
            }
        )
    elif arguments.command == "binding":
        if arguments.binding_command == "create":
            config = json.loads(arguments.config.read_text(encoding="utf-8"))
            created = runtime.bindings.create(
                domain=arguments.domain,
                direction=BindingDirection(arguments.direction),
                provider=arguments.provider,
                provider_config=config,
            )
            _output(_binding_document(created))
        elif arguments.binding_command == "transition":
            updated = runtime.bindings.transition(
                arguments.binding_id, BindingState(arguments.state)
            )
            _output(_binding_document(updated))
        elif arguments.binding_command == "switch":
            previous, active = runtime.bindings.switch(arguments.candidate_id)
            _output(
                {
                    "draining": _binding_document(previous) if previous else None,
                    "active": _binding_document(active),
                }
            )
        else:
            _output(_binding_document(runtime.bindings.get(arguments.binding_id)))
    elif arguments.command == "evidence":
        evidence_id = runtime.registry.record_evidence(
            provider=arguments.provider,
            domain_scope=arguments.domain_scope,
            capability=Capability(arguments.capability),
            passed=arguments.passed,
            artifact_sha256=arguments.artifact_sha256,
            evidence_uri=arguments.evidence_uri,
            observed_at=arguments.observed_at,
            expires_at=arguments.expires_at,
            reviewer=arguments.reviewer,
        )
        _output({"evidence_id": evidence_id})
    elif arguments.command == "unknown":
        if arguments.unknown_command == "list":
            _output(runtime.repository.list_unknown(limit=arguments.limit))
        else:
            state = runtime.repository.reconcile_unknown(
                arguments.submission_id,
                accepted=arguments.accepted,
                provider_receipt_id=arguments.provider_receipt_id,
                resolution=arguments.evidence,
            )
            _output({"submission_id": arguments.submission_id, "state": state.value})
    elif arguments.command == "quarantine":
        _output(runtime.repository.list_quarantine(limit=arguments.limit))


if __name__ == "__main__":
    main()
