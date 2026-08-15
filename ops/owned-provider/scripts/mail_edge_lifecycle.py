"""Provider-neutral operator lifecycle and quarantine controls."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, is_dataclass
from typing import Mapping

from app.mail_edge.client import MailEdgeClient
from app.mail_edge.configuration import configuration_from_environment
from app.mail_edge.control import MailEdgeControlService
from app.mail_edge.repository import RouteBindingProjectionRepository
from server import create_light_app


def render(value: object) -> object:
    if hasattr(value, "to_wire"):
        return render(value.to_wire())
    if is_dataclass(value):
        return render(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): render(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [render(child) for child in value]
    return value


def evidence(value: str) -> Mapping[str, object]:
    document = json.loads(value)
    if not isinstance(document, dict):
        raise ValueError("evidence must be one JSON object")
    return document


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    children = root.add_subparsers(dest="command", required=True)
    binding = children.add_parser("binding-inspect")
    binding.add_argument("binding_id")
    binding.add_argument("binding_version", type=int)
    transition = children.add_parser("binding-transition")
    transition.add_argument("binding_id")
    transition.add_argument("binding_version", type=int)
    transition.add_argument("action", choices=("activate", "drain", "retire"))
    transition.add_argument("expected_version", type=int)
    transition.add_argument("reason_code")
    outbound = children.add_parser("outbound-inspect")
    outbound.add_argument("intent_id")
    outbound_decide = children.add_parser("outbound-decide")
    outbound_decide.add_argument("intent_id")
    outbound_decide.add_argument(
        "action",
        choices=("resolve_accepted", "resolve_not_sent", "authorize_retry"),
    )
    outbound_decide.add_argument("expected_fence", type=int)
    outbound_decide.add_argument("expected_version", type=int)
    outbound_decide.add_argument("reason_code")
    outbound_decide.add_argument("evidence_json", type=evidence)
    inbound = children.add_parser("inbound-inspect")
    inbound.add_argument("receipt_id")
    inbound_decide = children.add_parser("inbound-decide")
    inbound_decide.add_argument("receipt_id")
    inbound_decide.add_argument("action", choices=("release", "terminal"))
    inbound_decide.add_argument("expected_fence", type=int)
    inbound_decide.add_argument("expected_version", type=int)
    inbound_decide.add_argument("reason_code")
    inbound_decide.add_argument("evidence_json", type=evidence)
    return root


def execute(arguments: argparse.Namespace, control: MailEdgeControlService) -> object:
    if arguments.command == "binding-inspect":
        return control.inspect_binding(arguments.binding_id, arguments.binding_version)
    if arguments.command == "binding-transition":
        return control.transition_binding(
            arguments.binding_id,
            arguments.binding_version,
            arguments.action,
            expected_version=arguments.expected_version,
            reason_code=arguments.reason_code,
        )
    if arguments.command == "outbound-inspect":
        return control.inspect_outbound_quarantine(arguments.intent_id)
    if arguments.command == "outbound-decide":
        return control.decide_outbound_quarantine(
            arguments.intent_id,
            arguments.action,
            evidence=arguments.evidence_json,
            expected_fence=arguments.expected_fence,
            expected_version=arguments.expected_version,
            reason_code=arguments.reason_code,
        )
    if arguments.command == "inbound-inspect":
        return control.inspect_inbound_quarantine(arguments.receipt_id)
    if arguments.command == "inbound-decide":
        return control.decide_inbound_quarantine(
            arguments.receipt_id,
            arguments.action,
            evidence=arguments.evidence_json,
            expected_fence=arguments.expected_fence,
            expected_version=arguments.expected_version,
            reason_code=arguments.reason_code,
        )
    raise RuntimeError("unsupported Mail Edge lifecycle command")


def main() -> None:
    configuration = configuration_from_environment()
    if configuration is None:
        raise SystemExit("Mail Edge integration is disabled")
    client = MailEdgeClient(configuration)
    try:
        control = MailEdgeControlService(
            client, RouteBindingProjectionRepository(configuration.tenant_id)
        )
        with create_light_app().app_context():
            result = execute(parser().parse_args(), control)
        print(json.dumps(render(result), sort_keys=True))
    finally:
        if not client.close():
            raise RuntimeError("Mail Edge client did not close cleanly")


if __name__ == "__main__":
    main()
