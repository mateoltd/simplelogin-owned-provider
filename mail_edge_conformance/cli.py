"""Command-line qualification and activation-policy entry points."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .corpus import MANIFEST_PATH, load_corpus
from .evidence import CapabilityEvidence, load_evidence
from .live import MailgunLiveConfiguration, run_live_mailgun
from .policy import evaluate_activation
from .providers.mailgun import MailgunAdapter, MailgunContractTransport
from .qualification import qualify_corpus, qualify_size_boundary, run_failure_matrix


def main() -> None:
    parser = argparse.ArgumentParser(prog="mail-edge-conformance")
    subparsers = parser.add_subparsers(dest="command", required=True)
    neutral = subparsers.add_parser("neutral")
    neutral.add_argument("--adapter", choices=("reference", "mailgun"), required=True)
    neutral.add_argument("--size-limit", type=int, default=8192)
    neutral.add_argument("--output", type=Path, required=True)
    live = subparsers.add_parser("live-mailgun")
    live.add_argument("--output", type=Path, required=True)
    policy = subparsers.add_parser("policy")
    policy.add_argument("--adapter", required=True)
    policy.add_argument("evidence", nargs="+", type=Path)
    subparsers.add_parser("corpus")
    args = parser.parse_args()
    if args.command == "neutral":
        document = _neutral_evidence(args.adapter, args.size_limit)
        document.write(args.output)
        print(json.dumps(document.as_json(), sort_keys=True))
    elif args.command == "live-mailgun":
        config = MailgunLiveConfiguration.from_environment()
        started = datetime.now(timezone.utc)
        results = run_live_mailgun(config)
        document = CapabilityEvidence(
            adapter="mailgun",
            adapter_version=MailgunAdapter.adapter_version,
            mode="live-provider",
            source_revision=_source_revision(),
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            results=results,
            corpus_manifest_sha256=_manifest_sha256(),
            isolated_staging_domains=config.isolated_domains,
        )
        document.write(args.output)
        print(json.dumps(document.as_json(), sort_keys=True))
    elif args.command == "policy":
        decision = evaluate_activation(args.adapter, load_evidence(args.evidence))
        print(json.dumps(decision.as_json(), indent=2, sort_keys=True))
        raise SystemExit(0 if decision.qualified else 1)
    else:
        print(
            json.dumps(
                {
                    "schema": "mail-edge-eml-corpus-summary/v1",
                    "manifest_sha256": _manifest_sha256(),
                    "cases": [
                        {
                            "id": case.case_id,
                            "sha256": case.sha256,
                            "wire_bytes": len(case.rfc822_bytes),
                            "features": list(case.features),
                        }
                        for case in load_corpus()
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )


def _neutral_evidence(adapter_name: str, size_limit: int) -> CapabilityEvidence:
    if size_limit < 1024:
        raise ValueError("neutral size limit must be at least 1024 bytes")
    started = datetime.now(timezone.utc)
    if adapter_name == "mailgun":
        transport = MailgunContractTransport(size_limit=size_limit)
        adapter = MailgunAdapter(
            domain="qualification.invalid",
            api_key="offline-fixture-not-a-secret",
            api_base="http://mailgun-contract.invalid",
            transport=transport,
            allow_test_endpoint=True,
        )
        results = (
            *qualify_corpus(adapter, transport),
            *qualify_size_boundary(adapter, transport, limit=size_limit),
            *run_failure_matrix(),
        )
        version = MailgunAdapter.adapter_version
        non_activatable = False
    else:
        from .qualification import CapturingAdapter

        adapter = CapturingAdapter(size_limit=size_limit)
        results = (
            *qualify_corpus(adapter, adapter),
            *qualify_size_boundary(adapter, adapter, limit=size_limit),
            *run_failure_matrix(),
        )
        version = "reference-v1"
        non_activatable = True
    return CapabilityEvidence(
        adapter="mailgun" if adapter_name == "mailgun" else "neutral-reference",
        adapter_version=version,
        mode="neutral-contract",
        source_revision=_source_revision(),
        started_at=started,
        finished_at=datetime.now(timezone.utc),
        results=tuple(results),
        corpus_manifest_sha256=_manifest_sha256(),
        non_activatable=non_activatable,
    )


def _source_revision() -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
    ).strip()


def _manifest_sha256() -> str:
    return hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()


if __name__ == "__main__":
    main()
