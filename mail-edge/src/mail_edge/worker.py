"""Crash-recoverable ingress, outbound, and retention workers."""

from __future__ import annotations

import argparse
import os
import time
from datetime import UTC, datetime

from .contracts import OutboundResult, SubmissionOutcome
from .errors import ConfigurationError
from .handoff import HTTPSHandoffSink
from .runtime import Runtime, build_runtime, handoff_token, required_env


def process_ingress_once(runtime: Runtime, sink: HTTPSHandoffSink) -> bool:
    claimed = runtime.repository.claim_ingress()
    if claimed is None:
        return False
    result = sink.deliver(claimed)
    runtime.repository.complete_ingress(
        claimed.id,
        success=result.success,
        retryable=result.retryable,
        diagnostic=result.diagnostic_code,
    )
    return True


def process_outbound_once(runtime: Runtime) -> bool:
    claimed = runtime.repository.claim_outbound()
    if claimed is None:
        return False
    try:
        if claimed.binding.provider != "mailgun":
            raise ConfigurationError("no production adapter for pinned provider")
        adapter = runtime.mailgun_adapter(claimed.binding)
        result = adapter.submit(claimed.submission)
    except ConfigurationError:
        result = OutboundResult(
            submission_id=claimed.submission.submission_id,
            outcome=SubmissionOutcome.TEMPORARY_FAILURE,
            provider_receipt_id=None,
            occurred_at=datetime.now(UTC),
            diagnostic_code="adapter_configuration_unavailable",
        )
    runtime.repository.complete_outbound(result)
    return True


def _sink() -> HTTPSHandoffSink:
    return HTTPSHandoffSink(
        required_env("MAIL_EDGE_HANDOFF_URL"),
        handoff_token(),
        allow_insecure_for_tests=os.environ.get("MAIL_EDGE_TEST_ALLOW_HTTP") == "1",
    )


def run(kind: str, *, once: bool, idle_seconds: float = 1.0) -> None:
    runtime = build_runtime()
    sink = _sink() if kind in {"all", "ingress"} else None
    while True:
        worked = False
        if kind in {"all", "ingress"}:
            assert sink is not None
            worked = process_ingress_once(runtime, sink) or worked
        if kind in {"all", "outbound"}:
            worked = process_outbound_once(runtime) or worked
        if kind in {"all", "retention"}:
            worked = runtime.repository.retention_sweep() > 0 or worked
            worked = runtime.repository.orphan_sweep() > 0 or worked
        if once:
            return
        if not worked:
            time.sleep(idle_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--kind", choices=("all", "ingress", "outbound", "retention"), default="all"
    )
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--idle-seconds", type=float, default=1.0)
    arguments = parser.parse_args()
    run(arguments.kind, once=arguments.once, idle_seconds=arguments.idle_seconds)


if __name__ == "__main__":
    main()
