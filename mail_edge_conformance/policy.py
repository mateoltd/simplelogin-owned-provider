"""Fail-closed adapter activation policy based only on qualification evidence."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable

from .corpus import MANIFEST_PATH, load_corpus
from .evidence import CapabilityEvidence


REQUIRED_FAULT_RESULTS = frozenset(
    {
        "fault:notices-duplicated",
        "fault:events-duplicated",
        "fault:events-reordered",
        "fault:signature-replay",
        "fault:signature-invalid",
        "fault:rejection",
        "fault:delay",
        "fault:soft-bounce",
        "fault:hard-bounce",
        "fault:complaint",
        "fault:timeout-before-acceptance",
        "fault:timeout-after-acceptance",
        "fault:crash-after-core-data",
        "fault:credential-failure",
        "fault:quota-exhaustion",
        "fault:provider-pause",
        "fault:cutover",
        "fault:drain",
        "fault:rollback",
        "fault:unknown-reconciliation",
        "fault:unknown-reconciliation-unresolved",
    }
)
REQUIRED_LOCAL_E2E_RESULTS = frozenset(
    {
        "e2e:simplelogin-edge-mailbox",
        "e2e:reverse-alias-thread",
        "e2e:semantic-fidelity",
    }
)
REQUIRED_LIVE_RESULTS = frozenset(
    {
        "live:credentials-explicit",
        "live:isolated-staging-domains",
        "live:delivery-correlation",
        "live:event-correlation",
        "live:size-boundary",
    }
)


@dataclass(frozen=True)
class ActivationDecision:
    adapter: str
    adapter_version: str | None
    qualified: bool
    blockers: tuple[str, ...]
    evidence_revisions: tuple[str, ...]

    def as_json(self) -> dict[str, object]:
        return {
            "schema": "mail-edge-activation-decision/v1",
            "adapter": self.adapter,
            "adapter_version": self.adapter_version,
            "qualified": self.qualified,
            "blockers": list(self.blockers),
            "evidence_revisions": list(self.evidence_revisions),
            "basis": "executed-capability-evidence-only",
        }


def evaluate_activation(
    adapter: str, evidence: Iterable[CapabilityEvidence]
) -> ActivationDecision:
    matching = tuple(item for item in evidence if item.adapter == adapter)
    blockers: list[str] = []
    if not matching:
        return ActivationDecision(adapter, None, False, ("no evidence",), ())
    versions = {item.adapter_version for item in matching}
    if len(versions) != 1:
        blockers.append("evidence spans multiple adapter versions")
    revisions = {item.source_revision for item in matching}
    if len(revisions) != 1:
        blockers.append("evidence spans multiple source revisions")
    if any(item.non_activatable for item in matching):
        blockers.append("adapter is marked non-activatable")

    by_mode = {
        mode: [item for item in matching if item.mode == mode]
        for mode in (
            "neutral-contract",
            "local-e2e",
            "live-provider",
        )
    }
    for mode, documents in by_mode.items():
        if not documents:
            blockers.append(f"missing {mode} evidence")

    current_manifest_digest = hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()
    for mode in ("neutral-contract", "live-provider"):
        if any(
            item.corpus_manifest_sha256 != current_manifest_digest
            for item in by_mode[mode]
        ):
            blockers.append(f"{mode} evidence does not match the current corpus")

    result_statuses: dict[tuple[str, str], set[str]] = {}
    for document in matching:
        for result in document.results:
            result_statuses.setdefault((document.mode, result.result_id), set()).add(
                result.status
            )

    required_corpus = {f"corpus:{case.case_id}" for case in load_corpus()} | {
        "thread:reverse-alias-four-message"
    }
    _require_results(
        result_statuses,
        "neutral-contract",
        required_corpus | REQUIRED_FAULT_RESULTS,
        blockers,
    )
    if not any(
        mode == "neutral-contract"
        and identifier.startswith("boundary:")
        and status == "passed"
        for (mode, identifier), statuses in result_statuses.items()
        for status in statuses
    ):
        blockers.append("neutral-contract has no passed size-boundary observations")
    _require_results(result_statuses, "local-e2e", REQUIRED_LOCAL_E2E_RESULTS, blockers)
    _require_results(
        result_statuses,
        "live-provider",
        REQUIRED_LIVE_RESULTS | required_corpus,
        blockers,
    )

    live_documents = by_mode["live-provider"]
    if live_documents and not all(
        item.isolated_staging_domains for item in live_documents
    ):
        blockers.append("live evidence does not name isolated staging domains")
    return ActivationDecision(
        adapter=adapter,
        adapter_version=next(iter(versions)) if len(versions) == 1 else None,
        qualified=not blockers,
        blockers=tuple(sorted(set(blockers))),
        evidence_revisions=tuple(sorted(revisions)),
    )


def _require_results(
    statuses: dict[tuple[str, str], set[str]],
    mode: str,
    required: frozenset[str] | set[str],
    blockers: list[str],
) -> None:
    for result_id in sorted(required):
        observed = statuses.get((mode, result_id), set())
        if observed != {"passed"}:
            description = ",".join(sorted(observed)) if observed else "missing"
            blockers.append(f"{mode} {result_id} is {description}")
