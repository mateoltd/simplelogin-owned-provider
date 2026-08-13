import json
from datetime import datetime, timezone

from mail_edge_conformance.corpus import load_corpus
from mail_edge_conformance.evidence import (
    CapabilityEvidence,
    QualificationResult,
    load_evidence,
)
from mail_edge_conformance.policy import (
    REQUIRED_LIVE_RESULTS,
    REQUIRED_LOCAL_E2E_RESULTS,
    evaluate_activation,
)
from mail_edge_conformance.qualification import run_neutral_suite


NOW = datetime(2026, 8, 13, 12, tzinfo=timezone.utc)


def _result(identifier, gate="test"):
    return QualificationResult(identifier, gate, "passed", "executed", {})


def _evidence(mode, results, domains=(), revision="a" * 40, manifest=None):
    if manifest is None and mode in {"neutral-contract", "live-provider"}:
        from mail_edge_conformance.cli import _manifest_sha256

        manifest = _manifest_sha256()
    return CapabilityEvidence(
        adapter="mailgun",
        adapter_version="messages-mime-v1",
        mode=mode,
        source_revision=revision,
        started_at=NOW,
        finished_at=NOW,
        results=tuple(results),
        corpus_manifest_sha256=manifest,
        isolated_staging_domains=domains,
    )


def test_evidence_digest_detects_tampering(tmp_path):
    evidence = _evidence("neutral-contract", run_neutral_suite())
    path = tmp_path / "evidence.json"
    evidence.write(path)
    assert load_evidence((path,)) == (evidence,)
    document = json.loads(path.read_text())
    document["results"][0]["status"] = "failed"
    path.write_text(json.dumps(document))
    try:
        load_evidence((path,))
    except ValueError as error:
        assert "digest mismatch" in str(error)
    else:
        raise AssertionError("tampered evidence was accepted")


def test_activation_requires_executed_contract_local_and_live_evidence():
    neutral = _evidence("neutral-contract", run_neutral_suite())
    local = _evidence(
        "local-e2e",
        [_result(item, "end-to-end") for item in REQUIRED_LOCAL_E2E_RESULTS],
    )
    live_results = [_result(item, "live") for item in REQUIRED_LIVE_RESULTS]
    live_results.extend(
        _result(f"corpus:{case.case_id}", "mime-fidelity") for case in load_corpus()
    )
    live_results.append(_result("thread:reverse-alias-four-message", "threading"))
    live = _evidence(
        "live-provider", live_results, ("stage-a.invalid", "stage-b.invalid")
    )
    decision = evaluate_activation("mailgun", (neutral, local, live))
    assert decision.qualified
    assert not decision.blockers

    without_live = evaluate_activation("mailgun", (neutral, local))
    assert not without_live.qualified
    assert any(
        "missing live-provider evidence" in item for item in without_live.blockers
    )


def test_marketing_name_or_empty_evidence_never_qualifies():
    decision = evaluate_activation("mailgun", ())
    assert not decision.qualified
    assert decision.blockers == ("no evidence",)


def test_activation_rejects_mixed_revisions_stale_corpus_and_failed_duplicates():
    neutral_results = run_neutral_suite()
    neutral = _evidence("neutral-contract", neutral_results)
    local = _evidence(
        "local-e2e",
        [_result(item, "end-to-end") for item in REQUIRED_LOCAL_E2E_RESULTS],
        revision="c" * 40,
    )
    decision = evaluate_activation("mailgun", (neutral, local))
    assert "evidence spans multiple source revisions" in decision.blockers

    stale = _evidence("neutral-contract", neutral_results, manifest="d" * 64)
    decision = evaluate_activation("mailgun", (stale,))
    assert (
        "neutral-contract evidence does not match the current corpus"
        in decision.blockers
    )

    failed = QualificationResult(
        neutral_results[0].result_id,
        neutral_results[0].gate,
        "failed",
        "executed",
        {},
    )
    duplicate = _evidence("neutral-contract", (failed,))
    decision = evaluate_activation("mailgun", (neutral, duplicate))
    assert any(
        neutral_results[0].result_id in blocker and "failed,passed" in blocker
        for blocker in decision.blockers
    )
