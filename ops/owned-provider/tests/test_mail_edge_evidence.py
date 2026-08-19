from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPOSITORY / "ops" / "owned-provider" / "scripts"))

from mail_edge_evidence import ARTIFACTS, audit_evidence, canonical_json  # noqa: E402

SOURCE_SHA = "1" * 40
EVIDENCE_SHA = "2" * 40


def write_fixture(directory: Path) -> None:
    artifact_digests = []
    for index, name in enumerate(ARTIFACTS):
        payload = json.dumps(
            {"index": index, "sourceSha": SOURCE_SHA}, sort_keys=True
        ).encode()
        (directory / name).write_bytes(payload)
        artifact_digests.append(hashlib.sha256(payload).hexdigest())
    (directory / "production-drills").mkdir()
    (directory / "production-drills/evidence.json").write_text("{}")
    (directory / "qualification-public.pem").write_text(
        "-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n"
    )
    evidence = {
        "limitations": ["fixture limitation"],
        "qualificationStatus": "limited",
        "reports": [
            {"artifactDigestSha256": digest, "id": str(index), "status": "pass"}
            for index, digest in enumerate(artifact_digests)
        ],
        "schemaVersion": "w9-qualification-v1",
        "sourceSha": SOURCE_SHA,
    }
    (directory / "qualification.v1.json").write_text(json.dumps(evidence))
    signed = {
        "evidence": evidence,
        "evidenceDigestSha256": hashlib.sha256(canonical_json(evidence)).hexdigest(),
        "schemaVersion": "w9-signed-qualification-v1",
        "signature": {"algorithm": "ed25519", "keyId": "fixture", "value": "value"},
    }
    (directory / "qualification.signed.v1.json").write_text(json.dumps(signed))


def test_evidence_audit_binds_source_canonical_payload_and_artifacts(tmp_path: Path):
    write_fixture(tmp_path)

    result = audit_evidence(tmp_path, SOURCE_SHA, EVIDENCE_SHA)

    assert result["source_commit"] == SOURCE_SHA
    assert result["evidence_commit"] == EVIDENCE_SHA
    assert result["qualification_status"] == "limited"
    assert result["report_count"] == 4


def test_evidence_audit_rejects_payload_substitution(tmp_path: Path):
    write_fixture(tmp_path)
    unsigned = json.loads((tmp_path / "qualification.v1.json").read_text())
    unsigned["sourceSha"] = "3" * 40
    (tmp_path / "qualification.v1.json").write_text(json.dumps(unsigned))

    with pytest.raises(ValueError, match="signed and unsigned"):
        audit_evidence(tmp_path, SOURCE_SHA, EVIDENCE_SHA)
