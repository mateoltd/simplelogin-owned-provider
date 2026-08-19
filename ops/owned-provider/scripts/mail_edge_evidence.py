"""Audit the immutable relationship between Mail Edge source and signed evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

SHA256 = re.compile(r"^[0-9a-f]{64}$")
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
ARTIFACTS = (
    "asset-validation.v1.json",
    "formal-execution.v1.json",
    "gate-receipts.v1.json",
    "local-qualification.v1.json",
)
REQUIRED_PATHS = ARTIFACTS + (
    "production-drills/evidence.json",
    "qualification-public.pem",
    "qualification.signed.v1.json",
    "qualification.v1.json",
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def audit_evidence(
    directory: Path, source_sha: str, evidence_sha: str
) -> dict[str, Any]:
    if not SOURCE_SHA.fullmatch(source_sha) or not SOURCE_SHA.fullmatch(evidence_sha):
        raise ValueError("source and evidence SHAs must be exact lowercase Git commits")
    missing = [name for name in REQUIRED_PATHS if not (directory / name).is_file()]
    if missing:
        raise ValueError(f"evidence paths are missing: {missing}")

    unsigned = load_json(directory / "qualification.v1.json")
    signed = load_json(directory / "qualification.signed.v1.json")
    if not isinstance(signed, dict) or set(signed) != {
        "evidence",
        "evidenceDigestSha256",
        "schemaVersion",
        "signature",
    }:
        raise ValueError("signed evidence envelope has an unexpected shape")
    if signed["evidence"] != unsigned:
        raise ValueError("signed and unsigned qualification payloads differ")
    if unsigned.get("sourceSha") != source_sha:
        raise ValueError("qualification payload does not identify the pinned source")
    if unsigned.get("schemaVersion") != "w9-qualification-v1":
        raise ValueError("qualification payload schema is unsupported")
    if signed["schemaVersion"] != "w9-signed-qualification-v1":
        raise ValueError("signed qualification schema is unsupported")

    digest = sha256_bytes(canonical_json(unsigned))
    if (
        not SHA256.fullmatch(str(signed["evidenceDigestSha256"]))
        or signed["evidenceDigestSha256"] != digest
    ):
        raise ValueError(
            "canonical qualification digest differs from the signed envelope"
        )
    signature = signed.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
        raise ValueError("qualification signature is not Ed25519")
    public_key = (directory / "qualification-public.pem").read_text(encoding="ascii")
    if "BEGIN PUBLIC KEY" not in public_key or "PRIVATE KEY" in public_key:
        raise ValueError("qualification trust material is not a public key")

    reports = unsigned.get("reports")
    if not isinstance(reports, list) or not reports:
        raise ValueError("qualification reports are missing")
    report_digests = {
        report.get("artifactDigestSha256")
        for report in reports
        if isinstance(report, dict)
    }
    artifact_digests = {
        name: sha256_bytes((directory / name).read_bytes()) for name in ARTIFACTS
    }
    unbound = sorted(set(artifact_digests.values()) - report_digests)
    if unbound:
        raise ValueError(f"qualification artifacts are not bound by reports: {unbound}")

    for name in ARTIFACTS:
        artifact = load_json(directory / name)
        if (
            isinstance(artifact, dict)
            and "sourceSha" in artifact
            and artifact["sourceSha"] != source_sha
        ):
            raise ValueError(f"{name} does not identify the pinned source")

    status = unsigned.get("qualificationStatus")
    limitations = unsigned.get("limitations")
    if status not in {"failed", "limited", "qualified"}:
        raise ValueError("qualification status is invalid")
    if not isinstance(limitations, list) or any(
        not isinstance(item, str) or not item for item in limitations
    ):
        raise ValueError("qualification limitations are invalid")
    if status != "qualified" and not limitations:
        raise ValueError("non-qualified evidence must state its limitations")

    return {
        "artifact_sha256": artifact_digests,
        "canonical_digest_sha256": digest,
        "evidence_commit": evidence_sha,
        "key_id": signature.get("keyId"),
        "limitations": limitations,
        "qualification_status": status,
        "report_count": len(reports),
        "source_commit": source_sha,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--evidence-sha", required=True)
    args = parser.parse_args()
    result = audit_evidence(args.directory, args.source_sha, args.evidence_sha)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
