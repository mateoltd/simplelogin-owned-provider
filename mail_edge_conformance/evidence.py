"""Machine-readable evidence format. Only executed observations are representable."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


EVIDENCE_SCHEMA = "mail-edge-capability-evidence/v1"
VALID_STATUSES = frozenset({"passed", "failed", "blocked"})
VALID_MODES = frozenset({"neutral-contract", "local-e2e", "live-provider"})
VALID_METHODS = frozenset({"executed", "fault-injected"})
_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class QualificationResult:
    result_id: str
    gate: str
    status: str
    method: str
    observed: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUSES:
            raise ValueError(f"invalid evidence status: {self.status}")
        if self.method not in VALID_METHODS:
            raise ValueError(f"invalid evidence method: {self.method}")
        if not self.result_id or not self.gate:
            raise ValueError("result ID and gate are required")

    def as_json(self) -> dict[str, Any]:
        return {
            "id": self.result_id,
            "gate": self.gate,
            "status": self.status,
            "method": self.method,
            "observed": self.observed,
        }


@dataclass(frozen=True)
class CapabilityEvidence:
    adapter: str
    adapter_version: str
    mode: str
    source_revision: str
    started_at: datetime
    finished_at: datetime
    results: tuple[QualificationResult, ...]
    corpus_manifest_sha256: str | None = None
    isolated_staging_domains: tuple[str, ...] = ()
    non_activatable: bool = False

    def __post_init__(self) -> None:
        if self.mode not in VALID_MODES:
            raise ValueError(f"invalid evidence mode: {self.mode}")
        if not self.adapter or not self.adapter_version:
            raise ValueError("adapter identity and version are required")
        if _COMMIT_SHA.fullmatch(self.source_revision) is None:
            raise ValueError("source revision must be a full lowercase commit SHA")
        if self.started_at.tzinfo is None or self.finished_at.tzinfo is None:
            raise ValueError("evidence timestamps must be timezone-aware")
        if self.finished_at < self.started_at:
            raise ValueError("evidence finished before it started")
        identifiers = [item.result_id for item in self.results]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("evidence result IDs must be unique within one run")
        if self.mode != "live-provider" and self.isolated_staging_domains:
            raise ValueError("staging domains are valid only for live evidence")
        if (
            self.corpus_manifest_sha256 is not None
            and _SHA256.fullmatch(self.corpus_manifest_sha256) is None
        ):
            raise ValueError("corpus manifest digest must be a lowercase SHA-256")

    @property
    def passed(self) -> bool:
        return bool(self.results) and all(
            item.status == "passed" for item in self.results
        )

    def as_json(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "schema": EVIDENCE_SCHEMA,
            "adapter": {
                "name": self.adapter,
                "version": self.adapter_version,
                "non_activatable": self.non_activatable,
            },
            "execution": {
                "mode": self.mode,
                "source_revision": self.source_revision,
                "started_at": self.started_at.astimezone(timezone.utc).isoformat(),
                "finished_at": self.finished_at.astimezone(timezone.utc).isoformat(),
            },
            "corpus_manifest_sha256": self.corpus_manifest_sha256,
            "isolated_staging_domains": list(self.isolated_staging_domains),
            "results": [item.as_json() for item in self.results],
        }
        canonical = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        document["evidence_sha256"] = hashlib.sha256(canonical).hexdigest()
        return document

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.as_json(), indent=2, sort_keys=True, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )

    @classmethod
    def from_json(cls, value: dict[str, Any]) -> "CapabilityEvidence":
        if value.get("schema") != EVIDENCE_SCHEMA:
            raise ValueError("unsupported capability evidence schema")
        supplied_digest = value.get("evidence_sha256")
        unsigned = dict(value)
        unsigned.pop("evidence_sha256", None)
        canonical = json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()
        if supplied_digest != digest:
            raise ValueError("capability evidence digest mismatch")
        adapter = value["adapter"]
        execution = value["execution"]
        results = tuple(
            QualificationResult(
                result_id=item["id"],
                gate=item["gate"],
                status=item["status"],
                method=item["method"],
                observed=dict(item.get("observed", {})),
            )
            for item in value["results"]
        )
        return cls(
            adapter=adapter["name"],
            adapter_version=adapter["version"],
            mode=execution["mode"],
            source_revision=execution["source_revision"],
            started_at=datetime.fromisoformat(execution["started_at"]),
            finished_at=datetime.fromisoformat(execution["finished_at"]),
            results=results,
            corpus_manifest_sha256=value.get("corpus_manifest_sha256"),
            isolated_staging_domains=tuple(value.get("isolated_staging_domains", ())),
            non_activatable=bool(adapter.get("non_activatable", False)),
        )


def load_evidence(paths: Iterable[Path]) -> tuple[CapabilityEvidence, ...]:
    return tuple(
        CapabilityEvidence.from_json(json.loads(path.read_text(encoding="utf-8")))
        for path in paths
    )
