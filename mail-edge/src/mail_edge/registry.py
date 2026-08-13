"""Capability declarations and evidence-gated product policy."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from .contracts import BindingDirection, isoformat, normalize_domain
from .db import Database
from .errors import QualificationError
from .ids import uuid7_str


class Capability(StrEnum):
    EXACT_DOMAIN_ROUTING = "exact_domain_routing"
    MANAGED_INBOUND = "managed_inbound"
    RAW_MIME_INGRESS = "raw_mime_ingress"
    ENVELOPE_FIDELITY = "envelope_fidelity"
    WEBHOOK_AUTH_AND_REPLAY = "webhook_auth_and_replay"
    INBOUND_RETRY_WINDOW = "inbound_retry_window"
    PREBUILT_MIME_SUBMISSION = "prebuilt_mime_submission"
    UNKNOWN_OUTCOME_SAFETY = "unknown_outcome_safety"
    FEEDBACK_CORRELATION = "feedback_correlation"
    FEEDBACK_COMPLETENESS = "feedback_completeness"
    MIME_FIDELITY = "mime_fidelity"
    SAFE_RETENTION = "safe_retention"
    DOMAIN_DNS = "domain_dns"
    ACCOUNT_ISOLATION = "account_isolation"


@dataclass(frozen=True, slots=True)
class EvidenceRequirement:
    capability: Capability
    exact_domain: bool = True


@dataclass(frozen=True, slots=True)
class ProductPolicy:
    version: str
    inbound: tuple[EvidenceRequirement, ...]
    outbound: tuple[EvidenceRequirement, ...]

    def requirements(
        self, direction: BindingDirection
    ) -> tuple[EvidenceRequirement, ...]:
        return self.inbound if direction is BindingDirection.INBOUND else self.outbound


POLICY_V1 = ProductPolicy(
    version="mail-edge-product-v1",
    inbound=(
        EvidenceRequirement(Capability.EXACT_DOMAIN_ROUTING),
        EvidenceRequirement(Capability.MANAGED_INBOUND),
        EvidenceRequirement(Capability.RAW_MIME_INGRESS),
        EvidenceRequirement(Capability.ENVELOPE_FIDELITY),
        EvidenceRequirement(Capability.WEBHOOK_AUTH_AND_REPLAY),
        EvidenceRequirement(Capability.INBOUND_RETRY_WINDOW),
        EvidenceRequirement(Capability.MIME_FIDELITY),
        EvidenceRequirement(Capability.SAFE_RETENTION),
        EvidenceRequirement(Capability.DOMAIN_DNS),
        EvidenceRequirement(Capability.ACCOUNT_ISOLATION, exact_domain=False),
    ),
    outbound=(
        EvidenceRequirement(Capability.EXACT_DOMAIN_ROUTING),
        EvidenceRequirement(Capability.PREBUILT_MIME_SUBMISSION),
        EvidenceRequirement(Capability.ENVELOPE_FIDELITY),
        EvidenceRequirement(Capability.UNKNOWN_OUTCOME_SAFETY),
        EvidenceRequirement(Capability.FEEDBACK_CORRELATION),
        EvidenceRequirement(Capability.FEEDBACK_COMPLETENESS),
        EvidenceRequirement(Capability.WEBHOOK_AUTH_AND_REPLAY),
        EvidenceRequirement(Capability.MIME_FIDELITY),
        EvidenceRequirement(Capability.SAFE_RETENTION),
        EvidenceRequirement(Capability.DOMAIN_DNS),
        EvidenceRequirement(Capability.ACCOUNT_ISOLATION, exact_domain=False),
    ),
)


PROVIDER_CAPABILITIES: dict[str, frozenset[Capability]] = {
    # This is an implementation declaration, not qualification or GA approval.
    "mailgun": frozenset(Capability),
}


class CapabilityRegistry:
    def __init__(self, database: Database, policy: ProductPolicy = POLICY_V1):
        self.database = database
        self.policy = policy

    def record_evidence(
        self,
        *,
        provider: str,
        domain_scope: str,
        capability: Capability,
        passed: bool,
        artifact_sha256: str,
        evidence_uri: str,
        observed_at: datetime,
        expires_at: datetime,
        reviewer: str,
    ) -> str:
        supported = PROVIDER_CAPABILITIES.get(provider)
        if supported is None or capability not in supported:
            raise QualificationError(
                "provider adapter does not declare this capability"
            )
        scope = "*" if domain_scope == "*" else normalize_domain(domain_scope)
        if not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256):
            raise QualificationError("evidence artifact must have a SHA-256 digest")
        if observed_at.tzinfo is None or expires_at.tzinfo is None:
            raise QualificationError("evidence timestamps must be timezone-aware")
        if expires_at <= observed_at:
            raise QualificationError("evidence must expire after observation")
        if not reviewer.strip() or len(reviewer) > 128:
            raise QualificationError("a bounded reviewer identity is required")
        if len(evidence_uri) > 1024:
            raise QualificationError("evidence URI is too long")
        if not evidence_uri.startswith(("https://", "file://", "artifact:")):
            raise QualificationError("evidence URI must identify a durable artifact")
        evidence_id = uuid7_str()
        created_at = isoformat(datetime.now(UTC))
        with self.database.transaction(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO capability_evidence(
                    id, provider, domain_scope, capability, policy_version, passed,
                    artifact_sha256, evidence_uri, observed_at, expires_at, reviewer,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id,
                    provider,
                    scope,
                    capability.value,
                    self.policy.version,
                    1 if passed else 0,
                    artifact_sha256,
                    evidence_uri,
                    isoformat(observed_at),
                    isoformat(expires_at),
                    reviewer.strip(),
                    created_at,
                ),
            )
        return evidence_id

    def missing_evidence(
        self,
        provider: str,
        domain: str,
        direction: BindingDirection,
        *,
        now: datetime | None = None,
    ) -> list[Capability]:
        supported = PROVIDER_CAPABILITIES.get(provider)
        if supported is None:
            return [
                requirement.capability
                for requirement in self.policy.requirements(direction)
            ]
        normalized_domain = normalize_domain(domain)
        current = isoformat(now or datetime.now(UTC))
        missing: list[Capability] = []
        with self.database.transaction() as connection:
            for requirement in self.policy.requirements(direction):
                if requirement.capability not in supported:
                    missing.append(requirement.capability)
                    continue
                scope = normalized_domain if requirement.exact_domain else "*"
                row = connection.execute(
                    """
                    SELECT id FROM capability_evidence
                    WHERE provider = ? AND domain_scope = ? AND capability = ?
                      AND policy_version = ? AND passed = 1 AND expires_at > ?
                    ORDER BY observed_at DESC LIMIT 1
                    """,
                    (
                        provider,
                        scope,
                        requirement.capability.value,
                        self.policy.version,
                        current,
                    ),
                ).fetchone()
                if row is None:
                    missing.append(requirement.capability)
        return missing

    def assert_activation(
        self,
        provider: str,
        domain: str,
        direction: BindingDirection,
        *,
        now: datetime | None = None,
    ) -> None:
        missing = self.missing_evidence(provider, domain, direction, now=now)
        if missing:
            joined = ",".join(capability.value for capability in missing)
            raise QualificationError(f"activation lacks policy evidence: {joined}")
