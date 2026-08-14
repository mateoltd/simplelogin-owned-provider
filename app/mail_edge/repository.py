from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Optional

import arrow
from sqlalchemy.exc import IntegrityError

from app.db import Session
from app.models import (
    CustomDomain,
    MailEdgeCallbackReceipt,
    MailEdgeOutboundProjection,
    MailEdgeReplayNonce,
    MailEdgeRouteBindingProjection,
    SLDomain,
)

from .contracts import RouteBindingSnapshot
from .errors import (
    MailEdgeAmbiguousDeliveryError,
    MailEdgeAuthenticationError,
    MailEdgeContractError,
)


OUTBOUND_STATE_EDGES = {
    "accepted": frozenset({"ready", "canceled"}),
    "ready": frozenset({"dispatching", "canceled"}),
    "dispatching": frozenset(
        {
            "provider_accepted",
            "retry_wait",
            "failed_not_sent",
            "quarantined_unknown",
        }
    ),
    "retry_wait": frozenset({"dispatching"}),
    "quarantined_unknown": frozenset({"provider_accepted", "failed_not_sent", "ready"}),
    "provider_accepted": frozenset(),
    "failed_not_sent": frozenset(),
    "canceled": frozenset(),
}
OUTBOUND_CONTEXT_FIELDS = frozenset(
    {
        "user_id",
        "alias_id",
        "contact_id",
        "mailbox_id",
        "email_log_id",
        "idempotency_subject",
    }
)


def validate_outbound_context(context: Mapping[str, object]) -> None:
    if not isinstance(context, Mapping) or set(context) != OUTBOUND_CONTEXT_FIELDS:
        raise MailEdgeContractError("OUTBOUND_CONTEXT_INVALID")
    for field in ("user_id", "alias_id", "mailbox_id"):
        value = context[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise MailEdgeContractError("OUTBOUND_CONTEXT_INVALID")
    for field in ("contact_id", "email_log_id"):
        value = context[field]
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value < 1
        ):
            raise MailEdgeContractError("OUTBOUND_CONTEXT_INVALID")
    subject = context["idempotency_subject"]
    if not isinstance(subject, str) or not 1 <= len(subject) <= 1024:
        raise MailEdgeContractError("OUTBOUND_IDEMPOTENCY_SUBJECT_INVALID")


def outbound_state_reachable(current: str, target: str) -> bool:
    pending = list(OUTBOUND_STATE_EDGES.get(current, ()))
    visited = set()
    while pending:
        state = pending.pop()
        if state == target:
            return True
        if state not in visited:
            visited.add(state)
            pending.extend(OUTBOUND_STATE_EDGES.get(state, ()))
    return False


class ReplayNonceRepository:
    PURGE_BATCH_SIZE = 1000

    def consume(self, key_id: str, nonce: str, expires_at: datetime) -> None:
        digest = hashlib.sha256(nonce.encode("ascii")).hexdigest()
        try:
            with Session.begin_nested():
                Session.add(
                    MailEdgeReplayNonce(
                        key_id=key_id,
                        nonce_digest=digest,
                        expires_at=arrow.get(expires_at.astimezone(timezone.utc)),
                    )
                )
                Session.flush()
            expired_ids = (
                Session.query(MailEdgeReplayNonce.id)
                .filter(MailEdgeReplayNonce.expires_at < arrow.utcnow())
                .order_by(MailEdgeReplayNonce.expires_at, MailEdgeReplayNonce.id)
                .limit(self.PURGE_BATCH_SIZE)
                .subquery()
            )
            Session.query(MailEdgeReplayNonce).filter(
                MailEdgeReplayNonce.id.in_(Session.query(expired_ids.c.id))
            ).delete(synchronize_session=False)
            Session.commit()
        except IntegrityError:
            raise MailEdgeAuthenticationError("HOST_SIGNATURE_REPLAYED")


@dataclass(frozen=True)
class CallbackClaim:
    receipt_id: int
    completed_acknowledgement: Optional[Mapping[str, object]]


class CallbackReceiptRepository:
    def claim(
        self, tenant_id: str, operation: str, subject_id: str, body_sha256: str
    ) -> CallbackClaim:
        try:
            with Session.begin_nested():
                receipt = MailEdgeCallbackReceipt(
                    tenant_id=tenant_id,
                    operation=operation,
                    subject_id=subject_id,
                    body_sha256=body_sha256,
                    status="processing",
                )
                Session.add(receipt)
                Session.flush()
            Session.commit()
            return CallbackClaim(receipt.id, None)
        except IntegrityError:
            pass
        receipt = MailEdgeCallbackReceipt.filter_by(
            tenant_id=tenant_id, operation=operation, subject_id=subject_id
        ).first()
        if receipt is None or receipt.body_sha256 != body_sha256:
            raise MailEdgeAmbiguousDeliveryError("CALLBACK_FINGERPRINT_CONFLICT")
        if receipt.status != "completed" or receipt.acknowledgement is None:
            raise MailEdgeAmbiguousDeliveryError("CALLBACK_OUTCOME_UNKNOWN")
        return CallbackClaim(receipt.id, dict(receipt.acknowledgement))

    def complete(self, receipt_id: int, acknowledgement: Mapping[str, object]) -> None:
        updated = (
            MailEdgeCallbackReceipt.query()
            .filter(MailEdgeCallbackReceipt.id == receipt_id)
            .filter(MailEdgeCallbackReceipt.status == "processing")
            .update({"status": "completed", "acknowledgement": dict(acknowledgement)})
        )
        if updated != 1:
            Session.rollback()
            raise MailEdgeAmbiguousDeliveryError("CALLBACK_SETTLEMENT_CONFLICT")
        Session.commit()


class RouteBindingProjectionRepository:
    def __init__(self, tenant_id: str):
        self._tenant_id = tenant_id

    @staticmethod
    def _domain_authorized(domain: str) -> bool:
        public_domain = (
            SLDomain.filter_by(domain=domain).with_entities(SLDomain.id).first()
        )
        if public_domain is not None:
            return True
        custom_domain = CustomDomain.filter_by(
            domain=domain, pending_deletion=False
        ).first()
        return (
            custom_domain is not None
            and custom_domain.ownership_verified
            and custom_domain.verified
        )

    def activate(self, binding: RouteBindingSnapshot) -> None:
        if binding.tenant_id != self._tenant_id:
            raise MailEdgeContractError(
                "ROUTE_BINDING_TENANT_MISMATCH", http_status=404
            )
        if binding.direction not in {"inbound", "outbound"}:
            raise MailEdgeContractError("ROUTE_BINDING_DIRECTION_INVALID")
        if not self._domain_authorized(binding.domain_a_label):
            raise MailEdgeContractError(
                "ROUTE_BINDING_DOMAIN_NOT_AUTHORIZED", http_status=404
            )
        projected_generation = MailEdgeRouteBindingProjection.filter_by(
            tenant_id=binding.tenant_id,
            domain_a_label=binding.domain_a_label,
            direction=binding.direction,
            binding_id=binding.binding_id,
            binding_version=binding.binding_version,
        ).first()
        if projected_generation is not None:
            if projected_generation.state == "active":
                return
            raise MailEdgeContractError("ROUTE_BINDING_GENERATION_NOT_ACTIVATABLE")
        current = (
            MailEdgeRouteBindingProjection.query()
            .filter_by(
                tenant_id=binding.tenant_id,
                domain_a_label=binding.domain_a_label,
                direction=binding.direction,
                state="active",
            )
            .with_for_update()
            .first()
        )
        if current is not None:
            if (
                current.binding_id == binding.binding_id
                and current.binding_version == binding.binding_version
            ):
                return
            current.state = "draining"
        Session.add(
            MailEdgeRouteBindingProjection(
                tenant_id=binding.tenant_id,
                domain_a_label=binding.domain_a_label,
                direction=binding.direction,
                binding_id=binding.binding_id,
                binding_version=binding.binding_version,
                state="active",
            )
        )
        try:
            Session.commit()
        except IntegrityError:
            Session.rollback()
            raise MailEdgeAmbiguousDeliveryError("ROUTE_BINDING_ACTIVATION_CONFLICT")

    def authorize_delivery(self, binding: RouteBindingSnapshot) -> bool:
        if (
            binding.tenant_id != self._tenant_id
            or binding.direction != "inbound"
            or not self._domain_authorized(binding.domain_a_label)
        ):
            return False
        projected = MailEdgeRouteBindingProjection.filter_by(
            tenant_id=binding.tenant_id,
            domain_a_label=binding.domain_a_label,
            direction=binding.direction,
            binding_id=binding.binding_id,
            binding_version=binding.binding_version,
        ).first()
        return projected is not None and projected.state in {"active", "draining"}

    def retire(self, binding: RouteBindingSnapshot) -> None:
        if binding.tenant_id != self._tenant_id:
            raise MailEdgeContractError(
                "ROUTE_BINDING_TENANT_MISMATCH", http_status=404
            )
        updated = (
            MailEdgeRouteBindingProjection.query()
            .filter_by(
                tenant_id=binding.tenant_id,
                domain_a_label=binding.domain_a_label,
                direction=binding.direction,
                binding_id=binding.binding_id,
                binding_version=binding.binding_version,
                state="draining",
            )
            .update({"state": "retired"})
        )
        if updated != 1:
            Session.rollback()
            raise MailEdgeContractError("ROUTE_BINDING_GENERATION_NOT_RETIRABLE")
        Session.commit()


class OutboundProjectionRepository:
    @staticmethod
    def _matches(existing, intent, context: Mapping[str, object]) -> bool:
        return (
            existing.request_fingerprint == intent.fingerprint
            and existing.user_id == context["user_id"]
            and existing.alias_id == context["alias_id"]
            and existing.contact_id == context["contact_id"]
            and existing.mailbox_id == context["mailbox_id"]
        )

    def record_accepted(
        self, tenant_id: str, intent, context: Mapping[str, object]
    ) -> None:
        validate_outbound_context(context)
        existing = MailEdgeOutboundProjection.filter_by(
            tenant_id=tenant_id, intent_id=intent.intent_id
        ).first()
        if existing is not None:
            if not self._matches(existing, intent, context):
                raise MailEdgeAmbiguousDeliveryError("OUTBOUND_FINGERPRINT_CONFLICT")
            return
        Session.add(
            MailEdgeOutboundProjection(
                tenant_id=tenant_id,
                intent_id=intent.intent_id,
                user_id=context["user_id"],
                alias_id=context["alias_id"],
                contact_id=context["contact_id"],
                mailbox_id=context["mailbox_id"],
                email_log_id=context["email_log_id"],
                state=intent.state,
                request_fingerprint=intent.fingerprint,
                version=intent.version,
                quarantined=intent.state == "quarantined_unknown",
            )
        )
        try:
            Session.commit()
        except IntegrityError:
            Session.rollback()
            existing = MailEdgeOutboundProjection.filter_by(
                tenant_id=tenant_id, intent_id=intent.intent_id
            ).first()
            if existing is None or not self._matches(existing, intent, context):
                raise MailEdgeAmbiguousDeliveryError("OUTBOUND_PROJECTION_CONFLICT")

    def stage_feedback(self, feedback) -> None:
        projection = MailEdgeOutboundProjection.filter_by(
            tenant_id=feedback.tenant_id, intent_id=feedback.intent_id
        ).first()
        if projection is None:
            raise MailEdgeContractError(
                "OUTBOUND_PROJECTION_NOT_FOUND", http_status=404
            )
        projection.feedback_kind = feedback.kind

    def project_status(self, tenant_id: str, intent) -> None:
        projection = MailEdgeOutboundProjection.filter_by(
            tenant_id=tenant_id, intent_id=intent.intent_id
        ).first()
        if projection is None:
            raise MailEdgeContractError(
                "OUTBOUND_PROJECTION_NOT_FOUND", http_status=404
            )
        if projection.request_fingerprint != intent.fingerprint:
            raise MailEdgeAmbiguousDeliveryError("OUTBOUND_FINGERPRINT_CONFLICT")
        if intent.version < projection.version:
            return
        if intent.version == projection.version:
            if intent.state != projection.state:
                raise MailEdgeAmbiguousDeliveryError("OUTBOUND_VERSION_CONFLICT")
            return
        if not outbound_state_reachable(projection.state, intent.state):
            raise MailEdgeAmbiguousDeliveryError("OUTBOUND_STATE_REGRESSION")
        projection.state = intent.state
        projection.version = intent.version
        projection.quarantined = intent.state == "quarantined_unknown"
        Session.commit()
