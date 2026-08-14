from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from types import SimpleNamespace
from typing import Callable, Mapping, Optional, Protocol

from .configuration import HostAuthentication
from .contracts import ApplicationDelivery, ApplicationFeedback, canonical_mailbox
from .errors import MailEdgeAmbiguousDeliveryError, MailEdgeContractError
from .security import HostSignature, verify_host_signature


class ReplayNonces(Protocol):
    def consume(self, key_id: str, nonce: str, expires_at: datetime) -> None:
        ...


class CallbackClaim(Protocol):
    receipt_id: int
    completed_acknowledgement: Optional[Mapping[str, object]]


class CallbackReceipts(Protocol):
    def claim(
        self, tenant_id: str, operation: str, subject_id: str, body_sha256: str
    ) -> CallbackClaim:
        ...

    def complete(self, receipt_id: int, acknowledgement: Mapping[str, object]) -> None:
        ...


class BindingAuthorizer(Protocol):
    def authorize_delivery(self, binding) -> bool:
        ...


class AuthenticatedHostOperations:
    def __init__(self, authentication: HostAuthentication, replay_nonces: ReplayNonces):
        self._authentication = authentication
        self._replay_nonces = replay_nonces

    def verify(
        self,
        signature_value: object,
        *,
        operation: str,
        subject_id: str,
        body: bytes,
        now: datetime,
    ) -> HostSignature:
        signed = verify_host_signature(
            signature_value,
            keys=self._authentication.verification_keys,
            audience=self._authentication.audience,
            operation=operation,
            subject_id=subject_id,
            body=body,
            now=now,
            maximum_age_seconds=self._authentication.maximum_age_seconds,
            maximum_future_skew_seconds=self._authentication.maximum_future_skew_seconds,
        )
        self._replay_nonces.consume(
            signed.key_id,
            signed.nonce,
            datetime.fromisoformat(signed.timestamp.replace("Z", "+00:00")).astimezone(
                timezone.utc
            )
            + timedelta(seconds=self._authentication.maximum_age_seconds),
        )
        return signed


class ApplicationDeliveryService:
    """Host sink independent of transport; a future frozen adapter supplies the granted raw stream."""

    def __init__(
        self,
        tenant_id: str,
        callbacks: CallbackReceipts,
        bindings: BindingAuthorizer,
        deliver_message: Callable[[object, object], str],
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self._tenant_id = tenant_id
        self._callbacks = callbacks
        self._bindings = bindings
        self._deliver_message = deliver_message
        self._clock = clock

    def deliver(
        self, delivery: ApplicationDelivery, raw_message: bytes, callback_body: bytes
    ) -> Mapping[str, object]:
        if delivery.tenant_id != self._tenant_id:
            raise MailEdgeContractError(
                "APPLICATION_DELIVERY_TENANT_MISMATCH", http_status=404
            )
        if len(delivery.envelope.rcpt_to) != 1:
            raise MailEdgeAmbiguousDeliveryError("APPLICATION_DESTINATION_AMBIGUOUS")
        recipient_domain = canonical_mailbox(delivery.envelope.rcpt_to[0].address)[2]
        if recipient_domain != delivery.binding.domain_a_label:
            raise MailEdgeContractError(
                "APPLICATION_DELIVERY_DOMAIN_MISMATCH", http_status=404
            )
        if not self._bindings.authorize_delivery(delivery.binding):
            raise MailEdgeContractError(
                "APPLICATION_DELIVERY_BINDING_REJECTED", http_status=409
            )
        if (
            not isinstance(raw_message, bytes)
            or len(raw_message) != delivery.raw.size
            or hashlib.sha256(raw_message).hexdigest() != delivery.raw.sha256
        ):
            raise MailEdgeContractError("APPLICATION_DELIVERY_RAW_MISMATCH")
        if not isinstance(callback_body, bytes):
            raise MailEdgeContractError("APPLICATION_DELIVERY_BODY_INVALID")
        body_sha256 = hashlib.sha256(callback_body).hexdigest()
        claim = self._callbacks.claim(
            delivery.tenant_id,
            "application_delivery",
            delivery.delivery_id,
            body_sha256,
        )
        if claim.completed_acknowledgement is not None:
            return claim.completed_acknowledgement
        envelope = SimpleNamespace(
            mail_from=delivery.envelope.mail_from or "",
            rcpt_tos=[recipient.address for recipient in delivery.envelope.rcpt_to],
            mail_options=[],
            rcpt_options=[],
            original_content=raw_message,
            mail_edge_delivery_id=delivery.delivery_id,
        )
        result = self._deliver_message(envelope, message_from_bytes(raw_message))
        if not isinstance(result, str) or not result.startswith("2"):
            raise MailEdgeContractError(
                "APPLICATION_DELIVERY_NOT_ACCEPTED", http_status=503
            )
        acknowledgement = {
            "deliveryId": delivery.delivery_id,
            "acceptedAt": self._clock()
            .astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        self._callbacks.complete(claim.receipt_id, acknowledgement)
        return acknowledgement


class ApplicationFeedbackService:
    def __init__(
        self,
        tenant_id: str,
        callbacks: CallbackReceipts,
        apply_feedback: Callable[[ApplicationFeedback], None],
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self._tenant_id = tenant_id
        self._callbacks = callbacks
        self._apply_feedback = apply_feedback
        self._clock = clock

    def deliver(
        self, feedback: ApplicationFeedback, callback_body: bytes
    ) -> Mapping[str, object]:
        if feedback.tenant_id != self._tenant_id:
            raise MailEdgeContractError(
                "APPLICATION_FEEDBACK_TENANT_MISMATCH", http_status=404
            )
        if not isinstance(callback_body, bytes):
            raise MailEdgeContractError("APPLICATION_FEEDBACK_BODY_INVALID")
        digest = hashlib.sha256(callback_body).hexdigest()
        claim = self._callbacks.claim(
            feedback.tenant_id,
            "application_feedback",
            feedback.feedback_event_id,
            digest,
        )
        if claim.completed_acknowledgement is not None:
            return claim.completed_acknowledgement
        self._apply_feedback(feedback)
        acknowledgement = {
            "deliveryId": feedback.feedback_event_id,
            "acceptedAt": self._clock()
            .astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        self._callbacks.complete(claim.receipt_id, acknowledgement)
        return acknowledgement
