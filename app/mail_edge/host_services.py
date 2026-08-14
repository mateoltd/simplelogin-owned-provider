from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from types import SimpleNamespace
from typing import Callable, Mapping, Optional, Protocol

from .configuration import HostAuthentication
from .contracts import (
    ApplicationDelivery,
    ApplicationFeedback,
    canonical_json,
    canonical_mailbox,
)
from .errors import MailEdgeAmbiguousDeliveryError, MailEdgeContractError
from .security import (
    HostSignature,
    parse_host_signature_headers,
    verify_host_signature,
)


class ReplayNonces(Protocol):
    def consume(self, key_id: str, nonce: str, expires_at: datetime) -> None:
        ...


class CallbackClaim(Protocol):
    receipt_id: int
    fence: int
    completed_acknowledgement: Optional[Mapping[str, object]]


class CallbackReceipts(Protocol):
    def claim(
        self,
        tenant_id: str,
        operation: str,
        subject_id: str,
        body_sha256: str,
        lease_seconds: int,
    ) -> CallbackClaim:
        ...

    def complete(
        self, receipt_id: int, fence: int, acknowledgement: Mapping[str, object]
    ) -> None:
        ...

    def start_business_effect(self, receipt_id: int, fence: int) -> None:
        ...


class BindingAuthorizer(Protocol):
    def authorize_delivery(self, binding) -> bool:
        ...


class DestinationResolver(Protocol):
    def resolve_destination(self, destination, envelope):
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

    def verify_headers(
        self,
        headers: Mapping[str, object],
        *,
        operation: str,
        subject_id: str,
        body: bytes,
        now: datetime,
    ) -> HostSignature:
        return self.verify(
            parse_host_signature_headers(headers),
            operation=operation,
            subject_id=subject_id,
            body=body,
            now=now,
        )


class ApplicationDeliveryService:
    """Fenced host sink for a verified destination and granted raw message."""

    def __init__(
        self,
        tenant_id: str,
        callbacks: CallbackReceipts,
        bindings: BindingAuthorizer,
        destinations: DestinationResolver,
        deliver_message: Callable[[object, object], str],
        callback_lease_seconds: int = 60,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self._tenant_id = tenant_id
        self._callbacks = callbacks
        self._bindings = bindings
        self._destinations = destinations
        self._deliver_message = deliver_message
        self._callback_lease_seconds = callback_lease_seconds
        self._clock = clock

    def claim(
        self, delivery: ApplicationDelivery, callback_body: bytes
    ) -> CallbackClaim:
        if delivery.tenant_id != self._tenant_id:
            raise MailEdgeContractError(
                "APPLICATION_DELIVERY_TENANT_MISMATCH", http_status=404
            )
        if not isinstance(callback_body, bytes):
            raise MailEdgeContractError("APPLICATION_DELIVERY_BODY_INVALID")
        stable_delivery = {
            "binding": dict(delivery.binding.to_wire()),
            "deliveryId": delivery.delivery_id,
            "destination": dict(delivery.destination.to_wire()),
            "envelope": dict(delivery.envelope.to_wire()),
            "raw": dict(delivery.raw.to_wire()),
            "receiptId": delivery.receipt_id,
            "tenantId": delivery.tenant_id,
        }
        return self._callbacks.claim(
            delivery.tenant_id,
            "application_delivery",
            delivery.delivery_id,
            hashlib.sha256(canonical_json(stable_delivery)).hexdigest(),
            self._callback_lease_seconds,
        )

    def deliver(
        self, delivery: ApplicationDelivery, raw_message: bytes, callback_body: bytes
    ) -> Mapping[str, object]:
        claim = self.claim(delivery, callback_body)
        if claim.completed_acknowledgement is not None:
            return claim.completed_acknowledgement
        return self.deliver_claimed(delivery, raw_message, claim)

    def deliver_claimed(
        self, delivery: ApplicationDelivery, raw_message: bytes, claim: CallbackClaim
    ) -> Mapping[str, object]:
        route = self._destinations.resolve_destination(
            delivery.destination, delivery.envelope
        )
        recipient_address, _, recipient_domain = canonical_mailbox(route.address)
        envelope_recipients = {
            canonical_mailbox(recipient.address)[0]
            for recipient in delivery.envelope.rcpt_to
        }
        if (
            recipient_domain != delivery.binding.domain_a_label
            or recipient_address not in envelope_recipients
        ):
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
        envelope = SimpleNamespace(
            mail_from=delivery.envelope.mail_from or "<>",
            rcpt_tos=[recipient_address],
            mail_options=[],
            rcpt_options=[],
            original_content=raw_message,
            mail_edge_delivery_id=delivery.delivery_id,
            mail_edge_destination_id=delivery.destination.destination_id,
        )
        message = message_from_bytes(raw_message)
        self._callbacks.start_business_effect(claim.receipt_id, claim.fence)
        try:
            result = self._deliver_message(envelope, message)
        except Exception:
            raise MailEdgeAmbiguousDeliveryError(
                "APPLICATION_DELIVERY_OUTCOME_UNKNOWN"
            ) from None
        if not isinstance(result, str) or not result.startswith("2"):
            raise MailEdgeAmbiguousDeliveryError("APPLICATION_DELIVERY_OUTCOME_UNKNOWN")
        acknowledgement = {
            "deliveryId": delivery.delivery_id,
            "acceptedAt": self._clock()
            .astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        self._callbacks.complete(claim.receipt_id, claim.fence, acknowledgement)
        return acknowledgement


class ApplicationFeedbackService:
    def __init__(
        self,
        tenant_id: str,
        callbacks: CallbackReceipts,
        apply_feedback: Callable[[ApplicationFeedback], None],
        callback_lease_seconds: int = 60,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self._tenant_id = tenant_id
        self._callbacks = callbacks
        self._apply_feedback = apply_feedback
        self._callback_lease_seconds = callback_lease_seconds
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
            self._callback_lease_seconds,
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
        self._callbacks.complete(claim.receipt_id, claim.fence, acknowledgement)
        return acknowledgement
