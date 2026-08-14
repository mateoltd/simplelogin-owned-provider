from __future__ import annotations

import hashlib
from types import MappingProxyType
from typing import Iterable

from app.mail_sender import SendRequest
from app.message_utils import message_to_bytes

from .client import MailEdgeClient, OutboundIntent
from .contracts import (
    SmtpEnvelope,
    SmtpRecipient,
    canonical_json,
    canonical_mailbox,
    parse_smtp_envelope,
)
from .errors import (
    MailEdgeAmbiguousDeliveryError,
    MailEdgeContractError,
    MailEdgeError,
)
from .repository import OutboundProjectionRepository, validate_outbound_context


def _option_values(options: Iterable[object]) -> tuple[str, ...]:
    return tuple(str(option).strip() for option in options)


def _recipient_dsn(options: tuple[str, ...]):
    result = {}
    seen = set()
    for option in options:
        name, separator, value = option.partition("=")
        name = name.upper()
        if name not in {"NOTIFY", "ORCPT"}:
            continue
        if not separator or name in seen:
            raise MailEdgeContractError("SMTP_RECIPIENT_OPTIONS_INVALID")
        seen.add(name)
        if name == "NOTIFY":
            atoms = [atom.lower() for atom in value.split(",")]
            result["notify"] = atoms
        else:
            result["originalRecipient"] = value
    return MappingProxyType(result) if result else None


def _envelope_dsn(options: tuple[str, ...]):
    result = {}
    seen = set()
    for option in options:
        name, separator, value = option.partition("=")
        name = name.upper()
        if name not in {"RET", "ENVID"}:
            continue
        if not separator or name in seen:
            raise MailEdgeContractError("SMTP_MAIL_OPTIONS_INVALID")
        seen.add(name)
        if name == "RET":
            result["ret"] = "headers" if value.upper() == "HDRS" else value.lower()
        else:
            result["envelopeId"] = value
    return MappingProxyType(result) if result else None


def envelope_from_send_request(request: SendRequest) -> SmtpEnvelope:
    recipients = request.envelope_to
    if isinstance(recipients, str):
        recipients = [recipients]
    recipient_options = _option_values(request.rcpt_options)
    parsed_recipients = tuple(
        SmtpRecipient(
            canonical_mailbox(recipient)[0], _recipient_dsn(recipient_options)
        )
        for recipient in recipients
    )
    options = _option_values(request.mail_options)
    body = None
    require_tls = None
    smtp_utf8 = any(option.upper() == "SMTPUTF8" for option in options)
    for option in options:
        upper = option.upper()
        if upper.startswith("BODY="):
            body = upper[5:].lower()
        elif upper == "REQUIRETLS":
            require_tls = True
    mail_from = (
        canonical_mailbox(request.envelope_from)[0] if request.envelope_from else None
    )
    smtp_utf8 = (
        smtp_utf8
        or (mail_from is not None and not mail_from.isascii())
        or any(not recipient.address.isascii() for recipient in parsed_recipients)
    )
    envelope = SmtpEnvelope(
        mail_from=mail_from,
        rcpt_to=parsed_recipients,
        smtp_utf8=smtp_utf8,
        body=body,
        require_tls=require_tls,
        dsn=_envelope_dsn(options),
    )
    return parse_smtp_envelope(dict(envelope.to_wire()))


class MailEdgeOutboundTransport:
    def __init__(
        self, client: MailEdgeClient, projections: OutboundProjectionRepository
    ):
        self._client = client
        self._projections = projections

    def send(self, send_request: SendRequest) -> bool:
        context = send_request.mail_edge_context
        validate_outbound_context(context)
        try:
            raw = message_to_bytes(send_request.msg)
        except Exception as error:
            raise MailEdgeContractError(
                "OUTBOUND_MESSAGE_SERIALIZATION_FAILED"
            ) from error
        envelope = envelope_from_send_request(send_request)
        idempotency_subject = context["idempotency_subject"]
        key_digest = hashlib.sha256(
            canonical_json(
                {
                    "schemaVersion": "v1",
                    "submissionId": idempotency_subject,
                    "userId": context["user_id"],
                    "aliasId": context["alias_id"],
                    "contactId": context["contact_id"],
                    "mailboxId": context["mailbox_id"],
                }
            )
        ).hexdigest()
        intent = self._client.submit_message(
            envelope, raw, idempotency_key=f"sl-{key_digest}"
        )
        try:
            self._projections.record_accepted(self._client.tenant_id, intent, context)
        except MailEdgeError:
            raise
        except Exception as error:
            raise MailEdgeAmbiguousDeliveryError(
                "OUTBOUND_PROJECTION_PERSISTENCE_UNKNOWN"
            ) from error
        return True


class OutboundStatusProjectionService:
    def __init__(
        self, client: MailEdgeClient, projections: OutboundProjectionRepository
    ):
        self._client = client
        self._projections = projections

    def refresh(self, intent_id: str) -> OutboundIntent:
        intent = self._client.get_outbound_intent(intent_id)
        self._projections.project_status(self._client.tenant_id, intent)
        return intent
