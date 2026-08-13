"""Mailgun SMTP submission and webhook normalization."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import smtplib
import ssl
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from email.parser import BytesHeaderParser
from email.policy import SMTP
from urllib.parse import unquote_to_bytes

from mail_edge.contracts import (
    Envelope,
    Feedback,
    FeedbackKind,
    InboundNotice,
    InboundRawMessage,
    OutboundResult,
    OutboundSubmission,
    SubmissionOutcome,
    address_domain,
    normalize_domain,
)
from mail_edge.errors import ContractError
from mail_edge.ids import deterministic_uuid7
from mail_edge.redaction import bounded_diagnostics, diagnostic_code

_SMTP_RECEIPT = re.compile(rb"\bid[=: ]+<?([A-Za-z0-9._+-]{6,})>?", re.I)


@dataclass(frozen=True, slots=True)
class MailgunCredentials:
    smtp_username: str
    smtp_password: str
    webhook_signing_key: str


def verify_mailgun_signature(
    *,
    timestamp: str,
    token: str,
    signature: str,
    signing_key: str,
    now: datetime | None = None,
    maximum_age_seconds: int = 900,
) -> datetime:
    try:
        timestamp_int = int(timestamp)
        occurred = datetime.fromtimestamp(timestamp_int, UTC)
    except (ValueError, OverflowError) as exc:
        raise ContractError("invalid webhook timestamp") from exc
    current = now or datetime.now(UTC)
    if abs((current - occurred).total_seconds()) > maximum_age_seconds:
        raise ContractError("webhook timestamp is outside the replay window")
    expected = hmac.new(
        signing_key.encode(), f"{timestamp}{token}".encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ContractError("invalid webhook signature")
    return occurred


def parse_urlencoded_bytes(
    payload: bytes, *, maximum_fields: int = 64
) -> dict[str, list[bytes]]:
    fields: dict[str, list[bytes]] = {}
    if not payload:
        return fields
    parts = payload.split(b"&")
    if len(parts) > maximum_fields:
        raise ContractError("too many form fields")
    for part in parts:
        key, separator, value = part.partition(b"=")
        if not separator:
            raise ContractError("malformed form field")
        decoded_key = unquote_to_bytes(key.replace(b"+", b" ")).decode(
            "ascii", "strict"
        )
        decoded_value = unquote_to_bytes(value.replace(b"+", b" "))
        fields.setdefault(decoded_key, []).append(decoded_value)
    return fields


def _single(
    fields: dict[str, list[bytes]], key: str, *, required: bool = True
) -> bytes:
    values = fields.get(key, [])
    if not values:
        if required:
            raise ContractError(f"missing webhook field: {key}")
        return b""
    if len(values) != 1:
        raise ContractError(f"duplicate webhook field: {key}")
    return values[0]


def _text(fields: dict[str, list[bytes]], key: str, *, required: bool = True) -> str:
    try:
        return _single(fields, key, required=required).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(f"webhook field is not UTF-8: {key}") from exc


def _message_id(message_headers: str, raw_mime: bytes) -> str | None:
    try:
        pairs = json.loads(message_headers)
        if isinstance(pairs, list):
            for pair in pairs:
                if (
                    isinstance(pair, list)
                    and len(pair) == 2
                    and str(pair[0]).lower() == "message-id"
                ):
                    return str(pair[1])[:998]
    except (ValueError, TypeError):
        pairs = []
    parsed = BytesHeaderParser(policy=SMTP).parsebytes(raw_mime, headersonly=True)
    value = parsed.get("Message-ID")
    return str(value)[:998] if value else None


class MailgunAdapter:
    provider = "mailgun"

    def __init__(
        self,
        *,
        credentials: MailgunCredentials,
        smtp_host: str = "smtp.mailgun.org",
        smtp_port: int = 587,
        timeout_seconds: float = 30,
        diagnostic_salt: bytes = b"mail-edge-mailgun",
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        self.credentials = credentials
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.timeout_seconds = timeout_seconds
        self.diagnostic_salt = diagnostic_salt
        self.tls_context = tls_context or ssl.create_default_context()

    def normalize_inbound(
        self,
        payload: bytes,
        *,
        domain: str,
        binding_generation: int,
        now: datetime | None = None,
        maximum_age_seconds: int = 900,
    ) -> tuple[InboundNotice, InboundRawMessage, str]:
        fields = parse_urlencoded_bytes(payload)
        timestamp = _text(fields, "timestamp")
        token = _text(fields, "token")
        occurred = verify_mailgun_signature(
            timestamp=timestamp,
            token=token,
            signature=_text(fields, "signature"),
            signing_key=self.credentials.webhook_signing_key,
            now=now,
            maximum_age_seconds=maximum_age_seconds,
        )
        normalized_domain = normalize_domain(domain)
        sender = _text(fields, "sender")
        recipient = _text(fields, "recipient")
        if address_domain(recipient) != normalized_domain:
            raise ContractError("recipient does not match exact inbound domain")
        raw_mime = _single(fields, "body-mime")
        if not raw_mime:
            raise ContractError("raw MIME webhook field is empty")
        envelope = Envelope(sender=sender, recipients=(recipient,))
        stable_id = deterministic_uuid7(int(timestamp) * 1000, token.encode())
        notice_id = str(stable_id)
        raw_id = str(
            deterministic_uuid7(int(timestamp) * 1000, b"raw:" + token.encode())
        )
        message_headers = _text(fields, "message-headers", required=False)
        diagnostics = bounded_diagnostics(
            {
                "spam_flag": _text(fields, "X-Mailgun-Sflag", required=False),
                "dkim_check": _text(
                    fields, "X-Mailgun-Dkim-Check-Result", required=False
                ),
                "spf_check": _text(fields, "X-Mailgun-Spf", required=False),
            },
            salt=self.diagnostic_salt,
            known_secrets=(
                self.credentials.smtp_password,
                self.credentials.webhook_signing_key,
            ),
        )
        notice = InboundNotice(
            notice_id=notice_id,
            provider=self.provider,
            provider_event_id=token,
            provider_message_id=_message_id(message_headers, raw_mime),
            domain=normalized_domain,
            binding_generation=binding_generation,
            envelope=envelope,
            occurred_at=occurred,
            raw_available=True,
            diagnostics=diagnostics,
        )
        message = InboundRawMessage(
            message_id=raw_id,
            notice_id=notice_id,
            domain=normalized_domain,
            binding_generation=binding_generation,
            envelope=envelope,
            raw_mime=raw_mime,
        )
        return notice, message, token

    def normalize_feedback(
        self,
        payload: bytes,
        *,
        expected_domain: str,
        now: datetime | None = None,
        maximum_age_seconds: int = 900,
    ) -> tuple[Feedback, str]:
        try:
            document = json.loads(payload)
            signature = document["signature"]
            event = document["event-data"]
            timestamp = str(signature["timestamp"])
            token = str(signature["token"])
            occurred = verify_mailgun_signature(
                timestamp=timestamp,
                token=token,
                signature=str(signature["signature"]),
                signing_key=self.credentials.webhook_signing_key,
                now=now,
                maximum_age_seconds=maximum_age_seconds,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ContractError("malformed feedback webhook") from exc
        domain_data = event.get("domain", {})
        event_domain = (
            domain_data.get("name") if isinstance(domain_data, dict) else domain_data
        )
        if normalize_domain(str(event_domain)) != normalize_domain(expected_domain):
            raise ContractError("feedback domain does not match exact binding")
        event_name = str(event.get("event", "")).lower()
        severity = str(event.get("severity", "")).lower()
        kind_map = {
            "accepted": FeedbackKind.ACCEPTED,
            "delivered": FeedbackKind.DELIVERED,
            "complained": FeedbackKind.COMPLAINED,
            "rejected": FeedbackKind.REJECTED,
        }
        if event_name == "failed":
            kind = (
                FeedbackKind.FAILED_TEMPORARY
                if severity == "temporary"
                else FeedbackKind.FAILED_PERMANENT
            )
        elif event_name == "stored":
            kind = FeedbackKind.ACCEPTED
        else:
            try:
                kind = kind_map[event_name]
            except KeyError as exc:
                raise ContractError("unsupported feedback event") from exc
        event_id = str(event.get("id", ""))
        if not event_id or len(event_id) > 256:
            raise ContractError("feedback event ID is missing or too long")
        variables = event.get("user-variables", {})
        if not isinstance(variables, dict):
            variables = {}
        submission_id = variables.get("mail_edge_submission_id")
        recipient = str(event.get("recipient", ""))
        recipient_hash = hashlib.sha256(
            self.diagnostic_salt + recipient.lower().encode("utf-8", "replace")
        ).hexdigest()
        delivery = event.get("delivery-status", {})
        if not isinstance(delivery, dict):
            delivery = {}
        diagnostic = diagnostic_code(
            f"mailgun_{event_name}_{severity}_{delivery.get('code', '')}"
        )
        feedback_id = str(
            deterministic_uuid7(
                int(float(event.get("timestamp", occurred.timestamp())) * 1000),
                event_id.encode(),
            )
        )
        feedback = Feedback(
            feedback_id=feedback_id,
            provider=self.provider,
            provider_event_id=event_id,
            kind=kind,
            occurred_at=datetime.fromtimestamp(
                float(event.get("timestamp", occurred.timestamp())), UTC
            ),
            recipient_hash=recipient_hash,
            submission_id=str(submission_id) if submission_id else None,
            provider_receipt_id=None,
            diagnostic_code=diagnostic,
        )
        return feedback, token

    @staticmethod
    def _wire_message(submission: OutboundSubmission) -> bytes:
        metadata = json.dumps(
            {"mail_edge_submission_id": submission.submission_id},
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        control = (
            b"X-Mailgun-Variables: "
            + metadata
            + b"\r\nX-Mailgun-Suppress-Headers: all\r\n"
        )
        return control + submission.raw_mime

    def submit(self, submission: OutboundSubmission) -> OutboundResult:
        current = datetime.now(UTC)
        smtp: smtplib.SMTP | None = None
        stage = "connect"
        try:
            smtp = smtplib.SMTP(timeout=self.timeout_seconds)
            smtp.connect(self.smtp_host, self.smtp_port)
            stage = "ehlo"
            code, _ = smtp.ehlo()
            if code != 250:
                raise smtplib.SMTPHeloError(code, b"ehlo rejected")
            stage = "starttls"
            code, response = smtp.starttls(context=self.tls_context)
            if code != 220:
                raise smtplib.SMTPResponseException(code, response)
            smtp.ehlo()
            stage = "auth"
            smtp.login(self.credentials.smtp_username, self.credentials.smtp_password)
            stage = "mail"
            code, response = smtp.mail(submission.envelope.sender)
            if code != 250:
                return self._definite_response(submission, code, response, current)
            for recipient in submission.envelope.recipients:
                stage = "rcpt"
                code, response = smtp.rcpt(recipient)
                if code not in {250, 251}:
                    return self._definite_response(submission, code, response, current)
            stage = "data"
            code, response = smtp.data(self._wire_message(submission))
            if code != 250:
                return self._definite_response(submission, code, response, current)
            match = _SMTP_RECEIPT.search(response or b"")
            receipt = (
                match.group(1).decode("ascii", "replace")
                if match
                else "smtp-ack-"
                + hashlib.sha256(
                    submission.submission_id.encode() + (response or b"accepted")
                ).hexdigest()[:32]
            )
            return OutboundResult(
                submission_id=submission.submission_id,
                outcome=SubmissionOutcome.ACCEPTED,
                provider_receipt_id=receipt,
                occurred_at=current,
                diagnostic_code="mailgun_smtp_accepted",
            )
        except smtplib.SMTPResponseException as exc:
            if stage == "data":
                return self._definite_response(
                    submission, exc.smtp_code, exc.smtp_error, current
                )
            return OutboundResult(
                submission_id=submission.submission_id,
                outcome=SubmissionOutcome.TEMPORARY_FAILURE,
                provider_receipt_id=None,
                occurred_at=current,
                diagnostic_code=f"mailgun_before_data_{stage}_{exc.smtp_code}",
            )
        except (smtplib.SMTPServerDisconnected, TimeoutError, OSError):
            outcome = (
                SubmissionOutcome.UNKNOWN
                if stage == "data"
                else SubmissionOutcome.TEMPORARY_FAILURE
            )
            return OutboundResult(
                submission_id=submission.submission_id,
                outcome=outcome,
                provider_receipt_id=None,
                occurred_at=current,
                diagnostic_code=f"mailgun_{stage}_transport_failure",
            )
        finally:
            if smtp is not None:
                with suppress(OSError):
                    smtp.close()

    @staticmethod
    def _definite_response(
        submission: OutboundSubmission,
        code: int,
        response: bytes,
        occurred_at: datetime,
    ) -> OutboundResult:
        if 400 <= code < 500:
            outcome = SubmissionOutcome.TEMPORARY_FAILURE
            retry_after = None
        else:
            outcome = SubmissionOutcome.REJECTED
            retry_after = None
        return OutboundResult(
            submission_id=submission.submission_id,
            outcome=outcome,
            provider_receipt_id=None,
            occurred_at=occurred_at,
            diagnostic_code=f"mailgun_smtp_{code}",
            retry_after_seconds=retry_after,
        )
