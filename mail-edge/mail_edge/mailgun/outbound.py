"""Mailgun `/messages.mime` outbound adapter."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import quote

from ..config import DomainRegistry, RetryPolicy, TimeoutPolicy
from ..contracts import OutboundMessage, SubmissionDisposition, SubmissionResult
from ..errors import ConfigurationError, MalformedPayload, TransportFailure
from ..ledger import DeliveryLedger
from ..multipart import MultipartFile, encode_multipart
from ..observability import NullObserver, Observer, Redactor
from ..transport import HTTPRequest, HTTPResponse, HTTPTransport
from ..validation import (
    inspect_mime,
    mailbox_domain,
    validate_delivery_id,
    validate_mailbox,
)
from .http import basic_auth, response_diagnostic, retry_after_seconds

_RETRYABLE_HTTP = {408, 425, 429, 503}
_AMBIGUOUS_HTTP = {500, 502, 504}


class MailgunOutboundAdapter:
    def __init__(
        self,
        registry: DomainRegistry,
        transport: HTTPTransport,
        ledger: DeliveryLedger,
        *,
        timeout: TimeoutPolicy = TimeoutPolicy(),
        retry: RetryPolicy = RetryPolicy(),
        observer: Observer | None = None,
        redactor: Redactor | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if observer is not None and redactor is None:
            raise ConfigurationError(
                "an explicit redactor is required when observability is enabled"
            )
        self._registry = registry
        self._transport = transport
        self._ledger = ledger
        self._timeout = timeout
        self._retry = retry
        self._observer = observer or NullObserver()
        self._redactor = redactor or Redactor(b"mail-edge-default-redaction-salt")
        self._clock = clock
        self._sleeper = sleeper

    def submit(self, message: OutboundMessage) -> SubmissionResult:
        try:
            validate_delivery_id(message.edge_delivery_id)
            validate_mailbox(
                message.envelope_from, smtp_utf8=message.smtp_utf8_required
            )
            if len(message.envelope_recipients) != 1:
                raise MalformedPayload(
                    "Mailgun requires one exact envelope recipient per delivery"
                )
            validate_mailbox(
                message.envelope_recipients[0], smtp_utf8=message.smtp_utf8_required
            )
            if message.mail_options or message.rcpt_options:
                raise MalformedPayload(
                    "Mailgun HTTP cannot preserve SMTP MAIL/RCPT options"
                )
            config = self._registry.exact(mailbox_domain(message.envelope_from))
            visible_message_id = inspect_mime(
                message.rfc822_bytes, max_bytes=config.max_message_bytes
            )
            self._ledger.prepare(
                message, domain=config.domain, message_id=visible_message_id
            )
            existing = self._ledger.get(message.edge_delivery_id)
            if existing is None:
                raise RuntimeError("prepared delivery disappeared")
            if existing.state not in {"PREPARED", "RETRYABLE_REJECTED"}:
                result = self._existing_result(existing)
                self._observe(message, result)
                return result
            if not self._ledger.mark_submitting(
                message.edge_delivery_id, now=self._clock()
            ):
                concurrent = self._ledger.get(message.edge_delivery_id)
                if concurrent is None:
                    raise RuntimeError(
                        "delivery disappeared while beginning submission"
                    )
                result = self._existing_result(concurrent)
                self._observe(message, result)
                return result
        except (MalformedPayload, ConfigurationError) as exc:
            result = SubmissionResult(
                disposition=SubmissionDisposition.PERMANENT_REJECTED,
                edge_delivery_id=message.edge_delivery_id,
                diagnostic=str(exc),
            )
            self._observe(message, result)
            return result

        fields: list[tuple[str, str]] = [
            ("from", message.envelope_from),
            ("to", message.envelope_recipients[0]),
            ("o:native-send", "yes"),
            ("o:tracking", "no"),
            ("o:tracking-clicks", "no"),
            ("o:tracking-opens", "no"),
        ]
        if config.test_mode:
            fields.append(("o:testmode", "yes"))
        content_type, body = encode_multipart(
            fields,
            (
                MultipartFile(
                    field="message",
                    filename="message.mime",
                    content_type="message/rfc822",
                    content=message.rfc822_bytes,
                ),
            ),
        )
        url = f"{config.api_base}/v3/{quote(config.domain, safe='')}/messages.mime"
        result = self._send(
            message=message,
            visible_message_id=visible_message_id,
            url=url,
            content_type=content_type,
            body=body,
            keys=config.api_keys,
        )
        self._ledger.record_result(result, now=self._clock())
        self._observe(message, result)
        return result

    @staticmethod
    def _existing_result(record) -> SubmissionResult:
        if record.state in {"AMBIGUOUS", "SUBMITTING"}:
            disposition = SubmissionDisposition.AMBIGUOUS
        elif record.state in {
            "PERMANENT_REJECTED",
            "rejected",
            "hard_bounce",
            "complaint",
        }:
            disposition = SubmissionDisposition.PERMANENT_REJECTED
        else:
            # ACCEPTED and all correlated post-acceptance states are definitive
            # evidence that another submission must not be made.
            disposition = SubmissionDisposition.ACCEPTED
        return SubmissionResult(
            disposition=disposition,
            edge_delivery_id=record.edge_delivery_id,
            provider_message_id=record.provider_message_id,
            visible_message_id=record.submitted_message_id,
            diagnostic=f"delivery already recorded as {record.state}",
        )

    def _send(self, *, message, visible_message_id, url, content_type, body, keys):
        last_response: HTTPResponse | None = None
        for key in keys.keys:
            attempt = 0
            while attempt < self._retry.max_attempts:
                attempt += 1
                request = HTTPRequest(
                    method="POST",
                    url=url,
                    headers={
                        "Authorization": basic_auth(key.secret),
                        "Content-Type": content_type,
                        "Content-Length": str(len(body)),
                        "Accept": "application/json",
                        "User-Agent": "provider-neutral-mail-edge/1",
                    },
                    body=body,
                    connect_timeout=self._timeout.connect_seconds,
                    read_timeout=self._timeout.read_seconds,
                    max_response_bytes=self._timeout.max_response_bytes,
                )
                try:
                    response = self._transport.send(request)
                except TransportFailure as exc:
                    if exc.request_sent:
                        return SubmissionResult(
                            disposition=SubmissionDisposition.AMBIGUOUS,
                            edge_delivery_id=message.edge_delivery_id,
                            visible_message_id=visible_message_id,
                            diagnostic="provider acknowledgement was not observed",
                        )
                    if attempt < self._retry.max_attempts:
                        self._sleep_backoff(attempt)
                        continue
                    return SubmissionResult(
                        disposition=SubmissionDisposition.RETRYABLE_REJECTED,
                        edge_delivery_id=message.edge_delivery_id,
                        visible_message_id=visible_message_id,
                        diagnostic="provider connection failed before submission",
                    )

                last_response = response
                if response.status in {401, 403}:
                    break
                if 200 <= response.status < 300:
                    try:
                        payload = json.loads(response.body)
                        provider_id = payload["id"]
                        if (
                            not isinstance(provider_id, str)
                            or not provider_id
                            or len(provider_id) > 998
                        ):
                            raise ValueError
                    except (
                        UnicodeDecodeError,
                        json.JSONDecodeError,
                        KeyError,
                        TypeError,
                        ValueError,
                    ):
                        return SubmissionResult(
                            disposition=SubmissionDisposition.AMBIGUOUS,
                            edge_delivery_id=message.edge_delivery_id,
                            visible_message_id=visible_message_id,
                            diagnostic="provider accepted HTTP request without a usable message id",
                        )
                    return SubmissionResult(
                        disposition=SubmissionDisposition.ACCEPTED,
                        edge_delivery_id=message.edge_delivery_id,
                        provider_message_id=provider_id,
                        visible_message_id=visible_message_id,
                    )
                if response.status in _AMBIGUOUS_HTTP:
                    return SubmissionResult(
                        disposition=SubmissionDisposition.AMBIGUOUS,
                        edge_delivery_id=message.edge_delivery_id,
                        visible_message_id=visible_message_id,
                        diagnostic="provider gateway did not prove rejection",
                    )
                if response.status in _RETRYABLE_HTTP:
                    if attempt < self._retry.max_attempts:
                        delay = retry_after_seconds(response)
                        self._sleep_backoff(attempt, delay)
                        continue
                    return SubmissionResult(
                        disposition=SubmissionDisposition.RETRYABLE_REJECTED,
                        edge_delivery_id=message.edge_delivery_id,
                        visible_message_id=visible_message_id,
                        diagnostic=response_diagnostic(response),
                        retry_after_seconds=retry_after_seconds(response),
                    )
                return SubmissionResult(
                    disposition=SubmissionDisposition.PERMANENT_REJECTED,
                    edge_delivery_id=message.edge_delivery_id,
                    visible_message_id=visible_message_id,
                    diagnostic=response_diagnostic(response),
                )
        diagnostic = (
            response_diagnostic(last_response) if last_response else "API key rejected"
        )
        return SubmissionResult(
            disposition=SubmissionDisposition.PERMANENT_REJECTED,
            edge_delivery_id=message.edge_delivery_id,
            visible_message_id=visible_message_id,
            diagnostic=diagnostic,
        )

    def _sleep_backoff(self, attempt: int, explicit: int | None = None) -> None:
        delay = explicit
        if delay is None:
            delay = min(
                self._retry.max_delay_seconds,
                self._retry.base_delay_seconds * (2 ** (attempt - 1)),
            )
        self._sleeper(delay)

    def _observe(self, message: OutboundMessage, result: SubmissionResult) -> None:
        recipient = (
            message.envelope_recipients[0] if message.envelope_recipients else "invalid"
        )
        self._observer.emit(
            "mailgun_submission",
            {
                "edge_delivery_id": message.edge_delivery_id,
                "sender_hash": self._redactor.address(message.envelope_from),
                "recipient_hash": self._redactor.address(recipient),
                "bytes": len(message.rfc822_bytes),
                "disposition": result.disposition.value,
                "diagnostic": self._redactor.diagnostic(result.diagnostic),
            },
        )
