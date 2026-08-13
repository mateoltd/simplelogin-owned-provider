"""Signed catch-all raw-MIME ingress adapter."""

from __future__ import annotations

import time
from collections.abc import Mapping
from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import unquote, urlsplit

from ..config import DomainRegistry, IngressContentPolicy, RetryPolicy, TimeoutPolicy
from ..contracts import InboundMessage
from ..errors import (
    ConfigurationError,
    MalformedPayload,
    ProviderAuthenticationError,
    TemporaryIngressFailure,
    TransportFailure,
)
from ..observability import NullObserver, Observer, Redactor
from ..security import MailgunSignatureVerifier, SQLiteReplayStore
from ..transport import HTTPTransport
from ..validation import inspect_mime, mailbox_domain, validate_mailbox
from .http import idempotent_request, json_object

_MAILGUN_STORAGE_HOSTS = {
    "storage-us-east4.api.mailgun.net",
    "storage-us-west1.api.mailgun.net",
    "storage-europe-west1.api.mailgun.net",
}


class MailgunIngressAdapter:
    def __init__(
        self,
        registry: DomainRegistry,
        transport: HTTPTransport,
        replay_store: SQLiteReplayStore,
        *,
        timeout: TimeoutPolicy = TimeoutPolicy(max_response_bytes=32_000_000),
        retry: RetryPolicy = RetryPolicy(),
        observer: Observer | None = None,
        redactor: Redactor | None = None,
        signature_clock: Callable[[], float] = time.time,
    ) -> None:
        if observer is not None and redactor is None:
            raise ConfigurationError(
                "an explicit redactor is required when observability is enabled"
            )
        self._registry = registry
        self._transport = transport
        self._replay = replay_store
        self._timeout = timeout
        self._retry = retry
        self._observer = observer or NullObserver()
        self._redactor = redactor or Redactor(b"mail-edge-default-redaction-salt")
        self._signature_clock = signature_clock

    @staticmethod
    def _text(
        fields: Mapping[str, str | bytes], name: str, *, allow_empty: bool = False
    ) -> str:
        value = fields.get(name)
        if isinstance(value, bytes):
            try:
                return value.decode("ascii")
            except UnicodeDecodeError as exc:
                raise MalformedPayload(f"non-ASCII {name}") from exc
        if not isinstance(value, str) or (not value and not allow_empty):
            raise MalformedPayload(f"missing {name}")
        return value

    def receive(self, fields: Mapping[str, str | bytes]) -> InboundMessage:
        domain = self._text(fields, "domain").rstrip(".").lower()
        config = self._registry.exact(domain)
        timestamp = self._text(fields, "timestamp")
        token = self._text(fields, "token")
        signature = self._text(fields, "signature")
        replay_namespace = f"mailgun:ingress:{config.domain}"
        MailgunSignatureVerifier(
            config.webhook_keys, self._replay, clock=self._signature_clock
        ).verify(
            timestamp=timestamp,
            token=token,
            signature=signature,
            namespace=replay_namespace,
        )

        envelope_from = self._text(fields, "sender", allow_empty=True)
        recipient = self._text(fields, "recipient")
        validate_mailbox(envelope_from, allow_null=True, smtp_utf8=True)
        validate_mailbox(recipient, smtp_utf8=True)
        if mailbox_domain(recipient) != config.domain:
            raise MalformedPayload(
                "ingress recipient is outside the signed Mailgun domain"
            )
        try:
            if config.ingress_policy is IngressContentPolicy.STORE_AND_FETCH:
                raw = self._fetch_stored(fields, config)
            else:
                value = fields.get("body-mime")
                if not isinstance(value, bytes):
                    raise MalformedPayload("body-mime must be supplied as raw bytes")
                raw = value
        except TemporaryIngressFailure:
            self._replay.release(replay_namespace, token)
            raise
        inspect_mime(raw, max_bytes=config.max_message_bytes)
        try:
            received_at = datetime.fromtimestamp(int(timestamp), tz=UTC)
        except (ValueError, OverflowError) as exc:
            raise MalformedPayload("invalid ingress timestamp") from exc
        result = InboundMessage(
            provider_event_id=f"mailgun-inbound:{token}",
            envelope_from=envelope_from,
            envelope_recipients=(recipient,),
            rfc822_bytes=raw,
            received_at=received_at,
        )
        self._observer.emit(
            "mailgun_ingress",
            {
                "provider_event_id": result.provider_event_id,
                "sender_hash": self._redactor.address(envelope_from),
                "recipient_hash": self._redactor.address(recipient),
                "bytes": len(raw),
                "stored_fetch": config.ingress_policy
                is IngressContentPolicy.STORE_AND_FETCH,
            },
        )
        return result

    def _fetch_stored(self, fields, config) -> bytes:
        message_url = self._text(fields, "message-url")
        target = urlsplit(message_url)
        host = (target.hostname or "").lower()
        expected_prefix = f"/v3/domains/{config.domain}/messages/"
        if (
            target.scheme != "https"
            or target.port not in {None, 443}
            or target.username
            or target.password
            or host not in _MAILGUN_STORAGE_HOSTS
            or not unquote(target.path).startswith(expected_prefix)
            or target.query
            or target.fragment
        ):
            raise MalformedPayload("unsafe Mailgun storage URL")
        try:
            response = idempotent_request(
                self._transport,
                method="GET",
                url=message_url,
                keys=config.api_keys,
                timeout=self._timeout,
                retry=self._retry,
                headers={"Accept": "message/rfc2822"},
            )
        except (TransportFailure, ProviderAuthenticationError) as exc:
            raise TemporaryIngressFailure("stored message fetch failed") from exc
        if response.status != 200:
            raise TemporaryIngressFailure("stored message is not currently retrievable")
        try:
            payload = json_object(response)
            body = payload["body-mime"]
            if not isinstance(body, str):
                raise TypeError
            return body.encode("utf-8", "surrogatepass")
        except (KeyError, TypeError, UnicodeError) as exc:
            raise TemporaryIngressFailure(
                "stored message response omitted raw MIME"
            ) from exc
