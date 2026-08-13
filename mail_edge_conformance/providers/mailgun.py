"""Mailgun prebuilt-MIME qualification adapter and event normalizer."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from typing import Any, Protocol

from ..contracts import (
    AdapterResult,
    DeliveryRequest,
    EventType,
    FeedbackEvent,
    SubmissionDisposition,
)


OFFICIAL_API_BASES = frozenset(
    {"https://api.mailgun.net", "https://api.eu.mailgun.net"}
)


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    headers: dict[str, str]


class HttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse:
        """Execute one provider request."""


class UrllibTransport:
    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse:
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                encoded = response.read(2 * 1024 * 1024 + 1)
                if len(encoded) > 2 * 1024 * 1024:
                    raise ValueError("Mailgun response exceeded 2 MiB")
                return HttpResponse(
                    response.status, encoded, dict(response.headers.items())
                )
        except urllib.error.HTTPError as error:
            return HttpResponse(
                error.code,
                error.read(2 * 1024 * 1024 + 1),
                dict(error.headers.items()),
            )


class MailgunContractTransport:
    """Offline deterministic server contract for the Mailgun adapter path."""

    def __init__(self, *, size_limit: int) -> None:
        self.size_limit = size_limit
        self.messages: dict[str, bytes] = {}
        self.fields: dict[str, list[str]] = {}

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse:
        if method == "GET" and "/events?" in url:
            return HttpResponse(200, b'{"items":[]}', {})
        if method != "POST" or not url.endswith("/messages.mime") or body is None:
            return HttpResponse(404, b'{"message":"not found"}', {})
        content_type = headers.get("Content-Type", "")
        envelope = (
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii")
            + body
        )
        multipart = BytesParser(policy=policy.default).parsebytes(envelope)
        fields: dict[str, list[str]] = {}
        message_bytes: bytes | None = None
        for part in multipart.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if name == "message":
                message_bytes = part.get_payload(decode=True)
            elif name:
                fields.setdefault(name, []).append(
                    part.get_payload(decode=True).decode("utf-8")
                )
        if message_bytes is None or not fields.get("to"):
            return HttpResponse(400, b'{"message":"malformed MIME request"}', {})
        if len(message_bytes) > self.size_limit:
            return HttpResponse(400, b'{"message":"message exceeds fixture limit"}', {})
        provider_id = (
            "<contract-" + hashlib.sha256(message_bytes).hexdigest()[:24] + ">"
        )
        self.messages[provider_id] = message_bytes
        self.fields = fields
        return HttpResponse(
            200,
            json.dumps({"id": provider_id, "message": "Queued. Thank you."}).encode(),
            {},
        )

    def get(self, edge_delivery_id: str, provider_message_id: str) -> bytes:
        return self.messages[provider_message_id]


class MailgunAdapter:
    name = "mailgun"
    adapter_version = "messages-mime-v1"

    def __init__(
        self,
        *,
        domain: str,
        api_key: str,
        api_base: str = "https://api.mailgun.net",
        transport: HttpTransport | None = None,
        allow_test_endpoint: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.domain = domain.strip().lower()
        self.api_key = api_key
        self.api_base = api_base.rstrip("/")
        self.transport = transport or UrllibTransport()
        self.timeout = timeout
        self._accepted: dict[str, str] = {}
        if not self.domain or "." not in self.domain:
            raise ValueError("Mailgun qualification requires a fully qualified domain")
        if not self.api_key:
            raise ValueError("Mailgun qualification requires an explicit API key")
        if not allow_test_endpoint and self.api_base not in OFFICIAL_API_BASES:
            raise ValueError("live Mailgun API base must be an official HTTPS endpoint")

    def submit(self, request: DeliveryRequest) -> AdapterResult:
        boundary = (
            "mail-edge-"
            + hashlib.sha256(request.edge_delivery_id.encode("ascii")).hexdigest()[:32]
        )
        body = _multipart_body(
            boundary,
            fields=(
                *(("to", recipient) for recipient in request.envelope_recipients),
                ("o:tracking", "no"),
                ("o:suppress-headers", "all"),
                ("v:edge_delivery_id", request.edge_delivery_id),
            ),
            message=request.rfc822_bytes,
        )
        headers = {
            "Authorization": "Basic "
            + base64.b64encode(f"api:{self.api_key}".encode()).decode("ascii"),
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
            "User-Agent": "mail-edge-conformance/1",
        }
        try:
            response = self.transport.request(
                "POST",
                f"{self.api_base}/v3/{urllib.parse.quote(self.domain, safe='')}/messages.mime",
                headers,
                body,
                self.timeout,
            )
        except (TimeoutError, socket.timeout):
            return AdapterResult(
                SubmissionDisposition.UNKNOWN,
                diagnostic_code="timeout",
                diagnostic="Mailgun acceptance could not be determined",
            )
        except urllib.error.URLError as error:
            return AdapterResult(
                SubmissionDisposition.RETRY,
                diagnostic_code="transport_unavailable",
                diagnostic=str(error.reason),
            )
        payload = _decode_json(response.body)
        if 200 <= response.status < 300:
            provider_id = str(payload.get("id", "")).strip()
            if not provider_id:
                return AdapterResult(
                    SubmissionDisposition.UNKNOWN,
                    diagnostic_code="missing_provider_id",
                    diagnostic="Mailgun accepted without a usable message ID",
                )
            self._accepted[request.edge_delivery_id] = provider_id
            return AdapterResult(
                SubmissionDisposition.ACCEPTED, provider_message_id=provider_id
            )
        diagnostic = str(payload.get("message") or f"HTTP {response.status}")
        if response.status == 400:
            return AdapterResult(
                SubmissionDisposition.REJECT,
                diagnostic_code="provider_rejected",
                diagnostic=diagnostic,
            )
        if response.status in {401, 403}:
            code = "credential_or_domain_rejected"
        elif response.status == 429:
            code = "quota_or_rate_limit"
        else:
            code = "provider_unavailable"
        return AdapterResult(
            SubmissionDisposition.RETRY,
            diagnostic_code=code,
            diagnostic=diagnostic,
        )

    def reconcile(self, edge_delivery_id: str) -> AdapterResult | None:
        provider_id = self._accepted.get(edge_delivery_id)
        if provider_id:
            return AdapterResult(
                SubmissionDisposition.ACCEPTED, provider_message_id=provider_id
            )
        for item in self.events(user_variable=edge_delivery_id):
            user_variables = item.get("user-variables", {})
            if user_variables.get("edge_delivery_id") != edge_delivery_id:
                continue
            message_id = _mailgun_message_id(item)
            if message_id:
                return AdapterResult(
                    SubmissionDisposition.ACCEPTED, provider_message_id=message_id
                )
        return None

    def accepted_provider_id(self, edge_delivery_id: str) -> str | None:
        return self._accepted.get(edge_delivery_id)

    def events(
        self,
        *,
        message_id: str | None = None,
        user_variable: str | None = None,
    ) -> tuple[dict[str, Any], ...]:
        query: dict[str, str] = {"limit": "300"}
        if message_id:
            query["message-id"] = message_id
        if user_variable:
            query["user-variables"] = user_variable
        response = self.transport.request(
            "GET",
            f"{self.api_base}/v3/{urllib.parse.quote(self.domain, safe='')}/events?"
            + urllib.parse.urlencode(query),
            {"Authorization": _basic_auth(self.api_key)},
            None,
            self.timeout,
        )
        if response.status != 200:
            return ()
        items = _decode_json(response.body).get("items", ())
        if not isinstance(items, list):
            return ()
        return tuple(item for item in items if isinstance(item, dict))

    def wait_for_event(
        self,
        *,
        provider_message_id: str,
        edge_delivery_id: str,
        event_type: EventType,
        timeout: float,
    ) -> FeedbackEvent:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for item in self.events(message_id=provider_message_id):
                event = normalize_mailgun_event({"event-data": item})
                if event is None:
                    continue
                if (
                    event.event_type is event_type
                    and event.edge_delivery_id == edge_delivery_id
                ):
                    return event
            time.sleep(2)
        raise TimeoutError(
            f"Mailgun did not expose {event_type.value} for {edge_delivery_id}"
        )


class MailgunWebhookVerifier:
    """Authenticate timestamps/tokens exactly as Mailgun documents them."""

    def __init__(
        self,
        signing_key: str,
        *,
        replay_window_seconds: int = 300,
    ) -> None:
        if not signing_key:
            raise ValueError("Mailgun webhook signing key is required")
        self._key = signing_key.encode("utf-8")
        self._window = replay_window_seconds
        self._seen_tokens: set[str] = set()

    def verify(self, payload: dict[str, Any], *, now: int | None = None) -> str:
        signature = payload.get("signature")
        if not isinstance(signature, dict):
            return "invalid_signature"
        timestamp = str(signature.get("timestamp", ""))
        token = str(signature.get("token", ""))
        supplied = str(signature.get("signature", ""))
        try:
            timestamp_value = int(timestamp)
        except ValueError:
            return "invalid_signature"
        expected = hmac.new(
            self._key, (timestamp + token).encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, supplied):
            return "invalid_signature"
        current = int(time.time()) if now is None else now
        if abs(current - timestamp_value) > self._window:
            return "expired_signature"
        if token in self._seen_tokens:
            return "signature_replay"
        self._seen_tokens.add(token)
        return "verified"


def normalize_mailgun_event(payload: dict[str, Any]) -> FeedbackEvent | None:
    data = payload.get("event-data")
    if not isinstance(data, dict):
        raise ValueError("Mailgun event-data object is required")
    provider_event_id = str(data.get("id", "")).strip()
    provider_message_id = _mailgun_message_id(data)
    event_name = str(data.get("event", "")).lower()
    if event_name in {"accepted", "opened", "clicked", "unsubscribed", "stored"}:
        return None
    if event_name == "delivered":
        event_type = EventType.DELIVERED
    elif event_name == "complained":
        event_type = EventType.COMPLAINT
    elif event_name == "rejected":
        event_type = EventType.REJECTED
    elif event_name == "failed":
        severity = str(data.get("severity", "")).lower()
        reason = str(data.get("reason", "")).lower()
        delivery_status = data.get("delivery-status", {})
        if severity == "temporary":
            event_type = EventType.DELAYED
        elif reason == "bounce":
            event_type = EventType.HARD_BOUNCE
        else:
            event_type = EventType.SOFT_BOUNCE
        if not isinstance(delivery_status, dict):
            delivery_status = {}
    else:
        raise ValueError(f"unsupported Mailgun event type: {event_name}")
    delivery_status = data.get("delivery-status", {})
    if not isinstance(delivery_status, dict):
        delivery_status = {}
    user_variables = data.get("user-variables", {})
    if not isinstance(user_variables, dict):
        user_variables = {}
    if not provider_event_id or not provider_message_id:
        raise ValueError("Mailgun event lacks stable event or message ID")
    timestamp = float(data.get("timestamp", 0))
    return FeedbackEvent(
        provider_event_id=provider_event_id,
        provider_message_id=provider_message_id,
        edge_delivery_id=_optional_string(user_variables.get("edge_delivery_id")),
        event_type=event_type,
        recipient=str(data.get("recipient", "")),
        smtp_status=_optional_string(
            delivery_status.get("enhanced-code") or delivery_status.get("code")
        ),
        diagnostic=_optional_string(
            delivery_status.get("message") or data.get("reason")
        ),
        occurred_at=datetime.fromtimestamp(timestamp, tz=timezone.utc),
    )


def _multipart_body(
    boundary: str,
    *,
    fields: tuple[tuple[str, str], ...],
    message: bytes,
) -> bytes:
    delimiter = f"--{boundary}\r\n".encode("ascii")
    chunks: list[bytes] = []
    for name, value in fields:
        chunks.extend(
            (
                delimiter,
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(
                    "ascii"
                ),
                value.encode("utf-8"),
                b"\r\n",
            )
        )
    chunks.extend(
        (
            delimiter,
            b'Content-Disposition: form-data; name="message"; filename="message.eml"\r\n',
            b"Content-Type: application/octet-stream\r\n\r\n",
            message,
            b"\r\n",
            f"--{boundary}--\r\n".encode("ascii"),
        )
    )
    return b"".join(chunks)


def _decode_json(encoded: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(encoded or b"{}")
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _mailgun_message_id(data: dict[str, Any]) -> str:
    message = data.get("message", {})
    if isinstance(message, dict):
        headers = message.get("headers", {})
        if isinstance(headers, dict) and headers.get("message-id"):
            return str(headers["message-id"])
    return str(data.get("message-id", ""))


def _basic_auth(api_key: str) -> str:
    return "Basic " + base64.b64encode(f"api:{api_key}".encode()).decode("ascii")


def _optional_string(value: Any) -> str | None:
    return None if value is None else str(value)
