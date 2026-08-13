"""Deterministic provider HTTP server and local SMTP edge fixtures."""

from __future__ import annotations

import hashlib
import json
import smtplib
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from .contracts import AdapterResult, DeliveryRequest, SubmissionDisposition


@dataclass
class FixtureProvider:
    deliver: Callable[[DeliveryRequest], None] | None = None
    outcomes: deque[str] = field(default_factory=deque)
    deliveries: dict[str, DeliveryRequest] = field(default_factory=dict)
    provider_ids: dict[str, str] = field(default_factory=dict)
    test_index: dict[str, str] = field(default_factory=dict)
    subject_index: dict[str, list[str]] = field(default_factory=dict)

    def submit(self, request: DeliveryRequest) -> AdapterResult:
        outcome = self.outcomes.popleft() if self.outcomes else "accepted"
        provider_id = _provider_id(request)
        if outcome == "rejected":
            return AdapterResult(
                SubmissionDisposition.REJECT,
                diagnostic_code="5.7.1",
                diagnostic="deterministic rejection",
            )
        if outcome in {"credential", "quota", "provider_pause", "timeout_before"}:
            return AdapterResult(
                SubmissionDisposition.RETRY,
                diagnostic_code=outcome,
                diagnostic=f"deterministic {outcome}",
            )
        if outcome == "timeout_after":
            self._record_acceptance(request, provider_id)
            return AdapterResult(
                SubmissionDisposition.UNKNOWN,
                diagnostic_code="timeout_after_acceptance",
                diagnostic="acceptance acknowledgement was lost",
            )
        if outcome == "unknown":
            return AdapterResult(
                SubmissionDisposition.UNKNOWN,
                diagnostic_code="unknown",
                diagnostic="provider disposition is unknown",
            )
        if outcome != "accepted":
            raise ValueError(f"unsupported fixture outcome: {outcome}")
        self._record_acceptance(request, provider_id)
        if self.deliver is not None:
            self.deliver(request)
        return AdapterResult(
            SubmissionDisposition.ACCEPTED, provider_message_id=provider_id
        )

    def reconcile(self, edge_delivery_id: str) -> AdapterResult | None:
        provider_id = self.provider_ids.get(edge_delivery_id)
        if provider_id is None:
            return None
        return AdapterResult(
            SubmissionDisposition.ACCEPTED, provider_message_id=provider_id
        )

    def _record_acceptance(self, request: DeliveryRequest, provider_id: str) -> None:
        self.deliveries[request.edge_delivery_id] = request
        self.provider_ids[request.edge_delivery_id] = provider_id
        message = BytesParser(policy=policy.default).parsebytes(request.rfc822_bytes)
        test_id = message.get("X-Mail-Edge-Test-ID")
        if test_id:
            self.test_index[str(test_id)] = request.edge_delivery_id
        subject = message.get("Subject")
        if subject:
            self.subject_index.setdefault(str(subject), []).append(
                request.edge_delivery_id
            )


class FixtureHttpAdapter:
    name = "deterministic-provider-server"

    def __init__(self, base_url: str, *, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def submit(self, request: DeliveryRequest) -> AdapterResult:
        payload = _json_request(
            self.base_url + "/v1/submissions", "POST", request.as_json()
        )
        return AdapterResult.from_json(payload["result"])

    def reconcile(self, edge_delivery_id: str) -> AdapterResult | None:
        try:
            payload = _json_request(
                self.base_url
                + "/v1/reconcile/"
                + urllib.parse.quote(edge_delivery_id, safe=""),
                "GET",
            )
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise
        result = payload.get("result")
        return AdapterResult.from_json(result) if result else None

    def delivery_by_test_id(self, test_id: str) -> DeliveryRequest:
        payload = _json_request(
            self.base_url
            + "/v1/deliveries?test_id="
            + urllib.parse.quote(test_id, safe=""),
            "GET",
        )
        return DeliveryRequest.from_json(payload["delivery"])


class ProviderRequestHandler(BaseHTTPRequestHandler):
    server_version = "mail-edge-fixture-provider/1"

    @property
    def state(self) -> FixtureProvider:
        return self.server.fixture_state  # type: ignore[attr-defined]

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/health":
            self._reply(200, {"status": "ok"})
            return
        if parsed.path == "/v1/deliveries":
            query = urllib.parse.parse_qs(parsed.query)
            test_id = query.get("test_id", [None])[0]
            subject = query.get("subject", [None])[0]
            edge_id = self.state.test_index.get(str(test_id)) if test_id else None
            if edge_id is None and subject:
                candidates = self.state.subject_index.get(str(subject), [])
                edge_id = candidates[-1] if candidates else None
            request = self.state.deliveries.get(str(edge_id)) if edge_id else None
            if request is None:
                self._reply(404, {"error": "delivery not found"})
            else:
                self._reply(200, {"delivery": request.as_json()})
            return
        prefix = "/v1/reconcile/"
        if parsed.path.startswith(prefix):
            edge_id = urllib.parse.unquote(parsed.path[len(prefix) :])
            result = self.state.reconcile(edge_id)
            if result is None:
                self._reply(404, {"result": None})
            else:
                self._reply(200, {"result": result.as_json()})
            return
        self._reply(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/v1/submissions":
            request = DeliveryRequest.from_json(self._read_json())
            result = self.state.submit(request)
            self._reply(200, {"result": result.as_json()})
            return
        if self.path == "/v1/control":
            body = self._read_json()
            outcomes = body.get("outcomes")
            if not isinstance(outcomes, list) or not all(
                isinstance(item, str) for item in outcomes
            ):
                self._reply(400, {"error": "outcomes must be a string list"})
                return
            self.state.outcomes.extend(outcomes)
            self._reply(200, {"queued_outcomes": len(self.state.outcomes)})
            return
        self._reply(404, {"error": "not found"})

    def log_message(self, message_format: str, *args: object) -> None:
        return

    def _read_json(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 40 * 1024 * 1024:
            raise ValueError("fixture request length is invalid")
        return json.loads(self.rfile.read(length))

    def _reply(self, status: int, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def create_provider_server(
    host: str,
    port: int,
    state: FixtureProvider | None = None,
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), ProviderRequestHandler)
    server.fixture_state = state or FixtureProvider()  # type: ignore[attr-defined]
    return server


class EdgeSmtpHandler:
    def __init__(self, adapter: FixtureHttpAdapter) -> None:
        self.adapter = adapter
        self._lock = threading.Lock()
        self._counter = 0

    async def handle_DATA(self, server, session, envelope):  # noqa: N802
        encoded = bytes(envelope.original_content)
        with self._lock:
            self._counter += 1
            sequence = self._counter
        edge_id = (
            "local-"
            + hashlib.sha256(
                str(sequence).encode("ascii") + b"\0" + encoded
            ).hexdigest()[:24]
        )
        request = DeliveryRequest(
            edge_delivery_id=edge_id,
            envelope_from=envelope.mail_from,
            envelope_recipients=tuple(envelope.rcpt_tos),
            rfc822_bytes=encoded,
            smtp_utf8_required="SMTPUTF8" in envelope.mail_options,
            mail_options=tuple(envelope.mail_options),
            rcpt_options=tuple(envelope.rcpt_options),
        )
        result = self.adapter.submit(request)
        if result.disposition is SubmissionDisposition.ACCEPTED:
            return f"250 2.0.0 accepted as {result.provider_message_id}"
        if result.disposition is SubmissionDisposition.REJECT:
            return f"550 {result.diagnostic_code or '5.7.1'} {result.diagnostic or 'rejected'}"
        return f"451 4.4.2 {result.diagnostic or result.disposition.value}"


def smtp_delivery(host: str, port: int) -> Callable[[DeliveryRequest], None]:
    def deliver(request: DeliveryRequest) -> None:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            options = ["SMTPUTF8"] if request.smtp_utf8_required else []
            smtp.sendmail(
                request.envelope_from,
                list(request.envelope_recipients),
                request.rfc822_bytes,
                mail_options=options,
            )

    return deliver


def _provider_id(request: DeliveryRequest) -> str:
    return (
        "fixture-"
        + hashlib.sha256(
            request.edge_delivery_id.encode("ascii") + b"\0" + request.rfc822_bytes
        ).hexdigest()[:24]
    )


def _json_request(
    url: str, method: str, body: dict[str, object] | None = None
) -> dict[str, object]:
    encoded = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=encoded,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read(50 * 1024 * 1024 + 1)
    if len(payload) > 50 * 1024 * 1024:
        raise ValueError("fixture server response exceeded 50 MiB")
    return json.loads(payload)
