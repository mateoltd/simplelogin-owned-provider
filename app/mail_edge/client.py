from __future__ import annotations

import hashlib
import io
import json
import re
import threading
import time
from dataclasses import dataclass
from typing import BinaryIO, Callable, Optional

import requests

from .configuration import MailEdgeConfiguration
from .contracts import (
    OUTBOUND_STATES,
    RawMessageRef,
    SmtpEnvelope,
    canonical_json,
    parse_raw_message_ref,
    parse_rfc3339,
    parse_route_binding,
    parse_smtp_envelope,
    parse_uuid7,
    strict_json_loads,
)
from .errors import (
    MailEdgeAmbiguousDeliveryError,
    MailEdgeBackpressureError,
    MailEdgeContractError,
    MailEdgeError,
    MailEdgeUnavailableError,
)


REMOTE_ERROR_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
MAXIMUM_RESPONSE_BYTES = 64 * 1024


@dataclass(frozen=True)
class OutboundIntent:
    intent_id: str
    tenant_id: str
    fingerprint: str
    state: str
    version: int
    created_at: str
    raw: RawMessageRef
    envelope: SmtpEnvelope


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int,
        reset_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._failure_threshold = failure_threshold
        self._reset_seconds = reset_seconds
        self._clock = clock
        self._failures = 0
        self._opened_at: Optional[float] = None
        self._probe_in_flight = False
        self._lock = threading.Lock()

    def enter(self) -> None:
        with self._lock:
            if self._opened_at is None:
                return
            if (
                self._clock() - self._opened_at < self._reset_seconds
                or self._probe_in_flight
            ):
                raise MailEdgeUnavailableError("MAIL_EDGE_CIRCUIT_OPEN")
            self._probe_in_flight = True

    def success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self._probe_in_flight = False

    def failure(self) -> None:
        with self._lock:
            self._probe_in_flight = False
            self._failures += 1
            if self._failures >= self._failure_threshold:
                self._opened_at = self._clock()


class MailEdgeClient:
    """Bounded tenant client for the exact b6 reference-service HTTP surface."""

    def __init__(
        self,
        configuration: MailEdgeConfiguration,
        *,
        session: Optional[requests.Session] = None,
        breaker: Optional[CircuitBreaker] = None,
    ):
        self._configuration = configuration
        if session is None:
            session = requests.Session()
            session.trust_env = False
        self._session = session
        self._admission = threading.BoundedSemaphore(configuration.http.concurrency)
        self._breaker = breaker or CircuitBreaker(
            configuration.http.breaker_failures,
            configuration.http.breaker_reset_seconds,
        )

    @property
    def tenant_id(self) -> str:
        return self._configuration.tenant_id

    def _headers(self, content_type: Optional[str] = None) -> dict[str, str]:
        result = {
            "Authorization": f"Bearer {self._configuration.bearer_token}",
            "Accept": "application/json",
        }
        if content_type:
            result["Content-Type"] = content_type
        return result

    def _request(
        self,
        method: str,
        path: str,
        *,
        retry_proven_safe: bool,
        response_loss_certainty: str = "unknown",
        before_attempt: Optional[Callable[[], None]] = None,
        **kwargs,
    ) -> requests.Response:
        if not self._admission.acquire(blocking=False):
            raise MailEdgeBackpressureError()
        try:
            self._breaker.enter()
            attempts = (
                self._configuration.http.pre_dispatch_retries + 1
                if retry_proven_safe
                else 1
            )
            for attempt in range(attempts):
                try:
                    if before_attempt is not None:
                        before_attempt()
                    response = self._session.request(
                        method,
                        f"{self._configuration.base_url}{path}",
                        allow_redirects=False,
                        timeout=(
                            self._configuration.http.connect_seconds,
                            self._configuration.http.read_seconds,
                        ),
                        stream=True,
                        **kwargs,
                    )
                    if response.status_code == 429 or response.status_code >= 500:
                        self._breaker.failure()
                    else:
                        self._breaker.success()
                    return response
                except requests.ConnectTimeout:
                    if attempt + 1 == attempts:
                        self._breaker.failure()
                        raise MailEdgeUnavailableError("MAIL_EDGE_CONNECT_TIMEOUT")
                except requests.ReadTimeout:
                    if retry_proven_safe and attempt + 1 < attempts:
                        continue
                    self._breaker.failure()
                    raise MailEdgeUnavailableError(
                        "MAIL_EDGE_RESPONSE_TIMEOUT",
                        delivery_certainty=response_loss_certainty,
                    )
                except requests.ConnectionError:
                    if retry_proven_safe and attempt + 1 < attempts:
                        continue
                    self._breaker.failure()
                    raise MailEdgeUnavailableError(
                        "MAIL_EDGE_CONNECTION_LOST",
                        delivery_certainty=response_loss_certainty,
                    )
            raise AssertionError("unreachable")
        finally:
            self._admission.release()

    @staticmethod
    def _response_json(response: requests.Response):
        if not hasattr(response, "iter_content"):
            return response.json()
        body = bytearray()
        try:
            for chunk in response.iter_content(64 * 1024):
                body.extend(chunk)
                if len(body) > MAXIMUM_RESPONSE_BYTES:
                    raise MailEdgeContractError(
                        "MAIL_EDGE_RESPONSE_TOO_LARGE", http_status=502
                    )
            return strict_json_loads(bytes(body), MAXIMUM_RESPONSE_BYTES)
        finally:
            response.close()

    @staticmethod
    def _problem(response: requests.Response) -> MailEdgeError:
        certainty = "unknown"
        code = "MAIL_EDGE_REQUEST_FAILED"
        retryable = False
        try:
            body = MailEdgeClient._response_json(response)
            if isinstance(body, dict):
                if body.get("deliveryCertainty") in {"not_sent", "accepted", "unknown"}:
                    certainty = body["deliveryCertainty"]
                if isinstance(body.get("code"), str) and REMOTE_ERROR_CODE_RE.fullmatch(
                    body["code"]
                ):
                    code = body["code"]
                retryable = body.get("retryable") is True and certainty == "not_sent"
        except (
            ValueError,
            json.JSONDecodeError,
            MailEdgeContractError,
            requests.RequestException,
        ):
            pass
        return MailEdgeError(
            code=code,
            retryable=retryable,
            delivery_certainty=certainty,
            http_status=response.status_code,
        )

    def store_raw_message(self, raw: bytes) -> RawMessageRef:
        if (
            not isinstance(raw, bytes)
            or len(raw) > self._configuration.maximum_raw_bytes
        ):
            raise MailEdgeContractError("RAW_MESSAGE_SIZE_INVALID", http_status=413)
        return self.store_raw_stream(io.BytesIO(raw))

    def store_raw_stream(self, stream: BinaryIO) -> RawMessageRef:
        if not all(
            hasattr(stream, attribute) for attribute in ("read", "seek", "tell")
        ):
            raise MailEdgeContractError("RAW_MESSAGE_STREAM_INVALID")
        try:
            start = stream.tell()
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    raise MailEdgeContractError("RAW_MESSAGE_STREAM_INVALID")
                size += len(chunk)
                if size > self._configuration.maximum_raw_bytes:
                    raise MailEdgeContractError(
                        "RAW_MESSAGE_SIZE_INVALID", http_status=413
                    )
                digest.update(chunk)
            expected = digest.hexdigest()
            stream.seek(start)
        except (OSError, ValueError):
            raise MailEdgeContractError("RAW_MESSAGE_STREAM_INVALID")
        headers = self._headers("message/rfc822")
        headers["Content-Length"] = str(size)
        response = self._request(
            "POST",
            f"/v1/tenants/{self.tenant_id}/raw-messages",
            retry_proven_safe=True,
            response_loss_certainty="not_sent",
            before_attempt=lambda: stream.seek(start),
            headers=headers,
            data=stream,
        )
        if response.status_code != 201:
            raise self._problem(response)
        try:
            reference = parse_raw_message_ref(
                self._response_json(response), self._configuration.maximum_raw_bytes
            )
        except (ValueError, MailEdgeContractError, requests.RequestException):
            raise MailEdgeContractError(
                "MAIL_EDGE_RAW_RESPONSE_INVALID", http_status=502
            )
        if reference.sha256 != expected or reference.size != size:
            raise MailEdgeContractError(
                "MAIL_EDGE_RAW_RESPONSE_MISMATCH", http_status=502
            )
        return reference

    def create_outbound_intent(
        self, envelope: SmtpEnvelope, raw: RawMessageRef, *, idempotency_key: str
    ) -> OutboundIntent:
        if (
            not isinstance(idempotency_key, str)
            or not 1 <= len(idempotency_key) <= 200
            or not idempotency_key.isascii()
            or not idempotency_key.isprintable()
        ):
            raise MailEdgeContractError("IDEMPOTENCY_KEY_INVALID")
        request_body = canonical_json(
            {"envelope": dict(envelope.to_wire()), "raw": dict(raw.to_wire())}
        )
        headers = self._headers("application/json")
        headers["Idempotency-Key"] = idempotency_key
        response = self._request(
            "POST",
            f"/v1/tenants/{self.tenant_id}/outbound-intents",
            retry_proven_safe=True,
            headers=headers,
            data=request_body,
        )
        if response.status_code not in {200, 202}:
            raise self._problem(response)
        intent = self._parse_outbound_intent(response, ambiguous_on_invalid=True)
        if (
            intent.raw.sha256 != raw.sha256
            or intent.raw.size != raw.size
            or intent.raw.media_type != raw.media_type
            or intent.envelope != envelope
        ):
            raise MailEdgeAmbiguousDeliveryError("MAIL_EDGE_INTENT_RESPONSE_MISMATCH")
        return intent

    def _parse_outbound_intent(
        self, response: requests.Response, *, ambiguous_on_invalid: bool = False
    ) -> OutboundIntent:
        try:
            value = self._response_json(response)
            required = {
                "schemaVersion",
                "intentId",
                "tenantId",
                "raw",
                "envelope",
                "primaryBinding",
                "fallbackBindings",
                "transmissionRaw",
                "fingerprint",
                "state",
                "createdAt",
                "version",
            }
            if (
                not isinstance(value, dict)
                or set(value) != required
                or value["schemaVersion"] != "v1"
            ):
                raise ValueError
            if parse_uuid7(value["tenantId"], "TENANT_ID_INVALID") != self.tenant_id:
                raise ValueError
            raw = parse_raw_message_ref(
                value["raw"], self._configuration.maximum_raw_bytes
            )
            parse_raw_message_ref(
                value["transmissionRaw"], self._configuration.maximum_raw_bytes
            )
            envelope = parse_smtp_envelope(value["envelope"])
            primary_binding = parse_route_binding(value["primaryBinding"])
            if (
                primary_binding.tenant_id != self.tenant_id
                or primary_binding.direction != "outbound"
            ):
                raise ValueError
            if (
                not isinstance(value["fallbackBindings"], list)
                or len(value["fallbackBindings"]) > 8
            ):
                raise ValueError
            for binding in value["fallbackBindings"]:
                parsed_binding = parse_route_binding(binding)
                if (
                    parsed_binding.tenant_id != self.tenant_id
                    or parsed_binding.direction != "outbound"
                ):
                    raise ValueError
            if value["state"] not in OUTBOUND_STATES:
                raise ValueError
            fingerprint = value["fingerprint"]
            if (
                not isinstance(fingerprint, str)
                or len(fingerprint) != 64
                or any(c not in "0123456789abcdef" for c in fingerprint)
            ):
                raise ValueError
            version = value["version"]
            if isinstance(version, bool) or not isinstance(version, int) or version < 0:
                raise ValueError
            return OutboundIntent(
                intent_id=parse_uuid7(value["intentId"], "INTENT_ID_INVALID"),
                tenant_id=value["tenantId"],
                fingerprint=fingerprint,
                state=value["state"],
                version=version,
                created_at=parse_rfc3339(value["createdAt"], "CREATED_AT_INVALID"),
                raw=raw,
                envelope=envelope,
            )
        except (
            ValueError,
            MailEdgeContractError,
            KeyError,
            TypeError,
            requests.RequestException,
        ):
            if ambiguous_on_invalid:
                raise MailEdgeAmbiguousDeliveryError(
                    "MAIL_EDGE_INTENT_RESPONSE_INVALID"
                )
            raise MailEdgeContractError(
                "MAIL_EDGE_INTENT_RESPONSE_INVALID", http_status=502
            )

    def get_outbound_intent(self, intent_id: str) -> OutboundIntent:
        validated = parse_uuid7(intent_id, "INTENT_ID_INVALID")
        response = self._request(
            "GET",
            f"/v1/tenants/{self.tenant_id}/outbound-intents/{validated}",
            retry_proven_safe=True,
            response_loss_certainty="not_sent",
            headers=self._headers(),
        )
        if response.status_code != 200:
            raise self._problem(response)
        return self._parse_outbound_intent(response)

    def submit_message(
        self,
        envelope: SmtpEnvelope,
        raw_message: bytes,
        *,
        idempotency_key: str,
    ) -> OutboundIntent:
        raw = self.store_raw_message(raw_message)
        return self.create_outbound_intent(
            envelope, raw, idempotency_key=idempotency_key
        )

    def ready(self) -> bool:
        response = self._request(
            "GET",
            "/readyz",
            retry_proven_safe=True,
            response_loss_certainty="not_sent",
            headers={"Accept": "application/json"},
        )
        try:
            return response.status_code == 200
        finally:
            if hasattr(response, "close"):
                response.close()
