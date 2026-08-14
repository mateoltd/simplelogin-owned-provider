from __future__ import annotations

import hashlib
import hmac
import io
import json
import math
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, BinaryIO, Callable, Mapping, Optional

import requests

from .configuration import MailEdgeConfiguration
from .contracts import (
    OUTBOUND_STATES,
    RawAccessGrant,
    RawMessageRef,
    SmtpEnvelope,
    canonical_json,
    parse_raw_message_ref,
    parse_raw_access_grant,
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
    normalize_safe_details,
)


REMOTE_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
REMOTE_PROBLEM_POLICIES = {
    "validation-failed": ("VALIDATION_FAILED", 400),
    "authentication-failed": ("AUTHENTICATION_FAILED", 401),
    "authorization-failed": ("AUTHORIZATION_FAILED", 403),
    "not-found": ("NOT_FOUND", 404),
    "conflict": ("CONFLICT", 409),
    "idempotency-conflict": ("IDEMPOTENCY_CONFLICT", 409),
    "binding-unavailable": ("BINDING_UNAVAILABLE", 409),
    "capability-unsupported": ("CAPABILITY_UNSUPPORTED", 422),
    "rate-limited": ("RATE_LIMITED", 429),
    "ingress-limit-exceeded": ("INGRESS_LIMIT_EXCEEDED", 413),
    "ingress-failed": ("INGRESS_FAILED", 400),
    "storage-unavailable": ("STORAGE_UNAVAILABLE", 503),
    "workflow-conflict": ("WORKFLOW_CONFLICT", 409),
    "stale-fence": ("STALE_FENCE", 409),
    "illegal-transition": ("ILLEGAL_TRANSITION", 409),
    "provider-not-sent": ("PROVIDER_NOT_SENT", 502),
    "provider-outcome-unknown": ("PROVIDER_UNKNOWN", 502),
    "provider-rejected": ("PROVIDER_REJECTED", 502),
    "host-unavailable": ("HOST_UNAVAILABLE", 503),
    "internal": ("INTERNAL", 500),
}


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


def _exact_object(value: Any, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise MailEdgeContractError(
            "MAIL_EDGE_RESPONSE_CONTRACT_INVALID", http_status=502
        )
    return value


def _safe_integer(value: Any, minimum: int = 0) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= 9_007_199_254_740_991
    ):
        raise MailEdgeContractError(
            "MAIL_EDGE_RESPONSE_CONTRACT_INVALID", http_status=502
        )
    return value


def _parse_binding_control_view(value: Any, tenant_id: str) -> Mapping[str, Any]:
    candidate = _exact_object(
        value,
        {
            "binding",
            "state",
            "optimisticVersion",
            "qualifiedAt",
            "activatedAt",
            "drainingAt",
            "retiredAt",
            "checks",
            "pinnedInbound",
            "pinnedOutbound",
        },
    )
    binding = parse_route_binding(candidate["binding"])
    if binding.tenant_id != tenant_id or candidate["state"] not in {
        "draft",
        "testing",
        "active",
        "draining",
        "retired",
        "failed",
    }:
        raise MailEdgeContractError(
            "MAIL_EDGE_BINDING_RESPONSE_INVALID", http_status=502
        )
    for field in ("qualifiedAt", "activatedAt", "drainingAt", "retiredAt"):
        if candidate[field] is not None:
            parse_rfc3339(candidate[field], "MAIL_EDGE_BINDING_RESPONSE_INVALID")
    checks = candidate["checks"]
    if not isinstance(checks, list) or len(checks) > 1024:
        raise MailEdgeContractError(
            "MAIL_EDGE_BINDING_RESPONSE_INVALID", http_status=502
        )
    for check in checks:
        item = _exact_object(
            check, {"checkKind", "outcome", "evidenceAt", "expiresAt", "reportDigest"}
        )
        if item["checkKind"] not in {
            "capability",
            "dns",
            "control_plane",
            "live_conformance",
            "drift",
        } or item["outcome"] not in {"pass", "fail", "expired"}:
            raise MailEdgeContractError(
                "MAIL_EDGE_BINDING_RESPONSE_INVALID", http_status=502
            )
        parse_rfc3339(item["evidenceAt"], "MAIL_EDGE_BINDING_RESPONSE_INVALID")
        parse_rfc3339(item["expiresAt"], "MAIL_EDGE_BINDING_RESPONSE_INVALID")
        digest = item["reportDigest"]
        if not isinstance(digest, str) or not re.fullmatch(r"^[a-f0-9]{64}$", digest):
            raise MailEdgeContractError(
                "MAIL_EDGE_BINDING_RESPONSE_INVALID", http_status=502
            )
    _safe_integer(candidate["optimisticVersion"])
    _safe_integer(candidate["pinnedInbound"])
    _safe_integer(candidate["pinnedOutbound"])
    return MappingProxyType({**candidate, "binding": binding})


def _parse_outbound_quarantine_view(value: Any, tenant_id: str) -> Mapping[str, Any]:
    candidate = _exact_object(
        value,
        {
            "tenantId",
            "intentId",
            "intentState",
            "intentVersion",
            "attemptId",
            "attemptState",
            "attemptFence",
            "certainty",
        },
    )
    if parse_uuid7(candidate["tenantId"], "TENANT_ID_INVALID") != tenant_id:
        raise MailEdgeContractError(
            "MAIL_EDGE_QUARANTINE_RESPONSE_INVALID", http_status=502
        )
    parse_uuid7(candidate["intentId"], "INTENT_ID_INVALID")
    _safe_integer(candidate["intentVersion"])
    if candidate["attemptId"] is not None:
        parse_uuid7(candidate["attemptId"], "ATTEMPT_ID_INVALID")
    if candidate["attemptFence"] is not None:
        _safe_integer(candidate["attemptFence"])
    if candidate["certainty"] is not None and candidate["certainty"] not in {
        "not_sent",
        "accepted",
        "unknown",
    }:
        raise MailEdgeContractError(
            "MAIL_EDGE_QUARANTINE_RESPONSE_INVALID", http_status=502
        )
    for field in ("intentState", "attemptState"):
        item = candidate[field]
        if item is not None and (not isinstance(item, str) or not 1 <= len(item) <= 64):
            raise MailEdgeContractError(
                "MAIL_EDGE_QUARANTINE_RESPONSE_INVALID", http_status=502
            )
    return MappingProxyType(dict(candidate))


def _parse_inbound_quarantine_view(value: Any, tenant_id: str) -> Mapping[str, Any]:
    candidate = _exact_object(
        value,
        {"tenantId", "receiptId", "state", "version", "fence", "lastErrorCode"},
    )
    if parse_uuid7(candidate["tenantId"], "TENANT_ID_INVALID") != tenant_id:
        raise MailEdgeContractError(
            "MAIL_EDGE_QUARANTINE_RESPONSE_INVALID", http_status=502
        )
    parse_uuid7(candidate["receiptId"], "RECEIPT_ID_INVALID")
    _safe_integer(candidate["version"])
    _safe_integer(candidate["fence"])
    for field in ("state", "lastErrorCode"):
        item = candidate[field]
        if item is not None and (not isinstance(item, str) or not 1 <= len(item) <= 64):
            raise MailEdgeContractError(
                "MAIL_EDGE_QUARANTINE_RESPONSE_INVALID", http_status=502
            )
    return MappingProxyType(dict(candidate))


def _validate_decision_evidence(value: Any) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or len(value) > 64:
        raise MailEdgeContractError("QUARANTINE_EVIDENCE_INVALID")
    normalized: dict[str, object] = {}
    for key, item in value.items():
        invalid_number = (
            isinstance(item, int)
            and not isinstance(item, bool)
            and abs(item) > 9_007_199_254_740_991
        ) or (
            isinstance(item, float)
            and (not math.isfinite(item) or abs(item) > 9_007_199_254_740_991)
        )
        if (
            not isinstance(key, str)
            or not re.fullmatch(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$", key)
            or isinstance(item, (dict, list, tuple))
            or not isinstance(item, (str, int, float, bool))
            or (isinstance(item, str) and len(item) > 512)
            or invalid_number
        ):
            raise MailEdgeContractError("QUARANTINE_EVIDENCE_INVALID")
        normalized[key] = item
    return MappingProxyType(normalized)


def _validate_reason_code(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"^[a-z][a-z0-9_]{0,63}$", value):
        raise MailEdgeContractError("CONTROL_REASON_CODE_INVALID")
    return value


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
    """Bounded tenant client for the frozen v1 reference-service HTTP surface."""

    def __init__(
        self,
        configuration: MailEdgeConfiguration,
        *,
        session: Optional[requests.Session] = None,
        take_session_ownership: bool = False,
        breaker: Optional[CircuitBreaker] = None,
    ):
        if not isinstance(take_session_ownership, bool):
            raise TypeError("Mail Edge session ownership must be explicit.")
        self._configuration = configuration
        session_was_created = session is None
        if session is None:
            session = requests.Session()
            session.trust_env = False
        self._session = session
        self._owns_session = session_was_created or take_session_ownership
        self._admission = threading.BoundedSemaphore(configuration.http.concurrency)
        self._breaker = breaker or CircuitBreaker(
            configuration.http.breaker_failures,
            configuration.http.breaker_reset_seconds,
        )
        self._lifecycle = threading.Condition()
        self._accepting_operations = True
        self._active_operations = 0
        self._session_close_started = False
        self._closed = False
        self._close_succeeded = False

    @property
    def tenant_id(self) -> str:
        return self._configuration.tenant_id

    def _begin_operation(self) -> None:
        with self._lifecycle:
            if not self._accepting_operations:
                raise MailEdgeUnavailableError("MAIL_EDGE_CLIENT_CLOSED")
            self._active_operations += 1

    def _finish_operation(self) -> None:
        with self._lifecycle:
            if self._active_operations <= 0:
                raise RuntimeError("Mail Edge client operation accounting is invalid.")
            self._active_operations -= 1
            self._lifecycle.notify_all()

    def _headers(self, content_type: Optional[str] = None) -> dict[str, str]:
        result = {
            "Authorization": f"Bearer {self._configuration.bearer_token}",
            "Accept": "application/json",
        }
        if content_type:
            result["Content-Type"] = content_type
        return result

    def _operator_headers(
        self, *, privileged: bool = False, content_type: Optional[str] = None
    ) -> dict[str, str]:
        authentication = self._configuration.operator_authentication
        token = (
            authentication.privileged_operator_bearer_token
            if privileged
            else authentication.operator_bearer_token
        )
        if token is None:
            raise MailEdgeContractError(
                "MAIL_EDGE_OPERATOR_AUTHENTICATION_NOT_CONFIGURED", http_status=503
            )
        result = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if content_type is not None:
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
        self._begin_operation()
        operation_owned = True
        if not self._admission.acquire(blocking=False):
            self._finish_operation()
            raise MailEdgeBackpressureError()
        admission_owned = True
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
                    setattr(response, "_mail_edge_admission_owned", True)
                    setattr(response, "_mail_edge_operation_owned", True)
                    admission_owned = False
                    operation_owned = False
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
            if admission_owned:
                self._admission.release()
            if operation_owned:
                self._finish_operation()

    def _close_response(self, response: requests.Response) -> None:
        try:
            if hasattr(response, "close"):
                response.close()
        finally:
            if getattr(response, "_mail_edge_admission_owned", False):
                setattr(response, "_mail_edge_admission_owned", False)
                self._admission.release()
            if getattr(response, "_mail_edge_operation_owned", False):
                setattr(response, "_mail_edge_operation_owned", False)
                self._finish_operation()

    def _response_json(self, response: requests.Response):
        try:
            if not hasattr(response, "iter_content"):
                return response.json()
            body = bytearray()
            for chunk in response.iter_content(64 * 1024):
                body.extend(chunk)
                if len(body) > self._configuration.http.maximum_json_bytes:
                    raise MailEdgeContractError(
                        "MAIL_EDGE_RESPONSE_TOO_LARGE", http_status=502
                    )
            return strict_json_loads(
                bytes(body), self._configuration.http.maximum_json_bytes
            )
        finally:
            self._close_response(response)

    def _problem(self, response: requests.Response) -> MailEdgeError:
        certainty = "unknown"
        code = "MAIL_EDGE_REQUEST_FAILED"
        retryable = False
        safe_details = None
        try:
            response_headers = getattr(response, "headers", {})
            content_type = (
                response_headers.get("Content-Type", "")
                .split(";", 1)[0]
                .strip()
                .lower()
            )
            if (
                content_type != "application/problem+json"
                or response_headers.get("Content-Encoding") is not None
            ):
                raise MailEdgeContractError(
                    "MAIL_EDGE_PROBLEM_INVALID", http_status=502
                )
            body = self._response_json(response)
            required = {
                "schemaVersion",
                "type",
                "title",
                "status",
                "code",
                "retryable",
                "deliveryCertainty",
            }
            optional = {
                "detail",
                "instance",
                "traceId",
                "safeDetails",
                "occurredAt",
            }
            if (
                not isinstance(body, dict)
                or not required.issubset(body)
                or set(body) - required - optional
                or body["schemaVersion"] != "v1"
                or body["status"] != response.status_code
                or not isinstance(body["retryable"], bool)
                or body["deliveryCertainty"] not in {"not_sent", "accepted", "unknown"}
                or (body["deliveryCertainty"] == "unknown" and body["retryable"])
            ):
                raise MailEdgeContractError(
                    "MAIL_EDGE_PROBLEM_INVALID", http_status=502
                )
            remote_code = body["code"]
            if (
                not isinstance(remote_code, str)
                or not REMOTE_ERROR_CODE_RE.fullmatch(remote_code)
                or remote_code not in REMOTE_PROBLEM_POLICIES
                or body["type"] != f"https://mail-edge.dev/problems/{remote_code}"
                or not isinstance(body["title"], str)
                or not 1 <= len(body["title"]) <= 96
            ):
                raise MailEdgeContractError(
                    "MAIL_EDGE_PROBLEM_INVALID", http_status=502
                )
            parsed_code, canonical_status = REMOTE_PROBLEM_POLICIES[remote_code]
            if body["status"] != canonical_status:
                raise MailEdgeContractError(
                    "MAIL_EDGE_PROBLEM_INVALID", http_status=502
                )
            for field, maximum in (("detail", 256), ("instance", 256), ("traceId", 64)):
                item = body.get(field)
                if item is not None and (
                    not isinstance(item, str) or not 1 <= len(item) <= maximum
                ):
                    raise MailEdgeContractError(
                        "MAIL_EDGE_PROBLEM_INVALID", http_status=502
                    )
            if "occurredAt" in body:
                parse_rfc3339(body["occurredAt"], "MAIL_EDGE_PROBLEM_INVALID")
            parsed_certainty = body["deliveryCertainty"]
            parsed_retryable = body["retryable"] and parsed_certainty == "not_sent"
            parsed_safe_details = normalize_safe_details(
                body.get("safeDetails"), strict=True
            )
            certainty = parsed_certainty
            code = parsed_code
            retryable = parsed_retryable
            safe_details = parsed_safe_details
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
            safe_details=safe_details,
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

    def download_raw_to(self, grant: RawAccessGrant, target: BinaryIO) -> None:
        if not isinstance(grant, RawAccessGrant) or not hasattr(target, "write"):
            raise MailEdgeContractError("RAW_DOWNLOAD_INPUT_INVALID")
        try:
            issued_at = datetime.fromisoformat(grant.issued_at.replace("Z", "+00:00"))
            expires_at = datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError):
            raise MailEdgeContractError("RAW_DOWNLOAD_AUTHORIZATION_INVALID")
        now = datetime.now(timezone.utc)
        if (
            grant.tenant_id != self.tenant_id
            or not hmac.compare_digest(
                grant.audience.encode("utf-8"),
                self._configuration.host_authentication.audience.encode("ascii"),
            )
            or expires_at <= issued_at
            or (expires_at - issued_at).total_seconds() > 5 * 60
            or now < issued_at.astimezone(timezone.utc)
            or now >= expires_at.astimezone(timezone.utc)
        ):
            raise MailEdgeContractError(
                "RAW_DOWNLOAD_AUTHORIZATION_INVALID", http_status=403
            )
        self._begin_operation()
        if not self._admission.acquire(blocking=False):
            self._finish_operation()
            raise MailEdgeBackpressureError()
        response: Optional[requests.Response] = None
        try:
            self._breaker.enter()
            try:
                response = self._session.request(
                    "GET",
                    f"{self._configuration.base_url}{grant.download_path}",
                    allow_redirects=False,
                    timeout=(
                        self._configuration.http.connect_seconds,
                        self._configuration.http.read_seconds,
                    ),
                    stream=True,
                    headers={
                        "Accept": "message/rfc822",
                        "Accept-Encoding": "identity",
                        "Authorization": f"MailEdgeRaw {grant.opaque_token}",
                        "X-Mail-Edge-Operation": "raw_download",
                        "X-Mail-Edge-Signature-Audience": grant.audience,
                        "X-Mail-Edge-Subject-Id": grant.subject_id,
                    },
                )
            except requests.ConnectTimeout:
                self._breaker.failure()
                raise MailEdgeUnavailableError("MAIL_EDGE_CONNECT_TIMEOUT")
            except (requests.ConnectionError, requests.ReadTimeout):
                self._breaker.failure()
                raise MailEdgeUnavailableError("MAIL_EDGE_RAW_DOWNLOAD_UNAVAILABLE")
            if response.status_code != 200:
                if response.status_code == 429 or response.status_code >= 500:
                    self._breaker.failure()
                else:
                    self._breaker.success()
                raise self._problem(response)
            media_type = (
                response.headers.get("Content-Type", "").split(";", 1)[0].strip()
            )
            content_encoding = response.headers.get("Content-Encoding")
            accept_ranges = response.headers.get("Accept-Ranges")
            try:
                content_length = int(response.headers.get("Content-Length", ""))
            except (TypeError, ValueError):
                content_length = -1
            if (
                media_type != "message/rfc822"
                or content_encoding is not None
                or accept_ranges != "none"
                or content_length != grant.raw.size
                or content_length > self._configuration.maximum_raw_bytes
            ):
                raise MailEdgeContractError(
                    "MAIL_EDGE_RAW_DOWNLOAD_METADATA_INVALID", http_status=502
                )
            observed = 0
            digest = hashlib.sha256()
            try:
                for chunk in response.iter_content(64 * 1024):
                    if not chunk:
                        continue
                    if not isinstance(chunk, bytes):
                        raise MailEdgeContractError(
                            "MAIL_EDGE_RAW_DOWNLOAD_STREAM_INVALID", http_status=502
                        )
                    observed += len(chunk)
                    if observed > grant.raw.size:
                        raise MailEdgeContractError(
                            "MAIL_EDGE_RAW_DOWNLOAD_SIZE_INVALID", http_status=502
                        )
                    digest.update(chunk)
                    written = target.write(chunk)
                    if written is not None and written != len(chunk):
                        raise MailEdgeContractError("RAW_DOWNLOAD_TARGET_INVALID")
            except requests.RequestException:
                self._breaker.failure()
                raise MailEdgeUnavailableError("MAIL_EDGE_RAW_DOWNLOAD_UNAVAILABLE")
            if observed != grant.raw.size or not hmac.compare_digest(
                digest.hexdigest(), grant.raw.sha256
            ):
                raise MailEdgeContractError(
                    "MAIL_EDGE_RAW_DOWNLOAD_INTEGRITY_INVALID", http_status=502
                )
            self._breaker.success()
        except MailEdgeContractError:
            self._breaker.failure()
            raise
        except (OSError, ValueError):
            self._breaker.failure()
            raise MailEdgeContractError("RAW_DOWNLOAD_TARGET_INVALID") from None
        finally:
            try:
                if response is not None:
                    response.close()
            finally:
                self._admission.release()
                self._finish_operation()

    def issue_raw_access_grant(
        self,
        raw: RawMessageRef,
        *,
        purpose: str,
        single_use: bool,
        subject_id: str,
    ) -> RawAccessGrant:
        if purpose not in {"operator_review", "reconciliation"}:
            raise MailEdgeContractError("RAW_ACCESS_GRANT_PURPOSE_INVALID")
        if (
            not isinstance(subject_id, str)
            or not re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$", subject_id)
            or not isinstance(single_use, bool)
        ):
            raise MailEdgeContractError("RAW_ACCESS_GRANT_SUBJECT_INVALID")
        body = canonical_json(
            {
                "purpose": purpose,
                "raw": dict(raw.to_wire()),
                "singleUse": single_use,
                "subjectId": subject_id,
            }
        )
        response = self._request(
            "POST",
            f"/v1/tenants/{self.tenant_id}/raw-access-grants",
            retry_proven_safe=False,
            headers=self._headers("application/json"),
            data=body,
        )
        if response.status_code != 201:
            raise self._problem(response)
        grant = parse_raw_access_grant(
            self._response_json(response), self._configuration.maximum_raw_bytes
        )
        if (
            grant.tenant_id != self.tenant_id
            or grant.raw != raw
            or not hmac.compare_digest(
                grant.audience.encode("utf-8"),
                self._configuration.host_authentication.audience.encode("ascii"),
            )
            or grant.purpose != purpose
            or grant.single_use != single_use
            or not hmac.compare_digest(
                grant.subject_id.encode("utf-8"), subject_id.encode("ascii")
            )
        ):
            raise MailEdgeContractError(
                "MAIL_EDGE_RAW_GRANT_RESPONSE_MISMATCH", http_status=502
            )
        return grant

    def revoke_raw_access_grant(self, grant_id: str, expected_fence: int) -> None:
        validated = parse_uuid7(grant_id, "RAW_ACCESS_GRANT_ID_INVALID")
        _safe_integer(expected_fence)
        response = self._request(
            "POST",
            f"/v1/tenants/{self.tenant_id}/raw-access-grants/{validated}/revoke",
            retry_proven_safe=False,
            headers=self._headers("application/json"),
            data=canonical_json({"expectedFence": expected_fence}),
        )
        if response.status_code != 204:
            raise self._problem(response)
        self._close_response(response)

    def inspect_binding(
        self, binding_id: str, binding_version: int
    ) -> Mapping[str, Any]:
        validated = parse_uuid7(binding_id, "BINDING_ID_INVALID")
        _safe_integer(binding_version, 1)
        response = self._request(
            "GET",
            f"/v1/tenants/{self.tenant_id}/bindings/{validated}/versions/{binding_version}",
            retry_proven_safe=True,
            response_loss_certainty="not_sent",
            headers=self._headers(),
        )
        if response.status_code != 200:
            raise self._problem(response)
        view = _parse_binding_control_view(
            self._response_json(response), self.tenant_id
        )
        if (
            view["binding"].binding_id != validated
            or view["binding"].binding_version != binding_version
        ):
            raise MailEdgeContractError(
                "MAIL_EDGE_BINDING_RESPONSE_MISMATCH", http_status=502
            )
        return view

    def transition_binding(
        self,
        binding_id: str,
        binding_version: int,
        action: str,
        *,
        expected_version: int,
        reason_code: str,
    ) -> Mapping[str, Any]:
        validated = parse_uuid7(binding_id, "BINDING_ID_INVALID")
        _safe_integer(binding_version, 1)
        _safe_integer(expected_version)
        if action not in {"activate", "drain", "retire"}:
            raise MailEdgeContractError("BINDING_ACTION_INVALID")
        response = self._request(
            "POST",
            f"/v1/operator/tenants/{self.tenant_id}/bindings/{validated}/versions/{binding_version}/{action}",
            retry_proven_safe=False,
            headers=self._operator_headers(content_type="application/json"),
            data=canonical_json(
                {
                    "expectedVersion": expected_version,
                    "reasonCode": _validate_reason_code(reason_code),
                }
            ),
        )
        if response.status_code != 200:
            raise self._problem(response)
        view = _parse_binding_control_view(
            self._response_json(response), self.tenant_id
        )
        if (
            view["binding"].binding_id != validated
            or view["binding"].binding_version != binding_version
        ):
            raise MailEdgeContractError(
                "MAIL_EDGE_BINDING_RESPONSE_MISMATCH", http_status=502
            )
        return view

    def inspect_outbound_quarantine(self, intent_id: str) -> Mapping[str, Any]:
        validated = parse_uuid7(intent_id, "INTENT_ID_INVALID")
        response = self._request(
            "GET",
            f"/v1/tenants/{self.tenant_id}/outbound-intents/{validated}/quarantine",
            retry_proven_safe=True,
            response_loss_certainty="not_sent",
            headers=self._headers(),
        )
        if response.status_code != 200:
            raise self._problem(response)
        view = _parse_outbound_quarantine_view(
            self._response_json(response), self.tenant_id
        )
        if view["intentId"] != validated:
            raise MailEdgeContractError(
                "MAIL_EDGE_QUARANTINE_RESPONSE_MISMATCH", http_status=502
            )
        return view

    def decide_outbound_quarantine(
        self,
        intent_id: str,
        action: str,
        *,
        evidence: Mapping[str, object],
        expected_fence: int,
        expected_version: int,
        reason_code: str,
    ) -> Mapping[str, Any]:
        validated = parse_uuid7(intent_id, "INTENT_ID_INVALID")
        if action not in {
            "resolve_accepted",
            "resolve_not_sent",
            "authorize_retry",
        }:
            raise MailEdgeContractError("OUTBOUND_QUARANTINE_ACTION_INVALID")
        body = canonical_json(
            {
                "action": action,
                "evidence": dict(_validate_decision_evidence(evidence)),
                "expectedFence": _safe_integer(expected_fence),
                "expectedVersion": _safe_integer(expected_version),
                "reasonCode": _validate_reason_code(reason_code),
            }
        )
        response = self._request(
            "POST",
            f"/v1/operator/tenants/{self.tenant_id}/outbound-intents/{validated}/quarantine-decisions",
            retry_proven_safe=False,
            headers=self._operator_headers(
                privileged=action == "authorize_retry", content_type="application/json"
            ),
            data=body,
        )
        if response.status_code != 200:
            raise self._problem(response)
        view = _parse_outbound_quarantine_view(
            self._response_json(response), self.tenant_id
        )
        if view["intentId"] != validated:
            raise MailEdgeContractError(
                "MAIL_EDGE_QUARANTINE_RESPONSE_MISMATCH", http_status=502
            )
        return view

    def inspect_inbound_quarantine(self, receipt_id: str) -> Mapping[str, Any]:
        validated = parse_uuid7(receipt_id, "RECEIPT_ID_INVALID")
        response = self._request(
            "GET",
            f"/v1/tenants/{self.tenant_id}/inbound-receipts/{validated}/quarantine",
            retry_proven_safe=True,
            response_loss_certainty="not_sent",
            headers=self._headers(),
        )
        if response.status_code != 200:
            raise self._problem(response)
        view = _parse_inbound_quarantine_view(
            self._response_json(response), self.tenant_id
        )
        if view["receiptId"] != validated:
            raise MailEdgeContractError(
                "MAIL_EDGE_QUARANTINE_RESPONSE_MISMATCH", http_status=502
            )
        return view

    def decide_inbound_quarantine(
        self,
        receipt_id: str,
        action: str,
        *,
        evidence: Mapping[str, object],
        expected_fence: int,
        expected_version: int,
        reason_code: str,
    ) -> Mapping[str, Any]:
        validated = parse_uuid7(receipt_id, "RECEIPT_ID_INVALID")
        if action not in {"release", "terminal"}:
            raise MailEdgeContractError("INBOUND_QUARANTINE_ACTION_INVALID")
        body = canonical_json(
            {
                "action": action,
                "evidence": dict(_validate_decision_evidence(evidence)),
                "expectedFence": _safe_integer(expected_fence),
                "expectedVersion": _safe_integer(expected_version),
                "reasonCode": _validate_reason_code(reason_code),
            }
        )
        response = self._request(
            "POST",
            f"/v1/operator/tenants/{self.tenant_id}/inbound-receipts/{validated}/quarantine-decisions",
            retry_proven_safe=False,
            headers=self._operator_headers(content_type="application/json"),
            data=body,
        )
        if response.status_code != 200:
            raise self._problem(response)
        view = _parse_inbound_quarantine_view(
            self._response_json(response), self.tenant_id
        )
        if view["receiptId"] != validated:
            raise MailEdgeContractError(
                "MAIL_EDGE_QUARANTINE_RESPONSE_MISMATCH", http_status=502
            )
        return view

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
            self._close_response(response)

    def close(self, timeout_seconds: Optional[float] = None) -> bool:
        selected_timeout = (
            self._configuration.http.shutdown_seconds
            if timeout_seconds is None
            else timeout_seconds
        )
        if (
            isinstance(selected_timeout, bool)
            or not isinstance(selected_timeout, (int, float))
            or not math.isfinite(selected_timeout)
            or selected_timeout < 0
        ):
            raise ValueError("Mail Edge client shutdown timeout is invalid.")
        deadline = time.monotonic() + float(selected_timeout)
        with self._lifecycle:
            if self._closed:
                return self._close_succeeded
            self._accepting_operations = False
            while self._active_operations > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._lifecycle.wait(remaining)
            if self._session_close_started:
                while not self._closed:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False
                    self._lifecycle.wait(remaining)
                return self._close_succeeded
            self._session_close_started = True
        closed_cleanly = True
        if self._owns_session:
            try:
                self._session.close()
            except Exception:
                closed_cleanly = False
        with self._lifecycle:
            self._closed = True
            self._close_succeeded = closed_cleanly
            self._lifecycle.notify_all()
        return closed_cleanly

    def __enter__(self) -> MailEdgeClient:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
