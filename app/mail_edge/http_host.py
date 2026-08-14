from __future__ import annotations

import hmac
import logging
import time
from datetime import datetime, timezone
from typing import Callable, Mapping

from flask import Blueprint, Response, g, request

from app.db import Session
from app.log import LOG, RequestIdFilter

from .composition import MailEdgeBridge
from .contracts import (
    ApplicationDeliveryCallback,
    RawAccessGrant,
    canonical_json,
    parse_application_delivery_callback,
    parse_application_feedback,
    parse_recipient_route_request,
    parse_reverse_route_request,
    strict_json_loads,
)
from .errors import (
    MailEdgeContractError,
    MailEdgeError,
)
from .host_services import ApplicationDeliveryService
from .problem import problem_status, project_problem
from .resources import ResourceLease


MAXIMUM_RAW_GRANT_LIFETIME_SECONDS = 5 * 60


class _HostRedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.message_id = ""
        return True


HOST_LOG = logging.getLogger(f"{LOG.name}.mail_edge_host")
HOST_LOG.setLevel(LOG.level)
HOST_LOG.addFilter(RequestIdFilter())
HOST_LOG.addFilter(_HostRedactionFilter())


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _response(body: Mapping[str, object], subject_id: str) -> Response:
    response = Response(canonical_json(dict(body)), mimetype="application/json")
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Mail-Edge-Subject-Id"] = subject_id
    return response


def _read_json_body(maximum_bytes: int) -> tuple[bytes, object]:
    if request.headers.get("Content-Encoding") is not None:
        raise MailEdgeContractError("HOST_CONTENT_ENCODING_INVALID")
    if request.mimetype != "application/json":
        raise MailEdgeContractError("HOST_CONTENT_TYPE_INVALID")
    content_length = request.content_length
    if content_length is not None and content_length > maximum_bytes:
        raise MailEdgeContractError("JSON_BODY_TOO_LARGE", http_status=413)
    raw = request.stream.read(maximum_bytes + 1)
    if not isinstance(raw, bytes) or len(raw) > maximum_bytes:
        raise MailEdgeContractError("JSON_BODY_TOO_LARGE", http_status=413)
    return raw, strict_json_loads(raw, maximum_bytes)


def _validate_delivery_grant(
    callback: ApplicationDeliveryCallback,
    *,
    expected_audience: str,
    now: datetime,
) -> RawAccessGrant:
    grant = callback.raw_access_grant
    if not hmac.compare_digest(
        grant.audience.encode("utf-8"), expected_audience.encode("ascii")
    ):
        raise MailEdgeError(
            code="AUTHORIZATION_FAILED", retryable=False, http_status=403
        )
    issued_at = datetime.fromisoformat(grant.issued_at.replace("Z", "+00:00"))
    expires_at = datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00"))
    current = now.astimezone(timezone.utc)
    if (
        expires_at <= issued_at
        or (expires_at - issued_at).total_seconds() > MAXIMUM_RAW_GRANT_LIFETIME_SECONDS
        or current < issued_at.astimezone(timezone.utc)
        or current >= expires_at.astimezone(timezone.utc)
    ):
        raise MailEdgeError(
            code="AUTHORIZATION_FAILED", retryable=False, http_status=403
        )
    return grant


def create_mail_edge_host_blueprint(
    bridge: MailEdgeBridge,
    delivery_service: ApplicationDeliveryService,
    *,
    clock: Callable[[], datetime] = _utc_now,
) -> Blueprint:
    blueprint = Blueprint("mail_edge_host", __name__)
    request_limit = bridge.configuration.host_authentication.maximum_request_bytes
    admission = bridge.host_admission

    def authenticated_body(operation: str, subject_id: str, raw: bytes) -> None:
        bridge.authenticated_host_operations.verify_headers(
            request.headers,
            operation=operation,
            subject_id=subject_id,
            body=raw,
            now=clock(),
        )

    @blueprint.before_request
    def begin_observation() -> None:
        g.mail_edge_host_started = time.monotonic()
        g.mail_edge_host_admission = admission.acquire_callback()

    @blueprint.after_request
    def observe(response: Response) -> Response:
        lease = getattr(g, "mail_edge_host_admission", None)
        if isinstance(lease, ResourceLease):
            lease.release()
            g.mail_edge_host_admission = None
        started = getattr(g, "mail_edge_host_started", None)
        duration_ms = (
            max(0, int((time.monotonic() - started) * 1000))
            if isinstance(started, float)
            else 0
        )
        HOST_LOG.i(
            "mail_edge_host_callback operation=%s status=%s duration_ms=%s",
            request.endpoint or "unknown",
            response.status_code,
            duration_ms,
        )
        return response

    @blueprint.teardown_request
    def release_callback_admission(_error: object) -> None:
        """Release admission if normal after-request processing was interrupted."""

        lease = getattr(g, "mail_edge_host_admission", None)
        if isinstance(lease, ResourceLease):
            lease.release()
            g.mail_edge_host_admission = None

    @blueprint.errorhandler(MailEdgeError)
    def handle_mail_edge_error(error: MailEdgeError):
        Session.rollback()
        problem = project_problem(
            error,
            instance=request.path,
            trace_id=getattr(g, "request_id", None),
            occurred_at=clock(),
        )
        return Response(
            canonical_json(dict(problem)),
            status=problem_status(error),
            mimetype="application/problem+json",
            headers={"Cache-Control": "no-store"},
        )

    @blueprint.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        Session.rollback()
        HOST_LOG.e(
            "mail_edge_host_callback operation=%s error=internal exception_type=%s",
            request.endpoint or "unknown",
            type(error).__name__,
        )
        business_effect_possible = request.endpoint in {
            "mail_edge_host.delivery",
            "mail_edge_host.feedback",
        }
        internal = MailEdgeError(
            code="INTERNAL",
            retryable=False,
            delivery_certainty=("unknown" if business_effect_possible else "not_sent"),
            http_status=500,
        )
        problem = project_problem(
            internal,
            instance=request.path,
            trace_id=getattr(g, "request_id", None),
            occurred_at=clock(),
        )
        return Response(
            canonical_json(dict(problem)),
            status=500,
            mimetype="application/problem+json",
            headers={"Cache-Control": "no-store"},
        )

    @blueprint.route("/mail-edge/recipients", methods=["POST"])
    def recipients() -> Response:
        raw, value = _read_json_body(request_limit)
        callback = parse_recipient_route_request(value)
        authenticated_body("recipient_route", callback.receipt_id, raw)
        destinations = bridge.recipient_router.resolve_recipients(
            callback.tenant_id, callback.envelope, callback.receipt_id
        )
        return _response(
            {"destinations": [dict(destination) for destination in destinations]},
            callback.receipt_id,
        )

    @blueprint.route("/mail-edge/reverse-route", methods=["POST"])
    def reverse_route() -> Response:
        raw, value = _read_json_body(request_limit)
        callback = parse_reverse_route_request(
            value, bridge.configuration.maximum_raw_bytes
        )
        authenticated_body("reverse_route", callback.raw.blob_id, raw)
        resolution = bridge.reverse_route_resolver.resolve_reverse_route(
            callback.tenant_id,
            callback.envelope,
            callback.raw,
            callback.opaque_reply_token,
        )
        return _response(dict(resolution.to_wire()), callback.raw.blob_id)

    @blueprint.route("/mail-edge/delivery", methods=["POST"])
    def delivery() -> Response:
        raw, value = _read_json_body(request_limit)
        callback = parse_application_delivery_callback(
            value, bridge.configuration.maximum_raw_bytes
        )
        subject_id = callback.delivery.delivery_id
        authenticated_body("application_delivery", subject_id, raw)
        grant = _validate_delivery_grant(
            callback,
            expected_audience=bridge.configuration.host_authentication.audience,
            now=clock(),
        )
        with admission.acquire_delivery(callback.delivery.raw.size):
            claim = delivery_service.claim(callback.delivery, raw)
            if claim.completed_acknowledgement is not None:
                return _response(claim.completed_acknowledgement, subject_id)
            with admission.open_raw_message() as raw_message:
                bridge.client.download_raw_to(grant, raw_message)
                acknowledgement = delivery_service.deliver_claimed(
                    callback.delivery, raw_message, claim
                )
        return _response(acknowledgement, subject_id)

    @blueprint.route("/mail-edge/feedback", methods=["POST"])
    def feedback() -> Response:
        raw, value = _read_json_body(request_limit)
        callback = parse_application_feedback(value)
        authenticated_body("application_feedback", callback.feedback_event_id, raw)
        acknowledgement = bridge.feedback_service.deliver(callback, raw)
        return _response(acknowledgement, callback.feedback_event_id)

    return blueprint
