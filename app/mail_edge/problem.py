from __future__ import annotations

from datetime import datetime, timezone
from typing import Mapping, Optional

from .errors import (
    MailEdgeAmbiguousDeliveryError,
    MailEdgeAuthenticationError,
    MailEdgeAuthorizationError,
    MailEdgeBackpressureError,
    MailEdgeContractError,
    MailEdgeError,
    MailEdgeUnavailableError,
)


PROBLEM_POLICIES: Mapping[str, tuple[str, str, int, str]] = {
    "VALIDATION_FAILED": (
        "validation-failed",
        "Validation failed",
        400,
        "The request is not valid.",
    ),
    "AUTHENTICATION_FAILED": (
        "authentication-failed",
        "Authentication failed",
        401,
        "Authentication failed.",
    ),
    "AUTHORIZATION_FAILED": (
        "authorization-failed",
        "Authorization failed",
        403,
        "The operation is not permitted.",
    ),
    "NOT_FOUND": (
        "not-found",
        "Not found",
        404,
        "The requested resource was not found.",
    ),
    "CONFLICT": (
        "conflict",
        "Conflict",
        409,
        "The request conflicts with current state.",
    ),
    "IDEMPOTENCY_CONFLICT": (
        "idempotency-conflict",
        "Idempotency conflict",
        409,
        "The idempotency key was already used for a different request.",
    ),
    "BINDING_UNAVAILABLE": (
        "binding-unavailable",
        "Binding unavailable",
        409,
        "No eligible exact-domain binding is available.",
    ),
    "CAPABILITY_UNSUPPORTED": (
        "capability-unsupported",
        "Capability unsupported",
        422,
        "The selected route cannot satisfy the requested capabilities.",
    ),
    "RATE_LIMITED": (
        "rate-limited",
        "Rate limited",
        429,
        "The operation is temporarily rate limited.",
    ),
    "INGRESS_LIMIT_EXCEEDED": (
        "ingress-limit-exceeded",
        "Ingress limit exceeded",
        413,
        "The ingress payload exceeds its configured limit.",
    ),
    "INGRESS_FAILED": (
        "ingress-failed",
        "Ingress failed",
        400,
        "The ingress request could not be committed.",
    ),
    "STORAGE_UNAVAILABLE": (
        "storage-unavailable",
        "Storage unavailable",
        503,
        "Durable storage is temporarily unavailable.",
    ),
    "WORKFLOW_CONFLICT": (
        "workflow-conflict",
        "Workflow conflict",
        409,
        "The workflow changed before this operation could commit.",
    ),
    "STALE_FENCE": (
        "stale-fence",
        "Stale fence",
        409,
        "The workflow fence is stale.",
    ),
    "ILLEGAL_TRANSITION": (
        "illegal-transition",
        "Illegal transition",
        409,
        "The requested state transition is not legal.",
    ),
    "PROVIDER_NOT_SENT": (
        "provider-not-sent",
        "Provider did not send",
        502,
        "The provider conclusively did not accept the message.",
    ),
    "PROVIDER_UNKNOWN": (
        "provider-outcome-unknown",
        "Provider outcome unknown",
        502,
        "The provider outcome is unknown and requires reconciliation.",
    ),
    "PROVIDER_REJECTED": (
        "provider-rejected",
        "Provider rejected",
        502,
        "The provider rejected the operation.",
    ),
    "HOST_UNAVAILABLE": (
        "host-unavailable",
        "Host unavailable",
        503,
        "The host integration is temporarily unavailable.",
    ),
    "INTERNAL": (
        "internal",
        "Internal error",
        500,
        "An internal error occurred.",
    ),
}


def _problem_code(error: MailEdgeError) -> str:
    if error.code in PROBLEM_POLICIES:
        return error.code
    if isinstance(error, MailEdgeAuthenticationError):
        return "AUTHENTICATION_FAILED"
    if isinstance(error, MailEdgeAuthorizationError):
        return "NOT_FOUND"
    if isinstance(error, MailEdgeBackpressureError):
        return "RATE_LIMITED"
    if isinstance(error, MailEdgeUnavailableError):
        return "HOST_UNAVAILABLE"
    if isinstance(error, MailEdgeAmbiguousDeliveryError):
        return "WORKFLOW_CONFLICT"
    if isinstance(error, MailEdgeContractError):
        if error.http_status == 413:
            return "INGRESS_LIMIT_EXCEEDED"
        if error.http_status == 404:
            return "NOT_FOUND"
        if error.http_status == 409:
            return "CONFLICT"
        if error.http_status == 422:
            return "CAPABILITY_UNSUPPORTED"
        if error.http_status >= 500:
            return "HOST_UNAVAILABLE"
        return "VALIDATION_FAILED"
    return "INTERNAL"


def project_problem(
    error: MailEdgeError,
    *,
    instance: Optional[str] = None,
    trace_id: Optional[str] = None,
    occurred_at: Optional[datetime] = None,
) -> Mapping[str, object]:
    internal_code = _problem_code(error)
    code, title, status, detail = PROBLEM_POLICIES[internal_code]
    certainty = (
        error.delivery_certainty
        if error.delivery_certainty in {"not_sent", "accepted", "unknown"}
        else "not_sent"
    )
    retryable = bool(error.retryable and certainty != "unknown")
    problem: dict[str, object] = {
        "schemaVersion": "v1",
        "type": f"https://mail-edge.dev/problems/{code}",
        "title": title,
        "status": status,
        "detail": detail,
        "code": code,
        "retryable": retryable,
        "deliveryCertainty": certainty,
    }
    if instance:
        problem["instance"] = instance[:256]
    if trace_id:
        problem["traceId"] = trace_id[:64]
    observed_at = occurred_at or datetime.now(timezone.utc)
    problem["occurredAt"] = (
        observed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    return problem


def problem_status(error: MailEdgeError) -> int:
    return PROBLEM_POLICIES[_problem_code(error)][2]
