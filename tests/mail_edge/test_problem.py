from datetime import datetime, timezone

import pytest

from app.mail_edge.errors import (
    MailEdgeAmbiguousDeliveryError,
    MailEdgeBackpressureError,
    MailEdgeError,
)
from app.mail_edge.problem import problem_status, project_problem


def test_problem_projection_preserves_certainty_and_allowlisted_safe_details():
    occurred_at = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
    backpressure = MailEdgeBackpressureError()
    problem = project_problem(backpressure, occurred_at=occurred_at)
    assert problem_status(backpressure) == 429
    assert problem["code"] == "rate-limited"
    assert problem["deliveryCertainty"] == "not_sent"
    assert problem["retryable"] is True
    assert problem["safeDetails"] == {"retryAfterSeconds": 1}

    ambiguous = MailEdgeAmbiguousDeliveryError()
    problem = project_problem(ambiguous, occurred_at=occurred_at)
    assert problem_status(ambiguous) == 409
    assert problem["code"] == "workflow-conflict"
    assert problem["deliveryCertainty"] == "unknown"
    assert problem["retryable"] is False


def test_problem_projection_drops_unapproved_details_and_unknown_cannot_retry():
    error = MailEdgeError(
        code="VALIDATION_FAILED",
        retryable=False,
        safe_details={"field": "envelope", "emailAddress": "private@example.net"},
        http_status=400,
    )
    problem = project_problem(error)
    assert problem["safeDetails"] == {"field": "envelope"}
    assert "private@example.net" not in str(problem)

    with pytest.raises(ValueError):
        MailEdgeError(
            code="INTERNAL",
            retryable=True,
            delivery_certainty="unknown",
        )
