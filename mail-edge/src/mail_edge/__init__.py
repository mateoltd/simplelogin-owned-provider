"""Durable, provider-neutral mail edge."""

from .contracts import (
    BindingDirection,
    BindingState,
    Feedback,
    FeedbackKind,
    InboundNotice,
    InboundRawMessage,
    OutboundResult,
    OutboundSubmission,
    SubmissionOutcome,
)

__all__ = [
    "BindingDirection",
    "BindingState",
    "Feedback",
    "FeedbackKind",
    "InboundNotice",
    "InboundRawMessage",
    "OutboundResult",
    "OutboundSubmission",
    "SubmissionOutcome",
]

__version__ = "0.1.0"
