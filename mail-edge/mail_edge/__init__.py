"""Provider-neutral mail-edge contracts and Mailgun adapters."""

from .contracts import (
    DomainCapabilities,
    FeedbackEvent,
    FeedbackEventType,
    InboundMessage,
    OutboundMessage,
    ProviderRegion,
    SubmissionDisposition,
    SubmissionResult,
)

__all__ = [
    "DomainCapabilities",
    "FeedbackEvent",
    "FeedbackEventType",
    "InboundMessage",
    "OutboundMessage",
    "ProviderRegion",
    "SubmissionDisposition",
    "SubmissionResult",
]
