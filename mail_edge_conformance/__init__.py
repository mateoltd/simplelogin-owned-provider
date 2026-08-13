"""Provider-neutral mail-edge conformance contracts and qualification tools."""

from .contracts import (
    AdapterResult,
    DeliveryRequest,
    EventType,
    FeedbackEvent,
    SubmissionDisposition,
)
from .mime import (
    DEFAULT_TRANSPORT_HEADERS,
    SemanticComparison,
    TransportHeaderPolicy,
    compare_messages,
)

__all__ = [
    "AdapterResult",
    "DEFAULT_TRANSPORT_HEADERS",
    "DeliveryRequest",
    "EventType",
    "FeedbackEvent",
    "SemanticComparison",
    "SubmissionDisposition",
    "TransportHeaderPolicy",
    "compare_messages",
]
