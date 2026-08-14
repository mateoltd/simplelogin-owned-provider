from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional


@dataclass(frozen=True)
class MailEdgeError(Exception):
    code: str
    retryable: bool
    delivery_certainty: str = "not_sent"
    safe_details: Optional[Mapping[str, object]] = None
    http_status: int = 503

    def __str__(self) -> str:
        return self.code


class MailEdgeConfigurationError(MailEdgeError):
    def __init__(self, code: str):
        super().__init__(code=code, retryable=False, http_status=500)


class MailEdgeContractError(MailEdgeError):
    def __init__(self, code: str, *, http_status: int = 400):
        super().__init__(code=code, retryable=False, http_status=http_status)


class MailEdgeAuthenticationError(MailEdgeError):
    def __init__(self, code: str):
        super().__init__(code=code, retryable=False, http_status=401)


class MailEdgeAuthorizationError(MailEdgeError):
    def __init__(self, code: str):
        super().__init__(code=code, retryable=False, http_status=404)


class MailEdgeBackpressureError(MailEdgeError):
    def __init__(self, code: str = "HOST_BACKPRESSURE"):
        super().__init__(code=code, retryable=True, http_status=429)


class MailEdgeUnavailableError(MailEdgeError, TimeoutError):
    def __init__(
        self,
        code: str = "MAIL_EDGE_UNAVAILABLE",
        *,
        delivery_certainty: str = "not_sent",
    ):
        super().__init__(
            code=code,
            retryable=delivery_certainty != "unknown",
            delivery_certainty=delivery_certainty,
            http_status=503,
        )


class MailEdgeAmbiguousDeliveryError(MailEdgeError):
    def __init__(self, code: str = "AMBIGUOUS_HOST_DELIVERY"):
        super().__init__(
            code=code,
            retryable=False,
            delivery_certainty="unknown",
            http_status=409,
        )
