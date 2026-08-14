from __future__ import annotations

import math
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Optional


SAFE_DETAIL_KEY_RE = re.compile(r"^[a-z][A-Za-z0-9]{0,63}$")
DELIVERY_CERTAINTIES = frozenset({"not_sent", "accepted", "unknown"})


def normalize_safe_details(
    value: Optional[Mapping[str, object]], *, strict: bool = False
) -> Optional[Mapping[str, object]]:
    if value is None:
        return None
    if not isinstance(value, Mapping) or len(value) > 16:
        if strict:
            raise ValueError("Safe problem details are invalid.")
        return None
    normalized: dict[str, object] = {}
    for key, item in value.items():
        valid_number = (
            isinstance(item, int)
            and not isinstance(item, bool)
            and abs(item) <= 9_007_199_254_740_991
        ) or (
            isinstance(item, float)
            and math.isfinite(item)
            and abs(item) <= 9_007_199_254_740_991
        )
        valid = (
            isinstance(key, str)
            and SAFE_DETAIL_KEY_RE.fullmatch(key) is not None
            and (isinstance(item, (str, bool)) or valid_number)
            and (not isinstance(item, str) or len(item) <= 256)
        )
        if not valid:
            if strict:
                raise ValueError("Safe problem details are invalid.")
            continue
        normalized[key] = item
    if not normalized:
        return None
    return MappingProxyType(dict(sorted(normalized.items())))


@dataclass(frozen=True)
class MailEdgeError(Exception):
    code: str
    retryable: bool
    delivery_certainty: str = "not_sent"
    safe_details: Optional[Mapping[str, object]] = None
    http_status: int = 503

    def __post_init__(self) -> None:
        certainty = self.delivery_certainty
        if certainty not in DELIVERY_CERTAINTIES:
            raise ValueError("Mail Edge delivery certainty is invalid.")
        if certainty == "unknown" and self.retryable:
            raise ValueError(
                "Unknown Mail Edge outcomes cannot be automatically retried."
            )
        object.__setattr__(
            self, "safe_details", normalize_safe_details(self.safe_details)
        )

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
        super().__init__(
            code=code,
            retryable=True,
            safe_details={"retryAfterSeconds": 1},
            http_status=429,
        )


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
