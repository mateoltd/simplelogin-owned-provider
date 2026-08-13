"""Provider-neutral HTTPS handoff to the product-owned mail processor."""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

from .errors import ConfigurationError
from .repository import ClaimedIngress


@dataclass(frozen=True, slots=True)
class HandoffResult:
    success: bool
    retryable: bool
    diagnostic_code: str


class HTTPSHandoffSink:
    def __init__(
        self,
        endpoint: str,
        bearer_token: str,
        *,
        timeout_seconds: float = 30,
        tls_context: ssl.SSLContext | None = None,
        allow_insecure_for_tests: bool = False,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" and not allow_insecure_for_tests:
            raise ConfigurationError("handoff endpoint must use HTTPS")
        if not bearer_token:
            raise ConfigurationError("handoff bearer token is required")
        self.endpoint = endpoint.rstrip("/")
        self.bearer_token = bearer_token
        self.timeout_seconds = timeout_seconds
        self.tls_context = tls_context or ssl.create_default_context()

    def deliver(self, message: ClaimedIngress) -> HandoffResult:
        envelope = base64.urlsafe_b64encode(
            json.dumps(
                message.envelope.as_dict(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).decode()
        request = urllib.request.Request(
            f"{self.endpoint}/{message.id}",
            data=message.raw_mime,
            method="PUT",
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "Content-Type": "message/rfc822",
                "Content-Length": str(len(message.raw_mime)),
                "Mail-Edge-Message-ID": message.id,
                "Mail-Edge-Notice-ID": message.notice_id,
                "Mail-Edge-Domain": message.domain,
                "Mail-Edge-Binding-Generation": str(message.binding_generation),
                "Mail-Edge-Raw-SHA256": message.raw_sha256,
                "Mail-Edge-Envelope": envelope,
                "Idempotency-Key": message.id,
            },
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout_seconds, context=self.tls_context
            ) as response:
                code = response.status
        except urllib.error.HTTPError as exc:
            code = exc.code
        except (urllib.error.URLError, TimeoutError, OSError):
            return HandoffResult(False, True, "handoff_transport_failure")
        if 200 <= code < 300 or code == 409:
            return HandoffResult(True, False, "handoff_committed")
        if code == 429 or code >= 500:
            return HandoffResult(False, True, f"handoff_http_{code}")
        return HandoffResult(False, False, f"handoff_http_{code}")
