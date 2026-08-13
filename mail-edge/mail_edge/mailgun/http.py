"""Shared authenticated Mailgun HTTP operations."""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable
from email.utils import parsedate_to_datetime

from ..config import KeyRing, RetryPolicy, TimeoutPolicy
from ..errors import (
    ProviderAuthenticationError,
    ProviderProtocolError,
    TransportFailure,
)
from ..transport import HTTPRequest, HTTPResponse, HTTPTransport
from ..validation import bounded_text


def basic_auth(secret: str) -> str:
    encoded = base64.b64encode(f"api:{secret}".encode()).decode("ascii")
    return f"Basic {encoded}"


def json_object(response: HTTPResponse) -> dict[str, object]:
    try:
        value = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderProtocolError("provider returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise ProviderProtocolError("provider returned a non-object JSON response")
    return value


def response_diagnostic(response: HTTPResponse) -> str:
    try:
        value = json.loads(response.body)
        if isinstance(value, dict):
            for key in ("message", "reason", "error"):
                if key in value:
                    return (
                        bounded_text(value[key]) or f"provider HTTP {response.status}"
                    )
    except (UnicodeDecodeError, json.JSONDecodeError):
        value = None
    return f"provider HTTP {response.status}"


def retry_after_seconds(
    response: HTTPResponse, *, now: float | None = None
) -> int | None:
    value = response.headers.get("retry-after")
    if not value:
        reset = response.headers.get("x-ratelimit-reset")
        if reset and reset.isdigit():
            # Mailgun documents reset in Unix milliseconds.
            return max(0, min(3600, int(int(reset) / 1000 - (now or time.time()))))
        return None
    try:
        return max(0, min(3600, int(value)))
    except ValueError:
        try:
            target = parsedate_to_datetime(value).timestamp()
        except (TypeError, ValueError, OverflowError):
            return None
        return max(0, min(3600, int(target - (now or time.time()))))


def idempotent_request(
    transport: HTTPTransport,
    *,
    method: str,
    url: str,
    keys: KeyRing,
    timeout: TimeoutPolicy,
    retry: RetryPolicy,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> HTTPResponse:
    """Issue a read-only request with credential rotation and bounded retries."""
    last_response: HTTPResponse | None = None
    for key in keys.keys:
        attempt = 0
        while attempt < retry.max_attempts:
            attempt += 1
            request_headers = dict(headers or {})
            request_headers["Authorization"] = basic_auth(key.secret)
            request_headers["User-Agent"] = "provider-neutral-mail-edge/1"
            try:
                response = transport.send(
                    HTTPRequest(
                        method=method,
                        url=url,
                        headers=request_headers,
                        body=body,
                        connect_timeout=timeout.connect_seconds,
                        read_timeout=timeout.read_seconds,
                        max_response_bytes=timeout.max_response_bytes,
                    )
                )
            except TransportFailure:
                if attempt >= retry.max_attempts:
                    raise
                sleeper(
                    min(
                        retry.max_delay_seconds,
                        retry.base_delay_seconds * (2 ** (attempt - 1)),
                    )
                )
                continue
            last_response = response
            if response.status in {401, 403}:
                break
            if response.status in {408, 425, 429, 500, 502, 503, 504}:
                if attempt >= retry.max_attempts:
                    return response
                delay = retry_after_seconds(response)
                if delay is None:
                    delay = min(
                        retry.max_delay_seconds,
                        retry.base_delay_seconds * (2 ** (attempt - 1)),
                    )
                sleeper(delay)
                continue
            return response
    if last_response is not None and last_response.status in {401, 403}:
        raise ProviderAuthenticationError(
            "all configured Mailgun API keys were rejected"
        )
    if last_response is not None:
        return last_response
    raise ProviderProtocolError("no Mailgun API request was attempted")
