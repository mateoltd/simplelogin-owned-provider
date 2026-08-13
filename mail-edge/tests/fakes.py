"""Provider fakes live only at the test boundary."""

from __future__ import annotations

from collections import deque

from mail_edge.transport import HTTPRequest, HTTPResponse


class FakeTransport:
    def __init__(self, *outcomes: HTTPResponse | Exception) -> None:
        self.outcomes = deque(outcomes)
        self.requests: list[HTTPRequest] = []

    def send(self, request: HTTPRequest) -> HTTPResponse:
        self.requests.append(request)
        if not self.outcomes:
            raise AssertionError(f"unexpected request: {request.method} {request.url}")
        outcome = self.outcomes.popleft()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def response(
    status: int,
    body: bytes = b"{}",
    headers: dict[str, str] | None = None,
) -> HTTPResponse:
    return HTTPResponse(status=status, body=body, headers=headers or {})
