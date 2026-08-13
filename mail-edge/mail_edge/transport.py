"""TLS-verifying HTTP transport with bounded response reads."""

from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from .errors import TransportFailure


@dataclass(frozen=True, slots=True)
class HTTPRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None
    connect_timeout: float
    read_timeout: float
    max_response_bytes: int


@dataclass(frozen=True, slots=True)
class HTTPResponse:
    status: int
    headers: dict[str, str]
    body: bytes


class HTTPTransport(Protocol):
    def send(self, request: HTTPRequest) -> HTTPResponse: ...


class StdlibHTTPTransport:
    """HTTPS-only transport; failures after connect are conservatively ambiguous."""

    def __init__(self, context: ssl.SSLContext | None = None) -> None:
        self._context = context or ssl.create_default_context()

    def send(self, request: HTTPRequest) -> HTTPResponse:
        target = urlsplit(request.url)
        if (
            target.scheme != "https"
            or not target.hostname
            or target.username
            or target.password
        ):
            raise TransportFailure("refused non-HTTPS provider URL", request_sent=False)
        port = target.port or 443
        path = target.path or "/"
        if target.query:
            path = f"{path}?{target.query}"

        connection = http.client.HTTPSConnection(
            target.hostname,
            port,
            timeout=request.connect_timeout,
            context=self._context,
        )
        try:
            connection.connect()
        except (OSError, socket.timeout, ssl.SSLError) as exc:
            connection.close()
            raise TransportFailure(
                "provider connection failed", request_sent=False
            ) from exc

        try:
            if connection.sock is not None:
                connection.sock.settimeout(request.read_timeout)
            connection.request(
                request.method, path, body=request.body, headers=request.headers
            )
            response = connection.getresponse()
            declared_length = response.getheader("Content-Length")
            if (
                declared_length is not None
                and int(declared_length) > request.max_response_bytes
            ):
                raise TransportFailure(
                    "provider response exceeded the safe limit", request_sent=True
                )
            body = response.read(request.max_response_bytes + 1)
            if len(body) > request.max_response_bytes:
                raise TransportFailure(
                    "provider response exceeded the safe limit", request_sent=True
                )
            headers = {name.lower(): value for name, value in response.getheaders()}
            return HTTPResponse(status=response.status, headers=headers, body=body)
        except TransportFailure:
            raise
        except (
            OSError,
            socket.timeout,
            ssl.SSLError,
            http.client.HTTPException,
            ValueError,
        ) as exc:
            raise TransportFailure(
                "provider response was not completed", request_sent=True
            ) from exc
        finally:
            connection.close()
