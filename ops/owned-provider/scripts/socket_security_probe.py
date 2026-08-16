"""Exercise parser and size boundaries through the published host sockets."""

from __future__ import annotations

import argparse
import json
import socket
from dataclasses import dataclass

MAX_RESPONSE_BYTES = 1_048_576


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int


class SocketClient:
    """Own one bounded TCP connection and its response buffering."""

    def __init__(self, endpoint: Endpoint, timeout: float = 5.0) -> None:
        self._endpoint = endpoint
        self._timeout = timeout

    def exchange(self, payload: bytes) -> bytes:
        response = bytearray()
        with socket.create_connection(
            (self._endpoint.host, self._endpoint.port), timeout=self._timeout
        ) as client:
            client.settimeout(self._timeout)
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            while len(response) <= MAX_RESPONSE_BYTES:
                try:
                    chunk = client.recv(65_536)
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                response.extend(chunk)
        if len(response) > MAX_RESPONSE_BYTES:
            raise RuntimeError("socket response exceeded the audit bound")
        return bytes(response)


class SmtpClient:
    """Own an SMTP conversation and parse bounded multiline replies."""

    def __init__(self, endpoint: Endpoint, timeout: float = 5.0) -> None:
        self._socket = socket.create_connection(
            (endpoint.host, endpoint.port), timeout=timeout
        )
        self._socket.settimeout(timeout)

    def __enter__(self) -> "SmtpClient":
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self._socket.close()

    def reply(self) -> bytes:
        response = bytearray()
        while len(response) <= MAX_RESPONSE_BYTES:
            line = bytearray()
            while not line.endswith(b"\n"):
                chunk = self._socket.recv(1)
                if not chunk:
                    raise RuntimeError("SMTP socket closed before a complete reply")
                line.extend(chunk)
            response.extend(line)
            if len(line) >= 4 and line[3:4] == b" ":
                return bytes(response)
        raise RuntimeError("SMTP reply exceeded the audit bound")

    def command(self, command: bytes) -> bytes:
        self._socket.sendall(command + b"\r\n")
        return self.reply()


def http_request(path: str, headers: bytes = b"", body: bytes = b"") -> bytes:
    return (
        f"POST {path} HTTP/1.1\r\nHost: localhost\r\n".encode()
        + headers
        + b"Connection: close\r\n\r\n"
        + body
    )


def multipart_bomb(parts: int = 1001) -> tuple[bytes, bytes]:
    boundary = b"owned-provider-host-gate"
    body = bytearray()
    for index in range(parts):
        body.extend(b"--" + boundary + b"\r\n")
        body.extend(
            f'Content-Disposition: form-data; name="part-{index}"\r\n\r\nx\r\n'.encode()
        )
    body.extend(b"--" + boundary + b"--\r\n")
    headers = (
        b"Content-Type: multipart/form-data; boundary="
        + boundary
        + b"\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n"
    )
    return headers, bytes(body)


def require_rejected(
    response: bytes, *, expected: tuple[bytes, ...], name: str
) -> None:
    if not response.startswith(expected):
        raise RuntimeError(f"{name} was not rejected: {response[:160]!r}")
    if response.count(b"HTTP/1.1") != 1:
        raise RuntimeError(f"{name} produced more than one HTTP response")


def probe_http(endpoint: Endpoint) -> dict[str, str]:
    client = SocketClient(endpoint)
    duplicate_length = client.exchange(
        http_request(
            "/health",
            b"Content-Length: 4\r\nContent-Length: 52\r\n",
            b"testGET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
    )
    require_rejected(
        duplicate_length, expected=(b"HTTP/1.1 400",), name="duplicate length"
    )

    ambiguous_framing = client.exchange(
        http_request(
            "/health",
            b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",
            b"0\r\n\r\nGET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
    )
    require_rejected(
        ambiguous_framing,
        expected=(b"HTTP/1.1 400",),
        name="ambiguous transfer framing",
    )

    oversized_header = client.exchange(
        b"GET /health HTTP/1.1\r\nHost: localhost\r\nX-Large: "
        + b"a" * 9000
        + b"\r\nConnection: close\r\n\r\n"
    )
    require_rejected(
        oversized_header,
        expected=(b"HTTP/1.1 400", b"HTTP/1.1 431"),
        name="oversized header",
    )

    headers, body = multipart_bomb()
    excessive_parts = client.exchange(http_request("/auth/login", headers, body))
    require_rejected(
        excessive_parts,
        expected=(b"HTTP/1.1 413",),
        name="multipart part limit",
    )
    return {
        "duplicate_content_length": "rejected",
        "transfer_encoding_content_length": "rejected",
        "oversized_header": "rejected",
        "multipart_part_limit": "rejected",
    }


def probe_smtp(endpoint: Endpoint, size_limit: int) -> dict[str, str]:
    with SmtpClient(endpoint) as client:
        if not client.reply().startswith(b"220"):
            raise RuntimeError("SMTP greeting is invalid")
        if not client.command(b"EHLO socket-security-gate").startswith(b"250"):
            raise RuntimeError("SMTP EHLO failed")
        if not client.command(b"NOOP " + b"a" * 1100).startswith(b"500"):
            raise RuntimeError("SMTP overlong command was not rejected")

    with SmtpClient(endpoint) as client:
        client.reply()
        client.command(b"EHLO socket-security-gate")
        response = client.command(
            f"MAIL FROM:<socket-gate@example.invalid> SIZE={size_limit + 1}".encode()
        )
        if not response.startswith(b"552"):
            raise RuntimeError(f"SMTP declared oversize was not rejected: {response!r}")
    return {"overlong_command": "rejected", "declared_message_size": "rejected"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=17777)
    parser.add_argument("--smtp-port", type=int, default=20381)
    parser.add_argument("--smtp-size-limit", type=int, required=True)
    args = parser.parse_args()
    evidence = {
        "http": probe_http(Endpoint(args.host, args.http_port)),
        "smtp": probe_smtp(Endpoint(args.host, args.smtp_port), args.smtp_size_limit),
    }
    print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    main()
