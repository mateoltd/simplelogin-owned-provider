from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).parents[1]


def _free_port() -> int:
    with socket.socket() as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


class GunicornServer:
    def __init__(self) -> None:
        self.port = _free_port()
        self._process: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> "GunicornServer":
        self._process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "gunicorn",
                "tests.http_socket_fixture:app",
                "--bind",
                f"127.0.0.1:{self.port}",
                "--workers",
                "1",
                "--timeout",
                "5",
                "--access-logfile",
                "/dev/null",
                "--error-logfile",
                "/dev/null",
            ],
            cwd=REPOSITORY,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                raise RuntimeError("Gunicorn exited before accepting connections")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return self
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("Gunicorn did not start")

    def __exit__(self, _type, _value, _traceback) -> None:
        assert self._process is not None
        self._process.terminate()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=5)

    def request(self, payload: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=3) as client:
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            response = bytearray()
            while chunk := client.recv(65_536):
                response.extend(chunk)
            return bytes(response)


@pytest.fixture(scope="module")
def gunicorn_server():
    with GunicornServer() as server:
        yield server


def _request(path: str, headers: bytes = b"", body: bytes = b"") -> bytes:
    return (
        f"POST {path} HTTP/1.1\r\nHost: localhost\r\n".encode()
        + headers
        + b"Connection: close\r\n\r\n"
        + body
    )


@pytest.mark.parametrize(
    "payload",
    [
        _request(
            "/echo",
            b"Content-Length: 4\r\nContent-Length: 52\r\n",
            b"testGET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ),
        _request(
            "/echo",
            b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",
            b"0\r\n\r\nGET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ),
    ],
)
def test_gunicorn_rejects_ambiguous_framing_without_second_response(
    gunicorn_server, payload
):
    response = gunicorn_server.request(payload)

    assert response.startswith(b"HTTP/1.1 400")
    assert response.count(b"HTTP/1.1") == 1
    assert b"\r\nConnection: close\r\n" in response


def test_gunicorn_rejects_oversized_header(gunicorn_server):
    response = gunicorn_server.request(
        b"GET /health HTTP/1.1\r\nHost: localhost\r\nX-Large: "
        + b"a" * 9000
        + b"\r\nConnection: close\r\n\r\n"
    )

    assert response.startswith((b"HTTP/1.1 400", b"HTTP/1.1 431"))


def test_flask_rejects_multipart_part_bomb(gunicorn_server):
    boundary = b"owned-provider-boundary"
    body = bytearray()
    for index in range(1001):
        body.extend(b"--" + boundary + b"\r\n")
        body.extend(
            f'Content-Disposition: form-data; name="part-{index}"\r\n\r\nx\r\n'.encode()
        )
    body.extend(b"--" + boundary + b"--\r\n")
    response = gunicorn_server.request(
        _request(
            "/form",
            b"Content-Type: multipart/form-data; boundary="
            + boundary
            + b"\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\n",
            bytes(body),
        )
    )

    assert response.startswith(b"HTTP/1.1 413")
