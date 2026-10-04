from __future__ import annotations

import socket

import pytest
from aiosmtpd.controller import Controller


def _free_port() -> int:
    with socket.socket() as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


class RecordingHandler:
    def __init__(self) -> None:
        self.messages: list[bytes] = []

    async def handle_DATA(self, _server, _session, envelope):
        self.messages.append(envelope.original_content)
        return "250 accepted"


def _reply(client: socket.socket) -> bytes:
    response = bytearray()
    while True:
        line = bytearray()
        while not line.endswith(b"\n"):
            chunk = client.recv(1)
            if not chunk:
                raise RuntimeError("SMTP server closed before a complete response")
            line.extend(chunk)
        response.extend(line)
        if len(line) >= 4 and line[3:4] == b" ":
            return bytes(response)


def _command(client: socket.socket, command: bytes) -> bytes:
    client.sendall(command + b"\r\n")
    return _reply(client)


@pytest.fixture
def smtp_server():
    handler = RecordingHandler()
    controller = Controller(
        handler,
        hostname="127.0.0.1",
        port=_free_port(),
        data_size_limit=128,
    )
    controller.start()
    try:
        yield controller, handler
    finally:
        controller.stop()


def test_smtp_socket_bounds_commands_data_and_crlf_termination(smtp_server):
    controller, handler = smtp_server
    with socket.create_connection(
        (controller.hostname, controller.port), timeout=2
    ) as client:
        assert _reply(client).startswith(b"220")
        assert _command(client, b"EHLO socket-test").startswith(b"250")
        assert _command(client, b"NOOP " + b"a" * 1100).startswith(b"500")
        assert _command(client, b"MAIL FROM:<sender@example.com>").startswith(b"250")
        assert _command(client, b"RCPT TO:<recipient@example.net>").startswith(b"250")
        assert _command(client, b"DATA").startswith(b"354")

        client.sendall(b"Subject: boundary\r\n\r\nbody\n.\nNOOP\r\n")
        client.settimeout(0.2)
        with pytest.raises(TimeoutError):
            client.recv(1)

        client.settimeout(2)
        client.sendall(b"\r\n.\r\n")
        assert _reply(client).startswith(b"250")
        assert len(handler.messages) == 1
        assert b"\n.\nNOOP\r\n" in handler.messages[0]
        assert _command(client, b"NOOP").startswith(b"250")

        assert _command(client, b"MAIL FROM:<sender@example.com>").startswith(b"250")
        assert _command(client, b"RCPT TO:<recipient@example.net>").startswith(b"250")
        assert _command(client, b"DATA").startswith(b"354")
        client.sendall(b"x" * 256 + b"\r\n.\r\n")
        assert _reply(client).startswith(b"552")
        assert len(handler.messages) == 1
