from __future__ import annotations

import asyncio

from conftest import active_binding

from mail_edge.contracts import BindingDirection
from mail_edge.ids import uuid7_str
from mail_edge.smtp import DisconnectAfterCommit, SMTPSpoolServer


def _message(identifier: str, body: bytes = b"body\r\n") -> bytes:
    return (
        f"X-Mail-Edge-Submission-ID: {identifier}\r\n"
        "Message-ID: <message@aliases.example>\r\n"
        "From: alias@aliases.example\r\n"
        "To: recipient@outside.example\r\n"
        "Content-Type: text/plain\r\n\r\n"
    ).encode() + body


async def _read_response(reader: asyncio.StreamReader) -> list[bytes]:
    first = await reader.readline()
    if not first:
        return []
    lines = [first]
    if len(first) >= 4 and first[3:4] == b"-":
        code = first[:3]
        while True:
            line = await reader.readline()
            lines.append(line)
            if line.startswith(code + b" "):
                break
    return lines


async def _session(spool, commands):
    server = await asyncio.start_server(spool.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    responses = [await _read_response(reader)]
    for command in commands:
        writer.write(command)
        await writer.drain()
        responses.append(await _read_response(reader))
        if responses[-1] == []:
            break
    writer.close()
    await writer.wait_closed()
    server.close()
    await server.wait_closed()
    return responses


def _submit(spool, identifier, payload=None):
    message = payload if payload is not None else _message(identifier)
    return asyncio.run(
        _session(
            spool,
            [
                b"EHLO client\r\n",
                b"MAIL FROM:<bounce@aliases.example>\r\n",
                b"RCPT TO:<recipient@outside.example>\r\n",
                b"DATA\r\n",
                message + b".\r\n",
            ],
        )
    )


def test_unknown_domain_is_rejected_before_data_without_fallback(edge):
    active_binding(edge, BindingDirection.OUTBOUND)
    responses = asyncio.run(
        _session(
            SMTPSpoolServer(edge["repository"]),
            [b"EHLO client\r\n", b"MAIL FROM:<bounce@unknown.example>\r\n"],
        )
    )
    assert responses[-1][0].startswith(b"550 5.1.8")


def test_smtp_returns_250_only_after_durable_commit(edge):
    active_binding(edge, BindingDirection.OUTBOUND)
    identifier = uuid7_str()
    responses = _submit(SMTPSpoolServer(edge["repository"]), identifier)
    assert responses[-1][0].startswith(b"250 2.0.0 queued")
    with edge["database"].transaction() as connection:
        row = connection.execute(
            "SELECT state, raw_sha256 FROM outbound_messages WHERE id = ?",
            (identifier,),
        ).fetchone()
    assert row["state"] == "queued"
    assert edge["blobs"].exists(f"outbound/{identifier}/raw")


def test_before_commit_fault_returns_451_and_does_not_create_row(edge):
    active_binding(edge, BindingDirection.OUTBOUND)
    identifier = uuid7_str()

    def fail():
        raise RuntimeError("injected before commit")

    responses = _submit(
        SMTPSpoolServer(edge["repository"], _before_commit=fail), identifier
    )
    assert responses[-1][0].startswith(b"451 4.3.0")
    with edge["database"].transaction() as connection:
        assert (
            connection.execute(
                "SELECT id FROM outbound_messages WHERE id = ?", (identifier,)
            ).fetchone()
            is None
        )


def test_lost_ack_after_commit_replay_is_idempotent(edge):
    active_binding(edge, BindingDirection.OUTBOUND)
    identifier = uuid7_str()

    def disconnect():
        raise DisconnectAfterCommit

    responses = _submit(
        SMTPSpoolServer(edge["repository"], _after_commit=disconnect), identifier
    )
    assert responses[-1] == []
    replay = _submit(SMTPSpoolServer(edge["repository"]), identifier)
    assert replay[-1][0].startswith(b"250 2.0.0 queued")
    with edge["database"].transaction() as connection:
        count = connection.execute(
            "SELECT COUNT(*) AS count FROM outbound_messages WHERE id = ?",
            (identifier,),
        ).fetchone()["count"]
    assert count == 1


def test_malformed_and_oversize_mime_are_rejected_without_commit(edge):
    active_binding(edge, BindingDirection.OUTBOUND)
    malformed_id = uuid7_str()
    malformed = (
        f"X-Mail-Edge-Submission-ID: {malformed_id}\r\nFrom: alias@aliases.example\r\n"
    ).encode()
    malformed_response = _submit(
        SMTPSpoolServer(edge["repository"]), malformed_id, malformed
    )
    assert malformed_response[-1][0].startswith(b"554 5.6.0")
    oversized_id = uuid7_str()
    oversized_response = _submit(
        SMTPSpoolServer(edge["repository"], maximum_message_bytes=200),
        oversized_id,
        _message(oversized_id, b"x" * 500 + b"\r\n"),
    )
    assert oversized_response[-1][0].startswith(b"552 5.3.4")
    with edge["database"].transaction() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) AS count FROM outbound_messages"
            ).fetchone()["count"]
            == 0
        )
