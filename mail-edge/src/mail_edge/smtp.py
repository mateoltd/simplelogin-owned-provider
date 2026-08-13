"""Private SMTP spool. DATA is acknowledged only after blob and DB durability."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from email.parser import BytesHeaderParser
from email.policy import SMTP
from typing import Any

from .contracts import (
    BindingDirection,
    Envelope,
    OutboundSubmission,
    address_domain,
)
from .errors import ContractError, DuplicateConflict, MailEdgeError, UnknownDomain
from .ids import require_uuid7
from .repository import EdgeRepository
from .runtime import build_runtime

_MAIL = re.compile(r"^FROM:\s*<([^>]*)>(?:\s+(.*))?$", re.I)
_RCPT = re.compile(r"^TO:\s*<([^>]*)>(?:\s+.*)?$", re.I)


class DisconnectAfterCommit(Exception):
    """Test-boundary fault representing a lost SMTP acknowledgement."""


class SMTPSpoolServer:
    def __init__(
        self,
        repository: EdgeRepository,
        *,
        maximum_message_bytes: int = 25 * 1024 * 1024,
        maximum_recipients: int = 100,
        retention_hours: int = 24,
        command_timeout_seconds: float = 300,
        _before_commit: Callable[[], Any] | None = None,
        _after_commit: Callable[[], Any] | None = None,
    ) -> None:
        self.repository = repository
        self.maximum_message_bytes = maximum_message_bytes
        self.maximum_recipients = maximum_recipients
        self.retention_hours = retention_hours
        self.command_timeout_seconds = command_timeout_seconds
        self._before_commit = _before_commit
        self._after_commit = _after_commit

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        envelope_sender: str | None = None
        recipients: list[str] = []
        binding = None
        await self._reply(writer, "220 mail-edge ESMTP ready")
        try:
            while not reader.at_eof():
                line = await asyncio.wait_for(
                    reader.readline(), timeout=self.command_timeout_seconds
                )
                if not line:
                    break
                if len(line) > 4096 or not line.endswith(b"\n"):
                    await self._reply(writer, "500 5.5.2 malformed command")
                    continue
                try:
                    command_line = line.decode("ascii").strip("\r\n")
                except UnicodeDecodeError:
                    await self._reply(writer, "500 5.5.2 command must be ASCII")
                    continue
                command, _, argument = command_line.partition(" ")
                command = command.upper()
                if command in {"EHLO", "HELO"}:
                    await self._reply(
                        writer,
                        "250-mail-edge\r\n"
                        f"250-SIZE {self.maximum_message_bytes}\r\n"
                        "250 8BITMIME",
                    )
                elif command == "NOOP":
                    await self._reply(writer, "250 2.0.0 ok")
                elif command == "RSET":
                    envelope_sender, recipients, binding = None, [], None
                    await self._reply(writer, "250 2.0.0 reset")
                elif command == "QUIT":
                    await self._reply(writer, "221 2.0.0 bye")
                    break
                elif command == "MAIL":
                    match = _MAIL.fullmatch(argument)
                    if not match:
                        await self._reply(writer, "501 5.5.4 malformed MAIL FROM")
                        continue
                    sender = match.group(1)
                    options = self._options(match.group(2) or "")
                    try:
                        declared_domain = options.get("EDGE")
                        if sender:
                            sender_domain = address_domain(sender)
                            if declared_domain and declared_domain != sender_domain:
                                raise ContractError(
                                    "EDGE domain does not match MAIL FROM"
                                )
                            domain = sender_domain
                        else:
                            if not declared_domain:
                                raise ContractError("null sender requires EDGE domain")
                            domain = declared_domain
                        binding = self.repository.bindings.resolve_active(
                            domain, BindingDirection.OUTBOUND
                        )
                    except (ContractError, UnknownDomain):
                        await self._reply(writer, "550 5.1.8 unknown outbound domain")
                        envelope_sender, recipients, binding = None, [], None
                        continue
                    envelope_sender, recipients = sender, []
                    await self._reply(writer, "250 2.1.0 sender accepted")
                elif command == "RCPT":
                    if envelope_sender is None or binding is None:
                        await self._reply(writer, "503 5.5.1 MAIL FROM required")
                        continue
                    match = _RCPT.fullmatch(argument)
                    if not match:
                        await self._reply(writer, "501 5.5.4 malformed RCPT TO")
                        continue
                    if len(recipients) >= self.maximum_recipients:
                        await self._reply(writer, "452 4.5.3 too many recipients")
                        continue
                    try:
                        address_domain(match.group(1))
                    except ContractError:
                        await self._reply(writer, "501 5.1.3 invalid recipient")
                        continue
                    recipients.append(match.group(1))
                    await self._reply(writer, "250 2.1.5 recipient accepted")
                elif command == "DATA":
                    if envelope_sender is None or binding is None or not recipients:
                        await self._reply(writer, "503 5.5.1 envelope is incomplete")
                        continue
                    await self._reply(writer, "354 end with <CRLF>.<CRLF>")
                    try:
                        payload, failure = await self._read_data(reader)
                    except ValueError:
                        await self._reply(
                            writer, "554 5.6.0 MIME line exceeds parser limit"
                        )
                        break
                    if failure:
                        await self._reply(writer, failure)
                        envelope_sender, recipients, binding = None, [], None
                        continue
                    try:
                        submission_id = self._submission_id(payload)
                        submission = OutboundSubmission(
                            submission_id=submission_id,
                            domain=binding.domain,
                            binding_generation=binding.generation,
                            envelope=Envelope(
                                sender=envelope_sender, recipients=tuple(recipients)
                            ),
                            raw_mime=payload,
                        )
                        if self._before_commit:
                            self._before_commit()
                        self.repository.enqueue_outbound(
                            submission,
                            binding=binding,
                            retention_until=datetime.now(UTC)
                            + timedelta(hours=self.retention_hours),
                        )
                        if self._after_commit:
                            self._after_commit()
                    except DisconnectAfterCommit:
                        writer.close()
                        await writer.wait_closed()
                        return
                    except DuplicateConflict:
                        await self._reply(writer, "554 5.6.0 submission ID conflict")
                    except (ContractError, ValueError):
                        await self._reply(writer, "554 5.6.0 malformed message")
                    except MailEdgeError:
                        await self._reply(writer, "451 4.3.0 durable spool unavailable")
                    except Exception:
                        await self._reply(writer, "451 4.3.0 durable spool unavailable")
                    else:
                        await self._reply(
                            writer, f"250 2.0.0 queued as {submission_id}"
                        )
                    envelope_sender, recipients, binding = None, [], None
                else:
                    await self._reply(writer, "502 5.5.1 command not implemented")
        except (TimeoutError, ConnectionError):
            return
        finally:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()

    @staticmethod
    def _options(value: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for item in value.split():
            key, separator, option_value = item.partition("=")
            if separator:
                result[key.upper()] = option_value.lower().rstrip(".")
        return result

    async def _read_data(
        self, reader: asyncio.StreamReader
    ) -> tuple[bytes, str | None]:
        chunks: list[bytes] = []
        size = 0
        malformed = False
        oversized = False
        while True:
            line = await asyncio.wait_for(
                reader.readline(), timeout=self.command_timeout_seconds
            )
            if not line:
                raise ConnectionError("connection closed during DATA")
            if line == b".\r\n":
                break
            if not line.endswith(b"\r\n"):
                malformed = True
            if line.startswith(b".."):
                line = line[1:]
            size += len(line)
            if size > self.maximum_message_bytes:
                oversized = True
            elif not oversized:
                chunks.append(line)
        if oversized:
            return b"", "552 5.3.4 message exceeds fixed maximum size"
        if malformed:
            return b"", "554 5.6.0 DATA requires CRLF line endings"
        return b"".join(chunks), None

    @staticmethod
    def _submission_id(payload: bytes) -> str:
        if b"\x00" in payload or b"\r\n\r\n" not in payload:
            raise ContractError("message has no valid header/body boundary")
        header, _ = payload.split(b"\r\n\r\n", 1)
        if len(header) > 256 * 1024:
            raise ContractError("message header block is too large")
        parsed = BytesHeaderParser(policy=SMTP).parsebytes(header + b"\r\n\r\n")
        if parsed.defects:
            raise ContractError("message headers are malformed")
        values = parsed.get_all("X-Mail-Edge-Submission-ID", [])
        if len(values) != 1:
            raise ContractError("one submission ID header is required")
        if not parsed.get("From"):
            raise ContractError("From header is required")
        return require_uuid7(str(values[0]).strip())

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, response: str) -> None:
        writer.write(response.encode("ascii") + b"\r\n")
        await writer.drain()


def _private_bind(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host in {"localhost"}
    return address.is_private or address.is_loopback


async def serve(host: str, port: int, spool: SMTPSpoolServer) -> None:
    server = await asyncio.start_server(spool.handle, host, port, limit=1024 * 1024)
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host", default=os.environ.get("MAIL_EDGE_SMTP_HOST", "127.0.0.1")
    )
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("MAIL_EDGE_SMTP_PORT", "2525"))
    )
    parser.add_argument(
        "--maximum-bytes",
        type=int,
        default=int(
            os.environ.get("MAIL_EDGE_MAX_MESSAGE_BYTES", str(25 * 1024 * 1024))
        ),
    )
    arguments = parser.parse_args()
    if (
        not _private_bind(arguments.host)
        and os.environ.get("MAIL_EDGE_ALLOW_NONPRIVATE_SMTP_BIND") != "1"
    ):
        raise SystemExit("refusing a non-private SMTP bind")
    runtime = build_runtime()
    spool = SMTPSpoolServer(
        runtime.repository, maximum_message_bytes=arguments.maximum_bytes
    )
    asyncio.run(serve(arguments.host, arguments.port, spool))


if __name__ == "__main__":
    main()
