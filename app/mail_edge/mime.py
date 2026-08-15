from __future__ import annotations

import time
from email.feedparser import BytesFeedParser
from email.message import Message
from typing import Callable

from .configuration import MimeParserLimits
from .errors import MailEdgeContractError
from .resources import RawMessageResource


STRUCTURAL_DEFECTS = frozenset(
    {
        "CloseBoundaryNotFoundDefect",
        "FirstHeaderLineIsContinuationDefect",
        "HeaderDefect",
        "MalformedHeaderDefect",
        "MissingHeaderBodySeparatorDefect",
        "MultipartInvariantViolationDefect",
        "NoBoundaryInMultipartDefect",
        "StartBoundaryNotFoundDefect",
    }
)


class _ParseBudget:
    def __init__(
        self,
        limits: MimeParserLimits,
        deadline: float,
        clock: Callable[[], float],
    ):
        self.limits = limits
        self.deadline = deadline
        self.clock = clock
        self.parts = 0
        self.header_count = 0
        self.header_bytes = 0

    def check_deadline(self) -> None:
        if self.clock() > self.deadline:
            raise MailEdgeContractError("MIME_PARSE_TIME_LIMIT_EXCEEDED")

    def begin_part(self, depth: int) -> None:
        self.check_deadline()
        self.parts += 1
        if self.parts > self.limits.maximum_parts:
            raise MailEdgeContractError("MIME_PART_LIMIT_EXCEEDED")
        if depth > self.limits.maximum_depth:
            raise MailEdgeContractError("MIME_DEPTH_LIMIT_EXCEEDED")

    def observe_headers(self, lines: list[str]) -> None:
        self.check_deadline()
        header_count = 0
        header_bytes = 0
        for line in lines:
            encoded = line.encode("ascii", "surrogateescape")
            if len(encoded) > self.limits.maximum_line_bytes:
                raise MailEdgeContractError("MIME_HEADER_LINE_LIMIT_EXCEEDED")
            header_bytes += len(encoded)
            if line[:1] not in " \t":
                header_count += 1
        self.header_count += header_count
        self.header_bytes += header_bytes
        if self.header_count > self.limits.maximum_header_count:
            raise MailEdgeContractError("MIME_HEADER_COUNT_LIMIT_EXCEEDED")
        if self.header_bytes > self.limits.maximum_header_bytes:
            raise MailEdgeContractError("MIME_HEADER_BYTES_LIMIT_EXCEEDED")


class _BoundedBytesFeedParser(BytesFeedParser):
    def __init__(self, budget: _ParseBudget):
        self._mail_edge_budget = budget
        super().__init__()

    def _new_message(self) -> None:
        self._mail_edge_budget.begin_part(len(self._msgstack) + 1)
        super()._new_message()

    def _parse_headers(self, lines: list[str]) -> None:
        self._mail_edge_budget.observe_headers(lines)
        super()._parse_headers(lines)


def _observe_line_lengths(
    chunk: bytes, current_line_bytes: int, maximum_line_bytes: int
) -> int:
    segments = chunk.split(b"\n")
    if len(segments) == 1:
        current_line_bytes += len(chunk)
        if current_line_bytes > maximum_line_bytes:
            raise MailEdgeContractError("MIME_LINE_LIMIT_EXCEEDED")
        return current_line_bytes
    first = current_line_bytes + len(segments[0]) + 1
    if first > maximum_line_bytes:
        raise MailEdgeContractError("MIME_LINE_LIMIT_EXCEEDED")
    for segment in segments[1:-1]:
        if len(segment) + 1 > maximum_line_bytes:
            raise MailEdgeContractError("MIME_LINE_LIMIT_EXCEEDED")
    trailing = len(segments[-1])
    if trailing > maximum_line_bytes:
        raise MailEdgeContractError("MIME_LINE_LIMIT_EXCEEDED")
    return trailing


def _semantic_size(message: Message, header_bytes: int, maximum_bytes: int) -> int:
    total = header_bytes * 4
    for part in message.walk():
        payload = part.get_payload()
        if isinstance(payload, bytes):
            total += len(payload)
        elif isinstance(payload, str):
            total += len(payload.encode("utf-8", "surrogateescape"))
        if total > maximum_bytes:
            raise MailEdgeContractError("MIME_SEMANTIC_LIMIT_EXCEEDED")
    return total


def _reject_structural_defects(message: Message) -> None:
    for part in message.walk():
        for defect in part.defects:
            if type(defect).__name__ in STRUCTURAL_DEFECTS:
                raise MailEdgeContractError("MIME_STRUCTURE_INVALID")


class BoundedMimeParserService:
    """Chunked stdlib MIME parser with structural, semantic, and time ceilings."""

    def __init__(
        self,
        limits: MimeParserLimits,
        *,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._limits = limits
        self._clock = clock

    def parse(self, raw: RawMessageResource) -> Message:
        started = self._clock()
        budget = _ParseBudget(
            self._limits, started + self._limits.parser_seconds, self._clock
        )
        parser = _BoundedBytesFeedParser(budget)
        source = raw.rewind()
        current_line_bytes = 0
        try:
            while True:
                budget.check_deadline()
                chunk = source.read(64 * 1024)
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    raise MailEdgeContractError("MIME_STREAM_INVALID")
                current_line_bytes = _observe_line_lengths(
                    chunk, current_line_bytes, self._limits.maximum_line_bytes
                )
                parser.feed(chunk)
            message = parser.close()
            budget.check_deadline()
            _reject_structural_defects(message)
            _semantic_size(
                message, budget.header_bytes, self._limits.maximum_semantic_bytes
            )
            return message
        except MailEdgeContractError:
            raise
        except (IndexError, RecursionError, TypeError, UnicodeError, ValueError):
            raise MailEdgeContractError("MIME_STRUCTURE_INVALID") from None
        finally:
            raw.rewind()
