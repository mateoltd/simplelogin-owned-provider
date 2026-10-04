import hashlib
import tempfile

import pytest

from app.mail_edge.configuration import MimeParserLimits
from app.mail_edge.errors import MailEdgeContractError
from app.mail_edge.mime import BoundedMimeParserService
from app.mail_edge.resources import RawMessageResource


def limits(**overrides):
    values = {
        "maximum_parts": 32,
        "maximum_depth": 8,
        "maximum_header_count": 128,
        "maximum_header_bytes": 64 * 1024,
        "maximum_line_bytes": 64 * 1024,
        "maximum_semantic_bytes": 4 * 1024 * 1024,
        "parser_seconds": 5,
    }
    values.update(overrides)
    return MimeParserLimits(**values)


def parse(raw, selected_limits=None, clock=None):
    parser = BoundedMimeParserService(
        selected_limits or limits(), **({"clock": clock} if clock else {})
    )
    with RawMessageResource(len(raw), tempfile.gettempdir()) as resource:
        resource.write(raw)
        resource.seal(
            expected_size=len(raw), expected_sha256=hashlib.sha256(raw).hexdigest()
        )
        return parser.parse(resource)


def multipart(parts):
    boundary = "mail-edge-boundary"
    body = b"".join(
        b"--mail-edge-boundary\r\nContent-Type: text/plain\r\n\r\npart\r\n"
        for _ in range(parts)
    )
    return (
        f"Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n".encode()
        + body
        + b"--mail-edge-boundary--\r\n"
    )


def nested_multipart(depth):
    headers = []
    closings = []
    for index in range(depth):
        boundary = f"depth-{index}"
        headers.append(
            f"Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n"
            f"--{boundary}\r\n".encode()
        )
        closings.append(f"\r\n--{boundary}--\r\n".encode())
    return (
        b"".join(headers)
        + b"Content-Type: text/plain\r\n\r\nbody"
        + b"".join(reversed(closings))
    )


def test_large_message_is_parsed_from_file_backed_raw():
    raw = b"From: sender@example.net\r\nTo: alias@example.com\r\n\r\n" + b"x" * (
        2 * 1024 * 1024
    )
    message = parse(
        raw,
        limits(
            maximum_line_bytes=3 * 1024 * 1024, maximum_semantic_bytes=3 * 1024 * 1024
        ),
    )
    assert message["To"] == "alias@example.com"
    assert len(message.get_payload()) == 2 * 1024 * 1024


def test_part_bomb_depth_bomb_and_malformed_multipart_fail_closed():
    cases = (
        (multipart(5), limits(maximum_parts=4), "MIME_PART_LIMIT_EXCEEDED"),
        (
            nested_multipart(5),
            limits(maximum_depth=4),
            "MIME_DEPTH_LIMIT_EXCEEDED",
        ),
        (
            b"Content-Type: multipart/mixed; boundary=never-closed\r\n\r\n"
            b"--never-closed\r\nContent-Type: text/plain\r\n\r\nbody",
            limits(),
            "MIME_STRUCTURE_INVALID",
        ),
    )
    for raw, selected_limits, code in cases:
        with pytest.raises(MailEdgeContractError) as raised:
            parse(raw, selected_limits)
        assert raised.value.code == code


def test_header_line_semantic_and_parser_time_limits_fail_closed():
    raw = b"X-Long: " + b"x" * 100 + b"\r\n\r\nbody"
    with pytest.raises(MailEdgeContractError) as raised:
        parse(raw, limits(maximum_line_bytes=64))
    assert raised.value.code in {
        "MIME_LINE_LIMIT_EXCEEDED",
        "MIME_HEADER_LINE_LIMIT_EXCEEDED",
    }

    raw = b"From: sender@example.net\r\n\r\n" + b"x" * 1024
    with pytest.raises(MailEdgeContractError) as raised:
        parse(raw, limits(maximum_semantic_bytes=512))
    assert raised.value.code == "MIME_SEMANTIC_LIMIT_EXCEEDED"

    ticks = iter((0.0, 0.0, 2.0, 2.0))
    with pytest.raises(MailEdgeContractError) as raised:
        parse(
            b"From: sender@example.net\r\n\r\nbody",
            limits(parser_seconds=1),
            clock=lambda: next(ticks, 2.0),
        )
    assert raised.value.code == "MIME_PARSE_TIME_LIMIT_EXCEEDED"
