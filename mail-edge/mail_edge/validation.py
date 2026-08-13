"""SMTP-envelope and MIME validation without rewriting message bytes."""

from __future__ import annotations

import re
from email import policy
from email.parser import BytesParser

from .errors import MalformedPayload, MessageTooLarge

_MESSAGE_ID = re.compile(r"^<[^<>\s\x00-\x1f\x7f]+>$")


def validate_delivery_id(value: str) -> None:
    if (
        not value
        or len(value) > 200
        or any(ord(char) < 33 or ord(char) == 127 for char in value)
    ):
        raise MalformedPayload("invalid edge delivery id")


def validate_mailbox(
    value: str, *, allow_null: bool = False, smtp_utf8: bool = False
) -> None:
    if allow_null and value in {"", "<>"}:
        return
    if not value or len(value.encode("utf-8")) > 254:
        raise MalformedPayload("invalid SMTP mailbox")
    if (
        any(char in value for char in "\r\n\x00")
        or value.startswith("<")
        or value.endswith(">")
    ):
        raise MalformedPayload("invalid SMTP mailbox")
    if not smtp_utf8:
        try:
            value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise MalformedPayload(
                "SMTPUTF8 is required for a non-ASCII mailbox"
            ) from exc

    in_quote = False
    escaped = False
    at_index = -1
    for index, char in enumerate(value):
        if escaped:
            escaped = False
        elif char == "\\" and in_quote:
            escaped = True
        elif char == '"':
            in_quote = not in_quote
        elif char == "@" and not in_quote:
            at_index = index
    if in_quote or escaped or at_index <= 0 or at_index == len(value) - 1:
        raise MalformedPayload("invalid SMTP mailbox")
    domain = value[at_index + 1 :]
    if domain.startswith("[") and domain.endswith("]"):
        return
    labels = domain.rstrip(".").split(".")
    if any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in labels
    ):
        raise MalformedPayload("invalid SMTP mailbox domain")
    try:
        domain.encode("idna")
    except UnicodeError as exc:
        raise MalformedPayload("invalid SMTP mailbox domain") from exc


def mailbox_domain(value: str) -> str:
    validate_mailbox(value, smtp_utf8=True)
    in_quote = False
    escaped = False
    at_index = -1
    for index, char in enumerate(value):
        if escaped:
            escaped = False
        elif char == "\\" and in_quote:
            escaped = True
        elif char == '"':
            in_quote = not in_quote
        elif char == "@" and not in_quote:
            at_index = index
    return value[at_index + 1 :].rstrip(".").lower()


def inspect_mime(raw: bytes, *, max_bytes: int) -> str:
    if not isinstance(raw, bytes):
        raise MalformedPayload("raw MIME must cross the boundary as bytes")
    if len(raw) > max_bytes:
        raise MessageTooLarge(f"message exceeds the {max_bytes}-byte policy")
    if not raw:
        raise MalformedPayload("raw MIME is empty")
    if b"\x00" in raw:
        raise MalformedPayload("raw MIME contains a NUL byte")
    if b"\r\n\r\n" not in raw and b"\n\n" not in raw:
        raise MalformedPayload("raw MIME has no header/body separator")

    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        raise MalformedPayload("raw MIME could not be parsed") from exc
    if message.defects:
        raise MalformedPayload("raw MIME has structural defects")
    message_ids = message.get_all("Message-ID", [])
    if len(message_ids) != 1:
        raise MalformedPayload("raw MIME must contain exactly one Message-ID")
    message_id = str(message_ids[0]).strip()
    if len(message_id) > 998 or not _MESSAGE_ID.fullmatch(message_id):
        raise MalformedPayload("raw MIME has an invalid Message-ID")
    return message_id


def bounded_text(value: object, *, maximum: int = 512) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split())
    if not text:
        return None
    return text[:maximum]
