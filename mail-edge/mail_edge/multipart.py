"""Small binary-safe multipart encoder for Mailgun message submission."""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MultipartFile:
    field: str
    filename: str
    content_type: str
    content: bytes


def encode_multipart(
    fields: Iterable[tuple[str, str]], files: Iterable[MultipartFile]
) -> tuple[str, bytes]:
    boundary = f"mail-edge-{secrets.token_hex(16)}"
    chunks: list[bytes] = []

    def checked(value: str) -> bytes:
        if "\r" in value or "\n" in value or '"' in value:
            raise ValueError("unsafe multipart metadata")
        return value.encode("ascii")

    boundary_bytes = boundary.encode("ascii")
    for name, value in fields:
        chunks.extend(
            (
                b"--" + boundary_bytes + b"\r\n",
                b'Content-Disposition: form-data; name="'
                + checked(name)
                + b'"\r\n\r\n',
                value.encode("utf-8"),
                b"\r\n",
            )
        )
    for item in files:
        chunks.extend(
            (
                b"--" + boundary_bytes + b"\r\n",
                b'Content-Disposition: form-data; name="'
                + checked(item.field)
                + b'"; filename="'
                + checked(item.filename)
                + b'"\r\n',
                b"Content-Type: " + checked(item.content_type) + b"\r\n\r\n",
                item.content,
                b"\r\n",
            )
        )
    chunks.append(b"--" + boundary_bytes + b"--\r\n")
    return f"multipart/form-data; boundary={boundary}", b"".join(chunks)
