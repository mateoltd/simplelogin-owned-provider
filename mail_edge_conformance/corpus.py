"""Versioned real-EML corpus and deterministic boundary-size messages."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


CORPUS_DIRECTORY = Path(__file__).with_name("corpus")
MANIFEST_PATH = CORPUS_DIRECTORY / "manifest.json"


@dataclass(frozen=True)
class CorpusCase:
    case_id: str
    features: tuple[str, ...]
    rfc822_bytes: bytes
    smtp_utf8_required: bool
    thread: str | None = None
    sequence: int | None = None

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.rfc822_bytes).hexdigest()


def load_corpus() -> tuple[CorpusCase, ...]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest.get("schema") != "mail-edge-eml-corpus/v1":
        raise ValueError("unsupported mail-edge corpus manifest")
    cases: list[CorpusCase] = []
    for item in manifest["cases"]:
        path = CORPUS_DIRECTORY / item["file"]
        encoded = path.read_bytes()
        digest = hashlib.sha256(encoded).hexdigest()
        if digest != item["sha256"]:
            raise ValueError(f"corpus digest mismatch for {path.name}: {digest}")
        cases.append(
            CorpusCase(
                case_id=item["id"],
                features=tuple(item["features"]),
                rfc822_bytes=encoded,
                smtp_utf8_required=bool(item.get("smtp_utf8_required", False)),
                thread=item.get("thread"),
                sequence=item.get("sequence"),
            )
        )
    identifiers = [case.case_id for case in cases]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("corpus case IDs must be unique")
    return tuple(cases)


def build_boundary_message(
    target_size: int,
    *,
    sender: str = "size-sender@sender.test",
    recipient: str = "size-recipient@receiver.test",
    test_id: str | None = None,
) -> bytes:
    """Build a valid deterministic message whose wire size is exactly target_size."""
    prefix = (
        f"From: Boundary Sender <{sender}>\r\n"
        f"To: Boundary Recipient <{recipient}>\r\n"
        f"Subject: Boundary message {target_size}\r\n"
        f"Message-ID: <boundary-{target_size}@sender.test>\r\n"
        + (f"X-Mail-Edge-Test-ID: {test_id}\r\n" if test_id else "")
        + "Date: Thu, 13 Aug 2026 12:00:00 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Transfer-Encoding: binary\r\n"
        "Content-Disposition: attachment; filename=boundary.bin\r\n"
        "\r\n"
    ).encode("ascii")
    if target_size < len(prefix):
        raise ValueError(f"target_size must be at least {len(prefix)}")
    remaining = target_size - len(prefix)
    pattern = bytes(range(256))
    payload = (pattern * ((remaining + 255) // 256))[:remaining]
    message = prefix + payload
    if len(message) != target_size:
        raise AssertionError("boundary generator did not produce the requested size")
    return message


def boundary_cases(
    limit: int,
    *,
    sender: str = "size-sender@sender.test",
    recipient: str = "size-recipient@receiver.test",
) -> Iterator[CorpusCase]:
    for label, size in (
        ("limit-minus-one", limit - 1),
        ("limit", limit),
        ("limit-plus-one", limit + 1),
    ):
        case_id = f"size-{label}-{limit}"
        encoded = build_boundary_message(
            size, sender=sender, recipient=recipient, test_id=case_id
        )
        yield CorpusCase(
            case_id=case_id,
            features=("size-boundary", label),
            rfc822_bytes=encoded,
            smtp_utf8_required=False,
        )
