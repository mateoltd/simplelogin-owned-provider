"""Semantic MIME comparison with an exact transport-header allowlist."""

from __future__ import annotations

import hashlib
import re
import urllib.parse
from dataclasses import dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser
from typing import Iterable


# These are transport artifacts, not provider identities. Date and Message-ID are
# deliberately absent and must be opted into by a qualification run.
DEFAULT_TRANSPORT_HEADERS = frozenset(
    {
        "arc-authentication-results",
        "arc-message-signature",
        "arc-seal",
        "authentication-results",
        "dkim-signature",
        "received",
        "return-path",
    }
)

_STRUCTURAL_HEADERS = frozenset(
    {
        "content-disposition",
        "content-id",
        "content-transfer-encoding",
        "content-type",
        "mime-version",
    }
)
_VISIBLE_HEADERS = ("from", "reply-to", "to", "cc", "subject")
_THREAD_HEADERS = ("message-id", "in-reply-to", "references")
_CID_REFERENCE = re.compile(rb"cid:([^\s\"'<>\)]+)", re.IGNORECASE)


@dataclass(frozen=True)
class TransportHeaderPolicy:
    allowed: frozenset[str] = DEFAULT_TRANSPORT_HEADERS

    def __post_init__(self) -> None:
        normalized = frozenset(name.strip().lower() for name in self.allowed)
        if normalized != self.allowed:
            object.__setattr__(self, "allowed", normalized)
        if any(not name or "*" in name for name in normalized):
            raise ValueError(
                "transport headers must be explicit names, never wildcards"
            )

    @classmethod
    def with_additional(cls, names: Iterable[str]) -> "TransportHeaderPolicy":
        return cls(
            DEFAULT_TRANSPORT_HEADERS | frozenset(name.lower() for name in names)
        )


@dataclass(frozen=True)
class PartSemantic:
    path: tuple[int, ...]
    content_type: str
    content_parameters: tuple[tuple[str, str], ...]
    disposition: str | None
    filename: str | None
    content_id: str | None
    decoded_sha256: str | None
    decoded_size: int | None
    other_headers: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class MessageSemantic:
    headers: tuple[tuple[str, str], ...]
    parts: tuple[PartSemantic, ...]
    attachment_hashes: tuple[tuple[tuple[int, ...], str | None, str, str, int], ...]
    cid_graph: tuple[tuple[str, str, tuple[tuple[int, ...], ...]], ...]
    visible_identity: tuple[tuple[str, tuple[str, ...]], ...]
    threading: tuple[tuple[str, tuple[str, ...]], ...]


@dataclass(frozen=True)
class SemanticDifference:
    category: str
    location: str
    expected: object
    actual: object


@dataclass(frozen=True)
class SemanticComparison:
    equivalent: bool
    violations: tuple[SemanticDifference, ...]
    allowed_transport_mutations: tuple[SemanticDifference, ...]
    expected: MessageSemantic
    actual: MessageSemantic

    def require_equivalent(self) -> None:
        if self.equivalent:
            return
        detail = "; ".join(
            f"{item.category} at {item.location}: {item.expected!r} != {item.actual!r}"
            for item in self.violations
        )
        raise AssertionError(detail)


def compare_messages(
    expected_bytes: bytes,
    actual_bytes: bytes,
    transport_policy: TransportHeaderPolicy | None = None,
) -> SemanticComparison:
    header_policy = transport_policy or TransportHeaderPolicy()
    expected_message = BytesParser(policy=policy.default).parsebytes(expected_bytes)
    actual_message = BytesParser(policy=policy.default).parsebytes(actual_bytes)
    expected = describe_message(expected_message, header_policy)
    actual = describe_message(actual_message, header_policy)
    violations: list[SemanticDifference] = []

    _compare("headers", "root", expected.headers, actual.headers, violations)
    _compare("mime_topology", "message", expected.parts, actual.parts, violations)
    _compare(
        "attachment_hashes",
        "message",
        expected.attachment_hashes,
        actual.attachment_hashes,
        violations,
    )
    _compare(
        "content_id_graph", "message", expected.cid_graph, actual.cid_graph, violations
    )
    _compare(
        "visible_identity",
        "root",
        expected.visible_identity,
        actual.visible_identity,
        violations,
    )
    _compare("threading", "root", expected.threading, actual.threading, violations)

    allowed = _transport_mutations(expected_message, actual_message, header_policy)
    return SemanticComparison(
        equivalent=not violations,
        violations=tuple(violations),
        allowed_transport_mutations=allowed,
        expected=expected,
        actual=actual,
    )


def describe_message(
    message: Message, transport_policy: TransportHeaderPolicy | None = None
) -> MessageSemantic:
    header_policy = transport_policy or TransportHeaderPolicy()
    parts: list[PartSemantic] = []
    attachments: list[tuple[tuple[int, ...], str | None, str, str, int]] = []
    content_ids: dict[str, list[tuple[int, ...]]] = {}
    cid_references: dict[str, str] = {}

    def visit(part: Message, path: tuple[int, ...]) -> None:
        content_id = _normalize_content_id(part.get("Content-ID"))
        if content_id is not None:
            content_ids.setdefault(content_id, []).append(path)
        payload: bytes | None = None
        decoded_sha256: str | None = None
        decoded_size: int | None = None
        is_mime_container = part.get_content_maintype().lower() == "multipart"
        if not is_mime_container:
            decoded = part.get_payload(decode=True)
            if decoded is None:
                raw = part.get_payload()
                if isinstance(raw, str):
                    charset = part.get_content_charset() or "utf-8"
                    payload = raw.encode(charset, errors="surrogateescape")
                elif isinstance(raw, list):
                    payload = b"".join(
                        child.as_bytes(policy=policy.SMTP) for child in raw
                    )
                else:
                    payload = b""
            else:
                payload = decoded
            decoded_sha256 = hashlib.sha256(payload).hexdigest()
            decoded_size = len(payload)
            if part.get_content_type().lower() == "text/html":
                for match in _CID_REFERENCE.findall(payload):
                    reference = urllib.parse.unquote_to_bytes(
                        match.decode("ascii", "ignore")
                    )
                    normalized = (
                        reference.decode("utf-8", "replace").strip("<>").casefold()
                    )
                    cid_references[normalized] = hashlib.sha256(payload).hexdigest()

        content_parameters = tuple(
            sorted(
                (str(key).lower(), str(value))
                for key, value in (part.get_params(header="content-type") or [])[1:]
                if str(key).lower() != "boundary"
            )
        )
        other_headers = tuple(
            (name.lower(), _normalize_header_value(str(value)))
            for name, value in part.raw_items()
            if name.lower() not in _STRUCTURAL_HEADERS
            and name.lower() not in header_policy.allowed
            and path
        )
        semantic = PartSemantic(
            path=path,
            content_type=part.get_content_type().lower(),
            content_parameters=content_parameters,
            disposition=part.get_content_disposition(),
            filename=part.get_filename(),
            content_id=content_id,
            decoded_sha256=decoded_sha256,
            decoded_size=decoded_size,
            other_headers=other_headers,
        )
        parts.append(semantic)
        if payload is not None and (
            part.get_content_disposition() == "attachment"
            or part.get_filename() is not None
        ):
            attachments.append(
                (
                    path,
                    part.get_filename(),
                    part.get_content_type().lower(),
                    hashlib.sha256(payload).hexdigest(),
                    len(payload),
                )
            )
        if part.is_multipart():
            for index, child in enumerate(part.iter_parts()):
                visit(child, path + (index,))

    visit(message, ())
    cid_graph = tuple(
        sorted(
            (
                reference,
                cid_references[reference],
                tuple(content_ids.get(reference, ())),
            )
            for reference in cid_references
        )
    )
    return MessageSemantic(
        headers=_semantic_headers(message, header_policy),
        parts=tuple(parts),
        attachment_hashes=tuple(attachments),
        cid_graph=cid_graph,
        visible_identity=tuple(
            (
                name,
                tuple(
                    _normalize_header_value(str(value))
                    for value in message.get_all(name, ())
                ),
            )
            for name in _VISIBLE_HEADERS
        ),
        threading=tuple(
            (
                name,
                (
                    ()
                    if name in header_policy.allowed
                    else tuple(
                        _normalize_header_value(str(value))
                        for value in message.get_all(name, ())
                    )
                ),
            )
            for name in _THREAD_HEADERS
        ),
    )


def _semantic_headers(
    message: Message, header_policy: TransportHeaderPolicy
) -> tuple[tuple[str, str], ...]:
    return tuple(
        (name.lower(), _normalize_header_value(str(value)))
        for name, value in message.raw_items()
        if name.lower() not in _STRUCTURAL_HEADERS
        and name.lower() not in header_policy.allowed
    )


def _transport_mutations(
    expected: Message, actual: Message, header_policy: TransportHeaderPolicy
) -> tuple[SemanticDifference, ...]:
    changes: list[SemanticDifference] = []
    for name in sorted(header_policy.allowed):
        before = tuple(
            _normalize_header_value(str(value)) for value in expected.get_all(name, ())
        )
        after = tuple(
            _normalize_header_value(str(value)) for value in actual.get_all(name, ())
        )
        if before != after:
            changes.append(SemanticDifference("transport_header", name, before, after))
    return tuple(changes)


def _normalize_content_id(value: object | None) -> str | None:
    if value is None:
        return None
    return str(value).strip().strip("<>").casefold()


def _normalize_header_value(value: str) -> str:
    return " ".join(value.split())


def _compare(
    category: str,
    location: str,
    expected: object,
    actual: object,
    differences: list[SemanticDifference],
) -> None:
    if expected != actual:
        differences.append(SemanticDifference(category, location, expected, actual))
