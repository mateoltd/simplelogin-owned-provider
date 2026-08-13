from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from mail_edge.contracts import (
    Envelope,
    InboundRawMessage,
    OutboundSubmission,
    normalize_domain,
)
from mail_edge.errors import ContractError
from mail_edge.ids import deterministic_uuid7, require_uuid7, uuid7


def test_uuid7_version_variant_and_ordering():
    values = [uuid7(now_ms=1_700_000_000_000) for _ in range(100)]
    assert values == sorted(values)
    assert all(value.version == 7 for value in values)
    assert all(value.variant == uuid.RFC_4122 for value in values)
    assert len(set(values)) == len(values)


def test_deterministic_uuid7_is_stable_and_material_bound():
    first = deterministic_uuid7(1_700_000_000_000, b"provider-token")
    assert first == deterministic_uuid7(1_700_000_000_000, b"provider-token")
    assert first != deterministic_uuid7(1_700_000_000_000, b"other-token")
    assert require_uuid7(str(first)) == str(first)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Aliases.Example.", "aliases.example"),
        ("münich.example", "xn--mnich-kva.example"),
    ],
)
def test_domain_normalization_is_exact(value, expected):
    assert normalize_domain(value) == expected


@pytest.mark.parametrize("value", ["example", "*.example", ".example", "a..example"])
def test_invalid_or_wildcard_domains_are_rejected(value):
    with pytest.raises(ContractError):
        normalize_domain(value)


def test_raw_contract_keeps_bytes_and_hash_exact():
    raw = b"From: a@aliases.example\r\nContent-Type: text/plain\r\n\r\n\xff\x00body\r\n"
    message_id = str(uuid7())
    notice_id = str(uuid7())
    message = InboundRawMessage(
        message_id=message_id,
        notice_id=notice_id,
        domain="aliases.example",
        binding_generation=2,
        envelope=Envelope("sender@outside.example", ("alias@aliases.example",)),
        raw_mime=raw,
    )
    assert message.raw_mime == raw
    assert message.metadata()["raw_size"] == len(raw)


def test_outbound_requires_exact_envelope_sender_domain():
    with pytest.raises(ContractError):
        OutboundSubmission(
            submission_id=str(uuid7()),
            domain="aliases.example",
            binding_generation=1,
            envelope=Envelope("bounce@other.example", ("recipient@outside.example",)),
            raw_mime=b"From: alias@aliases.example\r\n\r\nbody\r\n",
        )


def test_neutral_contract_module_has_no_product_or_provider_payload_dependency():
    source = Path(__file__).parents[1] / "src/mail_edge/contracts.py"
    text = source.read_text(encoding="utf-8")
    assert "import app" not in text
    assert "email_handler" not in text
    assert "mailgun" not in text.lower()
    assert "amazon ses" not in text.lower()
