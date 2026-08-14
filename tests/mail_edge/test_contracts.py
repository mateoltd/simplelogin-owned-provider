import hashlib

import pytest

from app.mail_edge.contracts import (
    canonical_domain,
    canonical_mailbox,
    compile_header_patch_plan,
    parse_application_feedback,
    parse_raw_message_ref,
    parse_smtp_envelope,
)
from app.mail_edge.errors import MailEdgeContractError


TENANT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401111"


def test_domain_is_exact_canonical_alabel_and_local_part_preserves_case():
    assert canonical_domain("example.com") == "example.com"
    assert canonical_mailbox("CaseSensitive@example.com") == (
        "CaseSensitive@example.com",
        "CaseSensitive",
        "example.com",
    )
    assert canonical_mailbox('"quoted local"@Example.COM') == (
        '"quoted local"@example.com',
        '"quoted local"',
        "example.com",
    )
    for invalid in ("Example.com", "*.example.com", "example.com."):
        with pytest.raises(MailEdgeContractError):
            canonical_domain(invalid)
    with pytest.raises(MailEdgeContractError):
        canonical_mailbox("alias@bad_domain.example")


def test_raw_reference_is_immutable_bounded_and_exact():
    reference = parse_raw_message_ref(
        {
            "schemaVersion": "v1",
            "blobId": TENANT_ID,
            "sha256": hashlib.sha256(b"message").hexdigest(),
            "size": 7,
            "mediaType": "message/rfc822",
        }
    )
    assert reference.size == 7
    with pytest.raises(MailEdgeContractError):
        parse_raw_message_ref({**dict(reference.to_wire()), "size": 26 * 1024 * 1024})


def test_envelope_rejects_duplicate_recipients_but_not_local_part_case_variants():
    value = {
        "schemaVersion": "v1",
        "mailFrom": None,
        "rcptTo": [{"address": "Alias@example.com"}, {"address": "alias@example.com"}],
        "smtpUtf8": False,
    }
    assert len(parse_smtp_envelope(value).rcpt_to) == 2
    value["rcptTo"].append({"address": "Alias@example.com"})
    with pytest.raises(MailEdgeContractError):
        parse_smtp_envelope(value)


def test_dsn_is_validated_and_canonicalized_to_contract_order():
    envelope = parse_smtp_envelope(
        {
            "schemaVersion": "v1",
            "mailFrom": None,
            "rcptTo": [
                {
                    "address": "alias@example.com",
                    "dsn": {
                        "notify": ["delay", "success", "failure"],
                        "originalRecipient": "rfc822;alias@example.com",
                    },
                }
            ],
            "smtpUtf8": False,
            "dsn": {"ret": "headers", "envelopeId": "visible+2Btoken"},
        }
    )
    assert envelope.rcpt_to[0].dsn["notify"] == ["success", "failure", "delay"]
    for bad in ("alias@example.com", "rfc822;bad space@example.com"):
        value = dict(envelope.to_wire())
        value["rcptTo"] = [
            {"address": "alias@example.com", "dsn": {"originalRecipient": bad}}
        ]
        with pytest.raises(MailEdgeContractError):
            parse_smtp_envelope(value)


def test_default_reverse_plan_preserves_thread_headers_by_forbidding_mutation():
    digest = hashlib.sha256(b"source").hexdigest()
    plan = compile_header_patch_plan(
        ["From: alias@example.com", "To: sender@example.net"], digest
    )
    assert [operation["name"] for operation in plan["operations"]] == ["from", "to"]
    for name in ("Message-ID", "In-Reply-To", "References"):
        with pytest.raises(MailEdgeContractError):
            compile_header_patch_plan([f"{name}: <thread@example.com>"], digest)


def test_malformed_nested_values_fail_as_typed_contract_errors():
    envelope = {
        "schemaVersion": "v1",
        "mailFrom": None,
        "rcptTo": [{"address": "alias@example.com", "dsn": {"notify": [{}]}}],
        "smtpUtf8": False,
    }
    feedback = {
        "schemaVersion": "v1",
        "feedbackEventId": TENANT_ID,
        "tenantId": TENANT_ID,
        "intentId": TENANT_ID,
        "kind": {},
        "occurredAt": "2026-08-13T12:00:00Z",
        "normalizedEvidence": {},
    }
    for operation in (
        lambda: parse_smtp_envelope(envelope),
        lambda: parse_application_feedback(feedback),
        lambda: compile_header_patch_plan([], None),
    ):
        with pytest.raises(MailEdgeContractError):
            operation()
