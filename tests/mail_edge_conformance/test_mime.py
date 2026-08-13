from mail_edge_conformance.mime import (
    TransportHeaderPolicy,
    compare_messages,
)


BASE = (
    b"From: Sender <sender@sender.test>\r\n"
    b"To: Receiver <receiver@receiver.test>\r\n"
    b"Subject: semantic body\r\n"
    b"Date: Thu, 13 Aug 2026 12:00:00 +0000\r\n"
    b"Message-ID: <semantic@sender.test>\r\n"
    b"X-Duplicate: one\r\n"
    b"X-Duplicate: two\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
    b"caf=C3=A9\r\n"
)


def test_transport_allowlist_is_exact_and_date_is_not_implicit():
    with_received = b"Received: by receiver.test\r\n" + BASE
    result = compare_messages(BASE, with_received)
    assert result.equivalent
    assert [item.location for item in result.allowed_transport_mutations] == [
        "received"
    ]

    changed_date = BASE.replace(b"12:00:00", b"12:01:00")
    result = compare_messages(BASE, changed_date)
    assert not result.equivalent
    assert {item.category for item in result.violations} >= {
        "headers",
    }
    assert compare_messages(
        BASE,
        changed_date,
        TransportHeaderPolicy.with_additional(("date",)),
    ).equivalent

    with_bcc = b"Bcc: receiver@receiver.test\r\n" + BASE
    assert not compare_messages(BASE, with_bcc).equivalent
    assert compare_messages(
        BASE,
        with_bcc,
        TransportHeaderPolicy.with_additional(("bcc",)),
    ).equivalent


def test_decoded_body_is_equal_across_transfer_encodings():
    base64_message = BASE.replace(
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\ncaf=C3=A9",
        b"Content-Transfer-Encoding: base64\r\n\r\nY2Fmw6kNCg==",
    )
    assert compare_messages(BASE, base64_message).equivalent


def test_duplicate_header_order_and_body_mutation_fail():
    reordered = BASE.replace(
        b"X-Duplicate: one\r\nX-Duplicate: two",
        b"X-Duplicate: two\r\nX-Duplicate: one",
    )
    assert not compare_messages(BASE, reordered).equivalent
    mutated = BASE.replace(b"caf=C3=A9", b"caf=C3=A8")
    comparison = compare_messages(BASE, mutated)
    assert not comparison.equivalent
    assert any(item.category == "mime_topology" for item in comparison.violations)


def test_wildcard_transport_headers_are_forbidden():
    try:
        TransportHeaderPolicy(frozenset({"x-provider-*"}))
    except ValueError as error:
        assert "never wildcards" in str(error)
    else:
        raise AssertionError("wildcard transport allowlist was accepted")
