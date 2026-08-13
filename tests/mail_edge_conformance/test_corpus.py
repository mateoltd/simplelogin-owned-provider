from email import policy
from email.parser import BytesParser

from mail_edge_conformance.corpus import (
    boundary_cases,
    build_boundary_message,
    load_corpus,
)


def test_real_eml_corpus_covers_required_shapes():
    cases = load_corpus()
    features = {feature for case in cases for feature in case.features}
    assert len(cases) == 14
    assert {
        "multipart-alternative",
        "multipart-related",
        "content-id",
        "text-calendar",
        "utf8-headers",
        "utf8-local-parts",
        "7bit",
        "8bit",
        "quoted-printable",
        "base64",
        "binary",
        "long-headers",
        "folded-headers",
        "duplicate-headers",
        "message-rfc822",
        "mime-boundary-70",
        "pgp-mime",
        "smime",
        "reverse-alias",
    } <= features
    for case in cases:
        message = BytesParser(policy=policy.default).parsebytes(case.rfc822_bytes)
        assert message["From"]
        assert message["To"]
        assert message["Message-ID"]


def test_boundary_generator_produces_exact_wire_sizes():
    for size in (512, 4095, 4096, 4097):
        encoded = build_boundary_message(size, test_id=f"size-{size}")
        assert len(encoded) == size
        message = BytesParser(policy=policy.default).parsebytes(encoded)
        assert message["X-Mail-Edge-Test-ID"] == f"size-{size}"
    assert [len(case.rfc822_bytes) for case in boundary_cases(4096)] == [
        4095,
        4096,
        4097,
    ]
