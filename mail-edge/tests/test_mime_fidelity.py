from __future__ import annotations

import json

import pytest

from mail_edge.mailgun.outbound import MailgunOutboundAdapter

from .conftest import NOW, outbound
from .fakes import FakeTransport, response
from .test_outbound import multipart_parts


def mime_fixture(content_type: bytes, body: bytes, message_id: str) -> bytes:
    return (
        b"From: Alias <alias@edge.example.test>\r\n"
        b"To: Contact <contact@recipient.example>\r\n"
        b"Subject: fidelity\r\n"
        + f"Message-ID: <{message_id}@edge.example.test>\r\n".encode()
        + b"MIME-Version: 1.0\r\nContent-Type: "
        + content_type
        + b"\r\n\r\n"
        + body
    )


FIDELITY_MESSAGES = [
    mime_fixture(
        b'multipart/mixed; boundary="mix"',
        b"--mix\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
        + "hello π\r\n".encode()
        + b"--mix\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=blob.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAAECAwQF\r\n--mix--\r\n",
        "attachment",
    ),
    mime_fixture(
        b'multipart/related; boundary="rel"',
        b'--rel\r\nContent-Type: text/html\r\n\r\n<img src="cid:image-1">\r\n'
        b"--rel\r\nContent-Type: image/png\r\nContent-ID: <image-1>\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n--rel--\r\n",
        "cid",
    ),
    mime_fixture(
        b"text/calendar; method=REQUEST; charset=utf-8",
        b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:opaque\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        "calendar",
    ),
    mime_fixture(
        b'multipart/encrypted; protocol="application/pgp-encrypted"; boundary="pgp"',
        b"--pgp\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n"
        b"--pgp\r\nContent-Type: application/octet-stream\r\n\r\n-----BEGIN PGP MESSAGE-----\r\nopaque\r\n-----END PGP MESSAGE-----\r\n--pgp--\r\n",
        "pgp",
    ),
    mime_fixture(
        b"application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m",
        b"Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=smime.p7m\r\n\r\nTUlJQm9wYXF1ZQ==\r\n",
        "smime",
    ),
]


@pytest.mark.parametrize("raw", FIDELITY_MESSAGES)
def test_prebuilt_mime_is_byte_exact_at_provider_boundary(registry, ledger, raw):
    transport = FakeTransport(
        response(200, json.dumps({"id": "<provider@mg>"}).encode())
    )
    adapter = MailgunOutboundAdapter(
        registry, transport, ledger, clock=lambda: NOW, sleeper=lambda _delay: None
    )
    result = adapter.submit(outbound(edge_id=f"fidelity-{len(raw)}", raw=raw))
    assert result.disposition.value == "ACCEPTED"
    assert multipart_parts(transport.requests[0])["message"] == [raw]
