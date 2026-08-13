from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import ssl
import threading
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
from urllib.parse import quote_from_bytes

from conftest import active_binding
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from mail_edge.contracts import BindingDirection
from mail_edge.http_service import HookHandler
from mail_edge.runtime import Runtime


def _certificate(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    certificate_path = tmp_path / "hook-cert.pem"
    key_path = tmp_path / "hook-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    return certificate_path, key_path


def _form(now: datetime, raw: bytes, token: str = "w" * 50) -> bytes:
    timestamp = str(int(now.timestamp()))
    signature = hmac.new(
        b"webhook-key", f"{timestamp}{token}".encode(), hashlib.sha256
    ).hexdigest()
    values = {
        "timestamp": timestamp.encode(),
        "token": token.encode(),
        "signature": signature.encode(),
        "sender": b"sender@outside.example",
        "recipient": b"alias@aliases.example",
        "message-headers": json.dumps(
            [["Message-ID", "<message@outside.example>"]]
        ).encode(),
        "body-mime": raw,
    }
    return b"&".join(
        quote_from_bytes(key.encode()).encode()
        + b"="
        + quote_from_bytes(value).encode()
        for key, value in values.items()
    )


def test_tls_hook_commits_raw_mime_before_200_and_deduplicates_retry(edge, tmp_path):
    binding = active_binding(edge, BindingDirection.INBOUND)
    runtime = Runtime(
        database=edge["database"],
        blobs=edge["blobs"],
        registry=edge["registry"],
        bindings=edge["bindings"],
        repository=edge["repository"],
        provider_credentials={
            "mailgun-test": {
                "smtp_username": "smtp-user",
                "smtp_password": "smtp-password",
                "webhook_signing_key": "webhook-key",
            }
        },
        diagnostic_salt=b"test-diagnostic-salt-32-bytes!!",
    )
    handler = type("TestHookHandler", (HookHandler,), {"runtime": runtime})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    certificate, key = _certificate(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    raw = (
        b"From: sender@outside.example\r\nContent-Type: text/plain\r\n\r\nbody\xff\r\n"
    )
    body = _form(datetime.now(UTC), raw)
    try:
        responses = []
        for _ in range(2):
            connection = http.client.HTTPSConnection(
                "127.0.0.1",
                server.server_port,
                context=ssl._create_unverified_context(),
                timeout=5,
            )
            connection.request(
                "POST",
                f"/v1/hooks/mailgun/inbound/{binding.id}/raw-mime",
                body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response = connection.getresponse()
            responses.append((response.status, json.loads(response.read())))
            connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert responses[0][0] == 200
    assert responses[1][0] == 200
    assert responses[0][1]["message_id"] == responses[1][1]["message_id"]
    with edge["database"].transaction() as connection:
        row = connection.execute(
            "SELECT raw_blob_key, raw_sha256, state FROM ingress_messages"
        ).fetchone()
        count = connection.execute(
            "SELECT COUNT(*) AS count FROM ingress_messages"
        ).fetchone()["count"]
    assert count == 1
    assert row["state"] == "ready"
    assert edge["blobs"].get(row["raw_blob_key"]) == raw
    assert row["raw_sha256"] == hashlib.sha256(raw).hexdigest()
