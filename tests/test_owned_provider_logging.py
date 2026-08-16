import sys
from pathlib import Path

SCRIPTS = Path(__file__).parents[1] / "ops" / "owned-provider" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from log_wrapper import redact, sensitive_kinds  # noqa: E402


def test_redact_removes_email_ipv4_ipv6_and_authorization_material():
    raw = (
        "user=person@example.com peer=203.0.113.8 "
        "v6=[2001:db8::5]:443 Authorization: Bearer short-jwt-value"
    )

    redacted = redact(raw, [])

    assert "person@example.com" not in redacted
    assert "203.0.113.8" not in redacted
    assert "2001:db8::5" not in redacted
    assert "short-jwt-value" not in redacted
    assert sensitive_kinds(redacted) == set()


def test_redact_removes_each_line_of_a_multiline_secret():
    secrets = [
        "-----BEGIN PRIVATE KEY-----",
        "sensitive-base64-material",
        "-----END PRIVATE KEY-----",
    ]
    redacted = redact(" | ".join(secrets), secrets)

    assert all(secret not in redacted for secret in secrets)
    assert sensitive_kinds(redacted) == set()


def test_sensitive_scan_fails_closed_on_unredacted_fields():
    assert sensitive_kinds("mail person@example.com") == {"email"}
    assert sensitive_kinds("source 192.168.1.151") == {"ip"}
    assert sensitive_kinds("peer 2001:db8::1") == {"ip"}
    assert sensitive_kinds("api_key=not-redacted") == {"auth"}
    assert sensitive_kinds("token=" + "a" * 64) == {"auth", "token"}


def test_redact_removes_json_auth_fields_and_basic_credentials():
    raw = '{"token": "short-value", "authorization": "Basic dXNlcjpwYXNz"}'

    redacted = redact(raw, [])

    assert "short-value" not in redacted
    assert "dXNlcjpwYXNz" not in redacted
    assert sensitive_kinds(redacted) == set()
