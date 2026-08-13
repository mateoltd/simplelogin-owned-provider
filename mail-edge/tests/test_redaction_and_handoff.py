from __future__ import annotations

import pytest

from mail_edge.errors import ConfigurationError
from mail_edge.handoff import HTTPSHandoffSink
from mail_edge.redaction import bounded_diagnostics, redact_text


def test_redaction_removes_secrets_emails_ips_newlines_and_bounds_output():
    secret = "super-secret-provider-token"
    value = (
        f"failure for Person@Example.com from 192.0.2.44 token={secret}\n" + "x" * 1000
    )
    redacted = redact_text(
        value, salt=b"diagnostic-salt-123", known_secrets=(secret,), limit=120
    )
    assert "Person@Example.com" not in redacted
    assert "192.0.2.44" not in redacted
    assert secret not in redacted
    assert "\n" not in redacted
    assert len(redacted) <= 120


def test_diagnostics_have_bounded_count_keys_and_values():
    values = {f"Key {index}": "a@example.test " + "x" * 500 for index in range(20)}
    result = bounded_diagnostics(values, salt=b"diagnostic-salt-123")
    assert len(result) == 8
    assert all(len(key) <= 32 for key in result)
    assert all(len(value) <= 256 for value in result.values())


def test_handoff_refuses_cleartext_endpoint():
    with pytest.raises(ConfigurationError, match="HTTPS"):
        HTTPSHandoffSink("http://127.0.0.1/messages", "token")
