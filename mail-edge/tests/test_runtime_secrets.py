from __future__ import annotations

import base64
import json
import os

import pytest

from mail_edge.errors import ConfigurationError
from mail_edge.runtime import build_runtime, read_secret_file


def _secret(path, payload: bytes) -> str:
    path.write_bytes(payload)
    path.chmod(0o600)
    return str(path)


def test_secret_file_permissions_fail_closed(tmp_path):
    path = tmp_path / "secret"
    path.write_text("value", encoding="utf-8")
    path.chmod(0o644)
    with pytest.raises(ConfigurationError, match="group/world"):
        read_secret_file(str(path))


def test_runtime_loads_database_blob_and_provider_credentials_only_from_files(
    tmp_path, monkeypatch
):
    database_url = _secret(
        tmp_path / "database-url", f"sqlite://{tmp_path / 'edge.sqlite'}".encode()
    )
    blob_keys = _secret(
        tmp_path / "blob-keys",
        json.dumps(
            {
                "active_key_id": "key-1",
                "keys": {"key-1": base64.b64encode(b"k" * 32).decode()},
            }
        ).encode(),
    )
    credentials = _secret(
        tmp_path / "provider-credentials",
        json.dumps(
            {
                "mailgun-test": {
                    "smtp_username": "user",
                    "smtp_password": "password",
                    "webhook_signing_key": "webhook",
                }
            }
        ).encode(),
    )
    salt = _secret(tmp_path / "salt", b"diagnostic-salt-32-bytes-value")
    monkeypatch.setenv("MAIL_EDGE_DATABASE_URL_FILE", database_url)
    monkeypatch.setenv("MAIL_EDGE_BLOB_KEYS_FILE", blob_keys)
    monkeypatch.setenv("MAIL_EDGE_PROVIDER_CREDENTIALS_FILE", credentials)
    monkeypatch.setenv("MAIL_EDGE_DIAGNOSTIC_SALT_FILE", salt)
    monkeypatch.setenv("MAIL_EDGE_BLOB_ROOT", str(tmp_path / "blobs"))
    runtime = build_runtime()
    assert runtime.database.url.startswith("sqlite:")
    assert runtime.provider_credentials["mailgun-test"]["smtp_password"] == "password"
    assert os.stat(tmp_path / "blobs").st_mode & 0o777 == 0o700
