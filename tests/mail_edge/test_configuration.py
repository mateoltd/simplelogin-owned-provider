import json

import pytest

from app.mail_edge.configuration import load_mail_edge_configuration
from app.mail_edge.errors import MailEdgeConfigurationError


TENANT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401111"


def _document(secret_directory):
    return {
        "schemaVersion": "v1",
        "tenantId": TENANT_ID,
        "baseUrl": "http://mail-edge.internal:8080",
        "secretDirectory": str(secret_directory),
        "bearerToken": "secret://tenant-bearer",
        "opaqueTokenKey": "secret://opaque-token",
        "maximumRawBytes": 26214400,
        "http": {
            "connectSeconds": 1,
            "readSeconds": 5,
            "concurrency": 16,
            "breakerFailures": 3,
            "breakerResetSeconds": 10,
            "preDispatchRetries": 1,
        },
        "hostAuthentication": {
            "audience": "simplelogin-host",
            "maximumAgeSeconds": 300,
            "maximumFutureSkewSeconds": 30,
            "verificationKeys": {"host-key-1": "secret://host-key-1"},
        },
    }


def test_versioned_config_resolves_secret_references(tmp_path):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "tenant-bearer").write_text("b" * 32)
    (secrets / "opaque-token").write_text("o" * 32)
    (secrets / "host-key-1").write_text("h" * 32)
    path = tmp_path / "mail-edge.json"
    path.write_text(json.dumps(_document(secrets)))
    config = load_mail_edge_configuration(str(path))
    assert config.tenant_id == TENANT_ID
    assert config.bearer_token == "b" * 32
    assert config.opaque_token_key == b"o" * 32
    assert config.host_authentication.verification_keys == {"host-key-1": b"h" * 32}
    assert config.http.maximum_json_bytes == 1024 * 1024
    assert config.host_authentication.maximum_request_bytes == 1024 * 1024


def test_operator_credentials_are_separate_scopes_and_cannot_be_reused(tmp_path):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    values = {
        "tenant-bearer": "b" * 32,
        "opaque-token": "o" * 32,
        "host-key-1": "h" * 32,
        "operator": "u" * 32,
        "privileged-operator": "p" * 32,
    }
    for name, value in values.items():
        (secrets / name).write_text(value)
    document = _document(secrets)
    document["operatorAuthentication"] = {
        "operatorBearerToken": "secret://operator",
        "privilegedOperatorBearerToken": "secret://privileged-operator",
    }
    path = tmp_path / "mail-edge.json"
    path.write_text(json.dumps(document))
    config = load_mail_edge_configuration(str(path))
    assert config.operator_authentication.operator_bearer_token == "u" * 32
    assert config.operator_authentication.privileged_operator_bearer_token == "p" * 32

    document["operatorAuthentication"][
        "privilegedOperatorBearerToken"
    ] = "secret://operator"
    path.write_text(json.dumps(document))
    with pytest.raises(MailEdgeConfigurationError):
        load_mail_edge_configuration(str(path))


def test_config_rejects_inline_secret_unknown_fields_and_relative_path(tmp_path):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    for name in ("tenant-bearer", "opaque-token", "host-key-1"):
        (secrets / name).write_text("x" * 32)
    document = _document(secrets)
    path = tmp_path / "mail-edge.json"
    document["bearerToken"] = "inline-secret"
    path.write_text(json.dumps(document))
    with pytest.raises(MailEdgeConfigurationError):
        load_mail_edge_configuration(str(path))
    with pytest.raises(MailEdgeConfigurationError):
        load_mail_edge_configuration("relative.json")


def test_config_rejects_symlinked_secret(tmp_path):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    target = tmp_path / "bearer"
    target.write_text("b" * 32)
    (secrets / "tenant-bearer").symlink_to(target)
    (secrets / "opaque-token").write_text("o" * 32)
    (secrets / "host-key-1").write_text("h" * 32)
    path = tmp_path / "mail-edge.json"
    path.write_text(json.dumps(_document(secrets)))
    with pytest.raises(MailEdgeConfigurationError):
        load_mail_edge_configuration(str(path))


def test_config_rejects_duplicate_keys_non_finite_numbers_and_oversized_input(
    tmp_path,
):
    path = tmp_path / "mail-edge.json"
    for document in (
        b'{"schemaVersion":"v1","schemaVersion":"v1"}',
        b'{"schemaVersion":"v1","maximumRawBytes":NaN}',
        b"{" + b" " * (64 * 1024),
    ):
        path.write_bytes(document)
        with pytest.raises(MailEdgeConfigurationError):
            load_mail_edge_configuration(str(path))
