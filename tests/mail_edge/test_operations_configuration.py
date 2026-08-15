import copy
import json
import sys
from pathlib import Path


SCRIPTS = Path(__file__).parents[2] / "ops" / "owned-provider" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from mail_edge_config import (  # noqa: E402
    MAIL_EDGE_SECRET_NAMES,
    audit_mail_edge_document,
    build_mail_edge_document,
    referenced_secret_names,
)

from app.mail_edge.configuration import load_mail_edge_configuration  # noqa: E402


def _values(**overrides):
    values = {
        "OWNED_PROVIDER_SMTP_SIZE_LIMIT": "26214400",
        "OWNED_PROVIDER_GUNICORN_WORKERS": "2",
        "OWNED_PROVIDER_APP_MEMORY_LIMIT": "1536m",
    }
    values.update(overrides)
    return values


def _runtime(tmp_path):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    for index, name in enumerate(sorted(MAIL_EDGE_SECRET_NAMES), start=1):
        (secrets / name).write_text(f"{index:02d}" * 32)
        (secrets / name).chmod(0o600)
    return tmp_path


def test_operations_document_is_deterministic_and_accepted_by_host(tmp_path):
    runtime = _runtime(tmp_path)
    first = build_mail_edge_document(_values())
    second = build_mail_edge_document(_values())
    assert first == second
    assert referenced_secret_names(first) == {
        "mail_edge_tenant_bearer",
        "mail_edge_opaque_token_key",
        "mail_edge_host_key_current",
        "mail_edge_operator_bearer",
        "mail_edge_privileged_operator_bearer",
    }

    loadable = copy.deepcopy(first)
    loadable["secretDirectory"] = str(runtime / "secrets")
    loadable["hostDelivery"]["spoolDirectory"] = str(runtime)
    config_path = runtime / "mail-edge.json"
    config_path.write_text(json.dumps(loadable))
    configuration = load_mail_edge_configuration(str(config_path))
    assert configuration.maximum_raw_bytes == 26_214_400
    assert configuration.host_delivery.maximum_process_rss_bytes == 536_870_912
    assert configuration.host_authentication.verification_keys == {
        "host-key-current": (runtime / "secrets" / "mail_edge_host_key_current")
        .read_text()
        .encode()
    }


def test_operations_audit_rejects_cross_budget_and_unmanaged_secret(tmp_path):
    runtime = _runtime(tmp_path)
    values = _values()
    document = build_mail_edge_document(values)
    assert audit_mail_edge_document(document, values, runtime, production=False) == []

    unsafe = copy.deepcopy(document)
    unsafe["hostDelivery"]["maximumProcessRssBytes"] = 200_000_000
    unsafe["bearerToken"] = "secret://unmanaged"
    failures = audit_mail_edge_document(unsafe, values, runtime, production=False)
    assert "Mail Edge RSS ceiling is smaller than one maximum message" in failures
    assert any("unmanaged secrets" in failure for failure in failures)


def test_operations_document_supports_bounded_verification_key_overlap():
    document = build_mail_edge_document(
        _values(
            OWNED_PROVIDER_MAIL_EDGE_HOST_KEY_ID="host-key-2026-08",
            OWNED_PROVIDER_MAIL_EDGE_PREVIOUS_HOST_KEY_ID="host-key-2026-07",
        )
    )
    assert document["hostAuthentication"]["verificationKeys"] == {
        "host-key-2026-08": "secret://mail_edge_host_key_current",
        "host-key-2026-07": "secret://mail_edge_host_key_previous",
    }
