"""Build and audit the provider-neutral Mail Edge host configuration."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path
from typing import Mapping
from urllib.parse import urlparse


CONTAINER_CONFIG_PATH = "/run/mail-edge/config.json"
CONTAINER_SECRET_DIRECTORY = "/run/secrets"
CONTAINER_SPOOL_DIRECTORY = "/code/var/mail-edge-spool"
FIXTURE_TENANT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401111"
MAIL_EDGE_SECRET_NAMES = frozenset(
    {
        "mail_edge_tenant_bearer",
        "mail_edge_opaque_token_key",
        "mail_edge_host_key_current",
        "mail_edge_host_key_previous",
        "mail_edge_operator_bearer",
        "mail_edge_privileged_operator_bearer",
    }
)
ASCII_BEARER_SECRET_NAMES = frozenset(
    {
        "mail_edge_tenant_bearer",
        "mail_edge_operator_bearer",
        "mail_edge_privileged_operator_bearer",
    }
)
TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$")


def _integer(values: Mapping[str, str], name: str, default: int) -> int:
    raw = values.get(name, str(default))
    if not re.fullmatch(r"[0-9]+", raw):
        raise ValueError(f"{name} must be an unsigned integer")
    return int(raw)


def _number(values: Mapping[str, str], name: str, default: float) -> float:
    raw = values.get(name, str(default))
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", raw):
        raise ValueError(f"{name} must be a finite non-negative number")
    return float(raw)


def _enabled(values: Mapping[str, str], name: str, default: bool) -> bool:
    raw = values.get(name, "1" if default else "0")
    if raw not in {"0", "1"}:
        raise ValueError(f"{name} must be 0 or 1")
    return raw == "1"


def _token(values: Mapping[str, str], name: str, default: str) -> str:
    value = values.get(name, default)
    if not TOKEN.fullmatch(value):
        raise ValueError(f"{name} is not a bounded token")
    return value


def build_mail_edge_document(values: Mapping[str, str]) -> dict[str, object]:
    """Return the total v1 document represented by the operations environment."""

    current_key_id = _token(
        values, "OWNED_PROVIDER_MAIL_EDGE_HOST_KEY_ID", "host-key-current"
    )
    verification_keys = {
        current_key_id: "secret://mail_edge_host_key_current",
    }
    previous_key_id = values.get("OWNED_PROVIDER_MAIL_EDGE_PREVIOUS_HOST_KEY_ID", "")
    if previous_key_id:
        if not TOKEN.fullmatch(previous_key_id) or previous_key_id == current_key_id:
            raise ValueError(
                "OWNED_PROVIDER_MAIL_EDGE_PREVIOUS_HOST_KEY_ID must be a distinct bounded token"
            )
        verification_keys[previous_key_id] = "secret://mail_edge_host_key_previous"

    document: dict[str, object] = {
        "schemaVersion": "v1",
        "tenantId": values.get("OWNED_PROVIDER_MAIL_EDGE_TENANT_ID", FIXTURE_TENANT_ID),
        "baseUrl": values.get(
            "OWNED_PROVIDER_MAIL_EDGE_BASE_URL", "http://mail-edge-reference:8080"
        ),
        "secretDirectory": CONTAINER_SECRET_DIRECTORY,
        "bearerToken": "secret://mail_edge_tenant_bearer",
        "opaqueTokenKey": "secret://mail_edge_opaque_token_key",
        "maximumRawBytes": _integer(
            values, "OWNED_PROVIDER_MAIL_EDGE_MAXIMUM_RAW_BYTES", 26_214_400
        ),
        "http": {
            "connectSeconds": _number(
                values, "OWNED_PROVIDER_MAIL_EDGE_CONNECT_SECONDS", 1
            ),
            "readSeconds": _number(values, "OWNED_PROVIDER_MAIL_EDGE_READ_SECONDS", 10),
            "concurrency": _integer(
                values, "OWNED_PROVIDER_MAIL_EDGE_HTTP_CONCURRENCY", 32
            ),
            "breakerFailures": _integer(
                values, "OWNED_PROVIDER_MAIL_EDGE_BREAKER_FAILURES", 5
            ),
            "breakerResetSeconds": _number(
                values, "OWNED_PROVIDER_MAIL_EDGE_BREAKER_RESET_SECONDS", 30
            ),
            "preDispatchRetries": _integer(
                values, "OWNED_PROVIDER_MAIL_EDGE_PRE_DISPATCH_RETRIES", 1
            ),
            "maximumJsonBytes": _integer(
                values, "OWNED_PROVIDER_MAIL_EDGE_MAXIMUM_JSON_BYTES", 1_048_576
            ),
            "shutdownSeconds": _number(
                values, "OWNED_PROVIDER_MAIL_EDGE_SHUTDOWN_SECONDS", 30
            ),
        },
        "hostAuthentication": {
            "audience": _token(
                values, "OWNED_PROVIDER_MAIL_EDGE_AUDIENCE", "simplelogin-host"
            ),
            "maximumAgeSeconds": _integer(
                values, "OWNED_PROVIDER_MAIL_EDGE_SIGNATURE_MAXIMUM_AGE_SECONDS", 300
            ),
            "maximumFutureSkewSeconds": _integer(
                values, "OWNED_PROVIDER_MAIL_EDGE_SIGNATURE_FUTURE_SKEW_SECONDS", 30
            ),
            "maximumRequestBytes": _integer(
                values, "OWNED_PROVIDER_MAIL_EDGE_MAXIMUM_REQUEST_BYTES", 1_048_576
            ),
            "callbackLeaseSeconds": _integer(
                values, "OWNED_PROVIDER_MAIL_EDGE_CALLBACK_LEASE_SECONDS", 60
            ),
            "verificationKeys": verification_keys,
        },
        "hostDelivery": {
            "callbackConcurrency": _integer(
                values, "OWNED_PROVIDER_MAIL_EDGE_CALLBACK_CONCURRENCY", 8
            ),
            "deliveryConcurrency": _integer(
                values, "OWNED_PROVIDER_MAIL_EDGE_DELIVERY_CONCURRENCY", 2
            ),
            "maximumInFlightRawBytes": _integer(
                values,
                "OWNED_PROVIDER_MAIL_EDGE_MAXIMUM_IN_FLIGHT_RAW_BYTES",
                52_428_800,
            ),
            "maximumInFlightMemoryBytes": _integer(
                values,
                "OWNED_PROVIDER_MAIL_EDGE_MAXIMUM_IN_FLIGHT_MEMORY_BYTES",
                268_435_456,
            ),
            "maximumProcessRssBytes": _integer(
                values,
                "OWNED_PROVIDER_MAIL_EDGE_MAXIMUM_PROCESS_RSS_BYTES",
                536_870_912,
            ),
            "minimumSpoolFreeBytes": _integer(
                values,
                "OWNED_PROVIDER_MAIL_EDGE_MINIMUM_SPOOL_FREE_BYTES",
                67_108_864,
            ),
            "estimatedMemoryMultiplier": _integer(
                values, "OWNED_PROVIDER_MAIL_EDGE_ESTIMATED_MEMORY_MULTIPLIER", 8
            ),
            "estimatedMemoryFixedBytes": _integer(
                values,
                "OWNED_PROVIDER_MAIL_EDGE_ESTIMATED_MEMORY_FIXED_BYTES",
                8_388_608,
            ),
            "spoolDirectory": CONTAINER_SPOOL_DIRECTORY,
            "mime": {
                "maximumParts": _integer(
                    values, "OWNED_PROVIDER_MAIL_EDGE_MIME_MAXIMUM_PARTS", 256
                ),
                "maximumDepth": _integer(
                    values, "OWNED_PROVIDER_MAIL_EDGE_MIME_MAXIMUM_DEPTH", 16
                ),
                "maximumHeaderCount": _integer(
                    values,
                    "OWNED_PROVIDER_MAIL_EDGE_MIME_MAXIMUM_HEADER_COUNT",
                    1024,
                ),
                "maximumHeaderBytes": _integer(
                    values,
                    "OWNED_PROVIDER_MAIL_EDGE_MIME_MAXIMUM_HEADER_BYTES",
                    1_048_576,
                ),
                "maximumLineBytes": _integer(
                    values,
                    "OWNED_PROVIDER_MAIL_EDGE_MIME_MAXIMUM_LINE_BYTES",
                    1_048_576,
                ),
                "maximumSemanticBytes": _integer(
                    values,
                    "OWNED_PROVIDER_MAIL_EDGE_MIME_MAXIMUM_SEMANTIC_BYTES",
                    104_857_600,
                ),
                "parserSeconds": _number(
                    values, "OWNED_PROVIDER_MAIL_EDGE_MIME_PARSER_SECONDS", 10
                ),
            },
        },
    }
    if _enabled(
        values, "OWNED_PROVIDER_MAIL_EDGE_OPERATOR_AUTHENTICATION_ENABLED", True
    ):
        document["operatorAuthentication"] = {
            "operatorBearerToken": "secret://mail_edge_operator_bearer",
            "privilegedOperatorBearerToken": "secret://mail_edge_privileged_operator_bearer",
        }
    return document


def referenced_secret_names(document: Mapping[str, object]) -> frozenset[str]:
    references: set[str] = set()

    def visit(value: object) -> None:
        if isinstance(value, str) and value.startswith("secret://"):
            references.add(value.removeprefix("secret://"))
        elif isinstance(value, dict):
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(document)
    return frozenset(references)


def audit_mail_edge_document(
    document: Mapping[str, object],
    values: Mapping[str, str],
    runtime: Path,
    *,
    production: bool,
) -> list[str]:
    """Return actionable failures without opening network connections."""

    failures: list[str] = []
    try:
        tenant = uuid.UUID(str(document["tenantId"]))
        if tenant.version != 7:
            failures.append("Mail Edge tenant ID must be UUIDv7")
    except (KeyError, ValueError):
        failures.append("Mail Edge tenant ID is invalid")
    parsed = urlparse(str(document.get("baseUrl", "")))
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        failures.append("Mail Edge base URL is invalid")
    if production and parsed.scheme != "https":
        failures.append("production Mail Edge base URL must use HTTPS")
    if production and document.get("tenantId") == FIXTURE_TENANT_ID:
        failures.append("production Mail Edge tenant ID must replace the fixture UUID")

    try:
        maximum_raw = int(document["maximumRawBytes"])
        delivery = document["hostDelivery"]
        http = document["http"]
        if not isinstance(delivery, dict) or not isinstance(http, dict):
            raise TypeError
        maximum_message_memory = maximum_raw * int(
            delivery["estimatedMemoryMultiplier"]
        ) + int(delivery["estimatedMemoryFixedBytes"])
        if int(delivery["maximumInFlightRawBytes"]) < maximum_raw:
            failures.append("Mail Edge raw budget is smaller than one maximum message")
        if int(delivery["maximumInFlightMemoryBytes"]) < maximum_message_memory:
            failures.append(
                "Mail Edge memory budget is smaller than one maximum message"
            )
        if int(delivery["maximumProcessRssBytes"]) < maximum_message_memory:
            failures.append("Mail Edge RSS ceiling is smaller than one maximum message")
        if int(delivery["deliveryConcurrency"]) > int(delivery["callbackConcurrency"]):
            failures.append(
                "Mail Edge delivery concurrency exceeds callback concurrency"
            )
        if float(http["shutdownSeconds"]) >= 45:
            failures.append(
                "Mail Edge shutdown deadline must fit the 45-second service grace"
            )
        if maximum_raw > int(values.get("OWNED_PROVIDER_SMTP_SIZE_LIMIT", "26214400")):
            failures.append("Mail Edge raw maximum exceeds the SMTP admission limit")
        workers = int(values.get("OWNED_PROVIDER_GUNICORN_WORKERS", "2"))
        app_limit = parse_byte_size(
            values.get("OWNED_PROVIDER_APP_MEMORY_LIMIT", "1536m")
        )
        if workers * int(delivery["maximumProcessRssBytes"]) > app_limit:
            failures.append(
                "aggregate Mail Edge per-worker RSS ceilings exceed the app container limit"
            )
    except (KeyError, TypeError, ValueError):
        failures.append("Mail Edge resource budget is malformed")

    unknown = referenced_secret_names(document) - MAIL_EDGE_SECRET_NAMES
    if unknown:
        failures.append(
            f"Mail Edge config references unmanaged secrets: {sorted(unknown)}"
        )
    secret_values: dict[str, bytes] = {}
    for name in sorted(referenced_secret_names(document)):
        path = runtime / "secrets" / name
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise OSError
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                failures.append(f"Mail Edge secret is not mode 0600: {name}")
            value = path.read_bytes()
            if value.endswith(b"\n"):
                value = value[:-1]
            if not 32 <= len(value) <= 4096 or b"\0" in value:
                failures.append(f"Mail Edge secret length is invalid: {name}")
            if name in ASCII_BEARER_SECRET_NAMES:
                try:
                    decoded = value.decode("ascii")
                    if any(
                        character.isspace()
                        or ord(character) < 33
                        or ord(character) > 126
                        for character in decoded
                    ):
                        raise ValueError
                except (UnicodeDecodeError, ValueError):
                    failures.append(f"Mail Edge bearer token is invalid: {name}")
            secret_values[name] = value
        except OSError:
            failures.append(f"missing regular Mail Edge secret: {name}")
    operator = secret_values.get("mail_edge_operator_bearer")
    privileged = secret_values.get("mail_edge_privileged_operator_bearer")
    if operator is not None and privileged is not None and operator == privileged:
        failures.append("Mail Edge operator credentials must be distinct")
    if "mail_edge_host_key_previous" in referenced_secret_names(document):
        current_key = secret_values.get("mail_edge_host_key_current")
        previous_key = secret_values.get("mail_edge_host_key_previous")
        if current_key is not None and current_key == previous_key:
            failures.append("Mail Edge overlapping host keys must be distinct")
    return failures


def parse_byte_size(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([kKmMgG]?)", value)
    if match is None:
        raise ValueError("container memory limit is invalid")
    multipliers = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}
    return int(match.group(1)) * multipliers[match.group(2).lower()]


def write_mail_edge_configuration(path: Path, values: Mapping[str, str]) -> None:
    document = build_mail_edge_document(values)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.chmod(0o600)
    temporary.replace(path)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: mail_edge_config.py OUTPUT")
    write_mail_edge_configuration(Path(sys.argv[1]), os.environ)


if __name__ == "__main__":
    main()
