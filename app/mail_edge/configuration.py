from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Optional
from urllib.parse import urlparse

from .contracts import MAX_RAW_BYTES, TOKEN_RE, parse_uuid7, strict_json_loads
from .errors import MailEdgeConfigurationError, MailEdgeContractError


SECRET_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,127}$")
MAXIMUM_CONFIG_BYTES = 64 * 1024


@dataclass(frozen=True)
class HttpLimits:
    connect_seconds: float
    read_seconds: float
    concurrency: int
    breaker_failures: int
    breaker_reset_seconds: float
    pre_dispatch_retries: int


@dataclass(frozen=True)
class HostAuthentication:
    audience: str
    maximum_age_seconds: int
    maximum_future_skew_seconds: int
    verification_keys: Mapping[str, bytes]


@dataclass(frozen=True)
class MailEdgeConfiguration:
    tenant_id: str
    base_url: str
    bearer_token: str
    opaque_token_key: bytes
    maximum_raw_bytes: int
    http: HttpLimits
    host_authentication: HostAuthentication


def _invalid(code: str) -> None:
    raise MailEdgeConfigurationError(code)


def _strict_object(value, required: set[str], optional: set[str] = frozenset()):
    if (
        not isinstance(value, dict)
        or not required.issubset(value)
        or set(value) - required - optional
    ):
        _invalid("MAIL_EDGE_CONFIG_INVALID")
    return value


def _number(value, minimum: float, maximum: float, code: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not minimum <= value <= maximum
    ):
        _invalid(code)
    return float(value)


def _integer(value, minimum: int, maximum: int, code: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        _invalid(code)
    return value


def _secret(
    reference: object,
    secret_directory: Path,
    *,
    minimum_bytes: int = 32,
    maximum_bytes: int = 1024,
) -> bytes:
    if not isinstance(reference, str) or not reference.startswith("secret://"):
        _invalid("MAIL_EDGE_SECRET_REFERENCE_INVALID")
    name = reference[len("secret://") :]
    if not SECRET_NAME_RE.fullmatch(name):
        _invalid("MAIL_EDGE_SECRET_REFERENCE_INVALID")
    path = secret_directory / name
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or not 1 <= metadata.st_size <= 64 * 1024
        ):
            _invalid("MAIL_EDGE_SECRET_UNAVAILABLE")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
        with os.fdopen(descriptor, "rb") as handle:
            opened_metadata = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened_metadata.st_mode)
                or not 1 <= opened_metadata.st_size <= 64 * 1024
            ):
                _invalid("MAIL_EDGE_SECRET_UNAVAILABLE")
            value = handle.read(64 * 1024 + 1)
    except (OSError, ValueError):
        _invalid("MAIL_EDGE_SECRET_UNAVAILABLE")
    if value.endswith(b"\r\n"):
        value = value[:-2]
    elif value.endswith(b"\n"):
        value = value[:-1]
    if b"\0" in value or not minimum_bytes <= len(value) <= maximum_bytes:
        _invalid("MAIL_EDGE_SECRET_INVALID")
    return value


def load_mail_edge_configuration(
    path_value: Optional[str],
) -> Optional[MailEdgeConfiguration]:
    if not path_value:
        return None
    path = Path(path_value)
    if not path.is_absolute():
        _invalid("MAIL_EDGE_CONFIG_PATH_NOT_ABSOLUTE")
    try:
        with path.open("rb") as handle:
            raw_document = handle.read(MAXIMUM_CONFIG_BYTES + 1)
        document = strict_json_loads(raw_document, MAXIMUM_CONFIG_BYTES)
    except (OSError, MailEdgeContractError):
        _invalid("MAIL_EDGE_CONFIG_UNAVAILABLE")
    value = _strict_object(
        document,
        {
            "schemaVersion",
            "tenantId",
            "baseUrl",
            "secretDirectory",
            "bearerToken",
            "opaqueTokenKey",
            "maximumRawBytes",
            "http",
            "hostAuthentication",
        },
    )
    if value["schemaVersion"] != "v1":
        _invalid("MAIL_EDGE_CONFIG_VERSION_UNSUPPORTED")
    secret_directory = Path(value["secretDirectory"])
    if not secret_directory.is_absolute():
        _invalid("MAIL_EDGE_SECRET_DIRECTORY_NOT_ABSOLUTE")
    try:
        secret_directory = secret_directory.resolve(strict=True)
    except OSError:
        _invalid("MAIL_EDGE_SECRET_DIRECTORY_UNAVAILABLE")

    base_url = value["baseUrl"]
    if not isinstance(base_url, str):
        _invalid("MAIL_EDGE_BASE_URL_INVALID")
    parsed_url = urlparse(base_url)
    if (
        parsed_url.scheme not in {"http", "https"}
        or not parsed_url.hostname
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.query
        or parsed_url.fragment
    ):
        _invalid("MAIL_EDGE_BASE_URL_INVALID")
    base_url = base_url.rstrip("/")

    http = _strict_object(
        value["http"],
        {
            "connectSeconds",
            "readSeconds",
            "concurrency",
            "breakerFailures",
            "breakerResetSeconds",
            "preDispatchRetries",
        },
    )
    auth = _strict_object(
        value["hostAuthentication"],
        {
            "audience",
            "maximumAgeSeconds",
            "maximumFutureSkewSeconds",
            "verificationKeys",
        },
    )
    audience = auth["audience"]
    if not isinstance(audience, str) or not TOKEN_RE.fullmatch(audience):
        _invalid("MAIL_EDGE_AUDIENCE_INVALID")
    key_references = auth["verificationKeys"]
    if not isinstance(key_references, dict) or not 1 <= len(key_references) <= 16:
        _invalid("MAIL_EDGE_VERIFICATION_KEYS_INVALID")
    keys = {}
    for key_id, reference in key_references.items():
        if not isinstance(key_id, str) or not TOKEN_RE.fullmatch(key_id):
            _invalid("MAIL_EDGE_VERIFICATION_KEYS_INVALID")
        keys[key_id] = _secret(reference, secret_directory)

    bearer = _secret(
        value["bearerToken"], secret_directory, minimum_bytes=32, maximum_bytes=4096
    )
    try:
        bearer_token = bearer.decode("ascii")
    except UnicodeDecodeError:
        _invalid("MAIL_EDGE_BEARER_TOKEN_INVALID")
    if any(
        character.isspace() or ord(character) < 33 or ord(character) > 126
        for character in bearer_token
    ):
        _invalid("MAIL_EDGE_BEARER_TOKEN_INVALID")

    try:
        tenant_id = parse_uuid7(value["tenantId"], "MAIL_EDGE_TENANT_ID_INVALID")
    except MailEdgeContractError:
        _invalid("MAIL_EDGE_TENANT_ID_INVALID")

    return MailEdgeConfiguration(
        tenant_id=tenant_id,
        base_url=base_url,
        bearer_token=bearer_token,
        opaque_token_key=_secret(value["opaqueTokenKey"], secret_directory),
        maximum_raw_bytes=_integer(
            value["maximumRawBytes"], 1, MAX_RAW_BYTES, "MAIL_EDGE_RAW_LIMIT_INVALID"
        ),
        http=HttpLimits(
            connect_seconds=_number(
                http["connectSeconds"], 0.05, 30, "MAIL_EDGE_CONNECT_TIMEOUT_INVALID"
            ),
            read_seconds=_number(
                http["readSeconds"], 0.05, 120, "MAIL_EDGE_READ_TIMEOUT_INVALID"
            ),
            concurrency=_integer(
                http["concurrency"], 1, 1024, "MAIL_EDGE_CONCURRENCY_INVALID"
            ),
            breaker_failures=_integer(
                http["breakerFailures"], 1, 100, "MAIL_EDGE_BREAKER_INVALID"
            ),
            breaker_reset_seconds=_number(
                http["breakerResetSeconds"], 0.1, 300, "MAIL_EDGE_BREAKER_INVALID"
            ),
            pre_dispatch_retries=_integer(
                http["preDispatchRetries"], 0, 3, "MAIL_EDGE_RETRY_POLICY_INVALID"
            ),
        ),
        host_authentication=HostAuthentication(
            audience=audience,
            maximum_age_seconds=_integer(
                auth["maximumAgeSeconds"], 1, 900, "MAIL_EDGE_SIGNATURE_AGE_INVALID"
            ),
            maximum_future_skew_seconds=_integer(
                auth["maximumFutureSkewSeconds"],
                0,
                300,
                "MAIL_EDGE_SIGNATURE_SKEW_INVALID",
            ),
            verification_keys=MappingProxyType(keys),
        ),
    )


def configuration_from_environment() -> Optional[MailEdgeConfiguration]:
    return load_mail_edge_configuration(os.environ.get("MAIL_EDGE_CONFIG_PATH"))
