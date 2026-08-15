from __future__ import annotations

import hmac
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
MIME_PART_MEMORY_RESERVE_BYTES = 8 * 1024
MINIMUM_DELIVERY_FIXED_MEMORY_BYTES = 1024 * 1024


@dataclass(frozen=True)
class HttpLimits:
    connect_seconds: float
    read_seconds: float
    concurrency: int
    breaker_failures: int
    breaker_reset_seconds: float
    pre_dispatch_retries: int
    maximum_json_bytes: int = 1024 * 1024
    shutdown_seconds: float = 30


@dataclass(frozen=True)
class HostAuthentication:
    audience: str
    maximum_age_seconds: int
    maximum_future_skew_seconds: int
    verification_keys: Mapping[str, bytes]
    maximum_request_bytes: int = 1024 * 1024
    callback_lease_seconds: int = 60


@dataclass(frozen=True)
class MimeParserLimits:
    maximum_parts: int
    maximum_depth: int
    maximum_header_count: int
    maximum_header_bytes: int
    maximum_line_bytes: int
    maximum_semantic_bytes: int
    parser_seconds: float


@dataclass(frozen=True)
class HostDeliveryLimits:
    callback_concurrency: int
    delivery_concurrency: int
    maximum_in_flight_raw_bytes: int
    maximum_in_flight_memory_bytes: int
    maximum_process_rss_bytes: int
    minimum_spool_free_bytes: int
    estimated_memory_multiplier: int
    estimated_memory_fixed_bytes: int
    spool_directory: str
    mime: MimeParserLimits


@dataclass(frozen=True)
class OperatorAuthentication:
    operator_bearer_token: Optional[str] = None
    privileged_operator_bearer_token: Optional[str] = None


@dataclass(frozen=True)
class MailEdgeConfiguration:
    tenant_id: str
    base_url: str
    bearer_token: str
    opaque_token_key: bytes
    maximum_raw_bytes: int
    http: HttpLimits
    host_authentication: HostAuthentication
    host_delivery: HostDeliveryLimits
    operator_authentication: OperatorAuthentication = OperatorAuthentication()


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


def _ascii_bearer_secret(reference: object, secret_directory: Path) -> str:
    value = _secret(reference, secret_directory, minimum_bytes=32, maximum_bytes=4096)
    try:
        bearer = value.decode("ascii")
    except UnicodeDecodeError:
        _invalid("MAIL_EDGE_BEARER_TOKEN_INVALID")
    if any(
        character.isspace() or ord(character) < 33 or ord(character) > 126
        for character in bearer
    ):
        _invalid("MAIL_EDGE_BEARER_TOKEN_INVALID")
    return bearer


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
            "hostDelivery",
        },
        {"operatorAuthentication"},
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
        {"maximumJsonBytes", "shutdownSeconds"},
    )
    auth = _strict_object(
        value["hostAuthentication"],
        {
            "audience",
            "maximumAgeSeconds",
            "maximumFutureSkewSeconds",
            "verificationKeys",
        },
        {"maximumRequestBytes", "callbackLeaseSeconds"},
    )
    host_delivery = _strict_object(
        value["hostDelivery"],
        {
            "callbackConcurrency",
            "deliveryConcurrency",
            "maximumInFlightRawBytes",
            "maximumInFlightMemoryBytes",
            "maximumProcessRssBytes",
            "minimumSpoolFreeBytes",
            "estimatedMemoryMultiplier",
            "estimatedMemoryFixedBytes",
            "spoolDirectory",
            "mime",
        },
    )
    mime = _strict_object(
        host_delivery["mime"],
        {
            "maximumParts",
            "maximumDepth",
            "maximumHeaderCount",
            "maximumHeaderBytes",
            "maximumLineBytes",
            "maximumSemanticBytes",
            "parserSeconds",
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

    bearer_token = _ascii_bearer_secret(value["bearerToken"], secret_directory)

    operator_token: Optional[str] = None
    privileged_operator_token: Optional[str] = None
    if "operatorAuthentication" in value:
        operator_authentication = _strict_object(
            value["operatorAuthentication"],
            {"operatorBearerToken", "privilegedOperatorBearerToken"},
        )
        operator_token = _ascii_bearer_secret(
            operator_authentication["operatorBearerToken"], secret_directory
        )
        privileged_operator_token = _ascii_bearer_secret(
            operator_authentication["privilegedOperatorBearerToken"], secret_directory
        )
        if hmac.compare_digest(operator_token, privileged_operator_token):
            _invalid("MAIL_EDGE_OPERATOR_TOKENS_REUSED")

    try:
        tenant_id = parse_uuid7(value["tenantId"], "MAIL_EDGE_TENANT_ID_INVALID")
    except MailEdgeContractError:
        _invalid("MAIL_EDGE_TENANT_ID_INVALID")

    maximum_raw_bytes = _integer(
        value["maximumRawBytes"], 1, MAX_RAW_BYTES, "MAIL_EDGE_RAW_LIMIT_INVALID"
    )
    spool_directory_value = host_delivery["spoolDirectory"]
    if not isinstance(spool_directory_value, str):
        _invalid("MAIL_EDGE_SPOOL_DIRECTORY_INVALID")
    spool_directory = Path(spool_directory_value)
    if not spool_directory.is_absolute():
        _invalid("MAIL_EDGE_SPOOL_DIRECTORY_INVALID")
    try:
        spool_directory = spool_directory.resolve(strict=True)
        if not spool_directory.is_dir():
            _invalid("MAIL_EDGE_SPOOL_DIRECTORY_INVALID")
    except OSError:
        _invalid("MAIL_EDGE_SPOOL_DIRECTORY_INVALID")

    maximum_in_flight_raw_bytes = _integer(
        host_delivery["maximumInFlightRawBytes"],
        1,
        MAX_RAW_BYTES * 1024,
        "MAIL_EDGE_HOST_RAW_BUDGET_INVALID",
    )
    estimated_memory_multiplier = _integer(
        host_delivery["estimatedMemoryMultiplier"],
        4,
        16,
        "MAIL_EDGE_HOST_MEMORY_ESTIMATE_INVALID",
    )
    maximum_parts = _integer(
        mime["maximumParts"],
        1,
        10000,
        "MAIL_EDGE_MIME_PART_LIMIT_INVALID",
    )
    estimated_memory_fixed_bytes = _integer(
        host_delivery["estimatedMemoryFixedBytes"],
        0,
        256 * 1024 * 1024,
        "MAIL_EDGE_HOST_MEMORY_ESTIMATE_INVALID",
    )
    maximum_in_flight_memory_bytes = _integer(
        host_delivery["maximumInFlightMemoryBytes"],
        1,
        64 * 1024 * 1024 * 1024,
        "MAIL_EDGE_HOST_MEMORY_BUDGET_INVALID",
    )
    maximum_process_rss_bytes = _integer(
        host_delivery["maximumProcessRssBytes"],
        1,
        64 * 1024 * 1024 * 1024,
        "MAIL_EDGE_HOST_RSS_LIMIT_INVALID",
    )
    callback_concurrency = _integer(
        host_delivery["callbackConcurrency"],
        1,
        4096,
        "MAIL_EDGE_HOST_CALLBACK_CONCURRENCY_INVALID",
    )
    delivery_concurrency = _integer(
        host_delivery["deliveryConcurrency"],
        1,
        1024,
        "MAIL_EDGE_HOST_DELIVERY_CONCURRENCY_INVALID",
    )
    maximum_message_estimate = (
        maximum_raw_bytes * estimated_memory_multiplier + estimated_memory_fixed_bytes
    )
    minimum_fixed_memory = (
        MINIMUM_DELIVERY_FIXED_MEMORY_BYTES
        + maximum_parts * MIME_PART_MEMORY_RESERVE_BYTES
    )
    if (
        maximum_in_flight_raw_bytes < maximum_raw_bytes
        or maximum_in_flight_memory_bytes < maximum_message_estimate
        or maximum_process_rss_bytes < maximum_message_estimate
        or delivery_concurrency > callback_concurrency
        or estimated_memory_fixed_bytes < minimum_fixed_memory
    ):
        _invalid("MAIL_EDGE_HOST_RESOURCE_BUDGET_INVALID")

    return MailEdgeConfiguration(
        tenant_id=tenant_id,
        base_url=base_url,
        bearer_token=bearer_token,
        opaque_token_key=_secret(value["opaqueTokenKey"], secret_directory),
        maximum_raw_bytes=maximum_raw_bytes,
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
            maximum_json_bytes=_integer(
                http.get("maximumJsonBytes", 1024 * 1024),
                1024,
                4 * 1024 * 1024,
                "MAIL_EDGE_JSON_LIMIT_INVALID",
            ),
            shutdown_seconds=_number(
                http.get("shutdownSeconds", 30),
                0.1,
                300,
                "MAIL_EDGE_SHUTDOWN_TIMEOUT_INVALID",
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
            maximum_request_bytes=_integer(
                auth.get("maximumRequestBytes", 1024 * 1024),
                1024,
                1024 * 1024,
                "MAIL_EDGE_HOST_REQUEST_LIMIT_INVALID",
            ),
            callback_lease_seconds=_integer(
                auth.get("callbackLeaseSeconds", 60),
                1,
                900,
                "MAIL_EDGE_CALLBACK_LEASE_INVALID",
            ),
        ),
        host_delivery=HostDeliveryLimits(
            callback_concurrency=callback_concurrency,
            delivery_concurrency=delivery_concurrency,
            maximum_in_flight_raw_bytes=maximum_in_flight_raw_bytes,
            maximum_in_flight_memory_bytes=maximum_in_flight_memory_bytes,
            maximum_process_rss_bytes=maximum_process_rss_bytes,
            minimum_spool_free_bytes=_integer(
                host_delivery["minimumSpoolFreeBytes"],
                0,
                64 * 1024 * 1024 * 1024,
                "MAIL_EDGE_HOST_SPOOL_RESERVE_INVALID",
            ),
            estimated_memory_multiplier=estimated_memory_multiplier,
            estimated_memory_fixed_bytes=estimated_memory_fixed_bytes,
            spool_directory=str(spool_directory),
            mime=MimeParserLimits(
                maximum_parts=maximum_parts,
                maximum_depth=_integer(
                    mime["maximumDepth"],
                    1,
                    100,
                    "MAIL_EDGE_MIME_DEPTH_LIMIT_INVALID",
                ),
                maximum_header_count=_integer(
                    mime["maximumHeaderCount"],
                    1,
                    10000,
                    "MAIL_EDGE_MIME_HEADER_LIMIT_INVALID",
                ),
                maximum_header_bytes=_integer(
                    mime["maximumHeaderBytes"],
                    1024,
                    16 * 1024 * 1024,
                    "MAIL_EDGE_MIME_HEADER_LIMIT_INVALID",
                ),
                maximum_line_bytes=_integer(
                    mime["maximumLineBytes"],
                    998,
                    4 * 1024 * 1024,
                    "MAIL_EDGE_MIME_LINE_LIMIT_INVALID",
                ),
                maximum_semantic_bytes=_integer(
                    mime["maximumSemanticBytes"],
                    1,
                    MAX_RAW_BYTES * 16,
                    "MAIL_EDGE_MIME_SEMANTIC_LIMIT_INVALID",
                ),
                parser_seconds=_number(
                    mime["parserSeconds"],
                    0.05,
                    120,
                    "MAIL_EDGE_MIME_PARSER_TIMEOUT_INVALID",
                ),
            ),
        ),
        operator_authentication=OperatorAuthentication(
            operator_bearer_token=operator_token,
            privileged_operator_bearer_token=privileged_operator_token,
        ),
    )


def configuration_from_environment() -> Optional[MailEdgeConfiguration]:
    return load_mail_edge_configuration(os.environ.get("MAIL_EDGE_CONFIG_PATH"))
