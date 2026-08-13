"""Fail-closed runtime configuration and secret-file isolation."""

from __future__ import annotations

import base64
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .adapters.mailgun import MailgunAdapter, MailgunCredentials
from .bindings import Binding, BindingStore
from .blob import LocalEncryptedBlobStore
from .db import Database
from .errors import ConfigurationError
from .registry import CapabilityRegistry
from .repository import EdgeRepository


def read_secret_file(path_value: str, *, maximum_bytes: int = 64 * 1024) -> bytes:
    path = Path(path_value).resolve()
    try:
        metadata = path.stat()
    except FileNotFoundError as exc:
        raise ConfigurationError(f"secret file does not exist: {path.name}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ConfigurationError("secret path must be a regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ConfigurationError("secret file must not be group/world accessible")
    if metadata.st_size > maximum_bytes:
        raise ConfigurationError("secret file is too large")
    return path.read_bytes().rstrip(b"\r\n")


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"required configuration is missing: {name}")
    return value


@dataclass(frozen=True, slots=True)
class Runtime:
    database: Database
    blobs: LocalEncryptedBlobStore
    registry: CapabilityRegistry
    bindings: BindingStore
    repository: EdgeRepository
    provider_credentials: dict[str, dict[str, str]]
    diagnostic_salt: bytes

    def mailgun_adapter(self, binding: Binding) -> MailgunAdapter:
        reference = str(binding.provider_config.get("credential_ref", ""))
        credential = self.provider_credentials.get(reference)
        if credential is None:
            raise ConfigurationError("binding credential reference is unavailable")
        try:
            credentials = MailgunCredentials(
                smtp_username=credential["smtp_username"],
                smtp_password=credential["smtp_password"],
                webhook_signing_key=credential["webhook_signing_key"],
            )
        except KeyError as exc:
            raise ConfigurationError("Mailgun credential set is incomplete") from exc
        host = str(binding.provider_config.get("smtp_host", "smtp.mailgun.org"))
        port = int(binding.provider_config.get("smtp_port", 587))
        if not host or not 1 <= port <= 65535:
            raise ConfigurationError("invalid Mailgun SMTP endpoint")
        return MailgunAdapter(
            credentials=credentials,
            smtp_host=host,
            smtp_port=port,
            diagnostic_salt=self.diagnostic_salt,
        )


def build_runtime() -> Runtime:
    database_url = read_secret_file(
        required_env("MAIL_EDGE_DATABASE_URL_FILE")
    ).decode()
    blob_config = json.loads(
        read_secret_file(required_env("MAIL_EDGE_BLOB_KEYS_FILE")).decode()
    )
    try:
        active_key_id = str(blob_config["active_key_id"])
        keys = {
            str(key_id): base64.b64decode(str(encoded), validate=True)
            for key_id, encoded in blob_config["keys"].items()
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigurationError("blob key file is invalid") from exc
    credentials: dict[str, dict[str, str]] = json.loads(
        read_secret_file(
            required_env("MAIL_EDGE_PROVIDER_CREDENTIALS_FILE"),
            maximum_bytes=256 * 1024,
        ).decode()
    )
    if not isinstance(credentials, dict):
        raise ConfigurationError("provider credential file must contain an object")
    for reference, value in credentials.items():
        if not isinstance(reference, str) or not isinstance(value, dict):
            raise ConfigurationError("provider credential entry is invalid")
        if any(not isinstance(item, str) or not item for item in value.values()):
            raise ConfigurationError("provider credential values must be strings")
    diagnostic_salt = read_secret_file(required_env("MAIL_EDGE_DIAGNOSTIC_SALT_FILE"))
    if len(diagnostic_salt) < 16:
        raise ConfigurationError("diagnostic salt must contain at least 16 bytes")
    database = Database(database_url)
    blobs = LocalEncryptedBlobStore(
        Path(required_env("MAIL_EDGE_BLOB_ROOT")), keys, active_key_id
    )
    registry = CapabilityRegistry(database)
    bindings = BindingStore(database, registry)
    repository = EdgeRepository(
        database, blobs, bindings, diagnostic_salt=diagnostic_salt
    )
    return Runtime(
        database=database,
        blobs=blobs,
        registry=registry,
        bindings=bindings,
        repository=repository,
        provider_credentials=credentials,
        diagnostic_salt=diagnostic_salt,
    )


def handoff_token() -> str:
    return read_secret_file(required_env("MAIL_EDGE_HANDOFF_TOKEN_FILE")).decode()
