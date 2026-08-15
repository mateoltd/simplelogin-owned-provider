"""Fail closed on unsafe or fixture-like production configuration."""

from __future__ import annotations

import argparse
import ast
import ipaddress
import json
import os
import re
import stat
from pathlib import Path
from urllib.parse import urlparse

from mail_edge_config import (
    MAIL_EDGE_SECRET_NAMES,
    audit_mail_edge_document,
    build_mail_edge_document,
)


RESERVED_SUFFIXES = (".test", ".example", ".invalid", ".localhost")
HEX_SECRET_NAMES = {
    "master_enc_key_hex",
    "mac_key_hex",
    "abuser_hkdf_salt",
    "backup_encryption_key",
}
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def reserved(domain: str) -> bool:
    return domain.endswith(RESERVED_SUFFIXES) or any(
        domain == name or domain.endswith(f".{name}")
        for name in ("example.com", "example.net", "example.org")
    )


def valid_hostname(domain: str) -> bool:
    return (
        domain == domain.lower()
        and 0 < len(domain) <= 253
        and all(LABEL.fullmatch(label) for label in domain.split("."))
    )


def valid_domain(domain: str) -> bool:
    return "." in domain and valid_hostname(domain)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--production", action="store_true")
    args = parser.parse_args()
    failures = []
    warnings = []
    mode = os.environ.get("OWNED_PROVIDER_MODE", "test")
    url = urlparse(os.environ["OWNED_PROVIDER_URL"])
    alias_domains = json.loads(os.environ["OWNED_PROVIDER_ALIAS_DOMAINS"])
    custom_domains = json.loads(os.environ["OWNED_PROVIDER_CUSTOM_DOMAINS"])
    all_domains = alias_domains + custom_domains
    if len(set(all_domains)) != len(all_domains):
        failures.append("alias and custom domain lists must be unique")
    if any(
        not isinstance(domain, str) or not valid_domain(domain)
        for domain in all_domains
    ):
        failures.append(
            "domains must be valid lower-case host names without trailing dots"
        )
    try:
        mail_servers = ast.literal_eval(
            os.environ["OWNED_PROVIDER_EMAIL_SERVERS_WITH_PRIORITY"]
        )
        if not mail_servers or any(
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], int)
            or not 0 <= item[0] <= 65535
            or not isinstance(item[1], str)
            or not valid_hostname(item[1].rstrip("."))
            for item in mail_servers
        ):
            failures.append("mail servers must be (priority, hostname) tuples")
    except (KeyError, SyntaxError, ValueError):
        failures.append("mail server priority configuration is invalid")
    if args.production:
        if mode != "production":
            failures.append("production audit requires OWNED_PROVIDER_MODE=production")
        if url.scheme != "https" or not url.hostname:
            failures.append("production URL must use HTTPS")
        if os.environ.get("OWNED_PROVIDER_TEST_MODE"):
            failures.append("OWNED_PROVIDER_TEST_MODE must be absent in production")
        if any(reserved(domain) for domain in all_domains):
            failures.append(
                "production domains cannot use RFC-reserved fixture suffixes"
            )
        relay = os.environ["OWNED_PROVIDER_SMTP_RELAY_HOST"].lower()
        if relay in {"mailpit", "localhost", "127.0.0.1"}:
            failures.append("production SMTP relay cannot be the contained test sink")
        if os.environ.get("OWNED_PROVIDER_SMTP_BIND") in {None, ""}:
            failures.append("production SMTP bind address must be explicit")
        for name in ("OWNED_PROVIDER_HTTP_BIND", "OWNED_PROVIDER_OBSERVER_BIND"):
            if os.environ.get(name) not in {"127.0.0.1", "::1"}:
                failures.append(f"{name} must bind to loopback in production")
        try:
            outbound = ipaddress.ip_address(os.environ["OWNED_PROVIDER_OUTBOUND_IP"])
            if outbound.is_private or outbound.is_loopback or outbound.is_reserved:
                failures.append("production outbound address must be publicly routable")
        except (KeyError, ValueError):
            failures.append("production outbound address is missing or invalid")
    if not alias_domains:
        failures.append("at least one alias domain is required")
    if not custom_domains:
        warnings.append("no operator-owned custom domains are pre-provisioned")
    try:
        gunicorn_timeout = int(
            os.environ.get("OWNED_PROVIDER_GUNICORN_TIMEOUT_SECONDS", "90")
        )
        if not 30 <= gunicorn_timeout <= 300:
            raise ValueError
    except ValueError:
        failures.append("Gunicorn timeout must be an integer from 30 through 300")
    secret_names = {
        "postgres_password",
        "flask_secret",
        "partner_api_token_secret",
        "recovery_code_hmac_secret",
        "alias_transfer_token_secret",
        "verp_email_secret",
        "master_enc_key_hex",
        "mac_key_hex",
        "abuser_hkdf_salt",
        "admin_password",
        "dkim_private_key",
        "backup_encryption_key",
    } | MAIL_EDGE_SECRET_NAMES
    for name in sorted(secret_names):
        path = args.runtime / "secrets" / name
        if not path.is_file():
            failures.append(f"missing secret file: {name}")
        elif stat.S_IMODE(path.stat().st_mode) != 0o600:
            failures.append(f"secret file is not mode 0600: {name}")
        else:
            value = path.read_text(errors="replace").strip()
            if name in HEX_SECRET_NAMES and not re.fullmatch(r"[0-9a-f]{64}", value):
                failures.append(f"secret must be 32 bytes encoded as hex: {name}")
            elif name == "admin_password" and len(value) < 20:
                failures.append("operator password must contain at least 20 characters")
            elif name == "dkim_private_key" and (
                "PRIVATE KEY-----" not in value or len(value) < 1000
            ):
                failures.append("DKIM private key is missing or malformed")
            elif (
                name not in HEX_SECRET_NAMES | {"admin_password", "dkim_private_key"}
                and len(value) < 32
            ):
                failures.append(f"secret must contain at least 32 characters: {name}")
    config_path = Path(os.environ["OWNED_PROVIDER_CONFIG_FILE"])
    if stat.S_IMODE(config_path.stat().st_mode) != 0o600:
        failures.append("effective configuration file must be mode 0600")
    mail_edge_enabled = os.environ.get("OWNED_PROVIDER_MAIL_EDGE_ENABLED", "0") == "1"
    mail_edge_config_path = args.runtime / "mail-edge.json"
    try:
        if stat.S_IMODE(mail_edge_config_path.stat().st_mode) != 0o600:
            failures.append("Mail Edge configuration file must be mode 0600")
        mail_edge_document = json.loads(
            mail_edge_config_path.read_text(encoding="utf-8")
        )
        if mail_edge_document != build_mail_edge_document(os.environ):
            failures.append("Mail Edge configuration is stale or not deterministic")
        failures.extend(
            audit_mail_edge_document(
                mail_edge_document,
                os.environ,
                args.runtime,
                production=args.production and mail_edge_enabled,
            )
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        failures.append(
            f"Mail Edge configuration cannot be audited: {type(error).__name__}"
        )
    if args.production and not mail_edge_enabled:
        warnings.append("Mail Edge integration is disabled")
    result = {
        "mode": mode,
        "production_audit": args.production,
        "passed": not failures,
        "alias_domain_count": len(alias_domains),
        "custom_domain_count": len(custom_domains),
        "mail_edge_enabled": mail_edge_enabled,
        "failures": failures,
        "warnings": warnings,
    }
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
