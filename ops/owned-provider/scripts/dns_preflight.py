"""Read-only DNS and deliverability preflight for an owned mail domain."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path

import dns.exception
import dns.reversename
import dns.resolver
from cryptography.hazmat.primitives import serialization


def fqdn(value: str) -> str:
    return value.rstrip(".").lower() + "."


def txt_values(resolver: dns.resolver.Resolver, name: str) -> list[str]:
    answer = resolver.resolve(name, "TXT")
    return [b"".join(record.strings).decode() for record in answer]


def resolve_addresses(resolver: dns.resolver.Resolver, name: str) -> set[str]:
    values = set()
    for family in ("A", "AAAA"):
        try:
            values.update(str(item) for item in resolver.resolve(name, family))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
    return values


def spf_authorizes(
    resolver: dns.resolver.Resolver,
    domain: str,
    address: ipaddress._BaseAddress,
    visited: set[str],
) -> tuple[bool, list[str]]:
    domain = fqdn(domain)
    if domain in visited or len(visited) >= 10:
        return False, ["SPF include/redirect recursion or lookup limit reached"]
    visited.add(domain)
    records = [
        value
        for value in txt_values(resolver, domain)
        if value.lower().startswith("v=spf1 ")
    ]
    if len(records) != 1:
        return False, [f"expected one SPF record at {domain}, found {len(records)}"]
    warnings = []
    redirect = None
    for raw_term in records[0].split()[1:]:
        if raw_term.startswith("redirect="):
            redirect = raw_term.split("=", 1)[1]
            continue
        qualifier = "+"
        term = raw_term
        if raw_term[:1] in "+-~?":
            qualifier, term = raw_term[0], raw_term[1:]
        matched = False
        if term == "all":
            matched = True
        elif term.startswith("ip4:") or term.startswith("ip6:"):
            try:
                matched = address in ipaddress.ip_network(
                    term.split(":", 1)[1], strict=False
                )
            except ValueError:
                warnings.append(f"invalid SPF network: {term}")
        elif term == "a" or term.startswith("a:"):
            host = term.split(":", 1)[1] if ":" in term else domain
            matched = str(address) in resolve_addresses(resolver, host)
        elif term == "mx" or term.startswith("mx:"):
            host = term.split(":", 1)[1] if ":" in term else domain
            try:
                mx_hosts = [str(item.exchange) for item in resolver.resolve(host, "MX")]
                matched = any(
                    str(address) in resolve_addresses(resolver, mx) for mx in mx_hosts
                )
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                matched = False
        elif term.startswith("include:"):
            included, nested = spf_authorizes(
                resolver, term.split(":", 1)[1], address, visited
            )
            warnings.extend(nested)
            matched = included
        elif term.startswith(("exists:", "ptr")):
            warnings.append(f"SPF mechanism not evaluated by preflight: {term}")
        if matched:
            return qualifier == "+", warnings
    if redirect:
        return spf_authorizes(resolver, redirect, address, visited)
    return False, warnings


def check(args) -> dict:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout
    if args.nameserver:
        resolver.nameservers = args.nameserver
    failures = []
    warnings = []
    observed = {}
    domain = fqdn(args.domain)
    expected_mx = {fqdn(host) for host in args.mx_host}
    try:
        mx = sorted(
            (int(item.preference), fqdn(str(item.exchange)))
            for item in resolver.resolve(domain, "MX")
        )
        observed["mx"] = mx
        actual_hosts = {host for _, host in mx}
        missing = expected_mx - actual_hosts
        if missing:
            failures.append(f"MX does not contain expected hosts: {sorted(missing)}")
    except dns.exception.DNSException as error:
        failures.append(f"MX lookup failed: {type(error).__name__}")

    try:
        outbound = ipaddress.ip_address(args.outbound_ip)
        authorized, spf_warnings = spf_authorizes(resolver, domain, outbound, set())
        observed["spf_authorizes_outbound_ip"] = authorized
        warnings.extend(spf_warnings)
        if not authorized:
            failures.append(f"SPF does not authorize {outbound}")
    except (dns.exception.DNSException, ValueError) as error:
        failures.append(f"SPF check failed: {type(error).__name__}: {error}")

    selector_name = f"{args.dkim_selector}._domainkey.{domain}"
    try:
        dkim_records = [
            value for value in txt_values(resolver, selector_name) if "p=" in value
        ]
        observed["dkim_record_count"] = len(dkim_records)
        if len(dkim_records) != 1:
            failures.append(f"expected one DKIM record at {selector_name}")
        else:
            tags = {
                key.strip().lower(): value.strip()
                for part in dkim_records[0].split(";")
                if "=" in part
                for key, value in (part.split("=", 1),)
            }
            private_key = serialization.load_pem_private_key(
                Path(args.dkim_private_key).read_bytes(), password=None
            )
            expected_key = base64.b64encode(
                private_key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.PKCS1,
                )
            ).decode()
            observed["dkim_key_matches"] = (
                tags.get("p", "").replace(" ", "") == expected_key
            )
            if not observed["dkim_key_matches"]:
                failures.append(
                    "published DKIM key does not match the configured private key"
                )
    except (dns.exception.DNSException, ValueError, TypeError) as error:
        failures.append(f"DKIM check failed: {type(error).__name__}: {error}")

    try:
        dmarc_records = [
            value
            for value in txt_values(resolver, f"_dmarc.{domain}")
            if value.lower().startswith("v=dmarc1")
        ]
        observed["dmarc"] = dmarc_records
        if len(dmarc_records) != 1:
            failures.append("expected exactly one DMARC record")
        else:
            dmarc_tags = {
                key.strip().lower(): value.strip().lower()
                for part in dmarc_records[0].split(";")
                if "=" in part
                for key, value in (part.split("=", 1),)
            }
            observed["dmarc_policy"] = dmarc_tags.get("p")
            if dmarc_tags.get("p") not in {"quarantine", "reject"}:
                failures.append("DMARC policy must be quarantine or reject")
    except dns.exception.DNSException as error:
        failures.append(f"DMARC lookup failed: {type(error).__name__}")

    try:
        ptr_names = sorted(
            fqdn(str(item))
            for item in resolver.resolve(
                dns.reversename.from_address(args.outbound_ip), "PTR"
            )
        )
        observed["ptr"] = ptr_names
        if not ptr_names:
            failures.append("outbound address has no PTR")
        elif not any(
            args.outbound_ip in resolve_addresses(resolver, name) for name in ptr_names
        ):
            failures.append(
                "PTR forward-confirmation does not return the outbound address"
            )
        if args.ptr_host and fqdn(args.ptr_host) not in ptr_names:
            failures.append(f"PTR does not contain expected host {fqdn(args.ptr_host)}")
    except dns.exception.DNSException as error:
        failures.append(f"PTR lookup failed: {type(error).__name__}")

    return {
        "domain": domain,
        "outbound_ip": args.outbound_ip,
        "read_only": True,
        "passed": not failures,
        "failures": failures,
        "warnings": warnings,
        "observed": observed,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True)
    parser.add_argument("--mx-host", action="append", required=True)
    parser.add_argument("--outbound-ip", required=True)
    parser.add_argument("--ptr-host")
    parser.add_argument("--dkim-selector", default="dkim")
    parser.add_argument(
        "--dkim-private-key",
        default=os.environ.get("DKIM_PRIVATE_KEY_PATH"),
        required=False,
    )
    parser.add_argument("--nameserver", action="append")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    if not args.dkim_private_key:
        parser.error("--dkim-private-key or DKIM_PRIVATE_KEY_PATH is required")
    result = check(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
