"""Idempotent operator lifecycle controls for configured domains and mailboxes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from sqlalchemy import text

from app.db import Session
from app.models import CustomDomain, Mailbox, User
from server import create_light_app

LOCK_ID = 7_329_461_006


def operation_key(action: str, target: str) -> str:
    return hashlib.sha256(f"{action}\0{target.lower()}".encode()).hexdigest()


def was_recorded(key: str) -> bool:
    return bool(
        Session.execute(
            text("SELECT 1 FROM owned_provider.operation WHERE idempotency_key=:key"),
            {"key": key},
        ).scalar()
    )


def remember(key: str, operation: str, result: dict):
    Session.execute(
        text("""
        INSERT INTO owned_provider.operation(idempotency_key, operation, result)
        VALUES (:key, :operation, CAST(:result AS jsonb))
        ON CONFLICT (idempotency_key) DO NOTHING
        """),
        {"key": key, "operation": operation, "result": json.dumps(result)},
    )
    Session.commit()


def mailbox_action(action: str, email: str) -> dict:
    user = User.get_by(email=os.environ["ADMIN_EMAIL"])
    mailbox = Mailbox.get_by(user_id=user.id, email=email.lower())
    if mailbox is None:
        raise RuntimeError(f"unknown mailbox: {email}")
    key = operation_key(action, email)
    desired_disabled = action == "mailbox-disable"
    replayed = was_recorded(key) and mailbox.disabled == desired_disabled
    if action == "mailbox-enable":
        mailbox.disabled = False
    elif action == "mailbox-disable":
        if mailbox.id == user.default_mailbox_id:
            raise RuntimeError("refusing to disable the default mailbox")
        mailbox.disabled = True
    else:
        raise RuntimeError(f"unsupported mailbox action: {action}")
    Session.commit()
    result = {"action": action, "email": email.lower(), "disabled": mailbox.disabled}
    remember(key, action, result)
    return {**result, "replayed": replayed}


def verify_domain(domain_name: str, report_path: str) -> dict:
    report = json.load(open(report_path, encoding="utf-8"))
    domain_name = domain_name.lower().rstrip(".")
    if not report.get("passed") or report.get("domain", "").rstrip(".") != domain_name:
        raise RuntimeError("a passing DNS preflight for this exact domain is required")
    user = User.get_by(email=os.environ["ADMIN_EMAIL"])
    domain = CustomDomain.get_by(domain=domain_name)
    if domain is None or domain.user_id != user.id:
        raise RuntimeError(
            f"configured custom domain is missing or not owned: {domain_name}"
        )
    key = operation_key("domain-verify", domain_name + report["outbound_ip"])
    replayed = was_recorded(key) and all(
        (
            domain.ownership_verified,
            domain.verified,
            domain.dkim_verified,
            domain.spf_verified,
            domain.dmarc_verified,
            not domain.pending_deletion,
        )
    )
    domain.ownership_verified = True
    domain.verified = True
    domain.dkim_verified = True
    domain.spf_verified = True
    domain.dmarc_verified = True
    domain.pending_deletion = False
    Session.commit()
    result = {"action": "domain-verify", "domain": domain_name, "verified": True}
    remember(key, "domain-verify", result)
    return {**result, "replayed": replayed}


def status() -> dict:
    user = User.get_by(email=os.environ["ADMIN_EMAIL"])
    domains = (
        CustomDomain.filter_by(user_id=user.id).order_by(CustomDomain.domain).all()
    )
    mailboxes = Mailbox.filter_by(user_id=user.id).order_by(Mailbox.email).all()
    return {
        "domains": [
            {
                "domain": item.domain,
                "ownership": item.ownership_verified,
                "mx": item.verified,
                "spf": item.spf_verified,
                "dkim": item.dkim_verified,
                "dmarc": item.dmarc_verified,
                "pending_deletion": item.pending_deletion,
            }
            for item in domains
        ],
        "mailboxes": [
            {
                "email": item.email,
                "verified": item.verified,
                "disabled": item.disabled,
                "default": item.id == user.default_mailbox_id,
            }
            for item in mailboxes
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("status")
    for action in ("mailbox-enable", "mailbox-disable"):
        child = subparsers.add_parser(action)
        child.add_argument("email")
    domain = subparsers.add_parser("domain-verify")
    domain.add_argument("domain")
    domain.add_argument("dns_report")
    args = parser.parse_args()
    Session.execute(text("SELECT pg_advisory_lock(:lock)"), {"lock": LOCK_ID})
    try:
        if args.action == "status":
            result = status()
        elif args.action == "domain-verify":
            result = verify_domain(args.domain, args.dns_report)
        else:
            result = mailbox_action(args.action, args.email)
        print(json.dumps(result, sort_keys=True))
    finally:
        Session.execute(text("SELECT pg_advisory_unlock(:lock)"), {"lock": LOCK_ID})
        Session.commit()


if __name__ == "__main__":
    with create_light_app().app_context():
        main()
