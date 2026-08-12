"""Create a secret-free, relationship-complete recovery export for one user."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from app.db import Session
from app.models import (
    Alias,
    AliasMailbox,
    AliasUsedOn,
    Contact,
    CustomDomain,
    Directory,
    DirectoryMailbox,
    DomainMailbox,
    Mailbox,
    User,
)
from server import create_light_app


def enum_value(value):
    return value.value if hasattr(value, "value") else value


def canonical_hash(data: dict) -> str:
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def build_export(user: User) -> dict:
    mailboxes = Mailbox.filter_by(user_id=user.id).order_by(Mailbox.email).all()
    domains = (
        CustomDomain.filter_by(user_id=user.id).order_by(CustomDomain.domain).all()
    )
    directories = Directory.filter_by(user_id=user.id).order_by(Directory.name).all()
    aliases = Alias.filter_by(user_id=user.id).order_by(Alias.email).all()

    mailbox_by_id = {mailbox.id: mailbox.email for mailbox in mailboxes}
    domain_by_id = {domain.id: domain.domain for domain in domains}
    directory_by_id = {directory.id: directory.name for directory in directories}
    alias_by_id = {alias.id: alias.email for alias in aliases}

    data = {
        "user": {
            "email": user.email,
            "name": user.name,
            "activated": user.activated,
            "disabled": user.disabled,
            "lifetime": user.lifetime,
            "flags": user.flags,
            "alias_delete_action": enum_value(user.alias_delete_action),
            "random_alias_suffix": user.random_alias_suffix,
            "include_sender_in_reverse_alias": user.include_sender_in_reverse_alias,
            "default_mailbox": mailbox_by_id[user.default_mailbox_id],
        },
        "mailboxes": [
            {
                "email": mailbox.email,
                "verified": mailbox.verified,
                "force_spf": mailbox.force_spf,
                "disable_pgp": mailbox.disable_pgp,
                "disabled": mailbox.disabled,
                "flags": mailbox.flags,
                "generic_subject": mailbox.generic_subject,
            }
            for mailbox in mailboxes
        ],
        "custom_domains": [],
        "directories": [],
        "aliases": [],
        "contacts": [],
        "alias_used_on": [],
    }

    for domain in domains:
        domain_mailboxes = (
            Session.query(DomainMailbox)
            .filter(DomainMailbox.domain_id == domain.id)
            .order_by(DomainMailbox.mailbox_id)
            .all()
        )
        data["custom_domains"].append(
            {
                "domain": domain.domain,
                "name": domain.name,
                "verified": domain.verified,
                "dkim_verified": domain.dkim_verified,
                "spf_verified": domain.spf_verified,
                "dmarc_verified": domain.dmarc_verified,
                "ownership_verified": domain.ownership_verified,
                "catch_all": domain.catch_all,
                "random_prefix_generation": domain.random_prefix_generation,
                "is_sl_subdomain": domain.is_sl_subdomain,
                "pending_deletion": domain.pending_deletion,
                "mailboxes": sorted(
                    mailbox_by_id[item.mailbox_id] for item in domain_mailboxes
                ),
            }
        )

    for directory in directories:
        directory_mailboxes = (
            Session.query(DirectoryMailbox)
            .filter(DirectoryMailbox.directory_id == directory.id)
            .order_by(DirectoryMailbox.mailbox_id)
            .all()
        )
        data["directories"].append(
            {
                "name": directory.name,
                "disabled": directory.disabled,
                "mailboxes": sorted(
                    mailbox_by_id[item.mailbox_id] for item in directory_mailboxes
                ),
            }
        )

    for alias in aliases:
        secondary = (
            Session.query(AliasMailbox)
            .filter(AliasMailbox.alias_id == alias.id)
            .order_by(AliasMailbox.mailbox_id)
            .all()
        )
        data["aliases"].append(
            {
                "email": alias.email,
                "name": alias.name,
                "enabled": alias.enabled,
                "flags": alias.flags,
                "custom_domain": domain_by_id.get(alias.custom_domain_id),
                "automatic_creation": alias.automatic_creation,
                "directory": directory_by_id.get(alias.directory_id),
                "note": alias.note,
                "primary_mailbox": mailbox_by_id[alias.mailbox_id],
                "secondary_mailboxes": sorted(
                    mailbox_by_id[item.mailbox_id] for item in secondary
                ),
                "disable_pgp": alias.disable_pgp,
                "cannot_be_disabled": alias.cannot_be_disabled,
                "disable_email_spoofing_check": alias.disable_email_spoofing_check,
                "pinned": alias.pinned,
                "delete_on": alias.delete_on.isoformat() if alias.delete_on else None,
                "delete_reason": enum_value(alias.delete_reason),
            }
        )

    contacts = Contact.filter_by(user_id=user.id).order_by(Contact.id).all()
    for contact in contacts:
        data["contacts"].append(
            {
                "alias": alias_by_id[contact.alias_id],
                "name": contact.name,
                "website_email": contact.website_email,
                "website_from": contact.website_from,
                "reply_email": contact.reply_email,
                "is_cc": contact.is_cc,
                "mail_from": contact.mail_from,
                "invalid_email": contact.invalid_email,
                "block_forward": contact.block_forward,
                "automatic_created": contact.automatic_created,
                "flags": contact.flags,
            }
        )
    data["contacts"].sort(key=lambda item: (item["alias"], item["website_email"]))

    used_on = AliasUsedOn.filter_by(user_id=user.id).order_by(AliasUsedOn.id).all()
    data["alias_used_on"] = sorted(
        [
            {"alias": alias_by_id[item.alias_id], "hostname": item.hostname}
            for item in used_on
        ],
        key=lambda item: (item["alias"], item["hostname"]),
    )
    return data


def export_bundle(email: str) -> dict:
    user = User.get_by(email=email)
    if user is None:
        raise RuntimeError(f"unknown user: {email}")
    data = build_export(user)
    revision = Session.execute("SELECT version_num FROM alembic_version").scalar()
    return {
        "format": "simplelogin-owned-provider-recovery",
        "format_version": 1,
        "upstream_commit": Path("/code/ops/owned-provider/UPSTREAM_COMMIT")
        .read_text()
        .strip(),
        "schema_revision": revision,
        "data_sha256": canonical_hash(data),
        "counts": {
            key: len(value) for key, value in data.items() if isinstance(value, list)
        },
        "data": data,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    parser.add_argument("--email", default=os.environ["ADMIN_EMAIL"])
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with create_light_app().app_context():
        bundle = export_bundle(args.email)
    output.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "path": str(output),
                "data_sha256": bundle["data_sha256"],
                "counts": bundle["counts"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
