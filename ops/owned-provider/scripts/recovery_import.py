"""Restore aliases and their relationships from a recovery export into a clean DB."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import arrow

from app.db import Session
from app.models import (
    Alias,
    AliasDeleteReason,
    AliasMailbox,
    AliasUsedOn,
    Contact,
    CustomDomain,
    Directory,
    DirectoryMailbox,
    DomainMailbox,
    Mailbox,
    User,
    UserAliasDeleteAction,
)
from server import create_light_app

from recovery_export import build_export, canonical_hash


def load_bundle(path: Path) -> dict:
    bundle = json.loads(path.read_text())
    if bundle.get("format") != "simplelogin-owned-provider-recovery":
        raise RuntimeError("unsupported recovery export")
    if bundle.get("format_version") != 1:
        raise RuntimeError("unsupported recovery export version")
    if canonical_hash(bundle["data"]) != bundle.get("data_sha256"):
        raise RuntimeError("recovery export integrity check failed")
    current_revision = Session.execute(
        "SELECT version_num FROM alembic_version"
    ).scalar()
    if current_revision != bundle.get("schema_revision"):
        raise RuntimeError(
            f"schema mismatch: export {bundle.get('schema_revision')}, database {current_revision}"
        )
    return bundle


def restore(bundle: dict, password: str) -> dict:
    data = bundle["data"]
    user_data = data["user"]
    if User.get_by(email=user_data["email"]):
        raise RuntimeError("recovery import requires a clean target user")

    user = User.create(
        email=user_data["email"],
        name=user_data["name"],
        password=password,
        activated=True,
        lifetime=True,
        alias_delete_action=UserAliasDeleteAction(user_data["alias_delete_action"]),
    )
    Session.flush()
    Session.query(Alias).filter(Alias.user_id == user.id).delete(
        synchronize_session=False
    )
    Session.commit()

    mailbox_map = {user.default_mailbox.email: user.default_mailbox}
    for item in data["mailboxes"]:
        mailbox = mailbox_map.get(item["email"])
        if mailbox is None:
            mailbox = Mailbox.create(user_id=user.id, email=item["email"])
            mailbox_map[item["email"]] = mailbox
        for field in (
            "verified",
            "force_spf",
            "disable_pgp",
            "disabled",
            "flags",
            "generic_subject",
        ):
            setattr(mailbox, field, item[field])
    Session.flush()

    domain_map = {}
    for item in data["custom_domains"]:
        domain = CustomDomain.create(user_id=user.id, domain=item["domain"])
        for field in (
            "name",
            "verified",
            "dkim_verified",
            "spf_verified",
            "dmarc_verified",
            "ownership_verified",
            "catch_all",
            "random_prefix_generation",
            "is_sl_subdomain",
            "pending_deletion",
        ):
            setattr(domain, field, item[field])
        domain_map[item["domain"]] = domain
    Session.flush()
    for item in data["custom_domains"]:
        for mailbox_email in item["mailboxes"]:
            DomainMailbox.create(
                domain_id=domain_map[item["domain"]].id,
                mailbox_id=mailbox_map[mailbox_email].id,
            )

    directory_map = {}
    for item in data["directories"]:
        directory = Directory.create(
            user_id=user.id, name=item["name"], disabled=item["disabled"]
        )
        directory_map[item["name"]] = directory
    Session.flush()
    for item in data["directories"]:
        for mailbox_email in item["mailboxes"]:
            DirectoryMailbox.create(
                directory_id=directory_map[item["name"]].id,
                mailbox_id=mailbox_map[mailbox_email].id,
            )

    alias_map = {}
    for item in data["aliases"]:
        alias_fields = dict(
            user_id=user.id,
            email=item["email"],
            name=item["name"],
            mailbox_id=mailbox_map[item["primary_mailbox"]].id,
            directory_id=(
                directory_map[item["directory"]].id if item["directory"] else None
            ),
            note=item["note"],
        )
        if item["custom_domain"]:
            alias_fields["custom_domain_id"] = domain_map[item["custom_domain"]].id
        alias = Alias.create(**alias_fields)
        for field in (
            "enabled",
            "flags",
            "automatic_creation",
            "disable_pgp",
            "cannot_be_disabled",
            "disable_email_spoofing_check",
            "pinned",
        ):
            setattr(alias, field, item[field])
        alias.delete_on = arrow.get(item["delete_on"]) if item["delete_on"] else None
        alias.delete_reason = (
            AliasDeleteReason(item["delete_reason"])
            if item["delete_reason"] is not None
            else None
        )
        alias_map[item["email"]] = alias
    Session.flush()
    for item in data["aliases"]:
        for mailbox_email in item["secondary_mailboxes"]:
            if mailbox_email == item["primary_mailbox"]:
                continue
            AliasMailbox.create(
                alias_id=alias_map[item["email"]].id,
                mailbox_id=mailbox_map[mailbox_email].id,
            )

    for item in data["contacts"]:
        Contact.create(
            user_id=user.id,
            alias_id=alias_map[item["alias"]].id,
            name=item["name"],
            website_email=item["website_email"],
            website_from=item["website_from"],
            reply_email=item["reply_email"],
            is_cc=item["is_cc"],
            mail_from=item["mail_from"],
            invalid_email=item["invalid_email"],
            block_forward=item["block_forward"],
            automatic_created=item["automatic_created"],
            flags=item["flags"],
        )
    for item in data["alias_used_on"]:
        AliasUsedOn.create(
            user_id=user.id,
            alias_id=alias_map[item["alias"]].id,
            hostname=item["hostname"],
        )

    user.name = user_data["name"]
    user.activated = user_data["activated"]
    user.disabled = user_data["disabled"]
    user.lifetime = user_data["lifetime"]
    user.flags = user_data["flags"]
    user.alias_delete_action = UserAliasDeleteAction(user_data["alias_delete_action"])
    user.random_alias_suffix = user_data["random_alias_suffix"]
    user.include_sender_in_reverse_alias = user_data["include_sender_in_reverse_alias"]
    user.default_mailbox_id = mailbox_map[user_data["default_mailbox"]].id
    Session.commit()

    restored_data = build_export(user)
    restored_hash = canonical_hash(restored_data)
    if restored_hash != bundle["data_sha256"]:
        raise RuntimeError(
            f"post-import verification failed: expected {bundle['data_sha256']}, got {restored_hash}"
        )
    return {
        "data_sha256": restored_hash,
        "aliases": len(restored_data["aliases"]),
        "contacts": len(restored_data["contacts"]),
        "mailboxes": len(restored_data["mailboxes"]),
        "custom_domains": len(restored_data["custom_domains"]),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    args = parser.parse_args()
    password = Path(os.environ["ADMIN_PASSWORD_FILE"]).read_text().strip()
    if len(password) < 20:
        raise RuntimeError("operator password must contain at least 20 characters")
    with create_light_app().app_context():
        bundle = load_bundle(Path(args.input))
        result = restore(bundle, password)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
