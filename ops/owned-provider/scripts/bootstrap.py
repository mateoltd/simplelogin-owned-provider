"""Idempotently provision the private local operator account and local domains."""

import json
import os
from pathlib import Path

from app.db import Session
from app.models import CustomDomain, SLDomain, User, UserAliasDeleteAction
from server import create_light_app


ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]
CUSTOM_DOMAIN = os.environ["OWNED_PROVIDER_CUSTOM_DOMAIN"]
ALIAS_DOMAINS = tuple(json.loads(os.environ["ALIAS_DOMAINS"]))


def password() -> str:
    value = Path(os.environ["ADMIN_PASSWORD_FILE"]).read_text().strip()
    if len(value) < 20:
        raise RuntimeError("operator password must contain at least 20 characters")
    return value


def provision() -> dict:
    for order, raw_domain in enumerate(ALIAS_DOMAINS):
        domain = raw_domain.strip()
        sl_domain = SLDomain.get_by(domain=domain) or SLDomain.create(domain=domain)
        sl_domain.order = order
        sl_domain.hidden = False
        sl_domain.premium_only = False
        sl_domain.use_as_reverse_alias = True
    Session.commit()

    user = User.get_by(email=ADMIN_EMAIL)
    if user is None:
        user = User.create(
            email=ADMIN_EMAIL,
            name="Owned provider operator",
            password=password(),
            activated=True,
            lifetime=True,
            alias_delete_action=UserAliasDeleteAction.DeleteImmediately,
        )
    else:
        user.set_password(password())
    user.activated = True
    user.disabled = False
    user.lifetime = True
    user.alias_delete_action = UserAliasDeleteAction.DeleteImmediately
    user.flags = user.flags & ~User.FLAG_FREE_DISABLE_CREATE_CONTACTS
    Session.commit()

    custom_domain = CustomDomain.get_by(domain=CUSTOM_DOMAIN)
    if custom_domain is None:
        custom_domain = CustomDomain.create(user_id=user.id, domain=CUSTOM_DOMAIN)
    elif custom_domain.user_id != user.id:
        raise RuntimeError(f"custom domain {CUSTOM_DOMAIN} belongs to another user")
    custom_domain.ownership_verified = True
    custom_domain.verified = True
    custom_domain.dkim_verified = True
    custom_domain.spf_verified = True
    custom_domain.dmarc_verified = True
    custom_domain.pending_deletion = False
    Session.commit()

    return {
        "admin_email": user.email,
        "admin_user_id": user.id,
        "default_mailbox_id": user.default_mailbox_id,
        "custom_domain": custom_domain.domain,
        "custom_domain_id": custom_domain.id,
        "public_alias_domains": [domain.strip() for domain in ALIAS_DOMAINS],
    }


if __name__ == "__main__":
    with create_light_app().app_context():
        print(json.dumps(provision(), sort_keys=True))
