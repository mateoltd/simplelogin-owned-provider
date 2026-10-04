from __future__ import annotations

from typing import Optional

from app import config
from app.alias_utils import try_auto_create
from app.db import Session
from app.models import Alias, Contact, CustomDomain, SLDomain

from .routing import AliasRoute, ReverseAliasRoute


class SimpleLoginAliasRoutingRepository:
    """Exact indexed host-owned lookups; never scans a user's alias collection."""

    def resolve_or_create(self, address: str, domain: str) -> Optional[AliasRoute]:
        public_domain = (
            SLDomain.filter_by(domain=domain).with_entities(SLDomain.id).first()
        )
        custom_domain = CustomDomain.filter_by(
            domain=domain, pending_deletion=False
        ).first()
        if public_domain is not None:
            custom_domain = None
        if public_domain is None and custom_domain is None:
            return None
        alias = Alias.filter_by(email=address).first()
        if alias is None and custom_domain is not None:
            alias = try_auto_create(address)
            if alias is not None and alias.custom_domain_id != custom_domain.id:
                Session.rollback()
                return None
        if (
            alias is None
            or not alias.enabled
            or alias.is_trashed()
            or not alias.user.can_send_or_receive()
        ):
            return None
        if alias.email.rsplit("@", 1)[1] != domain:
            return None
        if custom_domain is not None and (
            alias.custom_domain_id != custom_domain.id
            or not custom_domain.ownership_verified
            or not custom_domain.verified
        ):
            return None
        return AliasRoute(alias.id, alias.email, domain)

    def resolve_reverse(
        self, reply_address: str, domain: str
    ) -> Optional[ReverseAliasRoute]:
        reverse_domain = (
            SLDomain.filter_by(domain=domain, use_as_reverse_alias=True)
            .with_entities(SLDomain.id)
            .first()
        )
        if reverse_domain is None and domain != config.EMAIL_DOMAIN:
            return None
        contacts = (
            Contact.query()
            .join(Alias, Contact.alias_id == Alias.id)
            .filter(Contact.reply_email == reply_address)
            .filter(Alias.enabled.is_(True), Alias.delete_on.is_(None))
            .limit(2)
            .all()
        )
        if len(contacts) != 1 or not contacts[0].user.can_send_or_receive():
            return None
        contact = contacts[0]
        alias_route = self.resolve_destination(contact.alias_id)
        if alias_route is None:
            return None
        return ReverseAliasRoute(
            alias_address=alias_route.address,
            target_address=contact.website_email,
            authorized_senders=tuple(contact.alias.authorized_addresses()),
        )

    def resolve_destination(self, alias_id: int) -> Optional[AliasRoute]:
        alias = Alias.get(alias_id)
        if (
            alias is None
            or not alias.enabled
            or alias.is_trashed()
            or not alias.user.can_send_or_receive()
        ):
            return None
        address = alias.email
        domain = address.rsplit("@", 1)[1]
        public_domain = (
            SLDomain.filter_by(domain=domain).with_entities(SLDomain.id).first()
        )
        if public_domain is not None:
            return AliasRoute(alias.id, address, domain)
        custom_domain = CustomDomain.filter_by(
            id=alias.custom_domain_id,
            domain=domain,
            pending_deletion=False,
            ownership_verified=True,
            verified=True,
        ).first()
        if custom_domain is None:
            return None
        return AliasRoute(alias.id, address, domain)
