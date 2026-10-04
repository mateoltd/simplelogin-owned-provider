"""Validate configured ownership and alias relationship invariants at any scale."""

from __future__ import annotations

import json
import os
from sqlalchemy import text

from app.db import Session
from app.mail_edge.configuration import configuration_from_environment
from app.models import CustomDomain, SLDomain, User
from server import create_light_app


def scalar(sql, params=None):
    return Session.execute(text(sql), params or {}).scalar()


def reconcile() -> dict:
    admin = User.get_by(email=os.environ["ADMIN_EMAIL"])
    if admin is None:
        raise RuntimeError("configured operator account is missing")
    custom_names = sorted(json.loads(os.environ["OWNED_PROVIDER_CUSTOM_DOMAINS"]))
    custom_domains = {
        item.domain: item
        for item in CustomDomain.filter(CustomDomain.domain.in_(custom_names)).all()
    }
    configured_sl = sorted(json.loads(os.environ["ALIAS_DOMAINS"]))
    missing_sl = [
        name for name in configured_sl if SLDomain.get_by(domain=name) is None
    ]
    mail_edge_configuration = configuration_from_environment()
    mail_edge_tenant = (
        mail_edge_configuration.tenant_id
        if mail_edge_configuration is not None
        else None
    )
    problems = {
        "missing_alias_domains": missing_sl,
        "missing_custom_domains": sorted(set(custom_names) - set(custom_domains)),
        "custom_domains_wrong_owner": sorted(
            name
            for name, domain in custom_domains.items()
            if domain.user_id != admin.id
        ),
        "alias_mailbox_wrong_owner": scalar(
            """
            SELECT count(*) FROM alias a JOIN mailbox m ON m.id=a.mailbox_id
            WHERE a.user_id <> m.user_id
            """
        ),
        "secondary_mailbox_wrong_owner": scalar(
            """
            SELECT count(*) FROM alias_mailbox am
            JOIN alias a ON a.id=am.alias_id JOIN mailbox m ON m.id=am.mailbox_id
            WHERE a.user_id <> m.user_id
            """
        ),
        "contact_wrong_owner": scalar(
            """
            SELECT count(*) FROM contact c JOIN alias a ON a.id=c.alias_id
            WHERE c.user_id <> a.user_id
            """
        ),
        "custom_alias_domain_mismatch": scalar(
            """
            SELECT count(*) FROM alias a
            JOIN custom_domain d ON d.id=a.custom_domain_id
            WHERE lower(split_part(a.email, '@', 2)) <> lower(d.domain)
            """
        ),
        "duplicate_alias_mailbox_links": scalar(
            """
            SELECT count(*) FROM (
                SELECT alias_id, mailbox_id FROM alias_mailbox
                GROUP BY alias_id, mailbox_id HAVING count(*) > 1
            ) duplicate
            """
        ),
        "mail_edge_outbound_wrong_owner": scalar(
            """
            SELECT count(*) FROM mail_edge_outbound_projection p
            JOIN alias a ON a.id=p.alias_id
            WHERE p.user_id <> a.user_id
               OR (p.mailbox_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM mailbox m
                    WHERE m.id=p.mailbox_id AND m.user_id=p.user_id))
               OR (p.contact_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM contact c
                    WHERE c.id=p.contact_id AND c.user_id=p.user_id
                      AND c.alias_id=p.alias_id))
            """
        ),
        "mail_edge_binding_unauthorized_domain": scalar(
            """
            SELECT count(*) FROM mail_edge_route_binding_projection p
            WHERE NOT EXISTS (
                    SELECT 1 FROM public_domain d WHERE lower(d.domain)=p.domain_a_label)
              AND NOT EXISTS (
                    SELECT 1 FROM custom_domain d
                    WHERE lower(d.domain)=p.domain_a_label
                      AND d.ownership_verified AND d.verified
                      AND NOT d.pending_deletion)
            """
        ),
        "mail_edge_ambiguous_callbacks": scalar(
            """
            SELECT count(*) FROM mail_edge_callback_receipt
            WHERE status='processing' AND business_started_at IS NOT NULL
            """
        ),
    }
    if mail_edge_tenant is not None:
        problems["mail_edge_tenant_mismatch"] = scalar(
            """
            SELECT sum(count) FROM (
              SELECT count(*) FROM mail_edge_callback_receipt WHERE tenant_id<>:tenant
              UNION ALL
              SELECT count(*) FROM mail_edge_outbound_projection WHERE tenant_id<>:tenant
              UNION ALL
              SELECT count(*) FROM mail_edge_route_binding_projection WHERE tenant_id<>:tenant
            ) mismatches
            """,
            {"tenant": mail_edge_tenant},
        )
    result = {
        "ok": not any(
            value if isinstance(value, bool) else bool(value)
            for value in problems.values()
        ),
        "aliases": scalar("SELECT count(*) FROM alias"),
        "mailboxes": scalar("SELECT count(*) FROM mailbox"),
        "custom_domains": scalar("SELECT count(*) FROM custom_domain"),
        "contacts": scalar("SELECT count(*) FROM contact"),
        "mail_edge_callbacks": scalar(
            "SELECT count(*) FROM mail_edge_callback_receipt"
        ),
        "mail_edge_outbound_projections": scalar(
            "SELECT count(*) FROM mail_edge_outbound_projection"
        ),
        "mail_edge_binding_projections": scalar(
            "SELECT count(*) FROM mail_edge_route_binding_projection"
        ),
        "problems": problems,
    }
    if not result["ok"]:
        raise SystemExit(json.dumps(result, sort_keys=True))
    return result


if __name__ == "__main__":
    with create_light_app().app_context():
        print(json.dumps(reconcile(), sort_keys=True))
