import hashlib

import pytest

from app.mail_edge.contracts import RawMessageRef, SmtpEnvelope, SmtpRecipient
from app.mail_edge.errors import MailEdgeAuthorizationError
from app.mail_edge.routing import (
    AliasRoute,
    OpaqueAliasTokenCodec,
    RecipientRouter,
    ReverseAliasRoute,
    ReverseRouteResolver,
)


TENANT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401111"
RECEIPT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401112"


class Repository:
    def __init__(self):
        self.addresses = {
            "Case@example.com": AliasRoute(7, "Case@example.com", "example.com"),
            "case@example.com": AliasRoute(8, "case@example.com", "example.com"),
        }

    def resolve_or_create(self, address, domain):
        return self.addresses.get(address)

    def resolve_reverse(self, reply_address, domain):
        if reply_address != "reply@example.com" or domain != "example.com":
            return None
        return ReverseAliasRoute(
            "alias@example.com", "sender@example.net", ("mailbox@example.org",)
        )


def test_recipient_router_preserves_local_case_and_rejects_cross_tenant():
    tokens = OpaqueAliasTokenCodec(TENANT_ID, b"k" * 32)
    router = RecipientRouter(TENANT_ID, Repository(), tokens)
    envelope = SmtpEnvelope(
        None,
        (SmtpRecipient("Case@example.com"), SmtpRecipient("case@example.com")),
        False,
    )
    destinations = router.resolve_recipients(TENANT_ID, envelope, RECEIPT_ID)
    assert len(destinations) == 2
    assert destinations[0]["destinationId"] != destinations[1]["destinationId"]
    assert all("example.com" not in item["opaqueToken"] for item in destinations)
    assert sorted(
        tokens.decode(item["opaqueToken"], "inbound") for item in destinations
    ) == [7, 8]
    final = destinations[0]["opaqueToken"][-1]
    tampered = destinations[0]["opaqueToken"][:-1] + ("A" if final != "A" else "B")
    with pytest.raises(MailEdgeAuthorizationError):
        tokens.decode(tampered, "inbound")
    with pytest.raises(MailEdgeAuthorizationError):
        tokens.decode(destinations[0]["opaqueToken"], "reverse")
    with pytest.raises(MailEdgeAuthorizationError):
        router.resolve_recipients(RECEIPT_ID, envelope, RECEIPT_ID)


def test_recipient_router_rejects_partial_or_unknown_domain_resolution():
    router = RecipientRouter(
        TENANT_ID, Repository(), OpaqueAliasTokenCodec(TENANT_ID, b"k" * 32)
    )
    envelope = SmtpEnvelope(
        None,
        (SmtpRecipient("Case@example.com"), SmtpRecipient("missing@example.net")),
        False,
    )
    with pytest.raises(MailEdgeAuthorizationError):
        router.resolve_recipients(TENANT_ID, envelope, RECEIPT_ID)


def test_reverse_route_is_exact_authorized_and_leaves_thread_fields_unmodified():
    resolver = ReverseRouteResolver(TENANT_ID, Repository())
    envelope = SmtpEnvelope(
        "mailbox@example.org", (SmtpRecipient("reply@example.com"),), False
    )
    raw = RawMessageRef(RECEIPT_ID, hashlib.sha256(b"raw").hexdigest(), 3)
    resolution = resolver.resolve_reverse_route(
        TENANT_ID, envelope, raw, "reply@example.com"
    )
    assert resolution.envelope.mail_from == "alias@example.com"
    assert resolution.envelope.rcpt_to[0].address == "sender@example.net"
    assert resolution.visible_header_fields == (
        "From: alias@example.com",
        "To: sender@example.net",
    )
    with pytest.raises(MailEdgeAuthorizationError):
        resolver.resolve_reverse_route(
            TENANT_ID,
            SmtpEnvelope(
                "attacker@example.org", (SmtpRecipient("reply@example.com"),), False
            ),
            raw,
            "reply@example.com",
        )
