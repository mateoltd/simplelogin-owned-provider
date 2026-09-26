from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Mapping, Optional, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from .contracts import (
    ApplicationDestination,
    RawMessageRef,
    SmtpEnvelope,
    SmtpRecipient,
    canonical_mailbox,
    construct_safe_header,
    parse_uuid7,
)
from .errors import MailEdgeAuthorizationError, MailEdgeContractError


OPAQUE_ALIAS_TOKEN_RE = re.compile(r"^v1\.[A-Za-z0-9_-]{22,2044}$")


@dataclass(frozen=True)
class AliasRoute:
    alias_id: int
    address: str
    domain: str


@dataclass(frozen=True)
class ReverseAliasRoute:
    alias_address: str
    target_address: str
    authorized_senders: tuple[str, ...]


@dataclass(frozen=True)
class ReverseRoute:
    envelope: SmtpEnvelope
    visible_header_fields: tuple[str, ...]
    policy_code: str = "reverse_alias"

    def to_wire(self) -> Mapping[str, object]:
        return {
            "envelope": dict(self.envelope.to_wire()),
            "visibleHeaderFields": list(self.visible_header_fields),
            "policyCode": self.policy_code,
        }


class AliasRoutingRepository(Protocol):
    def resolve_or_create(self, address: str, domain: str) -> Optional[AliasRoute]: ...

    def resolve_reverse(
        self, reply_address: str, domain: str
    ) -> Optional[ReverseAliasRoute]: ...

    def resolve_destination(self, alias_id: int) -> Optional[AliasRoute]: ...


class OpaqueAliasTokenCodec:
    def __init__(self, tenant_id: str, key: bytes):
        if not 32 <= len(key) <= 1024:
            raise MailEdgeContractError("OPAQUE_TOKEN_KEY_INVALID")
        self._tenant_id = tenant_id
        self._destination_key = hmac.new(
            key, b"mail-edge-destination-id-key-v1", hashlib.sha256
        ).digest()
        self._cipher = AESSIV(
            hmac.new(key, b"mail-edge-alias-token-key-v1", hashlib.sha512).digest()
        )

    def _associated_data(self, purpose: str) -> list[bytes]:
        if purpose not in {"inbound", "reverse"}:
            raise MailEdgeContractError("OPAQUE_TOKEN_PURPOSE_INVALID")
        return [
            b"mail-edge-alias-token-v1",
            self._tenant_id.encode("ascii"),
            purpose.encode("ascii"),
        ]

    def encode(self, alias_id: int, purpose: str) -> str:
        if (
            isinstance(alias_id, bool)
            or not isinstance(alias_id, int)
            or not 1 <= alias_id <= 9_223_372_036_854_775_807
        ):
            raise MailEdgeContractError("OPAQUE_TOKEN_ALIAS_INVALID")
        encrypted = self._cipher.encrypt(
            alias_id.to_bytes(8, "big"), self._associated_data(purpose)
        )
        return "v1." + base64.urlsafe_b64encode(encrypted).rstrip(b"=").decode("ascii")

    def destination_id(self, alias_id: int, purpose: str) -> str:
        if (
            isinstance(alias_id, bool)
            or not isinstance(alias_id, int)
            or not 1 <= alias_id <= 9_223_372_036_854_775_807
        ):
            raise MailEdgeContractError("OPAQUE_TOKEN_ALIAS_INVALID")
        self._associated_data(purpose)
        digest = hmac.new(
            self._destination_key,
            b":".join(
                (
                    self._tenant_id.encode("ascii"),
                    purpose.encode("ascii"),
                    alias_id.to_bytes(8, "big"),
                )
            ),
            hashlib.sha256,
        ).hexdigest()
        return "d-" + digest

    def decode(self, token: str, purpose: str) -> int:
        if not isinstance(token, str) or not OPAQUE_ALIAS_TOKEN_RE.fullmatch(token):
            raise MailEdgeAuthorizationError("OPAQUE_TOKEN_INVALID")
        encoded = token[3:]
        try:
            encrypted = base64.urlsafe_b64decode(
                encoded + "=" * ((4 - len(encoded) % 4) % 4)
            )
            if (
                base64.urlsafe_b64encode(encrypted).rstrip(b"=").decode("ascii")
                != encoded
            ):
                raise ValueError
            clear = self._cipher.decrypt(encrypted, self._associated_data(purpose))
        except (InvalidTag, ValueError):
            raise MailEdgeAuthorizationError("OPAQUE_TOKEN_INVALID")
        if len(clear) != 8:
            raise MailEdgeAuthorizationError("OPAQUE_TOKEN_INVALID")
        alias_id = int.from_bytes(clear, "big")
        if alias_id < 1:
            raise MailEdgeAuthorizationError("OPAQUE_TOKEN_INVALID")
        return alias_id


class RecipientRouter:
    def __init__(
        self,
        tenant_id: str,
        repository: AliasRoutingRepository,
        tokens: OpaqueAliasTokenCodec,
    ):
        self._tenant_id = tenant_id
        self._repository = repository
        self._tokens = tokens

    def resolve_recipients(
        self, tenant_id: str, envelope: SmtpEnvelope, receipt_id: str
    ) -> tuple[Mapping[str, str], ...]:
        if tenant_id != self._tenant_id:
            raise MailEdgeAuthorizationError("TENANT_OR_DOMAIN_NOT_FOUND")
        parse_uuid7(receipt_id, "RECEIPT_ID_INVALID")
        if len(envelope.rcpt_to) > 128:
            raise MailEdgeContractError("RECIPIENT_DESTINATION_LIMIT")
        destinations = []
        seen = set()
        for recipient in envelope.rcpt_to:
            address, _, domain = canonical_mailbox(recipient.address)
            route = self._repository.resolve_or_create(address, domain)
            if route is None:
                raise MailEdgeAuthorizationError("TENANT_OR_DOMAIN_NOT_FOUND")
            destination_id = self._tokens.destination_id(route.alias_id, "inbound")
            if destination_id in seen:
                continue
            seen.add(destination_id)
            destinations.append(
                {
                    "destinationId": destination_id,
                    "deliveryMode": "push",
                    "opaqueToken": self._tokens.encode(route.alias_id, "inbound"),
                }
            )
        if not destinations:
            raise MailEdgeAuthorizationError("RECIPIENTS_NOT_RESOLVED")
        return tuple(sorted(destinations, key=lambda item: item["destinationId"]))

    def resolve_destination(
        self, destination: ApplicationDestination, envelope: SmtpEnvelope
    ) -> AliasRoute:
        if destination.delivery_mode != "push":
            raise MailEdgeAuthorizationError("APPLICATION_DESTINATION_NOT_FOUND")
        alias_id = self._tokens.decode(destination.opaque_token, "inbound")
        expected_destination_id = self._tokens.destination_id(alias_id, "inbound")
        if not hmac.compare_digest(
            destination.destination_id.encode("utf-8"),
            expected_destination_id.encode("ascii"),
        ):
            raise MailEdgeAuthorizationError("APPLICATION_DESTINATION_NOT_FOUND")
        route = self._repository.resolve_destination(alias_id)
        if route is None:
            raise MailEdgeAuthorizationError("APPLICATION_DESTINATION_NOT_FOUND")
        recipients = {
            canonical_mailbox(recipient.address)[0] for recipient in envelope.rcpt_to
        }
        if canonical_mailbox(route.address)[0] not in recipients:
            raise MailEdgeAuthorizationError("APPLICATION_DESTINATION_NOT_FOUND")
        return route


class ReverseRouteResolver:
    def __init__(self, tenant_id: str, repository: AliasRoutingRepository):
        self._tenant_id = tenant_id
        self._repository = repository

    def resolve_reverse_route(
        self,
        tenant_id: str,
        envelope: SmtpEnvelope,
        raw: RawMessageRef,
        opaque_reply_token: str,
    ) -> ReverseRoute:
        if tenant_id != self._tenant_id:
            raise MailEdgeAuthorizationError("TENANT_OR_DOMAIN_NOT_FOUND")
        reply_address, _, reply_domain = canonical_mailbox(opaque_reply_token)
        route = self._repository.resolve_reverse(reply_address, reply_domain)
        if route is None:
            raise MailEdgeAuthorizationError("TENANT_OR_DOMAIN_NOT_FOUND")
        if (
            envelope.mail_from is None
            or envelope.mail_from not in route.authorized_senders
        ):
            raise MailEdgeAuthorizationError("REVERSE_ROUTE_NOT_AUTHORIZED")
        target = canonical_mailbox(route.target_address)[0]
        alias_address = canonical_mailbox(route.alias_address)[0]
        resolved = SmtpEnvelope(
            mail_from=alias_address,
            rcpt_to=(SmtpRecipient(target),),
            smtp_utf8=envelope.smtp_utf8
            or not target.isascii()
            or not alias_address.isascii(),
            body=envelope.body,
            require_tls=envelope.require_tls,
            dsn=envelope.dsn,
        )
        fields = (
            construct_safe_header("From", alias_address),
            construct_safe_header("To", target),
        )
        return ReverseRoute(resolved, fields)
