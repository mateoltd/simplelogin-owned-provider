from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping, Optional, Sequence

from .errors import MailEdgeContractError


UUID_V7_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PROVIDER_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
POLICY_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]{1,78}$")
DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$"
)
RFC3339_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)
BOUNDED_MAP_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")
EVIDENCE_KEY_RE = re.compile(r"^[a-z][A-Za-z0-9]*$")
XTEXT_RE = re.compile(r"^(?:[\x21-\x2a\x2c-\x3c\x3e-\x7e]|\+[0-9A-F]{2})+$")
ORCPT_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9-]{0,63};(?:[\x21-\x2a\x2c-\x3c\x3e-\x7e]|\+[0-9A-F]{2})+$"
)
ASCII_ATEXT = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-/=?^_`{|}~"
)
MAX_RAW_BYTES = 25 * 1024 * 1024
FEEDBACK_KINDS = frozenset(
    {
        "accepted",
        "delivered",
        "deferred",
        "bounced",
        "complained",
        "suppressed",
        "opened",
        "clicked",
        "unsubscribed",
    }
)
OUTBOUND_STATES = frozenset(
    {
        "accepted",
        "ready",
        "dispatching",
        "retry_wait",
        "provider_accepted",
        "failed_not_sent",
        "quarantined_unknown",
        "canceled",
    }
)
THREAD_HEADERS = frozenset({"message-id", "in-reply-to", "references"})
VISIBLE_HEADERS = frozenset({"cc", "from", "reply-to", "sender", "to"})


def _fail(code: str) -> None:
    raise MailEdgeContractError(code)


def _object(
    value: Any, required: set[str], optional: set[str] = frozenset()
) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != required | (set(value) & optional):
        _fail("CONTRACT_OBJECT_INVALID")
    if not required.issubset(value):
        _fail("CONTRACT_REQUIRED_FIELD_MISSING")
    return value


def _string(value: Any, minimum: int, maximum: int, code: str) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        _fail(code)
    return value


def _integer(value: Any, minimum: int, maximum: int, code: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        _fail(code)
    return value


def parse_uuid7(value: Any, code: str) -> str:
    if not isinstance(value, str) or not UUID_V7_RE.fullmatch(value):
        _fail(code)
    try:
        if uuid.UUID(value).version != 7:
            _fail(code)
    except ValueError:
        _fail(code)
    return value


def parse_rfc3339(value: Any, code: str) -> str:
    text = _string(value, 20, 35, code)
    if not RFC3339_RE.fullmatch(text):
        _fail(code)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        _fail(code)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail(code)
    return text


def canonical_json(value: Any) -> bytes:
    def validate(candidate: Any) -> None:
        if candidate is None or isinstance(candidate, (str, bool)):
            return
        if isinstance(candidate, int):
            if abs(candidate) > 9_007_199_254_740_991:
                _fail("CANONICAL_JSON_NUMBER_INVALID")
            return
        if isinstance(candidate, float):
            if not math.isfinite(candidate):
                _fail("CANONICAL_JSON_NUMBER_INVALID")
            return
        if isinstance(candidate, list):
            for item in candidate:
                validate(item)
            return
        if isinstance(candidate, dict) and all(
            isinstance(key, str) for key in candidate
        ):
            for item in candidate.values():
                validate(item)
            return
        _fail("CANONICAL_JSON_VALUE_INVALID")

    validate(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_canonical_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def canonical_domain(value: Any) -> str:
    domain = _string(value, 1, 253, "DOMAIN_INVALID")
    if domain.endswith(".") or "*" in domain:
        _fail("DOMAIN_NOT_EXACT")
    try:
        alabel = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        _fail("DOMAIN_INVALID")
    if domain != alabel or not DOMAIN_RE.fullmatch(alabel):
        _fail("DOMAIN_NOT_CANONICAL")
    return alabel


def canonical_mailbox(value: Any) -> tuple[str, str, str]:
    mailbox = _string(value, 3, 512, "MAILBOX_INVALID")
    if any(character in mailbox for character in "\r\n\0"):
        _fail("MAILBOX_INVALID")
    quoted = False
    escaped = False
    separator = -1
    for index, character in enumerate(mailbox):
        if escaped:
            escaped = False
            continue
        if quoted and character == "\\":
            escaped = True
            continue
        if character == '"':
            quoted = not quoted
        elif not quoted and character == "@":
            if separator != -1:
                _fail("MAILBOX_INVALID")
            separator = index
    if quoted or escaped or separator <= 0 or separator >= len(mailbox) - 1:
        _fail("MAILBOX_INVALID")
    local_part, raw_domain = mailbox[:separator], mailbox[separator + 1 :]
    if len(local_part.encode("utf-8")) > 64:
        _fail("MAILBOX_INVALID")
    if local_part.startswith('"') and local_part.endswith('"') and len(local_part) >= 2:
        escaped = False
        for character in local_part[1:-1]:
            code_point = ord(character)
            if escaped:
                if code_point < 32 or code_point == 127:
                    _fail("MAILBOX_INVALID")
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"' or code_point < 32 or code_point == 127:
                _fail("MAILBOX_INVALID")
        if escaped:
            _fail("MAILBOX_INVALID")
    else:
        if local_part.startswith(".") or local_part.endswith(".") or ".." in local_part:
            _fail("MAILBOX_INVALID")
        for character in local_part:
            if character == ".":
                continue
            if character.isascii():
                if character not in ASCII_ATEXT:
                    _fail("MAILBOX_INVALID")
            elif unicodedata.category(character)[0] in {"C", "Z"}:
                _fail("MAILBOX_INVALID")
    if raw_domain.endswith(".") or "*" in raw_domain or raw_domain.startswith("["):
        _fail("MAILBOX_INVALID")
    try:
        domain = raw_domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        _fail("MAILBOX_INVALID")
    if len(domain) > 253 or not DOMAIN_RE.fullmatch(domain):
        _fail("MAILBOX_INVALID")
    canonical = f"{local_part}@{domain}"
    if len(canonical.encode("utf-8")) > 254:
        _fail("MAILBOX_INVALID")
    return canonical, local_part, domain


@dataclass(frozen=True)
class RawMessageRef:
    blob_id: str
    sha256: str
    size: int
    media_type: str = "message/rfc822"
    schema_version: str = "v1"

    def to_wire(self) -> Mapping[str, Any]:
        return MappingProxyType(
            {
                "schemaVersion": self.schema_version,
                "blobId": self.blob_id,
                "sha256": self.sha256,
                "size": self.size,
                "mediaType": self.media_type,
            }
        )


def parse_raw_message_ref(
    value: Any, maximum_bytes: int = MAX_RAW_BYTES
) -> RawMessageRef:
    candidate = _object(
        value, {"schemaVersion", "blobId", "sha256", "size", "mediaType"}
    )
    if candidate["schemaVersion"] != "v1" or candidate["mediaType"] != "message/rfc822":
        _fail("RAW_REFERENCE_VERSION_INVALID")
    digest = candidate["sha256"]
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        _fail("RAW_REFERENCE_DIGEST_INVALID")
    return RawMessageRef(
        blob_id=parse_uuid7(candidate["blobId"], "RAW_REFERENCE_BLOB_ID_INVALID"),
        sha256=digest,
        size=_integer(
            candidate["size"], 0, maximum_bytes, "RAW_REFERENCE_SIZE_INVALID"
        ),
    )


@dataclass(frozen=True)
class ApplicationDestination:
    destination_id: str
    delivery_mode: str
    opaque_token: str

    def to_wire(self) -> Mapping[str, str]:
        return MappingProxyType(
            {
                "destinationId": self.destination_id,
                "deliveryMode": self.delivery_mode,
                "opaqueToken": self.opaque_token,
            }
        )


def parse_application_destination(value: Any) -> ApplicationDestination:
    candidate = _object(value, {"destinationId", "deliveryMode", "opaqueToken"})
    delivery_mode = candidate["deliveryMode"]
    if delivery_mode not in {"push", "pull"}:
        _fail("APPLICATION_DESTINATION_MODE_INVALID")
    return ApplicationDestination(
        destination_id=_string(
            candidate["destinationId"], 1, 256, "APPLICATION_DESTINATION_ID_INVALID"
        ),
        delivery_mode=delivery_mode,
        opaque_token=_string(
            candidate["opaqueToken"], 1, 4096, "APPLICATION_DESTINATION_TOKEN_INVALID"
        ),
    )


@dataclass(frozen=True)
class SmtpRecipient:
    address: str
    dsn: Optional[Mapping[str, Any]] = None

    def to_wire(self) -> Mapping[str, Any]:
        wire: dict[str, Any] = {"address": self.address}
        if self.dsn is not None:
            wire["dsn"] = dict(self.dsn)
        return MappingProxyType(wire)


@dataclass(frozen=True)
class SmtpEnvelope:
    mail_from: Optional[str]
    rcpt_to: tuple[SmtpRecipient, ...]
    smtp_utf8: bool
    body: Optional[str] = None
    require_tls: Optional[bool] = None
    dsn: Optional[Mapping[str, Any]] = None
    schema_version: str = "v1"

    def to_wire(self) -> Mapping[str, Any]:
        wire: dict[str, Any] = {
            "schemaVersion": self.schema_version,
            "mailFrom": self.mail_from,
            "rcptTo": [dict(recipient.to_wire()) for recipient in self.rcpt_to],
            "smtpUtf8": self.smtp_utf8,
        }
        if self.body is not None:
            wire["body"] = self.body
        if self.require_tls is not None:
            wire["requireTls"] = self.require_tls
        if self.dsn is not None:
            wire["dsn"] = dict(self.dsn)
        return MappingProxyType(wire)


def _parse_recipient_dsn(value: Any) -> Optional[Mapping[str, Any]]:
    if value is None:
        return None
    candidate = _object(value, set(), {"notify", "originalRecipient"})
    result: dict[str, Any] = {}
    if "notify" in candidate:
        notify = candidate["notify"]
        allowed = {"success", "failure", "delay"}
        if not isinstance(notify, list) or not notify or len(notify) > 3:
            _fail("DSN_NOTIFY_INVALID")
        if any(not isinstance(item, str) for item in notify):
            _fail("DSN_NOTIFY_INVALID")
        if len(set(notify)) != len(notify):
            _fail("DSN_NOTIFY_DUPLICATE")
        if notify == ["never"]:
            result["notify"] = ["never"]
        elif any(item not in allowed for item in notify):
            _fail("DSN_NOTIFY_INVALID")
        else:
            order = {"success": 0, "failure": 1, "delay": 2}
            result["notify"] = sorted(notify, key=order.__getitem__)
    if "originalRecipient" in candidate:
        original_recipient = _string(
            candidate["originalRecipient"], 3, 500, "DSN_ORIGINAL_RECIPIENT_INVALID"
        )
        if not ORCPT_RE.fullmatch(original_recipient):
            _fail("DSN_ORIGINAL_RECIPIENT_INVALID")
        result["originalRecipient"] = original_recipient
    return MappingProxyType(result)


def parse_smtp_envelope(value: Any) -> SmtpEnvelope:
    candidate = _object(
        value,
        {"schemaVersion", "mailFrom", "rcptTo", "smtpUtf8"},
        {"body", "requireTls", "dsn"},
    )
    if candidate["schemaVersion"] != "v1" or not isinstance(
        candidate["smtpUtf8"], bool
    ):
        _fail("SMTP_ENVELOPE_VERSION_INVALID")
    mail_from = candidate["mailFrom"]
    if mail_from is not None:
        mail_from = canonical_mailbox(mail_from)[0]
    recipients = candidate["rcptTo"]
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= 1000:
        _fail("SMTP_RECIPIENTS_INVALID")
    parsed_recipients: list[SmtpRecipient] = []
    comparison_keys: set[str] = set()
    requires_utf8 = mail_from is not None and not mail_from.isascii()
    for recipient in recipients:
        item = _object(recipient, {"address"}, {"dsn"})
        address, local_part, domain = canonical_mailbox(item["address"])
        comparison_key = f"{local_part}@{domain}"
        if comparison_key in comparison_keys:
            _fail("SMTP_RECIPIENT_DUPLICATE")
        comparison_keys.add(comparison_key)
        requires_utf8 = requires_utf8 or not address.isascii()
        parsed_recipients.append(
            SmtpRecipient(address, _parse_recipient_dsn(item.get("dsn")))
        )
    if requires_utf8 and not candidate["smtpUtf8"]:
        _fail("SMTPUTF8_REQUIRED")
    body = candidate.get("body")
    if body is not None and (
        not isinstance(body, str) or body not in {"7bit", "8bitmime", "binarymime"}
    ):
        _fail("SMTP_BODY_INVALID")
    require_tls = candidate.get("requireTls")
    if require_tls is not None and not isinstance(require_tls, bool):
        _fail("SMTP_REQUIRE_TLS_INVALID")
    envelope_dsn = candidate.get("dsn")
    parsed_envelope_dsn: Optional[Mapping[str, Any]] = None
    if envelope_dsn is not None:
        dsn_candidate = _object(envelope_dsn, set(), {"ret", "envelopeId"})
        parsed: dict[str, Any] = {}
        if "ret" in dsn_candidate:
            if not isinstance(dsn_candidate["ret"], str) or dsn_candidate[
                "ret"
            ] not in {
                "full",
                "headers",
            }:
                _fail("DSN_RET_INVALID")
            parsed["ret"] = dsn_candidate["ret"]
        if "envelopeId" in dsn_candidate:
            envelope_id = _string(
                dsn_candidate["envelopeId"], 1, 100, "DSN_ENVELOPE_ID_INVALID"
            )
            if not XTEXT_RE.fullmatch(envelope_id):
                _fail("DSN_ENVELOPE_ID_INVALID")
            parsed["envelopeId"] = envelope_id
        parsed_envelope_dsn = MappingProxyType(parsed)
    return SmtpEnvelope(
        mail_from=mail_from,
        rcpt_to=tuple(parsed_recipients),
        smtp_utf8=candidate["smtpUtf8"],
        body=body,
        require_tls=require_tls,
        dsn=parsed_envelope_dsn,
    )


@dataclass(frozen=True)
class RecipientRouteRequest:
    tenant_id: str
    envelope: SmtpEnvelope
    receipt_id: str


def parse_recipient_route_request(value: Any) -> RecipientRouteRequest:
    candidate = _object(value, {"schemaVersion", "tenantId", "envelope", "receiptId"})
    if candidate["schemaVersion"] != "v1":
        _fail("RECIPIENT_ROUTE_VERSION_INVALID")
    return RecipientRouteRequest(
        tenant_id=parse_uuid7(candidate["tenantId"], "TENANT_ID_INVALID"),
        envelope=parse_smtp_envelope(candidate["envelope"]),
        receipt_id=parse_uuid7(candidate["receiptId"], "RECEIPT_ID_INVALID"),
    )


@dataclass(frozen=True)
class ReverseRouteRequest:
    tenant_id: str
    envelope: SmtpEnvelope
    raw: RawMessageRef
    opaque_reply_token: str


def parse_reverse_route_request(
    value: Any, maximum_bytes: int = MAX_RAW_BYTES
) -> ReverseRouteRequest:
    candidate = _object(value, {"tenantId", "envelope", "raw", "opaqueReplyToken"})
    return ReverseRouteRequest(
        tenant_id=parse_uuid7(candidate["tenantId"], "TENANT_ID_INVALID"),
        envelope=parse_smtp_envelope(candidate["envelope"]),
        raw=parse_raw_message_ref(candidate["raw"], maximum_bytes),
        opaque_reply_token=_string(
            candidate["opaqueReplyToken"], 1, 4096, "OPAQUE_REPLY_TOKEN_INVALID"
        ),
    )


@dataclass(frozen=True)
class RouteBindingSnapshot:
    binding_id: str
    binding_version: int
    tenant_id: str
    domain_a_label: str
    direction: str
    provider_id: str
    adapter_version: str
    provider_instance_id: str
    provider_resource_ids: Mapping[str, str]
    capability_digest: str
    config_revision: str
    created_at: str
    adapter_mode: Optional[str] = None
    dispatch_transport: Optional[str] = None

    def to_wire(self) -> Mapping[str, Any]:
        wire: dict[str, Any] = {
            "schemaVersion": "v1",
            "bindingId": self.binding_id,
            "bindingVersion": self.binding_version,
            "tenantId": self.tenant_id,
            "domainALabel": self.domain_a_label,
            "direction": self.direction,
            "providerId": self.provider_id,
            "adapterVersion": self.adapter_version,
            "providerInstanceId": self.provider_instance_id,
            "providerResourceIds": dict(self.provider_resource_ids),
            "capabilityDigest": self.capability_digest,
            "configRevision": self.config_revision,
            "createdAt": self.created_at,
        }
        if self.adapter_mode is not None:
            wire["adapterMode"] = self.adapter_mode
        if self.dispatch_transport is not None:
            wire["dispatchTransport"] = self.dispatch_transport
        return MappingProxyType(wire)


def parse_route_binding(value: Any) -> RouteBindingSnapshot:
    required = {
        "schemaVersion",
        "bindingId",
        "bindingVersion",
        "tenantId",
        "domainALabel",
        "direction",
        "providerId",
        "adapterVersion",
        "providerInstanceId",
        "providerResourceIds",
        "capabilityDigest",
        "configRevision",
        "createdAt",
    }
    candidate = _object(value, required, {"adapterMode", "dispatchTransport"})
    if (
        candidate["schemaVersion"] != "v1"
        or not isinstance(candidate["direction"], str)
        or candidate["direction"] not in {"inbound", "outbound"}
    ):
        _fail("ROUTE_BINDING_INVALID")
    provider_id = _string(candidate["providerId"], 1, 63, "PROVIDER_ID_INVALID")
    if not PROVIDER_ID_RE.fullmatch(provider_id):
        _fail("PROVIDER_ID_INVALID")
    resources = candidate["providerResourceIds"]
    if not isinstance(resources, dict) or len(resources) > 32:
        _fail("PROVIDER_RESOURCE_IDS_INVALID")
    for key, item in resources.items():
        _string(key, 1, 64, "PROVIDER_RESOURCE_IDS_INVALID")
        if not BOUNDED_MAP_KEY_RE.fullmatch(key):
            _fail("PROVIDER_RESOURCE_IDS_INVALID")
        _string(item, 0, 512, "PROVIDER_RESOURCE_IDS_INVALID")
    capability_digest = candidate["capabilityDigest"]
    if not isinstance(capability_digest, str) or not SHA256_RE.fullmatch(
        capability_digest
    ):
        _fail("CAPABILITY_DIGEST_INVALID")
    adapter_mode = candidate.get("adapterMode")
    if adapter_mode is not None:
        adapter_mode = _string(adapter_mode, 1, 64, "ADAPTER_MODE_INVALID")
        if not re.fullmatch(r"^[a-z][a-z0-9_-]{0,63}$", adapter_mode):
            _fail("ADAPTER_MODE_INVALID")
    dispatch_transport = candidate.get("dispatchTransport")
    if dispatch_transport is not None and dispatch_transport not in {"http", "smtp"}:
        _fail("DISPATCH_TRANSPORT_INVALID")
    return RouteBindingSnapshot(
        binding_id=parse_uuid7(candidate["bindingId"], "BINDING_ID_INVALID"),
        binding_version=_integer(
            candidate["bindingVersion"],
            1,
            9_007_199_254_740_991,
            "BINDING_VERSION_INVALID",
        ),
        tenant_id=parse_uuid7(candidate["tenantId"], "TENANT_ID_INVALID"),
        domain_a_label=canonical_domain(candidate["domainALabel"]),
        direction=candidate["direction"],
        provider_id=provider_id,
        adapter_version=_string(
            candidate["adapterVersion"], 1, 64, "ADAPTER_VERSION_INVALID"
        ),
        provider_instance_id=parse_uuid7(
            candidate["providerInstanceId"], "PROVIDER_INSTANCE_ID_INVALID"
        ),
        provider_resource_ids=MappingProxyType(dict(resources)),
        capability_digest=capability_digest,
        config_revision=_string(
            candidate["configRevision"], 1, 128, "CONFIG_REVISION_INVALID"
        ),
        created_at=parse_rfc3339(candidate["createdAt"], "BINDING_CREATED_AT_INVALID"),
        adapter_mode=adapter_mode,
        dispatch_transport=dispatch_transport,
    )


@dataclass(frozen=True)
class ApplicationDelivery:
    delivery_id: str
    receipt_id: str
    tenant_id: str
    envelope: SmtpEnvelope
    raw: RawMessageRef
    destination: ApplicationDestination
    binding: RouteBindingSnapshot
    attempt: int
    occurred_at: str


def parse_application_delivery(
    value: Any, maximum_bytes: int = MAX_RAW_BYTES
) -> ApplicationDelivery:
    candidate = _object(
        value,
        {
            "schemaVersion",
            "deliveryId",
            "receiptId",
            "tenantId",
            "envelope",
            "raw",
            "destination",
            "binding",
            "attempt",
            "occurredAt",
        },
    )
    if candidate["schemaVersion"] != "v1":
        _fail("APPLICATION_DELIVERY_VERSION_INVALID")
    tenant_id = parse_uuid7(candidate["tenantId"], "TENANT_ID_INVALID")
    binding = parse_route_binding(candidate["binding"])
    if binding.tenant_id != tenant_id or binding.direction != "inbound":
        _fail("APPLICATION_DELIVERY_BINDING_INVALID")
    return ApplicationDelivery(
        delivery_id=parse_uuid7(candidate["deliveryId"], "DELIVERY_ID_INVALID"),
        receipt_id=parse_uuid7(candidate["receiptId"], "RECEIPT_ID_INVALID"),
        tenant_id=tenant_id,
        envelope=parse_smtp_envelope(candidate["envelope"]),
        raw=parse_raw_message_ref(candidate["raw"], maximum_bytes),
        destination=parse_application_destination(candidate["destination"]),
        binding=binding,
        attempt=_integer(
            candidate["attempt"], 1, 9_007_199_254_740_991, "DELIVERY_ATTEMPT_INVALID"
        ),
        occurred_at=parse_rfc3339(
            candidate["occurredAt"], "DELIVERY_OCCURRED_AT_INVALID"
        ),
    )


@dataclass(frozen=True)
class RawAccessGrant:
    grant_id: str
    tenant_id: str
    raw: RawMessageRef
    audience: str
    subject_id: str
    purpose: str
    single_use: bool
    opaque_token: str
    download_path: str
    issued_at: str
    expires_at: str


def parse_raw_access_grant(
    value: Any, maximum_bytes: int = MAX_RAW_BYTES
) -> RawAccessGrant:
    candidate = _object(
        value,
        {
            "schemaVersion",
            "grantId",
            "tenantId",
            "raw",
            "audience",
            "operation",
            "subjectId",
            "purpose",
            "singleUse",
            "opaqueToken",
            "downloadPath",
            "issuedAt",
            "expiresAt",
        },
    )
    if candidate["schemaVersion"] != "v1" or candidate["operation"] != "raw_download":
        _fail("RAW_ACCESS_GRANT_VERSION_INVALID")
    if candidate["purpose"] not in {
        "application_delivery",
        "operator_review",
        "reconciliation",
    }:
        _fail("RAW_ACCESS_GRANT_PURPOSE_INVALID")
    if not isinstance(candidate["singleUse"], bool):
        _fail("RAW_ACCESS_GRANT_SINGLE_USE_INVALID")
    grant_id = parse_uuid7(candidate["grantId"], "RAW_ACCESS_GRANT_ID_INVALID")
    download_path = _string(
        candidate["downloadPath"], 1, 256, "RAW_ACCESS_GRANT_PATH_INVALID"
    )
    if download_path != f"/v1/raw-access-grants/{grant_id}/raw":
        _fail("RAW_ACCESS_GRANT_PATH_INVALID")
    opaque_token = _string(
        candidate["opaqueToken"], 43, 128, "RAW_ACCESS_GRANT_TOKEN_INVALID"
    )
    if not re.fullmatch(r"^[A-Za-z0-9_-]{43,128}$", opaque_token):
        _fail("RAW_ACCESS_GRANT_TOKEN_INVALID")
    audience = _string(
        candidate["audience"], 1, 128, "RAW_ACCESS_GRANT_AUDIENCE_INVALID"
    )
    subject_id = _string(
        candidate["subjectId"], 1, 128, "RAW_ACCESS_GRANT_SUBJECT_INVALID"
    )
    if not TOKEN_RE.fullmatch(audience) or not TOKEN_RE.fullmatch(subject_id):
        _fail("RAW_ACCESS_GRANT_CONTEXT_INVALID")
    return RawAccessGrant(
        grant_id=grant_id,
        tenant_id=parse_uuid7(candidate["tenantId"], "TENANT_ID_INVALID"),
        raw=parse_raw_message_ref(candidate["raw"], maximum_bytes),
        audience=audience,
        subject_id=subject_id,
        purpose=candidate["purpose"],
        single_use=candidate["singleUse"],
        opaque_token=opaque_token,
        download_path=download_path,
        issued_at=parse_rfc3339(
            candidate["issuedAt"], "RAW_ACCESS_GRANT_ISSUED_AT_INVALID"
        ),
        expires_at=parse_rfc3339(
            candidate["expiresAt"], "RAW_ACCESS_GRANT_EXPIRES_AT_INVALID"
        ),
    )


@dataclass(frozen=True)
class ApplicationDeliveryCallback:
    delivery: ApplicationDelivery
    raw_access_grant: RawAccessGrant


def parse_application_delivery_callback(
    value: Any, maximum_bytes: int = MAX_RAW_BYTES
) -> ApplicationDeliveryCallback:
    candidate = _object(value, {"schemaVersion", "delivery", "rawAccessGrant"})
    if candidate["schemaVersion"] != "v1":
        _fail("APPLICATION_DELIVERY_CALLBACK_VERSION_INVALID")
    delivery = parse_application_delivery(candidate["delivery"], maximum_bytes)
    grant = parse_raw_access_grant(candidate["rawAccessGrant"], maximum_bytes)
    if (
        grant.tenant_id != delivery.tenant_id
        or grant.raw != delivery.raw
        or grant.subject_id != delivery.delivery_id
        or grant.purpose != "application_delivery"
        or not grant.single_use
    ):
        _fail("APPLICATION_DELIVERY_GRANT_INVALID")
    return ApplicationDeliveryCallback(delivery, grant)


@dataclass(frozen=True)
class ApplicationFeedback:
    feedback_event_id: str
    tenant_id: str
    intent_id: str
    kind: str
    occurred_at: str
    normalized_evidence: Mapping[str, object]
    attempt_id: Optional[str] = None
    recipient: Optional[str] = None


def parse_application_feedback(value: Any) -> ApplicationFeedback:
    candidate = _object(
        value,
        {
            "schemaVersion",
            "feedbackEventId",
            "tenantId",
            "intentId",
            "kind",
            "occurredAt",
            "normalizedEvidence",
        },
        {"attemptId", "recipient"},
    )
    if (
        candidate["schemaVersion"] != "v1"
        or not isinstance(candidate["kind"], str)
        or candidate["kind"] not in FEEDBACK_KINDS
    ):
        _fail("APPLICATION_FEEDBACK_INVALID")
    evidence = candidate["normalizedEvidence"]
    if not isinstance(evidence, dict) or len(evidence) > 32:
        _fail("NORMALIZED_EVIDENCE_INVALID")
    normalized: dict[str, object] = {}
    for key, item in evidence.items():
        _string(key, 1, 64, "NORMALIZED_EVIDENCE_INVALID")
        if not EVIDENCE_KEY_RE.fullmatch(key):
            _fail("NORMALIZED_EVIDENCE_INVALID")
        if isinstance(item, bool):
            normalized[key] = item
        elif (
            isinstance(item, (int, float))
            and not isinstance(item, bool)
            and math.isfinite(item)
            and abs(item) <= 9_007_199_254_740_991
        ):
            normalized[key] = item
        elif isinstance(item, str) and len(item) <= 256:
            normalized[key] = item
        else:
            _fail("NORMALIZED_EVIDENCE_INVALID")
    recipient = candidate.get("recipient")
    if recipient is not None:
        recipient = canonical_mailbox(recipient)[0]
    attempt_id = candidate.get("attemptId")
    if attempt_id is not None:
        attempt_id = parse_uuid7(attempt_id, "ATTEMPT_ID_INVALID")
    return ApplicationFeedback(
        feedback_event_id=parse_uuid7(
            candidate["feedbackEventId"], "FEEDBACK_EVENT_ID_INVALID"
        ),
        tenant_id=parse_uuid7(candidate["tenantId"], "TENANT_ID_INVALID"),
        intent_id=parse_uuid7(candidate["intentId"], "INTENT_ID_INVALID"),
        kind=candidate["kind"],
        occurred_at=parse_rfc3339(
            candidate["occurredAt"], "FEEDBACK_OCCURRED_AT_INVALID"
        ),
        normalized_evidence=MappingProxyType(normalized),
        attempt_id=attempt_id,
        recipient=recipient,
    )


def construct_safe_header(name: str, value: str) -> str:
    normalized_name = name.lower()
    if not HEADER_NAME_RE.fullmatch(normalized_name) or any(
        char in value for char in "\r\n\0"
    ):
        _fail("HEADER_FIELD_INVALID")
    if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value):
        _fail("HEADER_FIELD_INVALID")
    raw = f"{name}: {value}"
    if len(raw.encode("utf-8")) > 998:
        _fail("HEADER_FIELD_TOO_LONG")
    return raw


def compile_header_patch_plan(
    visible_header_fields: Sequence[str], source_sha256: str
) -> Mapping[str, Any]:
    if (
        not isinstance(source_sha256, str)
        or not SHA256_RE.fullmatch(source_sha256)
        or not isinstance(visible_header_fields, (list, tuple))
        or len(visible_header_fields) > 16
    ):
        _fail("HEADER_PATCH_PLAN_INVALID")
    operations: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_field in visible_header_fields:
        if not isinstance(raw_field, str) or any(
            char in raw_field for char in "\r\n\0"
        ):
            _fail("HEADER_PATCH_FIELD_INVALID")
        separator = raw_field.find(":")
        name = raw_field[:separator].lower() if separator >= 0 else ""
        if (
            not HEADER_NAME_RE.fullmatch(name)
            or name not in VISIBLE_HEADERS
            or name in THREAD_HEADERS
            or name in seen
            or len(raw_field.encode("utf-8")) > 998
        ):
            _fail("HEADER_PATCH_FIELD_INVALID")
        construct_safe_header(raw_field[:separator], raw_field[separator + 1 :])
        seen.add(name)
        operations.append(
            {
                "op": "replaceOccurrence",
                "name": name,
                "occurrence": 0,
                "rawField": raw_field,
            }
        )
    operations.sort(key=lambda operation: operation["name"])
    return MappingProxyType(
        {
            "schemaVersion": "v1",
            "sourceSha256": source_sha256,
            "operations": operations,
            "reason": "reverse_alias",
        }
    )


def strict_json_loads(raw: bytes, maximum_bytes: int) -> Any:
    if len(raw) > maximum_bytes:
        raise MailEdgeContractError("JSON_BODY_TOO_LARGE", http_status=413)

    def reject_constant(value: str) -> None:
        raise ValueError(value)

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(key)
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8"),
            parse_constant=reject_constant,
            object_pairs_hook=unique_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        _fail("JSON_BODY_INVALID")
