"""Read-only Mailgun domain, DNS, and tracking capability discovery."""

from __future__ import annotations

from urllib.parse import quote

from ..config import DomainRegistry, RetryPolicy, TimeoutPolicy
from ..contracts import DNSRecordCapability, DomainCapabilities
from ..errors import ProviderProtocolError
from ..transport import HTTPTransport
from .http import idempotent_request, json_object, response_diagnostic


class MailgunDiscoveryAdapter:
    def __init__(
        self,
        registry: DomainRegistry,
        transport: HTTPTransport,
        *,
        timeout: TimeoutPolicy = TimeoutPolicy(),
        retry: RetryPolicy = RetryPolicy(),
    ) -> None:
        self._registry = registry
        self._transport = transport
        self._timeout = timeout
        self._retry = retry

    def discover(self, domain: str) -> DomainCapabilities:
        config = self._registry.exact(domain)
        encoded = quote(config.domain, safe="")
        domain_response = idempotent_request(
            self._transport,
            method="GET",
            url=f"{config.api_base}/v4/domains/{encoded}",
            keys=config.api_keys,
            timeout=self._timeout,
            retry=self._retry,
        )
        tracking_response = idempotent_request(
            self._transport,
            method="GET",
            url=f"{config.api_base}/v3/domains/{encoded}/tracking",
            keys=config.api_keys,
            timeout=self._timeout,
            retry=self._retry,
        )
        if domain_response.status != 200:
            raise ProviderProtocolError(response_diagnostic(domain_response))
        if tracking_response.status != 200:
            raise ProviderProtocolError(response_diagnostic(tracking_response))
        domain_payload = json_object(domain_response)
        tracking_payload = json_object(tracking_response)
        try:
            details = domain_payload["domain"]
            if not isinstance(details, dict):
                raise TypeError
            tracking = tracking_payload["tracking"]
            if not isinstance(tracking, dict):
                raise TypeError
            discovered_domain = str(details["name"]).rstrip(".").lower()
            if discovered_domain != config.domain:
                raise ValueError
            return DomainCapabilities(
                domain=discovered_domain,
                region=config.region,
                state=str(details["state"]),
                domain_type=(
                    str(details["type"]) if details.get("type") is not None else None
                ),
                require_tls=bool(details.get("require_tls", False)),
                message_ttl_seconds=(
                    int(details["message_ttl"])
                    if details.get("message_ttl") is not None
                    else None
                ),
                click_tracking=self._tracking_active(tracking.get("click")),
                open_tracking=self._tracking_active(tracking.get("open")),
                unsubscribe_tracking=self._tracking_active(tracking.get("unsubscribe")),
                receiving_dns=self._dns(domain_payload.get("receiving_dns_records")),
                sending_dns=self._dns(domain_payload.get("sending_dns_records")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderProtocolError(
                "Mailgun domain response did not match its contract"
            ) from exc

    @staticmethod
    def _tracking_active(value: object) -> bool:
        return bool(isinstance(value, dict) and value.get("active"))

    @staticmethod
    def _dns(value: object) -> tuple[DNSRecordCapability, ...]:
        if value is None:
            return ()
        if not isinstance(value, list):
            raise TypeError
        records: list[DNSRecordCapability] = []
        for record in value:
            if not isinstance(record, dict):
                raise TypeError
            records.append(
                DNSRecordCapability(
                    name=str(record.get("name", "")),
                    record_type=str(record["record_type"]),
                    value=str(record["value"]),
                    priority=(
                        str(record["priority"]) if record.get("priority") else None
                    ),
                    valid=str(record.get("valid", "unknown")),
                    active=bool(record.get("is_active", False)),
                )
            )
        return tuple(records)
