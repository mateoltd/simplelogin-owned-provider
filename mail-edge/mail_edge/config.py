"""Validated Mailgun configuration with explicit key rotation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .contracts import ProviderRegion
from .errors import ConfigurationError

MAX_MESSAGE_BYTES = 24_000_000


class IngressContentPolicy(StrEnum):
    DIRECT_RAW_MIME = "DIRECT_RAW_MIME"
    STORE_AND_FETCH = "STORE_AND_FETCH"


@dataclass(frozen=True, slots=True)
class SecretKey:
    key_id: str
    secret: str

    def __post_init__(self) -> None:
        if not self.key_id or not self.secret:
            raise ConfigurationError("key id and secret are required")


@dataclass(frozen=True, slots=True)
class KeyRing:
    keys: tuple[SecretKey, ...]

    def __post_init__(self) -> None:
        if not self.keys:
            raise ConfigurationError("at least one key is required")
        if len({key.key_id for key in self.keys}) != len(self.keys):
            raise ConfigurationError("key ids must be unique")


@dataclass(frozen=True, slots=True)
class TimeoutPolicy:
    connect_seconds: float = 3.0
    read_seconds: float = 15.0
    max_response_bytes: int = 1_000_000

    def __post_init__(self) -> None:
        if self.connect_seconds <= 0 or self.read_seconds <= 0:
            raise ConfigurationError("timeouts must be positive")
        if not 1 <= self.max_response_bytes <= 64_000_000:
            raise ConfigurationError("response limit is outside the safe range")


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: float = 0.25
    max_delay_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 5:
            raise ConfigurationError("max attempts must be between 1 and 5")
        if (
            self.base_delay_seconds < 0
            or self.max_delay_seconds < self.base_delay_seconds
        ):
            raise ConfigurationError("invalid retry delays")


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    replay_seconds: int = 86_400
    normalized_event_seconds: int = 30 * 86_400
    terminal_delivery_seconds: int = 30 * 86_400
    ambiguous_delivery_seconds: int = 90 * 86_400

    def __post_init__(self) -> None:
        values = (
            self.replay_seconds,
            self.normalized_event_seconds,
            self.terminal_delivery_seconds,
            self.ambiguous_delivery_seconds,
        )
        if any(value <= 0 for value in values):
            raise ConfigurationError("retention periods must be positive")


@dataclass(frozen=True, slots=True)
class MailgunDomainConfig:
    domain: str
    region: ProviderRegion
    api_keys: KeyRing
    webhook_keys: KeyRing
    ingress_policy: IngressContentPolicy = IngressContentPolicy.DIRECT_RAW_MIME
    max_message_bytes: int = MAX_MESSAGE_BYTES
    test_mode: bool = False

    def __post_init__(self) -> None:
        normalized = self.domain.rstrip(".").lower()
        if not normalized or "@" in normalized or "/" in normalized:
            raise ConfigurationError("invalid Mailgun domain")
        if self.max_message_bytes != MAX_MESSAGE_BYTES:
            raise ConfigurationError("Mailgun policy must be exactly 24,000,000 bytes")
        object.__setattr__(self, "domain", normalized)

    @property
    def api_base(self) -> str:
        if self.region is ProviderRegion.EU:
            return "https://api.eu.mailgun.net"
        return "https://api.mailgun.net"


class DomainRegistry:
    """Exact-domain registry; it never falls through to another provider/domain."""

    def __init__(self, domains: tuple[MailgunDomainConfig, ...]) -> None:
        self._domains = {domain.domain: domain for domain in domains}
        if len(self._domains) != len(domains):
            raise ConfigurationError("Mailgun domains must be unique")
        if not domains:
            raise ConfigurationError("at least one Mailgun domain is required")

    def exact(self, domain: str) -> MailgunDomainConfig:
        normalized = domain.rstrip(".").lower()
        try:
            return self._domains[normalized]
        except KeyError as exc:
            raise ConfigurationError("domain is not configured for Mailgun") from exc

    def all(self) -> tuple[MailgunDomainConfig, ...]:
        return tuple(self._domains.values())
