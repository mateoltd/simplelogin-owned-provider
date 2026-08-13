"""Errors with boundary-safe diagnostics."""


class MailEdgeError(Exception):
    """Base error safe for callers to classify."""


class ConfigurationError(MailEdgeError):
    """Configuration violates a provider boundary invariant."""


class MalformedPayload(MailEdgeError):
    """Input cannot be represented safely by the neutral contract."""


class MessageTooLarge(MalformedPayload):
    """Raw MIME exceeds the configured hard policy."""


class SignatureRejected(MailEdgeError):
    """A provider signature is invalid or expired."""


class ReplayRejected(SignatureRejected):
    """A validly signed provider token has already been consumed."""


class TemporaryIngressFailure(MailEdgeError):
    """Ingress should be retried without changing its signed payload."""


class ProviderAuthenticationError(MailEdgeError):
    """All configured provider credentials were rejected."""


class ProviderProtocolError(MailEdgeError):
    """A provider response did not satisfy its documented shape."""


class TransportFailure(MailEdgeError):
    def __init__(self, diagnostic: str, *, request_sent: bool) -> None:
        super().__init__(diagnostic)
        self.request_sent = request_sent
