"""Typed failures whose classes are safe to use in operational control flow."""


class MailEdgeError(Exception):
    """Base error. Messages must not contain credentials or message content."""


class ConfigurationError(MailEdgeError):
    """Runtime or immutable provider configuration is unsafe or incomplete."""


class ContractError(MailEdgeError):
    """A neutral or provider-normalized input violates the edge contract."""


class UnknownDomain(ContractError):
    """No exact active binding exists; callers must never use a fallback."""


class InvalidTransition(ContractError):
    """A state reducer or binding lifecycle transition is forbidden."""


class QualificationError(ContractError):
    """Activation evidence does not satisfy current product policy."""


class DuplicateConflict(ContractError):
    """An idempotency identity was reused for different immutable content."""


class BlobIntegrityError(MailEdgeError):
    """Encrypted content is truncated, unauthenticated, or lacks its key."""
