"""Provider-specific normalization and submission adapters."""

from .mailgun import MailgunAdapter, MailgunCredentials

__all__ = ["MailgunAdapter", "MailgunCredentials"]
