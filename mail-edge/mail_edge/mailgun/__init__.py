"""Mailgun-specific parsing and HTTP behavior, contained at the adapter boundary."""

from .discovery import MailgunDiscoveryAdapter
from .feedback import MailgunFeedbackAdapter
from .inbound import MailgunIngressAdapter
from .outbound import MailgunOutboundAdapter
from .reconciliation import MailgunReconciler

__all__ = [
    "MailgunDiscoveryAdapter",
    "MailgunFeedbackAdapter",
    "MailgunIngressAdapter",
    "MailgunOutboundAdapter",
    "MailgunReconciler",
]
