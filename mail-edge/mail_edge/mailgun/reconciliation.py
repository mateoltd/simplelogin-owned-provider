"""Read-only reconciliation for ambiguous acknowledgement loss."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

from ..config import DomainRegistry, RetryPolicy, TimeoutPolicy
from ..errors import ProviderProtocolError, TransportFailure
from ..ledger import DeliveryLedger
from ..transport import HTTPTransport
from .feedback import MailgunFeedbackAdapter
from .http import idempotent_request, json_object


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    inspected: int
    correlated_events: int
    still_ambiguous: int
    provider_failures: int


class MailgunReconciler:
    """Queries provider events and applies evidence; it has no send operation."""

    def __init__(
        self,
        registry: DomainRegistry,
        transport: HTTPTransport,
        ledger: DeliveryLedger,
        *,
        timeout: TimeoutPolicy = TimeoutPolicy(),
        retry: RetryPolicy = RetryPolicy(),
    ) -> None:
        self._registry = registry
        self._transport = transport
        self._ledger = ledger
        self._timeout = timeout
        self._retry = retry

    def reconcile_ambiguous(
        self, *, now: datetime | None = None
    ) -> ReconciliationResult:
        observed_at = now or datetime.now(UTC)
        records = self._ledger.ambiguous()
        correlated = 0
        failures = 0
        for record in records:
            config = self._registry.exact(record.domain)
            query = json.dumps(
                {
                    "start": format_datetime(record.updated_at - timedelta(hours=1)),
                    "end": format_datetime(observed_at),
                    "events": [
                        "accepted",
                        "delivered",
                        "failed",
                        "complained",
                        "rejected",
                    ],
                    "filter": {
                        "AND": [
                            {
                                "attribute": "domain",
                                "comparator": "=",
                                "values": [{"value": config.domain}],
                            },
                            {
                                "attribute": "message_id",
                                "comparator": "=",
                                "values": [{"value": record.submitted_message_id}],
                            },
                        ]
                    },
                    "pagination": {"sort": "timestamp:asc", "limit": 100},
                },
                separators=(",", ":"),
            ).encode()
            url = f"{config.api_base}/v1/analytics/logs"
            try:
                response = idempotent_request(
                    self._transport,
                    method="POST",
                    url=url,
                    keys=config.api_keys,
                    timeout=self._timeout,
                    retry=self._retry,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                    body=query,
                )
                if response.status != 200:
                    failures += 1
                    continue
                payload = json_object(response)
                items = payload.get("items", [])
                if not isinstance(items, list):
                    raise ProviderProtocolError("Mailgun events response omitted items")
                for item in items:
                    if not isinstance(item, dict):
                        raise ProviderProtocolError(
                            "Mailgun event item was not an object"
                        )
                    event = MailgunFeedbackAdapter.normalize_event_data(item)
                    application = self._ledger.apply_feedback(
                        event, received_at=observed_at
                    )
                    if application.correlated and not application.duplicate:
                        correlated += 1
            except (TransportFailure, ProviderProtocolError):
                failures += 1
        return ReconciliationResult(
            inspected=len(records),
            correlated_events=correlated,
            still_ambiguous=len(self._ledger.ambiguous()),
            provider_failures=failures,
        )
