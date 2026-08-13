from __future__ import annotations

import json

from mail_edge.config import DomainRegistry, RetryPolicy
from mail_edge.contracts import ProviderRegion, SubmissionDisposition, SubmissionResult
from mail_edge.errors import TransportFailure
from mail_edge.mailgun.discovery import MailgunDiscoveryAdapter
from mail_edge.mailgun.reconciliation import MailgunReconciler

from .conftest import DOMAIN, NOW, domain_config, event_data, outbound
from .fakes import FakeTransport, response


def domain_payload():
    return {
        "domain": {
            "name": DOMAIN,
            "state": "active",
            "type": "custom",
            "require_tls": True,
            "message_ttl": 86400,
        },
        "receiving_dns_records": [
            {
                "name": DOMAIN,
                "record_type": "MX",
                "value": "mxa.eu.mailgun.org",
                "priority": "10",
                "valid": "valid",
                "is_active": True,
            }
        ],
        "sending_dns_records": [
            {
                "name": DOMAIN,
                "record_type": "TXT",
                "value": "v=spf1 include:mailgun.org ~all",
                "valid": "valid",
                "is_active": True,
            }
        ],
    }


def tracking_payload():
    return {
        "tracking": {
            "click": {"active": False},
            "open": {"active": False},
            "unsubscribe": {"active": False},
        }
    }


def test_read_only_domain_and_dns_discovery_uses_configured_region():
    registry = DomainRegistry((domain_config(region=ProviderRegion.EU),))
    transport = FakeTransport(
        response(200, json.dumps(domain_payload()).encode()),
        response(200, json.dumps(tracking_payload()).encode()),
    )
    capabilities = MailgunDiscoveryAdapter(registry, transport).discover(DOMAIN)

    assert capabilities.region is ProviderRegion.EU
    assert capabilities.state == "active"
    assert capabilities.require_tls
    assert capabilities.message_ttl_seconds == 86400
    assert not capabilities.click_tracking
    assert capabilities.receiving_dns[0].record_type == "MX"
    assert capabilities.sending_dns[0].value.startswith("v=spf1")
    assert {request.method for request in transport.requests} == {"GET"}
    assert all(
        request.url.startswith("https://api.eu.mailgun.net/")
        for request in transport.requests
    )
    assert all(request.body is None for request in transport.requests)


def mark_ambiguous(ledger):
    message = outbound()
    ledger.prepare(message, domain=DOMAIN, message_id="<submitted-1@edge.example.test>")
    ledger.mark_submitting(message.edge_delivery_id, now=NOW)
    ledger.record_result(
        SubmissionResult(
            disposition=SubmissionDisposition.AMBIGUOUS,
            edge_delivery_id=message.edge_delivery_id,
            visible_message_id="<submitted-1@edge.example.test>",
        ),
        now=NOW,
    )


def test_reconciliation_applies_provider_evidence_without_resending(registry, ledger):
    mark_ambiguous(ledger)
    item = event_data(
        event="accepted",
        event_id="found-accepted",
        message_id="<submitted-1@edge.example.test>",
    )
    transport = FakeTransport(response(200, json.dumps({"items": [item]}).encode()))
    result = MailgunReconciler(registry, transport, ledger).reconcile_ambiguous(now=NOW)

    assert result.inspected == 1
    assert result.correlated_events == 1
    assert result.still_ambiguous == 0
    assert ledger.get("edge-delivery-1").state == "accepted"
    assert [request.method for request in transport.requests] == ["POST"]
    assert transport.requests[0].url.endswith("/v1/analytics/logs")
    query = json.loads(transport.requests[0].body)
    assert query["filter"]["AND"][1]["values"][0]["value"] == (
        "<submitted-1@edge.example.test>"
    )


def test_missing_reconciliation_evidence_keeps_ambiguous(registry, ledger):
    mark_ambiguous(ledger)
    transport = FakeTransport(response(200, b'{"items":[]}'))
    result = MailgunReconciler(registry, transport, ledger).reconcile_ambiguous(now=NOW)
    assert result.still_ambiguous == 1
    assert ledger.get("edge-delivery-1").state == "AMBIGUOUS"
    assert all(
        not request.url.endswith("/messages.mime") for request in transport.requests
    )


def test_reconciliation_outage_never_triggers_send(registry, ledger):
    mark_ambiguous(ledger)
    transport = FakeTransport(
        TransportFailure("connect", request_sent=False),
        TransportFailure("connect", request_sent=False),
    )
    reconciler = MailgunReconciler(
        registry,
        transport,
        ledger,
        retry=RetryPolicy(max_attempts=2, base_delay_seconds=0, max_delay_seconds=0),
    )
    result = reconciler.reconcile_ambiguous(now=NOW)
    assert result.provider_failures == 1
    assert result.still_ambiguous == 1
    assert all(
        not request.url.endswith("/messages.mime") for request in transport.requests
    )
