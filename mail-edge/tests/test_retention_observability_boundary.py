from __future__ import annotations

import ast
import json
from datetime import timedelta
from pathlib import Path

from mail_edge.config import RetentionPolicy
from mail_edge.contracts import SubmissionDisposition, SubmissionResult
from mail_edge.mailgun.outbound import MailgunOutboundAdapter
from mail_edge.observability import Redactor

from .conftest import NOW, outbound, raw_message
from .fakes import FakeTransport, response


class CollectingObserver:
    def __init__(self):
        self.events = []

    def emit(self, event, fields):
        self.events.append((event, dict(fields)))


def test_observations_are_redacted_and_never_contain_provider_payload(registry, ledger):
    observer = CollectingObserver()
    transport = FakeTransport(response(400, b'{"message":"invalid request"}'))
    MailgunOutboundAdapter(
        registry,
        transport,
        ledger,
        observer=observer,
        redactor=Redactor(b"test-redaction-salt-value"),
        clock=lambda: NOW,
        sleeper=lambda _delay: None,
    ).submit(outbound())

    serialized = json.dumps(observer.events)
    assert "bounce+opaque@edge.example.test" not in serialized
    assert "contact@recipient.example" not in serialized
    assert "api-current-secret" not in serialized
    assert "sender_hash" in serialized and "recipient_hash" in serialized
    assert "invalid request" in serialized


def test_ledger_never_persists_rfc822_content(tmp_path):
    from mail_edge.ledger import DeliveryLedger

    path = tmp_path / "ledger.sqlite3"
    ledger = DeliveryLedger(path)
    raw = raw_message(body=b"uniquely-sensitive-body-marker\r\n")
    message = outbound(raw=raw)
    ledger.prepare(
        message,
        domain="edge.example.test",
        message_id="<submitted-1@edge.example.test>",
    )
    ledger.close()
    assert b"uniquely-sensitive-body-marker" not in path.read_bytes()


def test_retention_prunes_terminal_and_ambiguous_records(ledger):
    old = NOW - timedelta(days=120)
    terminal = outbound(edge_id="old-terminal")
    ledger.prepare(
        terminal, domain="edge.example.test", message_id="<terminal@edge.example.test>"
    )
    ledger.mark_submitting(terminal.edge_delivery_id, now=old)
    ledger.record_result(
        SubmissionResult(
            disposition=SubmissionDisposition.PERMANENT_REJECTED,
            edge_delivery_id=terminal.edge_delivery_id,
        ),
        now=old,
    )
    ambiguous = outbound(edge_id="old-ambiguous")
    ledger.prepare(
        ambiguous,
        domain="edge.example.test",
        message_id="<ambiguous@edge.example.test>",
    )
    ledger.mark_submitting(ambiguous.edge_delivery_id, now=old)
    ledger.record_result(
        SubmissionResult(
            disposition=SubmissionDisposition.AMBIGUOUS,
            edge_delivery_id=ambiguous.edge_delivery_id,
        ),
        now=old,
    )
    purged = ledger.purge(RetentionPolicy(), now=NOW)
    assert purged["terminal_deliveries"] == 1
    assert purged["ambiguous"] == 1
    assert ledger.get("old-terminal") is None
    assert ledger.get("old-ambiguous") is None


def test_production_package_has_no_application_imports_or_identity_ownership():
    package_root = Path(__file__).parents[1] / "mail_edge"
    forbidden_modules = {"app", "models"}
    forbidden_schema_names = {"aliases", "users", "contacts", "mailboxes"}
    all_source = ""
    for path in package_root.rglob("*.py"):
        source = path.read_text()
        all_source += source.lower()
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(
                    alias.name.split(".")[0] not in forbidden_modules
                    for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in forbidden_modules
    for schema_name in forbidden_schema_names:
        assert f"create table if not exists {schema_name}" not in all_source
