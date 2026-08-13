import threading
import urllib.request

from mail_edge_conformance.contracts import DeliveryRequest, SubmissionDisposition
from mail_edge_conformance.fixtures import (
    FixtureHttpAdapter,
    FixtureProvider,
    create_provider_server,
)


def _request(identifier="fixture-http"):
    return DeliveryRequest(
        edge_delivery_id=identifier,
        envelope_from="sender@sender.test",
        envelope_recipients=("receiver@receiver.test",),
        rfc822_bytes=(
            b"From: sender@sender.test\r\n"
            b"To: receiver@receiver.test\r\n"
            b"Subject: fixture\r\n"
            b"X-Mail-Edge-Test-ID: fixture-http\r\n\r\nbody"
        ),
    )


def test_provider_server_accepts_and_reconciles_deterministically():
    server = create_provider_server("127.0.0.1", 0, FixtureProvider())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        adapter = FixtureHttpAdapter(base)
        result = adapter.submit(_request())
        assert result.disposition is SubmissionDisposition.ACCEPTED
        assert adapter.reconcile("fixture-http") == result
        assert adapter.delivery_by_test_id("fixture-http") == _request()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_provider_server_fault_control_is_deterministic():
    server = create_provider_server("127.0.0.1", 0, FixtureProvider())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        control = urllib.request.Request(
            base + "/v1/control",
            data=b'{"outcomes":["credential","quota","rejected","timeout_after"]}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(control).read()
        adapter = FixtureHttpAdapter(base)
        observed = [
            adapter.submit(_request(f"fault-{index}")).disposition for index in range(4)
        ]
        assert observed == [
            SubmissionDisposition.RETRY,
            SubmissionDisposition.RETRY,
            SubmissionDisposition.REJECT,
            SubmissionDisposition.UNKNOWN,
        ]
        assert (
            adapter.reconcile("fault-3").disposition is SubmissionDisposition.ACCEPTED
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
