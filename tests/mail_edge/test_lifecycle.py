from app.mail_edge.client import MailEdgeClient
import pytest

from app.mail_edge.composition import (
    MailEdgeBridge,
    build_mail_edge_bridge,
    register_mail_edge_process_cleanup,
)
from app.mail_sender import MailSender
from tests.mail_edge.test_client import Session, configuration


class ClientTransport:
    def __init__(self, client):
        self.client = client
        self.close_calls = 0

    def send(self, _request):
        return True

    def close(self, timeout_seconds=None):
        self.close_calls += 1
        return self.client.close(timeout_seconds)


def bridge(sender, session):
    client = MailEdgeClient(
        configuration(), session=session, take_session_ownership=True
    )
    transport = ClientTransport(client)
    instance = MailEdgeBridge(
        configuration(),
        client,
        transport,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        sender,
    )
    return instance, transport


def test_sender_replacement_closes_only_owned_transport():
    sender = MailSender()
    first_session = Session([])
    first_bridge, first_transport = bridge(sender, first_session)
    sender.set_mail_edge_transport(first_transport, transfer_ownership=True)

    second_session = Session([])
    second_bridge, second_transport = bridge(sender, second_session)
    sender.set_mail_edge_transport(second_transport, transfer_ownership=True)
    assert first_transport.close_calls == 1
    assert first_session.close_calls == 1
    assert first_bridge.close()
    assert first_transport.close_calls == 1

    assert second_bridge.close()
    assert second_bridge.close()
    assert second_transport.close_calls == 1
    assert second_session.close_calls == 1

    external = ClientTransport(MailEdgeClient(configuration(), session=Session([])))
    sender.set_mail_edge_transport(external)
    sender.set_mail_edge_transport(None)
    assert external.close_calls == 0


def test_process_cleanup_registers_bridge_close_at_worker_lifecycle(monkeypatch):
    registered = []
    monkeypatch.setattr("app.mail_edge.composition.atexit.register", registered.append)
    sender = MailSender()
    instance, transport = bridge(sender, Session([]))
    sender.set_mail_edge_transport(transport, transfer_ownership=True)

    register_mail_edge_process_cleanup(instance)
    assert len(registered) == 1
    assert registered[0].__self__ is instance
    assert registered[0]()
    assert transport.close_calls == 1


def test_failed_composition_closes_its_new_owned_session(monkeypatch):
    session = Session([])
    monkeypatch.setattr("app.mail_edge.client.requests.Session", lambda: session)

    def fail_codec(*_args, **_kwargs):
        raise RuntimeError("composition failed")

    monkeypatch.setattr("app.mail_edge.composition.OpaqueAliasTokenCodec", fail_codec)
    with pytest.raises(RuntimeError, match="composition failed"):
        build_mail_edge_bridge(configuration(), sender=MailSender())
    assert session.close_calls == 1
