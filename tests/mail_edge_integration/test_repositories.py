import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from threading import Event, Thread, current_thread
from time import monotonic, sleep
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Query, scoped_session, sessionmaker

import app.models as models
import app.mail_edge.repository as repository_module
from app.db import engine

import pytest

from app.db import Session
from app.mail_edge.contracts import ApplicationFeedback, RouteBindingSnapshot
from app.mail_edge.errors import (
    MailEdgeAmbiguousDeliveryError,
    MailEdgeAuthenticationError,
    MailEdgeUnavailableError,
    MailEdgeContractError,
)
from app.mail_edge.host_services import ApplicationFeedbackService
from app.mail_edge.repository import (
    CallbackReceiptRepository,
    OutboundProjectionRepository,
    ReplayNonceRepository,
    RouteBindingProjectionRepository,
)
from app.mail_edge.simplelogin_repository import SimpleLoginAliasRoutingRepository
from app.models import (
    CustomDomain,
    Contact,
    MailEdgeCallbackReceipt,
    MailEdgeOutboundProjection,
    MailEdgeReplayNonce,
    MailEdgeRouteBindingProjection,
)
from app.models import Alias
from tests.utils import create_new_user, random_domain


TENANT_ID = "01890f31-7b4a-7cc8-8d32-2f6e9a401111"


def binding(version, binding_id, domain="sl.lan"):
    return RouteBindingSnapshot(
        binding_id=binding_id,
        binding_version=version,
        tenant_id=TENANT_ID,
        domain_a_label=domain,
        direction="inbound",
        provider_id="provider-neutral",
        adapter_version="v1",
        provider_instance_id="01890f31-7b4a-7cc8-8d32-2f6e9a401119",
        provider_resource_ids={},
        capability_digest="c" * 64,
        config_revision=f"revision-{version}",
        created_at="2026-08-13T12:00:00Z",
    )


def test_replay_nonce_is_durable_and_fail_closed(flask_client):
    repository = ReplayNonceRepository()
    expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
    Session.add(
        MailEdgeReplayNonce(
            key_id="expired-key",
            nonce_digest="e" * 64,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
    )
    Session.commit()
    nonce = "unique_nonce_value"
    digest = hashlib.sha256(nonce.encode("ascii")).hexdigest()
    MailEdgeReplayNonce.filter_by(key_id="host-key-1", nonce_digest=digest).delete()
    Session.commit()
    repository.consume("host-key-1", nonce, expiry)
    assert MailEdgeReplayNonce.filter_by(key_id="expired-key").first() is None
    with pytest.raises(MailEdgeAuthenticationError):
        repository.consume("host-key-1", nonce, expiry)
    MailEdgeReplayNonce.filter_by(key_id="host-key-1", nonce_digest=digest).delete()
    Session.commit()


def test_duplicate_callback_returns_ack_but_crash_window_is_ambiguous(flask_client):
    repository = CallbackReceiptRepository()
    MailEdgeCallbackReceipt.filter_by(
        tenant_id=TENANT_ID,
        operation="application_delivery",
        subject_id="delivery-1",
    ).delete()
    Session.commit()
    claim = repository.claim(
        TENANT_ID, "application_delivery", "delivery-1", "a" * 64, 60
    )
    with pytest.raises(MailEdgeUnavailableError):
        repository.claim(TENANT_ID, "application_delivery", "delivery-1", "a" * 64, 60)
    repository.start_business_effect(claim.receipt_id, claim.fence)
    with pytest.raises(MailEdgeAmbiguousDeliveryError):
        repository.claim(TENANT_ID, "application_delivery", "delivery-1", "a" * 64, 60)
    acknowledgement = {
        "deliveryId": "01890f31-7b4a-7cc8-8d32-2f6e9a401118",
        "acceptedAt": "2026-08-13T12:00:00Z",
    }
    repository.complete(claim.receipt_id, claim.fence, acknowledgement)
    duplicate = repository.claim(
        TENANT_ID, "application_delivery", "delivery-1", "a" * 64, 60
    )
    assert duplicate.completed_acknowledgement == acknowledgement
    with pytest.raises(MailEdgeAmbiguousDeliveryError):
        repository.claim(TENANT_ID, "application_delivery", "delivery-1", "b" * 64, 60)
    MailEdgeCallbackReceipt.filter_by(
        tenant_id=TENANT_ID,
        operation="application_delivery",
        subject_id="delivery-1",
    ).delete()
    Session.commit()


def test_route_generation_swap_drains_old_binding_and_authorizes_pinned_work(
    flask_client
):
    repository = RouteBindingProjectionRepository(TENANT_ID)
    MailEdgeRouteBindingProjection.filter_by(
        tenant_id=TENANT_ID, domain_a_label="sl.lan", direction="inbound"
    ).delete()
    Session.commit()
    old = binding(2, "01890f31-7b4a-7cc8-8d32-2f6e9a401112")
    new = binding(1, "01890f31-7b4a-7cc8-8d32-2f6e9a401113")
    repository.activate(old)
    repository.activate(new)
    rows = (
        MailEdgeRouteBindingProjection.filter_by(
            tenant_id=TENANT_ID, domain_a_label="sl.lan", direction="inbound"
        )
        .order_by(MailEdgeRouteBindingProjection.binding_version)
        .all()
    )
    assert [row.state for row in rows] == ["active", "draining"]
    assert repository.authorize_delivery(old)
    assert repository.authorize_delivery(new)
    with pytest.raises(MailEdgeContractError):
        repository.activate(old)
    repository.retire(old)
    assert not repository.authorize_delivery(old)
    assert repository.authorize_delivery(new)
    MailEdgeRouteBindingProjection.filter_by(
        tenant_id=TENANT_ID, domain_a_label="sl.lan", direction="inbound"
    ).delete()
    Session.commit()


def test_route_binding_rejects_unowned_exact_domain(flask_client):
    with pytest.raises(MailEdgeContractError):
        RouteBindingProjectionRepository(TENANT_ID).activate(
            binding(1, "01890f31-7b4a-7cc8-8d32-2f6e9a401115", "unowned.example")
        )
    Session.rollback()


def test_route_binding_rejects_cross_tenant_generation(flask_client):
    foreign = replace(
        binding(1, "01890f31-7b4a-7cc8-8d32-2f6e9a401116"),
        tenant_id="01890f31-7b4a-7cc8-8d32-2f6e9a401117",
    )
    with pytest.raises(MailEdgeContractError):
        RouteBindingProjectionRepository(TENANT_ID).activate(foreign)


def test_exact_custom_domain_catch_all_creation_is_local_and_idempotent(flask_client):
    user = create_new_user()
    user.lifetime = True
    custom_domain = CustomDomain.create(
        user_id=user.id,
        domain=random_domain(),
        catch_all=True,
        verified=True,
        ownership_verified=True,
        flush=True,
    )
    Session.commit()
    address = f"CaseSensitive@{custom_domain.domain}"
    repository = SimpleLoginAliasRoutingRepository()

    first = repository.resolve_or_create(address, custom_domain.domain)
    second = repository.resolve_or_create(address, custom_domain.domain)

    assert first is not None
    assert second == first
    assert first.address == address
    alias = Alias.get_by(id=first.alias_id)
    assert alias.user_id == user.id
    assert alias.custom_domain_id == custom_domain.id


def test_outbound_quarantine_and_feedback_projection_is_tenant_scoped(flask_client):
    user = create_new_user()
    alias = Alias.create_new_random(user)
    repository = OutboundProjectionRepository()
    intent_id = "01890f31-7b4a-7cc8-8d32-2f6e9a401120"
    accepted = SimpleNamespace(
        intent_id=intent_id, fingerprint="f" * 64, state="accepted", version=0
    )
    context = {
        "user_id": user.id,
        "alias_id": alias.id,
        "contact_id": None,
        "mailbox_id": user.default_mailbox_id,
        "email_log_id": None,
        "idempotency_subject": "message-id:<fixture@example.net>",
    }
    repository.record_accepted(TENANT_ID, accepted, context)
    quarantined = SimpleNamespace(
        intent_id=intent_id,
        fingerprint="f" * 64,
        state="quarantined_unknown",
        version=1,
    )
    repository.project_status(TENANT_ID, quarantined)
    with pytest.raises(MailEdgeAmbiguousDeliveryError):
        repository.project_status(
            TENANT_ID,
            SimpleNamespace(
                intent_id=intent_id,
                fingerprint="f" * 64,
                state="accepted",
                version=2,
            ),
        )
    feedback = ApplicationFeedback(
        feedback_event_id="01890f31-7b4a-7cc8-8d32-2f6e9a401121",
        tenant_id=TENANT_ID,
        intent_id=intent_id,
        kind="bounced",
        occurred_at="2026-08-13T12:00:00Z",
        normalized_evidence={},
    )
    service = ApplicationFeedbackService(
        TENANT_ID,
        CallbackReceiptRepository(),
        repository.stage_feedback,
        clock=lambda: datetime(2026, 8, 13, 12, 1, tzinfo=timezone.utc),
    )
    callback_body = b'{"schemaVersion":"v1","kind":"bounced"}'
    acknowledgement = service.deliver(feedback, callback_body)
    assert service.deliver(feedback, callback_body) == acknowledgement
    projection = MailEdgeOutboundProjection.filter_by(
        tenant_id=TENANT_ID, intent_id=intent_id
    ).first()
    assert projection.quarantined
    assert projection.feedback_kind == "bounced"
    MailEdgeOutboundProjection.filter_by(
        tenant_id=TENANT_ID, intent_id=intent_id
    ).delete()
    MailEdgeCallbackReceipt.filter_by(
        tenant_id=TENANT_ID,
        operation="application_feedback",
        subject_id=feedback.feedback_event_id,
    ).delete()
    Session.commit()


@pytest.mark.parametrize(
    "invalid_state", ["unverified", "unowned", "deleting", "unknown"]
)
def test_reverse_route_rejects_alias_domain_when_authority_is_lost(
    flask_client, invalid_state
):
    user = create_new_user()
    user.lifetime = True
    custom_domain = CustomDomain.create(
        user_id=user.id,
        domain=random_domain(),
        verified=True,
        ownership_verified=True,
        flush=True,
    )
    alias = Alias.create(
        user_id=user.id,
        email=f"alias@{custom_domain.domain}",
        custom_domain_id=custom_domain.id,
        mailbox_id=user.default_mailbox_id,
        flush=True,
    )
    contact = Contact.create(
        user_id=user.id,
        alias_id=alias.id,
        website_email="recipient@example.net",
        reply_email="route-authority@sl.lan",
        flush=True,
    )
    Session.commit()
    repository = SimpleLoginAliasRoutingRepository()
    assert repository.resolve_reverse(contact.reply_email, "sl.lan") is not None
    if invalid_state == "unverified":
        custom_domain.verified = False
    elif invalid_state == "unowned":
        custom_domain.ownership_verified = False
    elif invalid_state == "deleting":
        custom_domain.pending_deletion = True
    else:
        alias.custom_domain_id = None
    Session.commit()
    assert repository.resolve_destination(alias.id) is None
    assert repository.resolve_reverse(contact.reply_email, "sl.lan") is None


@pytest.mark.parametrize("newer_state", ["provider_accepted", "quarantined_unknown"])
def test_outbound_status_is_monotonic_across_independent_transactions(
    monkeypatch, newer_state
):
    # The normal client fixture uses one outer transaction. This regression needs
    # real committed rows and independently pooled PostgreSQL connections.
    older_read, release_older, newer_done = Event(), Event(), Event()
    failures, backend_pids = [], {}

    class PausingQuery(Query):
        def first(self):
            row = super().first()
            if current_thread().name == "older-status" and row is not None:
                older_read.set()
                if not release_older.wait(5):
                    raise RuntimeError("Older status was not released")
            return row

    sessions = scoped_session(sessionmaker(bind=engine, query_cls=PausingQuery))
    monkeypatch.setattr(models, "Session", sessions)
    monkeypatch.setattr(repository_module, "Session", sessions)
    intent_id = str(uuid4())
    user = models.User(email=f"projection-{intent_id}@example.invalid")
    sessions.add(user)
    sessions.flush()
    user_id = user.id
    mailbox = models.Mailbox(user_id=user.id, email=user.email, verified=True)
    sessions.add(mailbox)
    sessions.flush()
    alias = models.Alias(
        user_id=user.id, email=f"projection-{intent_id}@sl.lan", mailbox_id=mailbox.id
    )
    sessions.add(alias)
    sessions.flush()
    sessions.add(
        MailEdgeOutboundProjection(
            tenant_id=TENANT_ID,
            intent_id=intent_id,
            user_id=user.id,
            alias_id=alias.id,
            state="accepted",
            request_fingerprint="f" * 64,
            version=0,
        )
    )
    sessions.commit()
    sessions.remove()

    def project(name, state, version):
        try:
            backend_pids[name] = sessions.execute(
                text("SELECT pg_backend_pid()")
            ).scalar_one()
            OutboundProjectionRepository().project_status(
                TENANT_ID,
                SimpleNamespace(
                    intent_id=intent_id,
                    fingerprint="f" * 64,
                    state=state,
                    version=version,
                ),
            )
        except Exception as error:
            failures.append(error)
        finally:
            sessions.remove()
            if name == "newer-status":
                newer_done.set()

    older = Thread(
        name="older-status", target=project, args=("older-status", "dispatching", 2)
    )
    newer = Thread(
        name="newer-status",
        target=project,
        args=("newer-status", newer_state, 3),
    )
    try:
        older.start()
        assert older_read.wait(5)
        newer.start()
        # Establish either the historical race (newer committed first) or row
        # serialization (newer is waiting on the older transaction), then release.
        deadline = monotonic() + 5
        while not newer_done.is_set():
            pid = backend_pids.get("newer-status")
            with engine.connect() as observer:
                waiting = observer.execute(
                    text(
                        "SELECT wait_event_type = 'Lock' FROM pg_stat_activity WHERE pid = :pid"
                    ),
                    {"pid": pid},
                ).scalar()
            if waiting:
                break
            assert (
                monotonic() < deadline
            ), "Newer status neither committed nor waited on a row lock"
            sleep(0.01)
        release_older.set()
        older.join(5)
        newer.join(5)
        assert not older.is_alive() and not newer.is_alive()
        assert not failures
        assert backend_pids["older-status"] != backend_pids["newer-status"]
        projection = MailEdgeOutboundProjection.filter_by(
            tenant_id=TENANT_ID, intent_id=intent_id
        ).one()
        assert (projection.state, projection.version) == (newer_state, 3)
        assert projection.quarantined == (newer_state == "quarantined_unknown")
        repository = OutboundProjectionRepository()

        def status(state, version, fingerprint="f" * 64):
            return SimpleNamespace(
                intent_id=intent_id,
                fingerprint=fingerprint,
                state=state,
                version=version,
            )

        repository.project_status(TENANT_ID, status("dispatching", 2))
        repository.project_status(TENANT_ID, status(newer_state, 3))
        with pytest.raises(
            MailEdgeAmbiguousDeliveryError, match="OUTBOUND_VERSION_CONFLICT"
        ):
            repository.project_status(TENANT_ID, status("dispatching", 3))
        with pytest.raises(
            MailEdgeAmbiguousDeliveryError, match="OUTBOUND_FINGERPRINT_CONFLICT"
        ):
            repository.project_status(TENANT_ID, status("dispatching", 2, "a" * 64))
        with pytest.raises(
            MailEdgeContractError, match="OUTBOUND_PROJECTION_NOT_FOUND"
        ):
            repository.project_status(str(uuid4()), status(newer_state, 4))
        projection = MailEdgeOutboundProjection.filter_by(
            tenant_id=TENANT_ID, intent_id=intent_id
        ).one()
        assert (projection.state, projection.version, projection.quarantined) == (
            newer_state,
            3,
            newer_state == "quarantined_unknown",
        )
    finally:
        release_older.set()
        if older.ident is not None:
            older.join(5)
        if newer.ident is not None:
            newer.join(5)
        sessions.rollback()
        sessions.query(models.User).filter_by(id=user_id).delete()
        sessions.commit()
        sessions.remove()
