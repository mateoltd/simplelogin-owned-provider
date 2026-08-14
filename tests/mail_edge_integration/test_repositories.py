import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.db import Session
from app.mail_edge.contracts import ApplicationFeedback, RouteBindingSnapshot
from app.mail_edge.errors import (
    MailEdgeAmbiguousDeliveryError,
    MailEdgeAuthenticationError,
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
    claim = repository.claim(TENANT_ID, "application_delivery", "delivery-1", "a" * 64)
    with pytest.raises(MailEdgeAmbiguousDeliveryError):
        repository.claim(TENANT_ID, "application_delivery", "delivery-1", "a" * 64)
    acknowledgement = {
        "deliveryId": "01890f31-7b4a-7cc8-8d32-2f6e9a401118",
        "acceptedAt": "2026-08-13T12:00:00Z",
    }
    repository.complete(claim.receipt_id, acknowledgement)
    duplicate = repository.claim(
        TENANT_ID, "application_delivery", "delivery-1", "a" * 64
    )
    assert duplicate.completed_acknowledgement == acknowledgement
    with pytest.raises(MailEdgeAmbiguousDeliveryError):
        repository.claim(TENANT_ID, "application_delivery", "delivery-1", "b" * 64)
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
