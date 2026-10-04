from __future__ import annotations

import atexit
import threading
from dataclasses import dataclass
from typing import Optional

from app.mail_sender import MailSender, mail_sender

from .client import MailEdgeClient
from .configuration import MailEdgeConfiguration, configuration_from_environment
from .control import MailEdgeControlService
from .host_services import (
    ApplicationDeliveryService,
    ApplicationFeedbackService,
    AuthenticatedHostOperations,
)
from .mime import BoundedMimeParserService
from .outbound import MailEdgeOutboundTransport, OutboundStatusProjectionService
from .repository import (
    CallbackReceiptRepository,
    OutboundProjectionRepository,
    ReplayNonceRepository,
    RouteBindingProjectionRepository,
)
from .routing import OpaqueAliasTokenCodec, RecipientRouter, ReverseRouteResolver
from .resources import HostResourceAdmissionService
from .simplelogin_repository import SimpleLoginAliasRoutingRepository


@dataclass
class MailEdgeBridge:
    configuration: MailEdgeConfiguration
    client: MailEdgeClient
    outbound_transport: MailEdgeOutboundTransport
    outbound_status: OutboundStatusProjectionService
    recipient_router: RecipientRouter
    reverse_route_resolver: ReverseRouteResolver
    authenticated_host_operations: AuthenticatedHostOperations
    feedback_service: ApplicationFeedbackService
    callback_receipts: CallbackReceiptRepository
    binding_projections: RouteBindingProjectionRepository
    control: MailEdgeControlService
    host_admission: HostResourceAdmissionService
    mime_parser: BoundedMimeParserService
    sender: MailSender

    def __post_init__(self) -> None:
        self._close_lock = threading.Lock()
        self._closed = False

    def application_delivery_service(
        self, deliver_message
    ) -> ApplicationDeliveryService:
        return ApplicationDeliveryService(
            self.configuration.tenant_id,
            self.callback_receipts,
            self.binding_projections,
            self.recipient_router,
            deliver_message,
            self.mime_parser,
            self.configuration.host_authentication.callback_lease_seconds,
        )

    def close(self, timeout_seconds: Optional[float] = None) -> bool:
        selected_timeout = (
            self.configuration.http.shutdown_seconds
            if timeout_seconds is None
            else timeout_seconds
        )
        with self._close_lock:
            if self._closed:
                return True
            released = self.sender.release_mail_edge_transport(
                self.outbound_transport, timeout_seconds=selected_timeout
            )
            closed = (
                self.client.close(selected_timeout) if released is None else released
            )
            if closed:
                self._closed = True
            return closed


def register_mail_edge_process_cleanup(bridge: MailEdgeBridge) -> None:
    """Attach bridge cleanup to worker/process exit, never request teardown."""

    atexit.register(bridge.close)


def build_mail_edge_bridge(
    configuration: Optional[MailEdgeConfiguration] = None,
    *,
    sender: MailSender = mail_sender,
) -> Optional[MailEdgeBridge]:
    selected = (
        configuration if configuration is not None else configuration_from_environment()
    )
    if selected is None:
        sender.set_mail_edge_transport(None)
        return None
    client = MailEdgeClient(selected)
    try:
        outbound_projections = OutboundProjectionRepository()
        callback_receipts = CallbackReceiptRepository()
        binding_projections = RouteBindingProjectionRepository(selected.tenant_id)
        routing_repository = SimpleLoginAliasRoutingRepository()
        transport = MailEdgeOutboundTransport(client, outbound_projections)
        recipient_router = RecipientRouter(
            selected.tenant_id,
            routing_repository,
            OpaqueAliasTokenCodec(selected.tenant_id, selected.opaque_token_key),
        )
        control = MailEdgeControlService(client, binding_projections)
        host_admission = HostResourceAdmissionService(
            selected.host_delivery, selected.maximum_raw_bytes
        )
        mime_parser = BoundedMimeParserService(selected.host_delivery.mime)
        bridge = MailEdgeBridge(
            selected,
            client,
            transport,
            OutboundStatusProjectionService(client, outbound_projections),
            recipient_router,
            ReverseRouteResolver(selected.tenant_id, routing_repository),
            AuthenticatedHostOperations(
                selected.host_authentication, ReplayNonceRepository()
            ),
            ApplicationFeedbackService(
                selected.tenant_id,
                callback_receipts,
                outbound_projections.stage_feedback,
                selected.host_authentication.callback_lease_seconds,
            ),
            callback_receipts,
            binding_projections,
            control,
            host_admission,
            mime_parser,
            sender,
        )
    except BaseException:
        client.close(0)
        raise
    sender.set_mail_edge_transport(transport, transfer_ownership=True)
    return bridge
