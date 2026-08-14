from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.mail_sender import MailSender, mail_sender

from .client import MailEdgeClient
from .configuration import MailEdgeConfiguration, configuration_from_environment
from .host_services import (
    ApplicationDeliveryService,
    ApplicationFeedbackService,
    AuthenticatedHostOperations,
)
from .outbound import MailEdgeOutboundTransport, OutboundStatusProjectionService
from .repository import (
    CallbackReceiptRepository,
    OutboundProjectionRepository,
    ReplayNonceRepository,
    RouteBindingProjectionRepository,
)
from .routing import OpaqueAliasTokenCodec, RecipientRouter, ReverseRouteResolver
from .simplelogin_repository import SimpleLoginAliasRoutingRepository


@dataclass(frozen=True)
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

    def application_delivery_service(
        self, deliver_message
    ) -> ApplicationDeliveryService:
        return ApplicationDeliveryService(
            self.configuration.tenant_id,
            self.callback_receipts,
            self.binding_projections,
            deliver_message,
        )


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
    outbound_projections = OutboundProjectionRepository()
    callback_receipts = CallbackReceiptRepository()
    binding_projections = RouteBindingProjectionRepository(selected.tenant_id)
    routing_repository = SimpleLoginAliasRoutingRepository()
    transport = MailEdgeOutboundTransport(client, outbound_projections)
    sender.set_mail_edge_transport(transport)
    return MailEdgeBridge(
        selected,
        client,
        transport,
        OutboundStatusProjectionService(client, outbound_projections),
        RecipientRouter(
            selected.tenant_id,
            routing_repository,
            OpaqueAliasTokenCodec(selected.tenant_id, selected.opaque_token_key),
        ),
        ReverseRouteResolver(selected.tenant_id, routing_repository),
        AuthenticatedHostOperations(
            selected.host_authentication, ReplayNonceRepository()
        ),
        ApplicationFeedbackService(
            selected.tenant_id, callback_receipts, outbound_projections.stage_feedback
        ),
        callback_receipts,
        binding_projections,
    )
