from __future__ import annotations

from typing import Mapping

from .client import MailEdgeClient
from .repository import RouteBindingProjectionRepository


class MailEdgeControlService:
    """Provider-neutral tenant and operator controls over the frozen reference API."""

    def __init__(
        self,
        client: MailEdgeClient,
        binding_projections: RouteBindingProjectionRepository,
    ):
        self._client = client
        self._binding_projections = binding_projections

    def inspect_binding(self, binding_id: str, binding_version: int):
        view = self._client.inspect_binding(binding_id, binding_version)
        self._binding_projections.synchronize(view["binding"], view["state"])
        return view

    def transition_binding(
        self,
        binding_id: str,
        binding_version: int,
        action: str,
        *,
        expected_version: int,
        reason_code: str,
    ):
        view = self._client.transition_binding(
            binding_id,
            binding_version,
            action,
            expected_version=expected_version,
            reason_code=reason_code,
        )
        self._binding_projections.synchronize(view["binding"], view["state"])
        return view

    def inspect_outbound_quarantine(self, intent_id: str):
        return self._client.inspect_outbound_quarantine(intent_id)

    def decide_outbound_quarantine(
        self,
        intent_id: str,
        action: str,
        *,
        evidence: Mapping[str, object],
        expected_fence: int,
        expected_version: int,
        reason_code: str,
    ):
        return self._client.decide_outbound_quarantine(
            intent_id,
            action,
            evidence=evidence,
            expected_fence=expected_fence,
            expected_version=expected_version,
            reason_code=reason_code,
        )

    def inspect_inbound_quarantine(self, receipt_id: str):
        return self._client.inspect_inbound_quarantine(receipt_id)

    def decide_inbound_quarantine(
        self,
        receipt_id: str,
        action: str,
        *,
        evidence: Mapping[str, object],
        expected_fence: int,
        expected_version: int,
        reason_code: str,
    ):
        return self._client.decide_inbound_quarantine(
            receipt_id,
            action,
            evidence=evidence,
            expected_fence=expected_fence,
            expected_version=expected_version,
            reason_code=reason_code,
        )
