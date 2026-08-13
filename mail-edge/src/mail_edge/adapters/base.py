"""Provider adapter protocols; fake implementations belong only in tests."""

from __future__ import annotations

from typing import Protocol

from mail_edge.contracts import OutboundResult, OutboundSubmission


class OutboundAdapter(Protocol):
    def submit(self, submission: OutboundSubmission) -> OutboundResult: ...
