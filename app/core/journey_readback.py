"""Read-only authority boundary for a future MCR-C next-action integration.

An implementation must supply a complete, coherent snapshot (not a journey
page), server-selected addresses/candidates and the tenant's governed policy.
No implementation is installed until those authoritative reads exist.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, Sequence

from app.core.campaign_recycling import (
    Candidate,
    CampaignRecyclingEngine,
    LeadSnapshot,
    NextActionDecision,
    PolicyProfile,
)


class ReadbackUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class NextActionInputs:
    snapshot: LeadSnapshot
    candidates: Sequence[Candidate]
    policy: PolicyProfile
    evaluated_at: datetime
    kill_switch_open: bool
    evidence_stale_or_conflicting: bool


class NextActionAuthority(Protocol):
    async def load(
        self, *, tenant_id: str, lead_id: str, channel: str | None
    ) -> NextActionInputs:
        """Read complete tenant-bound inputs, or raise ReadbackUnavailable."""
        ...


class UnavailableNextActionAuthority:
    async def load(self, *, tenant_id: str, lead_id: str, channel: str | None):
        raise ReadbackUnavailable(
            "Authoritative campaign candidates and lead address selection are unavailable"
        )


async def evaluate_next_action(
    authority: NextActionAuthority, *, tenant_id: str, lead_id: str,
    channel: str | None = None,
) -> NextActionDecision:
    inputs = await authority.load(tenant_id=tenant_id, lead_id=lead_id, channel=channel)
    if (
        inputs.snapshot.tenant_id != tenant_id
        or inputs.snapshot.lead_id != lead_id
        or inputs.evaluated_at.tzinfo is None
        or (channel is not None and any(c.channel != channel for c in inputs.candidates))
    ):
        raise ReadbackUnavailable("Authoritative next-action inputs are inconsistent")
    return CampaignRecyclingEngine(inputs.policy).evaluate(
        inputs.snapshot, inputs.candidates, mode="read", now=inputs.evaluated_at,
        kill_switch_open=inputs.kill_switch_open,
        evidence_stale_or_conflicting=inputs.evidence_stale_or_conflicting,
    )
