from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .contracts import GateState, Gates


class ComplianceStatus(StrEnum):
    ELIGIBLE = "ELIGIBLE"
    BLOCKED_GLOBAL_DNC = "BLOCKED_GLOBAL_DNC"
    BLOCKED_CAMPAIGN_DNC = "BLOCKED_CAMPAIGN_DNC"
    BLOCKED_INTERNAL_SUPPRESSION = "BLOCKED_INTERNAL_SUPPRESSION"
    BLOCKED_CONSENT_WITHDRAWN = "BLOCKED_CONSENT_WITHDRAWN"
    REVIEW_CONSENT_UNKNOWN = "REVIEW_CONSENT_UNKNOWN"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"


@dataclass(frozen=True)
class ComplianceSnapshot:
    tenant_id: str
    campaign_id: str
    available: bool = True
    global_dnc: bool = False
    tenant_dnc: bool = False
    campaign_dnc: bool = False
    internal_suppression: bool = False
    email_suppressed: bool = False
    phone_suppressed: bool = False
    opted_out: bool = False
    legal_restriction: bool = False
    consent: str = "UNKNOWN"  # GRANTED, WITHDRAWN, UNKNOWN
    channel_eligible: bool = False


@dataclass(frozen=True)
class ComplianceDecision:
    status: ComplianceStatus
    gates: Gates
    reasons: tuple[str, ...]
    blocked: bool
    review_required: bool


def evaluate(
    snapshot: ComplianceSnapshot, tenant_id: str, campaign_id: str
) -> ComplianceDecision:
    if snapshot.tenant_id != tenant_id or snapshot.campaign_id != campaign_id:
        return _unavailable("COMPLIANCE_SCOPE_MISMATCH")
    if not snapshot.available:
        return _unavailable("COMPLIANCE_DEPENDENCY_UNAVAILABLE")
    gates = Gates(
        global_dnc=GateState.BLOCKED if snapshot.global_dnc else GateState.ELIGIBLE,
        campaign_dnc=GateState.BLOCKED if snapshot.campaign_dnc else GateState.ELIGIBLE,
        suppression=GateState.BLOCKED
        if snapshot.internal_suppression
        else GateState.ELIGIBLE,
        consent=(
            GateState.BLOCKED
            if snapshot.consent == "WITHDRAWN"
            else GateState.ELIGIBLE
            if snapshot.consent == "GRANTED"
            else GateState.REVIEW_REQUIRED
        ),
        channel_eligibility=(
            GateState.ELIGIBLE
            if snapshot.channel_eligible
            else GateState.REVIEW_REQUIRED
        ),
    )
    if snapshot.global_dnc:
        return ComplianceDecision(
            ComplianceStatus.BLOCKED_GLOBAL_DNC, gates, ("GLOBAL_DNC",), True, False
        )
    if snapshot.tenant_dnc:
        return ComplianceDecision(
            ComplianceStatus.BLOCKED_INTERNAL_SUPPRESSION,
            gates,
            ("TENANT_DNC",),
            True,
            False,
        )
    if snapshot.campaign_dnc:
        return ComplianceDecision(
            ComplianceStatus.BLOCKED_CAMPAIGN_DNC, gates, ("CAMPAIGN_DNC",), True, False
        )
    for active, reason in (
        (snapshot.email_suppressed, "EMAIL_SUPPRESSED"),
        (snapshot.phone_suppressed, "PHONE_SUPPRESSED"),
        (snapshot.opted_out, "OPTED_OUT"),
        (snapshot.legal_restriction, "LEGAL_RESTRICTION"),
        (snapshot.internal_suppression, "INTERNAL_SUPPRESSION"),
    ):
        if active:
            return ComplianceDecision(
                ComplianceStatus.BLOCKED_INTERNAL_SUPPRESSION,
                gates,
                (reason,),
                True,
                False,
            )
    if snapshot.consent == "WITHDRAWN":
        return ComplianceDecision(
            ComplianceStatus.BLOCKED_CONSENT_WITHDRAWN,
            gates,
            ("CONSENT_DENIED",),
            True,
            False,
        )
    if snapshot.consent != "GRANTED":
        return ComplianceDecision(
            ComplianceStatus.REVIEW_CONSENT_UNKNOWN,
            gates,
            ("CONSENT_UNKNOWN",),
            False,
            True,
        )
    return ComplianceDecision(
        ComplianceStatus.ELIGIBLE,
        gates,
        ("COMPLIANCE_ELIGIBLE",),
        False,
        not snapshot.channel_eligible,
    )


def _unavailable(reason: str) -> ComplianceDecision:
    state = GateState.DEPENDENCY_UNAVAILABLE
    return ComplianceDecision(
        ComplianceStatus.DEPENDENCY_UNAVAILABLE,
        Gates(
            global_dnc=state,
            campaign_dnc=state,
            suppression=state,
            consent=state,
            channel_eligibility=state,
        ),
        (reason,),
        True,
        True,
    )
