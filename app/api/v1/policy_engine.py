"""Audited external policy decision boundary."""

from uuid import UUID

from fastapi import APIRouter, Depends
from prometheus_client import Counter
from pydantic import ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.policy_engine import PolicyRequest, PolicyResult, evaluate
from app.core.telephony_commands import payload_hash
from app.db.models import AuditEvent, PolicyDecision
from app.db.session import get_session


router = APIRouter(prefix="/api/v1/policy", tags=["policy-engine"])
DECISIONS = Counter(
    "codestra_policy_decisions_total",
    "Canonical policy decisions",
    ["action", "allow", "enforced"],
)


class PolicyDecisionResponse(PolicyResult):
    model_config = ConfigDict(extra="forbid", frozen=True)
    authorization_scope: dict[str, str]
    decision_hash: str


@router.post("/decisions", response_model=PolicyDecisionResponse)
async def decide(
    request: PolicyRequest, db: AsyncSession = Depends(get_session)
) -> PolicyDecisionResponse:
    result = evaluate(request)
    payload = result.model_dump(mode="json")
    payload["authorization_scope"] = {
        "action": request.action,
        "subject": request.subject,
        "resource": request.resource,
        "environment": request.environment or "",
        "business_unit": request.business_unit or "",
        "campaign": request.campaign or "",
        "agent": request.agent or "",
    }
    db.add(
        PolicyDecision(
            id=UUID(result.decision_id),
            policy=result.policy_version,
            allowed=result.allow,
            reason=",".join(result.reason_codes),
            correlation_id=result.correlation_id,
            context=payload,
        )
    )
    db.add(
        AuditEvent(
            action=f"policy.{result.action}",
            subject=result.subject,
            correlation_id=result.correlation_id,
            decision="allow" if result.allow else "deny",
            redacted_payload={
                "decision_id": result.decision_id,
                "resource": result.resource,
                "reason_codes": result.reason_codes,
                "enforced": result.enforced,
            },
        )
    )
    await db.commit()
    DECISIONS.labels(
        result.action, str(result.allow).lower(), str(result.enforced).lower()
    ).inc()
    return PolicyDecisionResponse(
        **result.model_dump(),
        authorization_scope=payload["authorization_scope"],
        decision_hash=payload_hash(payload),
    )
