"""``POST /internal/v1/authorization/check`` - canonical internal decision endpoint.

Served by the ``middleware-policy-engine`` service (see
``app/entrypoints/policy_engine.py``) - the same dedicated process that
already serves ``POST /api/v1/policy/decisions`` via
``app.api.v1.policy_engine``. This module is a thin second route on that
same router's underlying decision function (``app.core.policy_engine.evaluate``)
so there remains exactly one running policy-decision service and one audit
trail, just reachable at both the legacy and canonical paths. It is
deliberately NOT mounted on the main monolith app (``app/main.py``): the
policy engine has its own dedicated deployment with its own database
secret (``QUARANTINE_*``-style secrets in ``deploy/compose.runtime.yaml``
show every service here gets its own scoped credentials), and duplicating
this router into a second running process would mean two services able to
write ``PolicyDecision``/``AuditEvent`` rows for the same decision space -
exactly the kind of duplicate-authority problem avoided elsewhere this
session (see the M2 provisioning-service reconciliation).

Auth: ``/api/v1/policy/decisions`` gets its bearer check "for free" from
``add_api_runtime``'s service-wide middleware, which only inspects paths
starting with ``/api/`` or ``/v1/`` - this route's canonical
``/internal/v1/...`` path falls outside that scope entirely (the same
reason other ``/internal/``-prefixed routes in this codebase, e.g.
``app/api/internal/ai_jobs.py`` and ``klyrow_mail.py``, each implement their
own explicit per-route auth rather than relying on it). So this handler
checks the identical ``settings.middleware_secret`` bearer credential
explicitly, via the same ``verify_bearer`` helper the middleware itself
uses - same credential, same failure semantics, just enforced inline
instead of picked up implicitly.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.policy_engine import PolicyDecisionResponse, DECISIONS
from app.core.auth import BearerAuthError, verify_bearer
from app.core.config import settings
from app.core.policy_engine import PolicyRequest, evaluate
from app.core.telephony_commands import payload_hash
from app.db.models import AuditEvent, PolicyDecision
from app.db.session import get_session

router = APIRouter(prefix="/internal/v1/authorization", tags=["internal-authorization"])


@router.post("/check", response_model=PolicyDecisionResponse)
async def check(
    request: PolicyRequest,
    db: AsyncSession = Depends(get_session),
    authorization: str = Header(default=""),
) -> PolicyDecisionResponse:
    try:
        verify_bearer(authorization, settings.middleware_secret)
    except BearerAuthError:
        status_code = 503 if not settings.middleware_secret else 401
        raise HTTPException(
            status_code,
            "authentication unavailable" if status_code == 503 else "unauthorized",
        )
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
