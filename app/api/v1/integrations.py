"""Explicit Odoo/n8n integration gateway routes.

Existing event and callback routes remain the implementation of record; these
namespaces make the ownership boundary unambiguous. Command execution is
fail-closed until the approved Odoo adapter and live-write flag are enabled.
"""

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.automation import canonical_hash, redact
from app.core.config import settings
from app.core.jwt_auth import JWTAuthError, KeycloakValidator, identity_validator_kwargs
from app.core.provisioning_auth import (
    ProvisioningPrincipal,
    require_provisioning_scope,
    require_tenant_match,
)
from app.db.models import (
    AuditEvent,
    IdempotencyRecord,
    IntegrationEvent,
    OdooResultDelivery,
)
from app.db.session import get_session
from app.adapters.odoo.campaign_control import (
    OdooCampaignAdapterError,
    read_campaign,
    read_desired_state,
)
from app.adapters.odoo.results import OdooResultError, _build_odoo_client
from app.core.endpoint_registry import RegistryDependencyUnavailable, ResolutionDenied
from app.legacy_effects import DENIED_RESPONSES, denial_dependency, deny

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


class RuntimeIntegrationStatus(BaseModel):
    """Read-only, secret-free runtime gate snapshot for certification tooling."""

    status: Literal["blocked", "ready"]
    source_sha: str
    image_digest: str
    environment: str
    auth_ready: bool
    external_effects_enabled: bool
    gates: dict[str, bool]
    timestamp: datetime


class CallbackResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command_id: str = Field(min_length=1, max_length=128)
    status: str = Field(min_length=1, max_length=64)
    payload: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=128)


class AutomationAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_type: Literal[
        "CREATE_ACTIVITY",
        "CREATE_INTERNAL_SUMMARY",
        "CREATE_DRAFT",
        "SET_NEXT_ACTION",
        "CHANGE_STATUS",
        "SEND_EMAIL",
        "SEND_SMS",
    ]
    entity_type: str = Field(min_length=1, max_length=128)
    entity_id: str = Field(min_length=1, max_length=128)
    values: dict[str, Any] = Field(default_factory=dict)


class AutomationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=255)
    workflow_key: str = Field(min_length=1, max_length=128)
    execution_id: str = Field(min_length=1, max_length=128)
    status: Literal["COMPLETED", "FAILED", "RETRY"]
    actions: list[AutomationAction] = Field(default_factory=list, max_length=100)
    completed_at: datetime


ODOO_CAMPAIGN_ACTION_TYPES = frozenset(
    {
        "CREATE_INTERNAL_SUMMARY",
        "SET_NEXT_ACTION",
        "CHANGE_STATUS",
    }
)


def _scope_values(claims: dict[str, Any], plural: str, singular: str) -> set[str]:
    values = claims.get(plural, claims.get(singular, []))
    if isinstance(values, str):
        return {item for item in values.replace(",", " ").split() if item}
    return {str(item) for item in values or []}


def _n8n_authorized_parties() -> frozenset[str]:
    listed = frozenset(
        value.strip()
        for value in settings.n8n_campaign_service_client_ids.split(",")
        if value.strip()
    )
    return listed or frozenset({settings.n8n_campaign_service_client_id})


_JWT_PERMISSION_DENIALS = frozenset(
    {
        "authorized party denied",
        "required role denied",
        "required scope denied",
        "business unit denied",
        "campaign denied",
    }
)


def _jwt_error_status(exc: JWTAuthError) -> int:
    """Map valid-token permission failures to 403 and identity failures to 401."""
    return 403 if str(exc) in _JWT_PERMISSION_DENIALS else 401


def _authenticate_n8n(authorization: str, required_scope: str) -> dict[str, Any]:
    """n8n service JWT, pinned to the deployment's own environment claim.

    The token's ``environment`` must equal ``settings.environment`` (staging
    tokens in staging, production tokens in production); a token minted for
    another environment is rejected even when every other claim is valid.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "bearer token required")
    try:
        return KeycloakValidator(
            issuer=settings.n8n_service_issuer,
            audience=settings.n8n_service_audience,
            jwks_url=settings.n8n_service_jwks_url,
            authorized_parties=_n8n_authorized_parties(),
            required_scopes=frozenset({required_scope}),
            required_environment=settings.environment,
        ).validate(authorization.removeprefix("Bearer ").strip())
    except JWTAuthError as exc:
        raise HTTPException(_jwt_error_status(exc), str(exc)) from exc


def _authenticate_odoo(authorization: str, required_scope: str) -> dict[str, Any]:
    """Campaign-read caller: a dedicated service client, pinned to this environment.

    Deliberately not the interactive agent-UI allowlist
    (``keycloak_authorized_parties``); an empty reader list authorizes nobody.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "bearer token required")
    readers = frozenset(
        value.strip()
        for value in settings.odoo_campaign_reader_client_ids.split(",")
        if value.strip()
    )
    if not readers:
        raise HTTPException(503, "campaign reader client is not configured")
    try:
        return KeycloakValidator(
            **identity_validator_kwargs(
                settings.identity,
                authorized_parties=readers,
                required_scopes=frozenset({required_scope}),
                required_environment=settings.environment,
            )
        ).validate(authorization.removeprefix("Bearer ").strip())
    except JWTAuthError as exc:
        raise HTTPException(_jwt_error_status(exc), str(exc)) from exc


def _require_campaign_claim(claims: dict[str, Any], campaign_id: str) -> None:
    if campaign_id not in _scope_values(claims, "campaigns", "campaign_scope"):
        raise HTTPException(403, "campaign scope denied")


def _require_context_binding(
    claims: dict[str, Any],
    *,
    tenant_id: str,
    business_unit_id: str,
) -> None:
    claimed_tenant = claims.get("tenant_id")
    if not claimed_tenant or not tenant_id or str(claimed_tenant) != tenant_id:
        raise HTTPException(403, "tenant scope denied")
    if business_unit_id not in _scope_values(
        claims, "business_units", "business_unit_scope"
    ):
        raise HTTPException(403, "business-unit scope denied")


def _odoo_payload(
    campaign_id: str, tenant_id: str, business_unit_id: str
) -> dict[str, str]:
    return {
        "organization_public_id": tenant_id,
        "business_unit_public_id": business_unit_id,
        "campaign_public_id": campaign_id,
    }


# Configuration, registry, and transport faults are dependency outages (503),
# distinct from Odoo answering with an error (502).
_ODOO_DEPENDENCY_ERRORS = (
    OdooResultError,
    ResolutionDenied,
    RegistryDependencyUnavailable,
    httpx.TransportError,
)


async def _odoo_read(
    operation: str,
    payload: dict[str, str],
    *,
    correlation_id: str,
    db: AsyncSession,
) -> dict[str, Any]:
    client = _build_odoo_client(db, payload)
    try:
        if operation == "campaigns.read":
            return await read_campaign(
                client,
                payload,
                request_id=f"REQ-{uuid4()}",
                correlation_id=correlation_id,
                traceparent=f"00-{canonical_hash({'correlation_id': correlation_id})[:32]}-{canonical_hash(payload)[:16]}-01",
            )
        return await read_desired_state(
            client,
            payload,
            request_id=f"REQ-{uuid4()}",
            correlation_id=correlation_id,
            traceparent=f"00-{canonical_hash({'correlation_id': correlation_id})[:32]}-{canonical_hash(payload)[:16]}-01",
        )
    finally:
        await client.aclose()


@router.get("/runtime", response_model=RuntimeIntegrationStatus)
async def runtime_integration_status() -> RuntimeIntegrationStatus:
    """Expose the current no-effect integration gates without secrets or endpoints.

    This is intentionally a snapshot of local configuration and source identity;
    it never labels a deployment certified and performs no provider or database
    mutation.
    """
    effects = {
        "callback_dispatch": settings.callback_dispatch_enabled,
        "email_delivery": settings.messaging_enabled,
        "external_delivery": settings.enable_external_delivery,
        "live_writes": settings.live_writes_enabled,
        "n8n_delivery": settings.n8n_event_delivery_enabled,
        "odoo_writes": settings.odoo_write_enabled
        or settings.odoo_automation_writes_enabled,
        "production_dialing": settings.external_dial_enabled,
        "sms_delivery": settings.messaging_enabled,
        "social_publish": getattr(settings, "social_publish_enabled", False),
        "vicidial_writes": settings.vicidial_write_enabled,
    }
    gates = {
        "authorization": settings.auth_ready,
        "database_configured": bool(
            settings.database_url or settings.database_url_file
        ),
        "redis_configured": bool(settings.redis_url or settings.redis_url_file),
        "effects_disabled": not any(effects.values()),
        "source_identified": bool(__import__("os").getenv("SOURCE_SHA")),
        "image_identified": bool(__import__("os").getenv("IMAGE_DIGEST")),
    }
    ready = all(gates.values())
    return RuntimeIntegrationStatus(
        status="ready" if ready else "blocked",
        source_sha=__import__("os").getenv("SOURCE_SHA", "unknown"),
        image_digest=__import__("os").getenv("IMAGE_DIGEST", "unknown"),
        environment=settings.environment,
        auth_ready=settings.auth_ready,
        external_effects_enabled=any(effects.values()),
        gates=gates,
        timestamp=datetime.now(timezone.utc),
    )


@router.get("/odoo/health")
async def odoo_health() -> dict[str, str]:
    return {"status": "ok", "gateway": "codestra-middleware", "provider": "odoo"}


@router.get("/odoo/readiness")
async def odoo_readiness() -> dict[str, str]:
    return {
        "status": "ready" if settings.auth_ready else "not-ready",
        "provider": "odoo",
    }


@router.get("/odoo/campaigns/{campaign_id}")
async def odoo_campaign_read(
    campaign_id: str,
    tenant_id: str = Query(min_length=1, max_length=128),
    business_unit_id: str = Query(min_length=1, max_length=128),
    authorization: str = Header(..., alias="Authorization"),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    claims = _authenticate_odoo(authorization, "odoo.campaigns.read")
    _require_campaign_claim(claims, campaign_id)
    _require_context_binding(
        claims, tenant_id=tenant_id, business_unit_id=business_unit_id
    )
    try:
        return await _odoo_read(
            "campaigns.read",
            _odoo_payload(campaign_id, tenant_id, business_unit_id),
            correlation_id=str(uuid4()),
            db=db,
        )
    except OdooCampaignAdapterError as exc:
        raise HTTPException(502, str(exc)) from exc
    except _ODOO_DEPENDENCY_ERRORS as exc:
        raise HTTPException(503, "Odoo campaign dependency unavailable") from exc


@router.get("/odoo/campaigns/{campaign_id}/desired-state")
async def odoo_campaign_desired_state(
    campaign_id: str,
    tenant_id: str = Query(min_length=1, max_length=128),
    business_unit_id: str = Query(min_length=1, max_length=128),
    authorization: str = Header(..., alias="Authorization"),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    claims = _authenticate_odoo(authorization, "odoo.campaigns.read")
    _require_campaign_claim(claims, campaign_id)
    _require_context_binding(
        claims, tenant_id=tenant_id, business_unit_id=business_unit_id
    )
    try:
        return await _odoo_read(
            "desired_state.read",
            _odoo_payload(campaign_id, tenant_id, business_unit_id),
            correlation_id=str(uuid4()),
            db=db,
        )
    except OdooCampaignAdapterError as exc:
        raise HTTPException(502, str(exc)) from exc
    except _ODOO_DEPENDENCY_ERRORS as exc:
        raise HTTPException(503, "Odoo campaign dependency unavailable") from exc


# Legacy placeholders below answered 202 without recording or executing
# anything (false acknowledgements of business writes and dispatches). They
# are permanently denied by config/legacy-effect-registry.v1.json and stay
# mounted only so former callers receive a 410 naming the successor.
@router.post(
    "/odoo/commands",
    responses=DENIED_RESPONSES,
    dependencies=[Depends(denial_dependency("LE-INTEGRATIONS-ODOO-COMMAND-PLACEHOLDER"))],
)
async def odoo_command() -> None:
    deny("LE-INTEGRATIONS-ODOO-COMMAND-PLACEHOLDER")


@router.get("/odoo/commands/{command_id}")
async def odoo_command_status(command_id: str) -> dict[str, str]:
    return {"command_id": command_id, "status": "not_configured"}


@router.get("/odoo/status")
async def odoo_integration_status(
    _principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
) -> dict[str, Any]:
    return {
        "health": await odoo_health(),
        "readiness": await odoo_readiness(),
        "automation_writes_enabled": settings.odoo_automation_writes_enabled,
    }


# NOTE on "Odoo integration mappings": this codebase already has a real,
# hardened campaign<->Odoo mapping projection at GET /v1/mappings/campaigns
# and /v1/mappings/campaigns/{code} (app/api/v1/mappings.py), backed by the
# reviewed, migration-seeded vicidial_campaign_registry table (odoo_business_
# unit_uuid/odoo_crm_team_uuid/odoo_campaign_uuid columns, plus a
# drift_status/last_read_back_at/observed_state_hash reconciliation-evidence
# trail enforced by a DB CHECK constraint - see migrations/versions/
# 0010_vicidial_registry_guards.py). Building a second, competing
# /odoo/mappings* implementation here would be exactly the duplication this
# session's mission repeatedly warns against. sync-status/sync-errors below
# read that same table rather than re-deriving the concept.
#
# What genuinely doesn't exist anywhere in this codebase: POST /odoo/mappings,
# PATCH/DELETE .../{id}, POST .../{id}/test, or POST /odoo/reconcile - there
# is no mapping-mutation code path at all. vicidial_campaign_registry appears
# to be intentionally reviewed/migration-controlled, not runtime-mutable
# (consistent with this deployment's broader "no direct production database
# edits" posture). Adding real write endpoints here would mean inventing a
# net-new mutation capability with no existing precedent to follow - a
# genuine architecture decision (should campaign<->Odoo mapping become
# runtime-mutable at all, and if so through what review/approval gate?), not
# something to fabricate silently. Left undone, flagged here rather than
# guessed at.


@router.get("/odoo/sync-status")
async def odoo_sync_status(
    business_unit: str = Query(
        ..., min_length=2, max_length=16, pattern=r"^[A-Za-z]+$"
    ),
    environment: Literal["test", "staging", "production"] = "staging",
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    authorized_unit = business_unit.upper()
    require_tenant_match(principal, authorized_unit)
    rows = (
        (
            await db.execute(
                text(
                    "SELECT drift_status, COUNT(*) AS count FROM vicidial_campaign_registry "
                    "WHERE environment=:environment AND business_unit_code=:unit "
                    "GROUP BY drift_status ORDER BY drift_status"
                ),
                {"environment": environment, "unit": authorized_unit},
            )
        )
        .mappings()
        .all()
    )
    by_status = {row["drift_status"]: row["count"] for row in rows}
    return {
        "business_unit": authorized_unit,
        "environment": environment,
        "mapping_count_by_drift_status": by_status,
        "total_mappings": sum(by_status.values()),
    }


@router.get("/odoo/sync-errors")
async def odoo_sync_errors(
    business_unit: str = Query(
        ..., min_length=2, max_length=16, pattern=r"^[A-Za-z]+$"
    ),
    environment: Literal["test", "staging", "production"] = "staging",
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    # "not_observed" is this column's server_default (never yet reconciled),
    # not itself an error - only rows that were checked and found drifted
    # are reported here.
    authorized_unit = business_unit.upper()
    require_tenant_match(principal, authorized_unit)
    rows = (
        (
            await db.execute(
                text(
                    "SELECT canonical_campaign_code, drift_status, last_read_back_at "
                    "FROM vicidial_campaign_registry "
                    "WHERE environment=:environment AND business_unit_code=:unit "
                    "AND drift_status NOT IN ('reconciled', 'not_observed') "
                    "ORDER BY canonical_campaign_code LIMIT :fetch_limit OFFSET :offset"
                ),
                {
                    "environment": environment,
                    "unit": authorized_unit,
                    "fetch_limit": limit + 1,
                    "offset": offset,
                },
            )
        )
        .mappings()
        .all()
    )
    has_more = len(rows) > limit
    page = rows[:limit]
    return {
        "business_unit": authorized_unit,
        "environment": environment,
        "items": [
            {
                "canonical_campaign_code": row["canonical_campaign_code"],
                "drift_status": row["drift_status"],
                "last_read_back_at": (
                    row["last_read_back_at"].isoformat()
                    if row["last_read_back_at"]
                    else None
                ),
            }
            for row in page
        ],
        "pagination": {
            "limit": limit,
            "offset": offset,
            "returned": len(page),
            "has_more": has_more,
        },
    }


@router.post(
    "/n8n/dispatch",
    responses=DENIED_RESPONSES,
    dependencies=[Depends(denial_dependency("LE-INTEGRATIONS-N8N-DISPATCH"))],
)
async def n8n_dispatch() -> None:
    deny("LE-INTEGRATIONS-N8N-DISPATCH")


@router.post("/n8n/results", status_code=202)
async def n8n_result(
    body: dict[str, Any],
    authorization: str = Header(alias="Authorization"),
    idempotency_key: str = Header(
        alias="Idempotency-Key", min_length=8, max_length=180
    ),
    db: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    if "event_id" in body:
        result = AutomationResult.model_validate(body)
        claims = _authenticate_n8n(authorization, "n8n.results.submit")
        return await _accept_standard_result(result, claims, idempotency_key, db)
    CallbackResult.model_validate(body)
    deny("LE-INTEGRATIONS-N8N-UNAUTHENTICATED-CALLBACK")


async def _accept_standard_result(
    result: AutomationResult,
    claims: dict[str, Any],
    idempotency_key: str,
    db: AsyncSession,
) -> dict[str, str]:
    if idempotency_key != result.idempotency_key:
        raise HTTPException(409, "idempotency binding conflict")
    event = await db.scalar(
        select(IntegrationEvent).where(
            IntegrationEvent.original_event_id == result.event_id
        )
    )
    envelope = event.payload_json if event else {}
    if (
        event is None
        or event.correlation_id != result.correlation_id
        or event.idempotency_key != result.idempotency_key
        or envelope.get("event_id") != result.event_id
        or envelope.get("campaign_id")
        not in _scope_values(claims, "campaigns", "campaign_scope")
        or envelope.get("business_unit_id")
        not in _scope_values(claims, "business_units", "business_unit_scope")
    ):
        raise HTTPException(409, "automation result source binding mismatch")
    if result.actions:
        unavailable = sorted(
            {
                action.action_type
                for action in result.actions
                if action.action_type not in ODOO_CAMPAIGN_ACTION_TYPES
            }
        )
        if unavailable:
            raise HTTPException(
                503,
                "automation action adapter is not production enabled: "
                + ",".join(unavailable),
            )
        if not settings.odoo_automation_writes_enabled:
            raise HTTPException(503, "Odoo automation writes are disabled")
    scope = "n8n-standard-result"
    key_hash = canonical_hash({"idempotency_key": result.idempotency_key})
    request_hash = canonical_hash(redact(result.model_dump(mode="json")))
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
        {"scope": f"{scope}:{key_hash}"},
    )
    prior = await db.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.scope == scope,
            IdempotencyRecord.key_hash == key_hash,
        )
    )
    response = {
        "accepted": "true",
        "event_id": result.event_id,
        "status": result.status,
    }
    if prior:
        if prior.request_hash != request_hash:
            await db.rollback()
            raise HTTPException(409, "automation result idempotency conflict")
        await db.commit()
        return response
    db.add(
        IdempotencyRecord(
            scope=scope,
            key_hash=key_hash,
            request_hash=request_hash,
            response=response,
            status_code=202,
            event_id=event.id,
        )
    )
    if result.actions:
        db.add(
            OdooResultDelivery(
                integration_event_id=event.id,
                originating_outbox_public_id=result.event_id,
                request_hash=request_hash,
                status="PENDING",
                standard_result_json=result.model_dump(mode="json"),
            )
        )
    db.add(
        AuditEvent(
            action="n8n.standard_result.accepted",
            subject=result.event_id,
            correlation_id=result.correlation_id,
            decision=result.status,
            redacted_payload={
                "workflow_key": result.workflow_key,
                "execution_id": result.execution_id,
            },
        )
    )
    await db.commit()
    return response


@router.get("/n8n/results/{event_id}")
async def n8n_result_status(
    event_id: str,
    authorization: str = Header(alias="Authorization"),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Delivery state of an accepted standard result, for the submitting n8n identity.

    Returns delivery state only. Missing and out-of-scope records are the same
    404 so the endpoint cannot be used to probe other campaigns' event ids.
    Results without actions create no delivery and therefore read back 404.
    """
    claims = _authenticate_n8n(authorization, "n8n.results.read")
    delivery = await db.scalar(
        select(OdooResultDelivery).where(
            OdooResultDelivery.originating_outbox_public_id == event_id,
            OdooResultDelivery.integration_event_id.is_not(None),
            OdooResultDelivery.standard_result_json.is_not(None),
        )
    )
    event = (
        await db.scalar(
            select(IntegrationEvent).where(
                IntegrationEvent.id == delivery.integration_event_id
            )
        )
        if delivery is not None
        else None
    )
    envelope = event.payload_json if event is not None else {}
    if (
        delivery is None
        or event is None
        or envelope.get("campaign_id")
        not in _scope_values(claims, "campaigns", "campaign_scope")
        or envelope.get("business_unit_id")
        not in _scope_values(claims, "business_units", "business_unit_scope")
    ):
        raise HTTPException(404, "standard result not found")
    return {
        "event_id": event_id,
        "receipt_id": str(delivery.result_public_id),
        "status": delivery.status,
        "attempts": delivery.attempts,
        "delivered_at": (
            delivery.delivered_at.isoformat() if delivery.delivered_at else None
        ),
        "last_error_class": delivery.last_error_class,
    }


@router.post(
    "/n8n/progress",
    responses=DENIED_RESPONSES,
    dependencies=[Depends(denial_dependency("LE-INTEGRATIONS-N8N-PROGRESS"))],
)
async def n8n_progress() -> None:
    deny("LE-INTEGRATIONS-N8N-PROGRESS")


@router.post(
    "/n8n/dead-letter",
    responses=DENIED_RESPONSES,
    dependencies=[Depends(denial_dependency("LE-INTEGRATIONS-N8N-DEAD-LETTER"))],
)
async def n8n_dead_letter() -> None:
    deny("LE-INTEGRATIONS-N8N-DEAD-LETTER")


@router.post(
    "/n8n/errors",
    responses=DENIED_RESPONSES,
    dependencies=[Depends(denial_dependency("LE-INTEGRATIONS-N8N-ERRORS"))],
)
async def n8n_error() -> None:
    deny("LE-INTEGRATIONS-N8N-ERRORS")


@router.post(
    "/n8n/reconciliation",
    responses=DENIED_RESPONSES,
    dependencies=[Depends(denial_dependency("LE-INTEGRATIONS-N8N-RECONCILIATION"))],
)
async def n8n_reconciliation() -> None:
    deny("LE-INTEGRATIONS-N8N-RECONCILIATION")
