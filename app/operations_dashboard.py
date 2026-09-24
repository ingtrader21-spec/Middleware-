from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .runtime_safety import runtime_safety_readback
from .security import RequestValidationError, authorize_tenant


router = APIRouter(
    prefix="/v1/operations-dashboard",
    tags=["operations-dashboard"],
)


async def _authorize_dashboard(request: Request, tenant_id: str | None = None) -> dict[str, Any]:
    claims = await request.app.state.runtime.tokens.verify(
        request.headers.get("Authorization", ""),
        expected_client_id="monitoring-readonly",
        required_scope="health.read",
    )
    if tenant_id is not None:
        authorize_tenant(claims, tenant_id)
    return claims


def _tenant_from_header(request: Request) -> str:
    tenant_id = request.headers.get("X-Tenant-ID", "")
    if not tenant_id:
        raise RequestValidationError("X-Tenant-ID is required")
    return tenant_id


def _checked_at() -> str:
    return datetime.now(UTC).isoformat()


def _communications_service(request: Request):
    return getattr(request.app.state.runtime, "communications", None)


def _message_counts(request: Request, tenant_id: str) -> dict[str, int]:
    service = _communications_service(request)
    if service is None:
        return {}
    counts = Counter(item.status for item in service.list_messages(tenant_id))
    return dict(sorted(counts.items()))


def _command_counts(request: Request, tenant_id: str) -> dict[str, int]:
    commands = getattr(request.app.state.runtime, "commands", None)
    store = getattr(commands, "store", None)
    raw_commands = getattr(store, "_commands", None)
    if not isinstance(raw_commands, dict):
        return {}
    counts: Counter[str] = Counter()
    for key, value in raw_commands.items():
        if not isinstance(key, tuple) or not key or key[0] != tenant_id:
            continue
        operation = value[1] if isinstance(value, tuple) and len(value) > 1 else value
        state = getattr(operation, "state", None)
        if isinstance(state, str):
            counts[state] += 1
    return dict(sorted(counts.items()))


@router.get("/overview")
async def overview(request: Request) -> JSONResponse:
    tenant_id = _tenant_from_header(request)
    await _authorize_dashboard(request, tenant_id)
    readiness = await request.app.state.runtime.readiness()
    safety = runtime_safety_readback(request.app.state.runtime.settings)
    return JSONResponse(
        status_code=200,
        content={
            "schemaVersion": "1.0",
            "checkedAt": _checked_at(),
            "tenantId": tenant_id,
            "environment": safety["environment"],
            "release": safety["release"],
            "readiness": {
                "ready": readiness.ready,
                "components": readiness.components,
            },
            "messages": _message_counts(request, tenant_id),
            "commands": _command_counts(request, tenant_id),
            "externalEffects": safety["external_effects"],
            "productionActivationConfigured": safety["production_activation_configured"],
        },
    )


@router.get("/auth-gateway")
async def auth_gateway(request: Request) -> JSONResponse:
    tenant_id = _tenant_from_header(request)
    await _authorize_dashboard(request, tenant_id)
    settings = request.app.state.runtime.settings
    return JSONResponse(
        status_code=200,
        content={
            "schemaVersion": "1.0",
            "checkedAt": _checked_at(),
            "tenantId": tenant_id,
            "issuer": "https://auth.codestra.co/realms/codestra",
            "gateway": "kong",
            "requiredHeaders": ["Authorization", "X-Tenant-ID", "X-Correlation-ID"],
            "commandPlaneHeaders": ["Authorization", "X-Tenant-ID", "X-Correlation-ID", "Idempotency-Key"],
            "expectedAudience": "middleware-api",
            "runtimeProfileId": settings.runtime_profile_id or "local-unlocked",
        },
    )


@router.get("/routes")
async def routes(request: Request) -> JSONResponse:
    tenant_id = _tenant_from_header(request)
    await _authorize_dashboard(request, tenant_id)
    return JSONResponse(
        status_code=200,
        content={
            "schemaVersion": "1.0",
            "checkedAt": _checked_at(),
            "tenantId": tenant_id,
            "routes": [
                {"method": "POST", "path": "/v1/commands", "scope": "product-specific command scope"},
                {"method": "GET", "path": "/v1/operations/{command_id}", "scope": "product-specific status scope"},
                {"method": "POST", "path": "/v1/communications/messages", "scope": "klyrow.middleware.command.write"},
                {"method": "GET", "path": "/v1/communications/messages", "scope": "klyrow.middleware.status.read"},
                {"method": "GET", "path": "/v1/communications/provider-health", "scope": "klyrow.middleware.status.read"},
                {"method": "GET", "path": "/v1/runtime/safety", "scope": "health.read"},
                {"method": "GET", "path": "/metrics", "scope": "metrics.read"},
            ],
        },
    )


@router.get("/providers")
async def providers(request: Request) -> JSONResponse:
    tenant_id = _tenant_from_header(request)
    await _authorize_dashboard(request, tenant_id)
    service = _communications_service(request)
    email_health = (
        await service.adapter.health(tenant_id)
        if service is not None
        else {"status": "disabled", "providers": []}
    )
    return JSONResponse(
        status_code=200,
        content={
            "schemaVersion": "1.0",
            "checkedAt": _checked_at(),
            "tenantId": tenant_id,
            "providers": email_health.get("providers", []),
            "summaryStatus": email_health.get("status", "disabled"),
        },
    )


@router.get("/messages/lifecycle")
async def message_lifecycle(request: Request) -> JSONResponse:
    tenant_id = _tenant_from_header(request)
    await _authorize_dashboard(request, tenant_id)
    return JSONResponse(
        status_code=200,
        content={
            "schemaVersion": "1.0",
            "checkedAt": _checked_at(),
            "tenantId": tenant_id,
            "counts": _message_counts(request, tenant_id),
        },
    )


@router.get("/webhooks")
async def webhooks(request: Request) -> JSONResponse:
    tenant_id = _tenant_from_header(request)
    await _authorize_dashboard(request, tenant_id)
    return JSONResponse(
        status_code=200,
        content={
            "schemaVersion": "1.0",
            "checkedAt": _checked_at(),
            "tenantId": tenant_id,
            "delivery": {
                "available": False,
                "reason": "webhook delivery telemetry API is not yet connected to durable storage",
            },
        },
    )


@router.get("/tenants/{tenant_id}")
async def tenant_activity(tenant_id: str, request: Request) -> JSONResponse:
    await _authorize_dashboard(request, tenant_id)
    return JSONResponse(
        status_code=200,
        content={
            "schemaVersion": "1.0",
            "checkedAt": _checked_at(),
            "tenantId": tenant_id,
            "messages": _message_counts(request, tenant_id),
            "commands": _command_counts(request, tenant_id),
        },
    )


@router.get("/queues")
async def queues(request: Request) -> JSONResponse:
    tenant_id = _tenant_from_header(request)
    await _authorize_dashboard(request, tenant_id)
    return JSONResponse(
        status_code=200,
        content={
            "schemaVersion": "1.0",
            "checkedAt": _checked_at(),
            "tenantId": tenant_id,
            "commands": _command_counts(request, tenant_id),
            "messageLifecycle": _message_counts(request, tenant_id),
        },
    )


@router.get("/release-gates")
async def release_gates(request: Request) -> JSONResponse:
    tenant_id = _tenant_from_header(request)
    await _authorize_dashboard(request, tenant_id)
    safety = runtime_safety_readback(request.app.state.runtime.settings)
    gates = {
        "stagingSafe": safety["staging_safe"],
        "allExternalEffectsDisabled": safety["all_external_effects_disabled"],
        "providerEffectsDisabled": safety["provider_effects_disabled"],
        "productionActivationConfigured": safety["production_activation_configured"],
        "productionDialing": safety["production_dialing"],
    }
    request.app.state.observability.record_operations_dashboard_release_gates(gates)
    return JSONResponse(
        status_code=200,
        content={
            "schemaVersion": "1.0",
            "checkedAt": _checked_at(),
            "tenantId": tenant_id,
            "gates": gates,
        },
    )


@router.get("/canaries")
async def canaries(request: Request) -> JSONResponse:
    tenant_id = _tenant_from_header(request)
    await _authorize_dashboard(request, tenant_id)
    canaries = [
        {"id": "klyrow-email", "channel": "email", "status": "pending_staging_evidence"},
        {"id": "telnexa-sms", "channel": "sms", "status": "pending_staging_evidence"},
        {"id": "vicidial-voice", "channel": "voice", "status": "pending_staging_evidence"},
        {"id": "postly-social", "channel": "social", "status": "pending_staging_evidence"},
    ]
    request.app.state.observability.record_operations_dashboard_canaries(canaries)
    return JSONResponse(
        status_code=200,
        content={
            "schemaVersion": "1.0",
            "checkedAt": _checked_at(),
            "tenantId": tenant_id,
            "canaries": canaries,
        },
    )
