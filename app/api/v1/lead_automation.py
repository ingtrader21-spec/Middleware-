from fastapi import APIRouter, Header, HTTPException, Request

from app.core.config import settings
from app.core.lead_automation import (
    Conflict,
    LeadAutomationError,
    LeadAutomationService,
    TenantScope,
)
from app.core.lead_callback_auth import CallbackAuthenticationError, verify_callback

router = APIRouter(tags=["lead-automation"])
service = LeadAutomationService()
service.enabled = settings.lead_automation_enabled
service.binding_enabled = settings.n8n_lead_binding_enabled
service.result_processing_enabled = settings.n8n_result_processing_enabled
service.odoo_apply_enabled = settings.odoo_lead_apply_enabled
service.action_switches.update(
    {
        "CREATE_LEAD": settings.lead_create_enabled,
        "UPDATE_ALLOWLISTED_FIELDS": settings.lead_update_enabled,
        "ASSIGN_AUTHORIZED_TEAM": settings.lead_assignment_enabled,
        "ASSIGN_AUTHORIZED_USER": settings.lead_assignment_enabled,
        "CHANGE_AUTHORIZED_STAGE": settings.lead_status_change_enabled,
        "CREATE_INTERNAL_CALLBACK_ACTIVITY": settings.lead_callback_create_enabled,
    }
)
used_callback_nonces: set[tuple[str, str, str, str]] = set()
CALLBACK_AUTH_HEADERS = (
    "X-Codestra-Signature-Version",
    "X-Service-Identity",
    "X-Service-Audience",
    "X-Codestra-Timestamp",
    "X-Codestra-Nonce",
    "X-Codestra-Content-SHA256",
    "X-Codestra-Signature",
    "Idempotency-Key",
    "X-Codestra-Environment",
    "X-Codestra-Scope",
)


def _unique_callback_headers(request: Request) -> dict[str, str]:
    raw_names = [name.lower() for name, _ in request.scope.get("headers", [])]
    for name in CALLBACK_AUTH_HEADERS:
        if raw_names.count(name.lower().encode("ascii")) != 1:
            raise CallbackAuthenticationError(
                "missing or duplicate callback authentication header"
            )
    return {name: request.headers.get(name, "") for name in CALLBACK_AUTH_HEADERS}


def receive_odoo_event(
    body: dict, idempotency_key: str = Header("", alias="Idempotency-Key")
):
    """Unauthenticated Odoo event receiver; deliberately not routed.

    Its former ``POST /api/v1/events/odoo`` registration was shadowed by the
    control-plane alias on every application and never served. It stays
    importable for callers of the service layer; the HTTP path is owned by the
    signed ingress routes.
    """
    if body.get("idempotency_key") != idempotency_key:
        raise HTTPException(409, "idempotency binding mismatch")
    try:
        return service.receive(body)
    except Conflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except LeadAutomationError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post("/api/v1/lead-automation/results")
async def receive_result(request: Request):
    raw = await request.body()
    body = await request.json()
    try:
        verify_callback(
            method=request.method,
            path=request.scope.get("raw_path", b"").decode("ascii", errors="strict"),
            query_string=request.scope.get("query_string", b""),
            body=raw,
            headers=_unique_callback_headers(request),
            secret=settings.lead_automation_hmac_secret.encode(),
            environment=body.get("environment", ""),
            used_nonces=used_callback_nonces,
        )
    except CallbackAuthenticationError as exc:
        raise HTTPException(401, str(exc)) from exc
    try:
        return service.receive_result(body, TenantScope.from_payload(body))
    except Conflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except LeadAutomationError as exc:
        raise HTTPException(403, str(exc)) from exc


@router.get("/api/v1/lead-automation/events/{automation_event_id}")
def status(
    automation_event_id: str,
    environment: str = Header(alias="X-Codestra-Environment"),
    business_unit_key: str = Header(alias="X-Codestra-Business-Unit"),
    campaign_key: str = Header(alias="X-Codestra-Campaign"),
):
    try:
        scope = TenantScope(environment, business_unit_key, campaign_key)
        return service.status(service._find(automation_event_id, scope))
    except LeadAutomationError as exc:
        raise HTTPException(404, str(exc)) from exc
