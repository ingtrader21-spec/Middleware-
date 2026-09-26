"""Section 6 Agent Provisioning lifecycle routes.

This module owns extension, WebRTC, readback and repair-intent lifecycle
surfaces while delegating the canonical provisioning saga/state machine to
app.api.v1.agent_provisioning. It intentionally defines no second saga.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.vicidial.mtls_client import VicidialMtlsClient
from app.api.v1.agent_provisioning import (
    TransitionRequest,
    _add_step,
    _get_request,
    _now,
    _set_provisioning_rls_context,
    _steps_for,
    _transition,
)
from app.core.config import settings
from app.core.provisioning_auth import (
    ProvisioningPrincipal,
    require_provisioning_scope,
    require_tenant_match,
)
from app.db.models import (
    AgentProvisioningRepairIntent,
    AgentProvisioningRequest,
    AgentWebrtcSession,
    TelephonyExtensionReservation,
)
from app.db.session import get_session

router = APIRouter(
    prefix="/platform/v1/agent-provisioning",
    tags=["agent-provisioning-lifecycle"],
)


class ExtensionReserveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=64)
    employee_id: str = Field(min_length=1, max_length=128)
    campaign_id: str = Field(min_length=1, max_length=64)
    extension_pool: str = Field(min_length=1, max_length=32)
    evidence_by_extension: dict[int, dict[str, str]]


class ExtensionAdoptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=64)
    provisioning_request_id: UUID
    employee_id: str = Field(min_length=1, max_length=128)
    campaign_id: str = Field(min_length=1, max_length=64)
    extension: str = Field(pattern=r"^[0-9]{3,6}$")


class RepairIntentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=64)
    drift_class: Literal["REMOTE_UNKNOWN", "REPAIR_REQUIRED"]
    proposed_action: str = Field(min_length=1, max_length=128)


@router.get("/requests/{request_id}/history")
async def provisioning_history(
    request_id: UUID,
    tenant_id: str | None = None,
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
):
    await _set_provisioning_rls_context(session, principal, tenant_id)
    request = await _get_request(request_id, session)
    require_tenant_match(principal, request.tenant_id)
    steps = await _steps_for(session, request)
    return {
        "request_id": str(request.id),
        "items": [
            {
                "system": step.system,
                "operation": step.operation,
                "attempt": step.attempt,
                "state": step.state,
                "provider_reference": step.external_reference,
                "readback_state": step.readback_state,
                "error_code": step.error_code,
                "started_at": step.started_at,
                "completed_at": step.completed_at,
            }
            for step in steps
        ],
    }


@router.post("/{request_id}/sync")
async def sync_agent(
    request_id: UUID,
    body: TransitionRequest,
    tenant_id: str | None = None,
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
):
    return await _transition(request_id, body, tenant_id, "reconcile", principal, session)


@router.post("/{request_id}/disable")
async def disable_agent(
    request_id: UUID,
    body: TransitionRequest,
    tenant_id: str | None = None,
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
):
    return await _transition(request_id, body, tenant_id, "revoke", principal, session)


@router.get("/{request_id}/readback")
async def provisioning_readback(
    request_id: UUID,
    tenant_id: str | None = None,
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
):
    await _set_provisioning_rls_context(session, principal, tenant_id)
    request = await _get_request(request_id, session)
    steps = await _steps_for(session, request)

    latest: dict[str, dict[str, Any]] = {}
    for step in steps:
        latest[step.system] = {
            "operation": step.operation,
            "state": step.state,
            "provider_reference": step.external_reference,
            "readback_state": step.readback_state,
            "observed_at": step.completed_at,
        }

    failed = [step for step in steps if step.state in {"failed", "blocked"}]
    if not failed and request.state == "EFFECTIVE":
        drift_class = "CONSISTENT"
    elif any(step.readback_state in {None, "unknown"} for step in failed):
        drift_class = "REMOTE_UNKNOWN"
    else:
        drift_class = "REPAIR_REQUIRED"

    existing = (
        await session.execute(
            select(AgentProvisioningRepairIntent)
            .where(
                AgentProvisioningRepairIntent.tenant_id == request.tenant_id,
                AgentProvisioningRepairIntent.request_id == request.id,
            )
            .order_by(AgentProvisioningRepairIntent.created_at.desc())
        )
    ).scalars().all()
    repairs = [
        {
            "id": str(intent.id),
            "drift_class": intent.drift_class,
            "proposed_action": intent.proposed_action,
            "state": intent.state,
            "effect_class": intent.effect_class,
        }
        for intent in existing
    ]

    return {
        "request_id": str(request.id),
        "tenant_id": request.tenant_id,
        "state": request.state,
        "drift_class": drift_class,
        "providers": latest,
        "repair_intents": repairs,
        "correlation_id": request.correlation_id,
        "updated_at": request.updated_at,
    }


@router.post("/{request_id}/repair-intents", status_code=201)
async def create_repair_intent(
    request_id: UUID,
    body: RepairIntentRequest,
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("integration.configure")
    ),
    session: AsyncSession = Depends(get_session),
):
    await _set_provisioning_rls_context(session, principal, body.tenant_id)
    request = await _get_request(request_id, session, for_update=True)

    existing = (
        await session.execute(
            select(AgentProvisioningRepairIntent).where(
                AgentProvisioningRepairIntent.tenant_id == request.tenant_id,
                AgentProvisioningRepairIntent.request_id == request.id,
                AgentProvisioningRepairIntent.state == "PROPOSED",
                AgentProvisioningRepairIntent.proposed_action == body.proposed_action,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return {
            "id": str(existing.id),
            "request_id": str(request.id),
            "state": existing.state,
            "replayed": True,
        }

    intent = AgentProvisioningRepairIntent(
        id=uuid4(),
        tenant_id=request.tenant_id,
        request_id=request.id,
        drift_class=body.drift_class,
        proposed_action=body.proposed_action,
        state="PROPOSED",
    )
    session.add(intent)
    await session.commit()
    return {
        "id": str(intent.id),
        "request_id": str(request.id),
        "state": intent.state,
        "replayed": False,
    }


@router.post("/reserve-extension")
async def reserve_agent_extension(
    body: ExtensionReserveRequest,
    idempotency_key: str = Header(
        ..., alias="Idempotency-Key", min_length=16, max_length=256
    ),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("integration.configure")
    ),
    session: AsyncSession = Depends(get_session),
):
    require_tenant_match(principal, body.tenant_id)
    await _set_provisioning_rls_context(session, principal, body.tenant_id)

    # Canonical telephony allocator remains the authority; provisioning only delegates.
    from app.api.v1.telephony import ReserveRequest, reserve

    if not body.evidence_by_extension:
        raise HTTPException(422, "authoritative extension evidence is required")

    payload = ReserveRequest(
        employee_id=body.employee_id,
        request_id=f"agent:{body.employee_id}:{body.campaign_id}",
        business_unit=body.campaign_id,
        role_class=body.extension_pool,
        idempotency_key=idempotency_key,
        evidence_by_extension=body.evidence_by_extension,
    )
    return await reserve(payload, session)


class WebRtcTicketRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provisioning_request_id: UUID
    tenant_id: str = Field(min_length=1, max_length=64)
    campaign_id: str = Field(min_length=1, max_length=64)
    extension: str = Field(pattern=r"^[0-9]{3,6}$")


@router.post("/adopt-extension")
async def adopt_agent_extension(
    body: ExtensionAdoptRequest,
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("integration.configure")
    ),
    session: AsyncSession = Depends(get_session),
):
    await _set_provisioning_rls_context(session, principal, body.tenant_id)
    row = (
        await session.execute(
            select(AgentProvisioningRequest)
            .where(
                AgentProvisioningRequest.id == body.provisioning_request_id,
                AgentProvisioningRequest.tenant_id == body.tenant_id,
                AgentProvisioningRequest.employee_id == body.employee_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "provisioning request not found")

    campaign = next(
        (
            item
            for item in row.campaigns_json
            if item.get("campaign_id") == body.campaign_id
        ),
        None,
    )
    if campaign is None:
        raise HTTPException(403, "CAMPAIGN_INVALID")

    reservation_key = f"agent:{body.employee_id}:{body.campaign_id}"
    reservation = (
        await session.execute(
            select(TelephonyExtensionReservation)
            .where(
                TelephonyExtensionReservation.employee_id == body.employee_id,
                TelephonyExtensionReservation.request_id == reservation_key,
                TelephonyExtensionReservation.extension == int(body.extension),
                TelephonyExtensionReservation.state == "RESERVED",
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if reservation is None:
        raise HTTPException(409, "EXTENSION_RESERVATION_MISMATCH")

    if not (settings.vicidial_write_enabled and settings.live_writes_enabled):
        raise HTTPException(403, "EFFECT_DISABLED")

    user_id = campaign.get("vicidial_user_id")
    supervisor = campaign.get("vicidial_supervisor_subject")
    if not user_id or not supervisor:
        raise HTTPException(409, "VICIDIAL_PROVISIONING_FAILED")

    result = VicidialMtlsClient(settings).adopt_extension(
        {
            "context": {
                "tenant_id": row.tenant_id,
                "business_unit": body.campaign_id,
                "supervisor_subject": supervisor,
            },
            "reservation": {
                "user_id": user_id,
                "extension": body.extension,
                "webrtc_enabled": bool(row.channels_json.get("webrtc")),
            },
        },
        correlation_id=row.correlation_id,
        request_id=row.request_id,
    )
    reservation.state = "DISABLED_READY"
    await _add_step(
        session,
        row,
        system="vicidial",
        operation="adopt_extension",
        state="succeeded",
        external_reference=str(body.extension),
        readback_state="adopted",
    )
    await session.commit()
    return {
        "request_id": str(row.id),
        "extension": body.extension,
        "state": "ADOPTED",
        "provider_reference": (
            result.get("operation_id") if isinstance(result, dict) else None
        ),
    }


@router.post("/{request_id}/release-extension")
async def release_agent_extension(
    request_id: UUID,
    body: TransitionRequest,
    campaign_id: str,
    tenant_id: str | None = None,
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("integration.configure")
    ),
    session: AsyncSession = Depends(get_session),
):
    await _set_provisioning_rls_context(session, principal, tenant_id)
    request = await _get_request(request_id, session, for_update=True)
    require_tenant_match(principal, request.tenant_id)

    active_session = (
        await session.execute(
            select(AgentWebrtcSession).where(
                AgentWebrtcSession.request_id == request.id,
                AgentWebrtcSession.state.in_(("ISSUED", "REGISTERING", "REGISTERED")),
            )
        )
    ).scalar_one_or_none()
    if active_session:
        raise HTTPException(409, "EXTENSION_CONFLICT: active WebRTC session")
    if campaign_id not in {
        item.get("campaign_id") for item in request.campaigns_json
    }:
        raise HTTPException(403, "CAMPAIGN_INVALID")

    reservation = (
        await session.execute(
            select(TelephonyExtensionReservation)
            .where(
                TelephonyExtensionReservation.employee_id == request.employee_id,
                TelephonyExtensionReservation.request_id
                == f"agent:{request.employee_id}:{campaign_id}",
                TelephonyExtensionReservation.state.in_(
                    ("RESERVED", "DISABLED_READY", "SUSPENDED")
                ),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if reservation is None:
        return {"request_id": str(request.id), "state": "RELEASED", "replayed": True}

    reservation.state = "RELEASED"
    reservation.released_at = _now()
    await _add_step(
        session,
        request,
        system="vicidial",
        operation="release_extension",
        state="succeeded",
        external_reference=str(reservation.extension),
        readback_state="released",
    )
    await session.commit()
    return {
        "request_id": str(request.id),
        "extension": reservation.extension,
        "state": "RELEASED",
        "replayed": False,
    }


@router.post("/webrtc/tickets", status_code=201)
async def issue_webrtc_ticket(
    body: WebRtcTicketRequest,
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("integration.configure")
    ),
    session: AsyncSession = Depends(get_session),
):
    await _set_provisioning_rls_context(session, principal, body.tenant_id)
    request = await _get_request(body.provisioning_request_id, session, for_update=True)
    require_tenant_match(principal, request.tenant_id)

    if request.state not in {"EFFECTIVE", "PARTIAL"}:
        raise HTTPException(409, "WEBRTC_PROVISIONING_FAILED: agent is not enabled")

    campaigns = {campaign.get("campaign_id") for campaign in request.campaigns_json}
    if body.campaign_id not in campaigns:
        raise HTTPException(403, "CAMPAIGN_INVALID")

    existing = (
        await session.execute(
            select(AgentWebrtcSession).where(
                AgentWebrtcSession.tenant_id == request.tenant_id,
                AgentWebrtcSession.employee_id == request.employee_id,
                AgentWebrtcSession.state.in_(("ISSUED", "REGISTERING", "REGISTERED")),
            )
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "WEBRTC_SESSION_ALREADY_ACTIVE")
    reservation = (
        await session.execute(
            select(TelephonyExtensionReservation)
            .where(
                TelephonyExtensionReservation.employee_id == request.employee_id,
                TelephonyExtensionReservation.request_id
                == f"agent:{request.employee_id}:{body.campaign_id}",
                TelephonyExtensionReservation.extension == int(body.extension),
                TelephonyExtensionReservation.state.in_(("DISABLED_READY", "ACTIVE")),
            )
        )
    ).scalar_one_or_none()
    if reservation is None:
        raise HTTPException(409, "EXTENSION_RESERVATION_MISMATCH")

    if not (settings.vicidial_write_enabled and settings.live_writes_enabled):
        raise HTTPException(403, "EFFECT_DISABLED")

    campaign = next(
        campaign
        for campaign in request.campaigns_json
        if campaign.get("campaign_id") == body.campaign_id
    )
    user_id = campaign.get("vicidial_user_id")
    supervisor = campaign.get("vicidial_supervisor_subject")
    if not user_id or not supervisor:
        raise HTTPException(409, "VICIDIAL_PROVISIONING_FAILED")

    result = VicidialMtlsClient(settings).provision_webrtc(
        {
            "context": {
                "tenant_id": request.tenant_id,
                "business_unit": body.campaign_id,
                "supervisor_subject": supervisor,
            },
            "webrtc": {"user_id": user_id},
        },
        correlation_id=request.correlation_id,
        request_id=request.request_id,
    )
    ref = (
        str(result.get("operation_id") or result.get("session_id") or uuid4())
        if isinstance(result, dict)
        else str(uuid4())
    )
    row = AgentWebrtcSession(
        id=uuid4(),
        request_id=request.id,
        tenant_id=request.tenant_id,
        employee_id=request.employee_id,
        campaign_id=body.campaign_id,
        extension=body.extension,
        provider_reference=ref,
        state="ISSUED",
        expires_at=_now() + timedelta(minutes=5),
        correlation_id=request.correlation_id,
    )
    session.add(row)
    await _add_step(
        session,
        request,
        system="vicidial",
        operation="issue_webrtc_ticket",
        state="succeeded",
        external_reference=ref,
        readback_state="issued",
    )
    await session.commit()

    # Never persist or replay credential material; return one-time ticket fields only.
    return {
        "session_id": str(row.id),
        "provider_reference": ref,
        "expires_at": row.expires_at,
        "ticket": result.get("ticket") if isinstance(result, dict) else None,
    }


@router.post("/{request_id}/webrtc/revoke")
async def revoke_webrtc_session(
    request_id: UUID,
    body: TransitionRequest,
    tenant_id: str | None = None,
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("integration.configure")
    ),
    session: AsyncSession = Depends(get_session),
):
    await _set_provisioning_rls_context(session, principal, tenant_id)
    request = await _get_request(request_id, session, for_update=True)
    require_tenant_match(principal, request.tenant_id)

    rows = list(
        (
            await session.execute(
                select(AgentWebrtcSession)
                .where(
                    AgentWebrtcSession.request_id == request.id,
                    AgentWebrtcSession.state.in_(
                        ("ISSUED", "REGISTERING", "REGISTERED")
                    ),
                )
                .with_for_update()
            )
        ).scalars().all()
    )
    if not rows:
        return {"request_id": str(request.id), "state": "REVOKED", "replayed": True}

    if settings.vicidial_write_enabled and settings.live_writes_enabled:
        campaign_id = rows[0].campaign_id
        campaign = next(
            (
                item
                for item in request.campaigns_json
                if item.get("campaign_id") == campaign_id
            ),
            None,
        )
        if campaign is None:
            raise HTTPException(409, "CAMPAIGN_INVALID")
        user_id = campaign.get("vicidial_user_id")
        supervisor = campaign.get("vicidial_supervisor_subject")
        if user_id and supervisor:
            VicidialMtlsClient(settings).revoke_webrtc(
                {
                    "context": {
                        "tenant_id": request.tenant_id,
                        "business_unit": campaign.get("campaign_id"),
                        "supervisor_subject": supervisor,
                    },
                    "user_id": user_id,
                },
                correlation_id=request.correlation_id,
                request_id=request.request_id,
            )

    for row in rows:
        row.state = "REVOKED"
        row.revoked_at = _now()

    await _add_step(
        session,
        request,
        system="vicidial",
        operation="revoke_webrtc",
        state="succeeded",
        readback_state="revoked",
    )
    await session.commit()
    return {"request_id": str(request.id), "state": "REVOKED", "replayed": False}
