"""Canonical lead readback. No commands, provider calls, or activation authority."""

from uuid import uuid4

import asyncpg
from fastapi import APIRouter, Depends, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from jsonschema import ValidationError

from app.api_inputs import required_header
from app.core.campaign_recycling import (
    CampaignRecyclingConflict,
    PostgresCampaignRecyclingStore,
)
from app.core.journey_contract import (
    document,
    journey_response,
    resolve,
    schema,
    validator,
)
from app.core.journey_readback import ReadbackUnavailable, UnavailableNextActionAuthority
from app.platform.principal import authenticate
from app.security import AuthorizationError, RequestValidationError, SecurityError

router = APIRouter(prefix="/platform/v1/leads", tags=["leads"])
CONTRACT = "campaign-engine.openapi.yaml"
ERROR_SCHEMA = resolve(
    document(CONTRACT)["components"]["schemas"]["ErrorEnvelope"], CONTRACT
)
ERRORS = {
    status: {
        "description": description,
        "content": {"application/json": {"schema": ERROR_SCHEMA}},
    }
    for status, description in [
        (400, "Invalid request"),
        (401, "Authentication required"),
        (403, "Scope or tenant denied"),
        (404, "Lead not found"),
        (503, "Required authority unavailable"),
    ]
}


async def get_store(request: Request):
    pool = getattr(getattr(request.app.state, "runtime", None), "pool", None)
    return PostgresCampaignRecyclingStore(pool) if pool is not None else None


def operation(name: str):
    path = "/platform/v1/leads/{lead_id}/" + name
    spec = resolve(document(CONTRACT)["paths"][path]["get"], CONTRACT)
    spec["parameters"] = [
        item for item in spec["parameters"] if item["name"] != "lead_id"
    ]
    # Authentication uses the shared verified principal, including the registered azp.
    return {
        **{key: spec[key] for key in ["parameters", "security"]},
        "x-codestra-effects": "none",
    }


def failure(status, code, message, cid):
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "code": code,
                "message": message,
                "correlation_id": cid,
                "retryable": status == 503,
                "details": {},
            }
        },
        headers={
            "X-Correlation-ID": cid,
            "Cache-Control": "no-store",
            **({"WWW-Authenticate": "Bearer"} if status == 401 else {}),
        },
    )


async def read(request, lead_id, store, *, next_action=False):
    cid = str(uuid4())
    try:
        cid = required_header(request, "X-Correlation-ID", minimum=1, maximum=180)
        tenant_id = required_header(request, "X-Tenant-ID", minimum=1, maximum=128)
        scope = "campaign.engine.read" if next_action else "leads.journey.read"
        principal = await authenticate(request, required_scope=scope)
        if not principal.authorized_for(tenant_id) or scope not in principal.scopes:
            raise AuthorizationError("scope or tenant denied")
        lead_schema = resolve(
            document("lifecycle.v1.schema.json")["$defs"]["LeadId"],
            "lifecycle.v1.schema.json",
        )
        from jsonschema import Draft202012Validator

        if not Draft202012Validator(lead_schema).is_valid(lead_id):
            raise RequestValidationError("invalid lead identifier")
        allowed = {"channel"} if next_action else {"limit", "cursor"}
        for key in request.query_params:
            if key not in allowed or len(request.query_params.getlist(key)) != 1:
                raise RequestValidationError("unknown or repeated query parameter")
        if next_action:
            channel = request.query_params.get("channel")
            if (
                channel is not None
                and channel
                not in document("channel-health.v1.schema.json")["$defs"]["Channel"][
                    "enum"
                ]
            ):
                raise RequestValidationError("invalid channel")
            # Explicit unavailable adapter: no synthetic catalog or partial journey
            # page may become decision input. Integration remains dependency-blocked.
            await UnavailableNextActionAuthority().load(
                tenant_id=tenant_id, lead_id=lead_id, channel=channel
            )
        raw_limit = request.query_params.get("limit", "100")
        if (
            not raw_limit.isascii()
            or not raw_limit.isdecimal()
            or len(raw_limit) > 3
            or not 1 <= int(raw_limit) <= 200
        ):
            raise RequestValidationError("limit must be between 1 and 200")
        if store is None:
            return failure(
                503,
                "dependency_unavailable",
                "Durable lead storage is unavailable",
                cid,
            )
        page = await store.journey(
            tenant_id=tenant_id,
            lead_id=lead_id,
            limit=int(raw_limit),
            cursor=request.query_params.get("cursor"),
        )
        if page["current"] is None:
            return failure(404, "not_found", "Lead lifecycle not found", cid)
        payload = jsonable_encoder(journey_response(page, tenant_id, lead_id))
        validator("journey-response.v1.schema.json").validate(payload)
        return JSONResponse(
            payload, headers={"X-Correlation-ID": cid, "Cache-Control": "no-store"}
        )
    except SecurityError as exc:
        return failure(exc.status_code, exc.code, str(exc), cid)
    except ReadbackUnavailable as exc:
        return failure(503, "dependency_unavailable", str(exc), cid)
    except CampaignRecyclingConflict:
        return failure(400, "invalid_cursor", "Invalid journey cursor", cid)
    except (
        asyncpg.PostgresError,
        asyncpg.InterfaceError,
        OSError,
        TimeoutError,
        ValidationError,
    ):
        return failure(
            503,
            "dependency_unavailable",
            "Durable lead readback is unavailable or inconsistent",
            cid,
        )


@router.get(
    "/{lead_id}/journey",
    operation_id="lead_journey_read",
    responses={
        **ERRORS,
        200: {
            "description": "Journey page",
            "content": {
                "application/json": {
                    "schema": schema("journey-response.v1.schema.json")
                }
            },
        },
    },
    openapi_extra=operation("journey"),
)
async def journey(request: Request, lead_id: str, store=Depends(get_store)):
    return await read(request, lead_id, store)


@router.get(
    "/{lead_id}/next-action",
    operation_id="lead_next_action_read",
    responses={
        **ERRORS,
        200: {
            "description": "Read-mode decision when authority is available",
            "content": {
                "application/json": {"schema": schema("next-action.v1.schema.json")}
            },
        },
    },
    openapi_extra={
        **operation("next-action"),
        "x-codestra-dry-run": "always",
        "x-runtime-blocked-by": "authoritative candidate catalog and address selection",
    },
)
async def next_action(request: Request, lead_id: str, store=Depends(get_store)):
    return await read(request, lead_id, store, next_action=True)


def install_leads_openapi(app):
    original = app.openapi

    def openapi():
        result = original()
        result.setdefault("components", {}).setdefault("securitySchemes", {})["codestraOAuth"] = document(CONTRACT)["components"]["securitySchemes"]["codestraOAuth"]
        for name in ("journey", "next-action"):
            operation = result["paths"]["/platform/v1/leads/{lead_id}/" + name]["get"]
            for parameter in operation["parameters"]:
                if parameter["name"] == "lead_id":
                    parameter["schema"] = resolve(document("lifecycle.v1.schema.json")["$defs"]["LeadId"], "lifecycle.v1.schema.json")
            operation["responses"].pop("422", None)
            for response in operation["responses"].values():
                response.setdefault("headers", {})["X-Correlation-ID"] = document(CONTRACT)["components"]["headers"]["CorrelationId"]
        return result

    app.openapi = openapi
