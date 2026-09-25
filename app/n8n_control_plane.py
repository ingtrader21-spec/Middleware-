from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from .api_inputs import authorization_header, required_header
from .legacy_effects import DENIED_RESPONSES, denial_dependency, deny
from .security import authorize_tenant
from .storage import StorageError

# Deprecated v1 aliases only. Their successor, /v2/automation/*, is mounted by
# app.router_registry in every application factory, never nested here. The
# submission alias is permanently denied (config/legacy-effect-registry.v1.json);
# the status read is the one justified read-only compatibility path.
router = APIRouter(tags=["n8n-control-plane"])

_LEGACY_SUNSET = "Wed, 30 Jun 2027 23:59:59 GMT"
_LEGACY_WARNING = (
    '299 - "Deprecated n8n v1 compatibility route; migrate to /v2/automation"'
)


def _legacy_headers(*, successor: str) -> dict[str, str]:
    return {
        "Deprecation": "true",
        "Sunset": _LEGACY_SUNSET,
        "Warning": _LEGACY_WARNING,
        "Link": successor,
    }


@router.post(
    "/v1/integrations/n8n/commands",
    deprecated=True,
    responses=DENIED_RESPONSES,
    dependencies=[Depends(denial_dependency("LE-N8N-V1-COMMAND-SUBMIT"))],
)
async def submit_n8n_command() -> None:
    """Permanently denied legacy n8n v1 submission (``LE-N8N-V1-COMMAND-SUBMIT``).

    The route stays mounted on the monolith only so former callers receive a
    410 naming the successor; the denial dependency answers before any body
    validation, token verification or command-ledger access. The canonical
    submission authority is the lease-bound ``POST /v2/automation/commands``.
    """
    deny("LE-N8N-V1-COMMAND-SUBMIT")


@router.get("/v1/integrations/n8n/operations/{command_id}", deprecated=True)
async def get_n8n_operation(command_id: UUID, request: Request) -> JSONResponse:
    """Return durable command state through the legacy n8n v1 compatibility route."""
    active = request.app.state.runtime
    claims = await active.tokens.verify(
        authorization_header(request),
        expected_client_id="n8n-automation",
        required_scope="middleware.status.read",
    )
    tenant_id = required_header(request, "X-Tenant-ID", minimum=1, maximum=128)
    authorize_tenant(claims, tenant_id)
    if active.commands is None:
        raise StorageError("command ledger is unavailable")
    operation = await active.commands.get(tenant_id, command_id)
    return JSONResponse(
        status_code=200,
        content=operation.model_dump(mode="json"),
        headers={
            "X-Correlation-ID": operation.correlation_id,
            **_legacy_headers(
                successor=f'</v2/automation/commands/{command_id}>; rel="successor-version"'
            ),
        },
    )
