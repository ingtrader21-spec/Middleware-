"""Service identity advertised to the recording exporter.

Formerly an inline route of the monolith module; mounted with the
monolith-only group by ``app.router_registry``.
"""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["recordings"])


@router.get("/.well-known/codestra-service")
async def service_identity() -> dict[str, object]:
    return {
        "service": "codestra-recording-api",
        "contract_version": "1.0",
        "hostname": "api.staging.internal.codestra.agency",
        "tls_sni_required": True,
    }
