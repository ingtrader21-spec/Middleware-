"""Short-lived nonce-bound n8n target identity evidence."""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException
import httpx

from app.core.automation import canonical_hash
from app.core.config import settings
from app.core.providers import get_http_client

router = APIRouter(tags=["n8n-target-attestation"])


@router.get("/internal/n8n-target-attestation")
async def n8n_target_attestation(
    nonce: Annotated[str, Header(alias="X-Codestra-Attestation-Nonce")],
    client: httpx.AsyncClient = Depends(get_http_client),
) -> dict[str, str]:
    if not nonce or len(nonce) > 128:
        raise HTTPException(400, "invalid attestation nonce")
    required = {
        "instance_id": settings.n8n_production_instance_id,
        "image_digest": settings.n8n_production_image_digest,
        "n8n_version": settings.n8n_production_version,
        "workflow_package_sha256": settings.n8n_workflow_package_sha256,
    }
    if not all(required.values()):
        raise HTTPException(503, "n8n target evidence is incomplete")
    try:
        health = await client.get(settings.n8n_runtime_health_url, timeout=3, follow_redirects=False)
    except httpx.HTTPError as exc:
        raise HTTPException(503, "n8n runtime health unavailable") from exc
    if health.status_code != 200 or health.is_redirect:
        raise HTTPException(503, "n8n runtime health rejected")
    issued_at = datetime.now(UTC)
    document = {
        "schema_version": "1.0",
        "service": "n8n",
        "environment": "production",
        "instance_id": required["instance_id"],
        "canonical_host": "n8n.internal.codestra.agency",
        "image_digest": required["image_digest"],
        "n8n_version": required["n8n_version"],
        "workflow_namespace": "codestra-production",
        "workflow_package_sha256": required["workflow_package_sha256"],
        "health": "healthy",
        "readiness": "ready",
        "issued_at": issued_at.isoformat(),
        "expires_at": (issued_at + timedelta(minutes=5)).isoformat(),
        "nonce": nonce,
    }
    document["evidence_hash"] = f"sha256:{canonical_hash(document)}"
    return document
