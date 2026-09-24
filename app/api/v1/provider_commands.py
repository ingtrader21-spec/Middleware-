from typing import Any

from fastapi import APIRouter, Header

from app.order_orchestration import verify_body_integrity
from app.provider_commands import POSTIZ_ALLOWED, POSTIZ_STORE, VICIDIAL_ALLOWED, VICIDIAL_STORE, ProviderCommand

router = APIRouter(prefix="/api/v1/integrations", tags=["provider-commands"])


def _check(body: Any, timestamp: str | None, nonce: str | None, signature: str | None, body_hash: str | None) -> None:
    verify_body_integrity(body, timestamp, nonce, signature, body_hash)


async def _create(store, allowed, provider, command, x_timestamp, x_nonce, x_signature, x_body_sha256):
    _check(command, x_timestamp, x_nonce, x_signature, x_body_sha256)
    return store.create(command, allowed, provider)


@router.post("/{provider}/commands", status_code=202)
async def create(provider: str, command: ProviderCommand, x_timestamp: str | None = Header(default=None), x_nonce: str | None = Header(default=None), x_signature: str | None = Header(default=None), x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    store, allowed = ((VICIDIAL_STORE, VICIDIAL_ALLOWED) if provider == "vicidial" else (POSTIZ_STORE, POSTIZ_ALLOWED))
    return await _create(store, allowed, provider, command, x_timestamp, x_nonce, x_signature, x_body_sha256)


@router.get("/{provider}/commands/{command_id}")
async def get(provider: str, command_id: str) -> dict[str, Any]:
    return (VICIDIAL_STORE if provider == "vicidial" else POSTIZ_STORE).get(command_id)


@router.post("/{provider}/commands/{command_id}/{action}", status_code=202)
async def transition(provider: str, command_id: str, action: str, x_timestamp: str | None = Header(default=None), x_nonce: str | None = Header(default=None), x_signature: str | None = Header(default=None), x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _check({}, x_timestamp, x_nonce, x_signature, x_body_sha256)
    status = {"start": "RUNNING", "progress": "RUNNING", "result": "COMPLETED", "error": "FAILED_FINAL", "cancel": "CANCELLED", "reconcile": "RECONCILED"}.get(action)
    if status is None:
        from fastapi import HTTPException
        raise HTTPException(404, "unknown provider command action")
    return (VICIDIAL_STORE if provider == "vicidial" else POSTIZ_STORE).transition(command_id, status)
