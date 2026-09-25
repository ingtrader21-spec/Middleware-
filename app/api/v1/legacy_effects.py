"""Read-only readback of the legacy-effect denial authority.

``GET /api/v1/legacy-effects`` returns the registry digest, the denial policy
and, per entry, whether this process mounts the path, whether the denial is
enforced on it and how many denials this process has answered.
``GET /api/v1/legacy-effects/{effect_id}`` returns one entry. Both routes sit
behind the request guard's service bearer; neither mutates anything.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Path, Request

from app.legacy_effects import readback

router = APIRouter(prefix="/api/v1/legacy-effects", tags=["legacy-effects"])


@router.get("")
async def list_legacy_effects(request: Request) -> dict[str, Any]:
    return readback(request.app)


@router.get("/{effect_id}")
async def get_legacy_effect(
    request: Request,
    effect_id: str = Path(min_length=4, max_length=96, pattern=r"^LE-[A-Z0-9-]+$"),
) -> dict[str, Any]:
    document = readback(request.app)
    entry = next((item for item in document["entries"] if item["id"] == effect_id), None)
    if entry is None:
        raise HTTPException(404, "legacy effect not found")
    return {
        "schema": document["schema"],
        "registry": document["registry"],
        "policy": document["policy"],
        "profile": document["profile"],
        "entry": entry,
    }
