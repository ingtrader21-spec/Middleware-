"""Permission-controlled exact global identity search."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.campaign_search import normalize_alias
from app.core.config import settings
from app.core.jwt_auth import JWTAuthError, KeycloakValidator, identity_validator_kwargs
from app.db.session import get_session


router = APIRouter(prefix="/v1/registry/search", tags=["campaign-registry"])
SEARCH_ROLES = frozenset({"codestra_agent", "codestra_closer", "codestra_supervisor"})


def campaign_scope_from_claims(claims: dict[str, Any]) -> frozenset[int]:
    roles = set(claims.get("realm_access", {}).get("roles", []))
    roles.update(claims.get("roles", []))
    if not roles.intersection(SEARCH_ROLES):
        raise JWTAuthError("campaign search role denied")
    raw = claims.get("campaign_numbers")
    if not isinstance(raw, list) or not raw:
        raise JWTAuthError("campaign scope missing")
    result: set[int] = set()
    for item in raw:
        if isinstance(item, bool):
            raise JWTAuthError("campaign scope invalid")
        try:
            value = int(item)
        except (TypeError, ValueError) as exc:
            raise JWTAuthError("campaign scope invalid") from exc
        if value <= 0 or value % 100:
            raise JWTAuthError("campaign scope invalid")
        result.add(value)
    return frozenset(result)


def _bearer(value: str) -> str:
    scheme, separator, token = value.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token.strip():
        raise JWTAuthError("bearer authorization required")
    return token.strip()


@router.get("")
async def exact_campaign_identity_search(
    q: str = Query(..., min_length=3, max_length=160),
    authorization: str = Header(..., alias="Authorization"),
    db: AsyncSession = Depends(get_session),
):
    try:
        token = _bearer(authorization)
        claims = KeycloakValidator(**identity_validator_kwargs(settings.identity)).validate(token)
        allowed = campaign_scope_from_claims(claims)
        alias = normalize_alias(q)
    except (JWTAuthError, ValueError) as exc:
        raise HTTPException(404, "identity not found") from exc
    row = (
        (
            await db.execute(
                text(
                    """
                SELECT a.alias,a.alias_type,r.campaign_number,r.campaign_code,
                       r.campaign_public_id,r.name,r.vicidial_campaign_id,
                       r.registry_status,o.public_id AS object_public_id,
                       o.identity_type,o.identity_state,o.dialing_state
                FROM campaign_search_alias a
                JOIN campaign_registry r USING(campaign_number)
                LEFT JOIN campaign_object_identity o
                  ON o.id=a.object_identity_id
                WHERE a.alias=:alias AND a.campaign_number=ANY(:campaigns)
                """
                ),
                {"alias": alias, "campaigns": list(sorted(allowed))},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        # Unauthorized and nonexistent objects are deliberately indistinguishable.
        raise HTTPException(404, "identity not found")
    return {
        "alias": row["alias"],
        "alias_type": row["alias_type"],
        "campaign": {
            "number": row["campaign_number"],
            "code": row["campaign_code"],
            "public_id": row["campaign_public_id"],
            "name": row["name"],
            "vicidial_campaign_id": row["vicidial_campaign_id"],
            "status": row["registry_status"],
        },
        "object": (
            {
                "public_id": row["object_public_id"],
                "type": row["identity_type"],
                "identity_state": row["identity_state"],
                "dialing_state": row["dialing_state"],
            }
            if row["object_public_id"]
            else None
        ),
    }
