from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


FORMATS = {
    "LEAD": ("L", 8),
    "CALLBACK": ("CB", 8),
    "TRANSFER": ("XF", 8),
    "LIST": ("LST", 4),
    "ACTIVATION": ("ACT", 3),
    "IMPORT_BATCH": ("IMP", 3),
}
CAMPAIGN_CODE = re.compile(r"^[A-Z]{3}$")


@dataclass(frozen=True)
class IssuedIdentity:
    campaign_number: int
    identity_type: str
    sequence_value: int
    public_id: str
    full_alias: str | None


def format_identity(
    campaign_number: int,
    campaign_code: str,
    identity_type: str,
    sequence_value: int,
    *,
    date_yyyymmdd: str | None = None,
    extension: int | None = None,
) -> IssuedIdentity:
    if campaign_number <= 0 or campaign_number % 100:
        raise ValueError("INVALID_CAMPAIGN_NUMBER")
    if not CAMPAIGN_CODE.fullmatch(campaign_code):
        raise ValueError("INVALID_CAMPAIGN_CODE")
    if sequence_value <= 0:
        raise ValueError("INVALID_SEQUENCE")
    if identity_type == "AGENT":
        if extension is None:
            raise ValueError("AGENT_EXTENSION_REQUIRED")
        value = f"{campaign_number}-A-{extension}"
        return IssuedIdentity(
            campaign_number, identity_type, sequence_value, value, None
        )
    if identity_type == "CALL":
        if not date_yyyymmdd or not re.fullmatch(r"\d{8}", date_yyyymmdd):
            raise ValueError("CALL_DATE_REQUIRED")
        value = f"{campaign_number}-C-{date_yyyymmdd}-{sequence_value:06d}"
        return IssuedIdentity(
            campaign_number, identity_type, sequence_value, value, None
        )
    try:
        token, width = FORMATS[identity_type]
    except KeyError as exc:
        raise ValueError("UNSUPPORTED_IDENTITY_TYPE") from exc
    if sequence_value >= 10**width:
        raise ValueError("IDENTITY_SEQUENCE_EXHAUSTED")
    value = f"{campaign_number}-{token}-{sequence_value:0{width}d}"
    alias = f"{campaign_code}-{value}" if identity_type == "LEAD" else None
    return IssuedIdentity(campaign_number, identity_type, sequence_value, value, alias)


async def reserve_sequence(
    db: AsyncSession, campaign_number: int, identity_type: str
) -> int:
    """Atomically reserve and return one never-reused sequence value."""
    # nextval is deliberately non-transactional, so a caller rollback leaves a
    # gap rather than making an issued number reusable.
    result = await db.execute(text("SELECT nextval('campaign_identity_global_seq')"))
    return int(result.scalar_one())


def authorize_campaign_scope(requested: int, allowed: frozenset[int]) -> None:
    if requested not in allowed:
        raise PermissionError("CAMPAIGN_SCOPE_DENIED")
