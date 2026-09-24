from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


ALIAS = re.compile(
    r"^(?:\d{3,6}|[A-Z]{3}|[A-Z]{3}\d{3}|CMP-\d{3,}-[A-Z]{3}|[A-Z]{3}-\d{3,}-(?:L|CB|XF|LST|ACT|IMP)-[A-Z0-9-]+|\d{3,}-(?:L|A|C|CB|XF|LST|ACT|IMP)-[A-Z0-9-]+)$"
)


@dataclass(frozen=True)
class SearchResult:
    alias: str
    campaign_number: int
    alias_type: str
    object_identity_id: str | None


def normalize_alias(value: str) -> str:
    normalized = value.strip().upper()
    if not ALIAS.fullmatch(normalized):
        raise ValueError("INVALID_SEARCH_ALIAS")
    return normalized


async def scoped_exact_search(
    db: AsyncSession, alias: str, allowed_campaigns: frozenset[int]
) -> SearchResult | None:
    normalized = normalize_alias(alias)
    if not allowed_campaigns:
        return None
    row = (
        (
            await db.execute(
                text(
                    """
                SELECT alias,campaign_number,alias_type,object_identity_id
                FROM campaign_search_alias
                WHERE alias=:alias AND campaign_number = ANY(:campaigns)
                """
                ),
                {"alias": normalized, "campaigns": list(sorted(allowed_campaigns))},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    return SearchResult(
        row["alias"],
        row["campaign_number"],
        row["alias_type"],
        str(row["object_identity_id"]) if row["object_identity_id"] else None,
    )
