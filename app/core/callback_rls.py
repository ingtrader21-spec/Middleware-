"""Transaction-local PostgreSQL RLS context for callback data."""

from collections.abc import Iterable

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def set_callback_rls_context(
    db: AsyncSession,
    *,
    tenant_id: str,
    campaign_ids: Iterable[str],
    actor_id: str,
    role: str,
    team_ids: Iterable[str] = (),
) -> None:
    campaigns = sorted({str(value) for value in campaign_ids if value})
    teams = sorted({str(value) for value in team_ids if value})
    if not tenant_id or not campaigns or not actor_id or not role:
        raise ValueError("complete callback RLS context is required")
    await db.execute(
        text("""SELECT
          set_config('app.tenant_id', :tenant, true),
          set_config('app.campaign_ids', :campaigns, true),
          set_config('app.actor_id', :actor, true),
          set_config('app.role', :role, true),
          set_config('app.team_ids', :teams, true)"""),
        {
            "tenant": tenant_id,
            "campaigns": ",".join(campaigns),
            "actor": actor_id,
            "role": role,
            "teams": ",".join(teams),
        },
    )
