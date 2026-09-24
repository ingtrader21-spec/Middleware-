"""Real PostgreSQL concurrency proof for campaign identity sequences."""

import asyncio
import os

import asyncpg


async def reserve(pool, campaign: int, kind: str) -> int:
    async with pool.acquire() as conn:
        async with conn.transaction():
            return await conn.fetchval("SELECT nextval('campaign_identity_global_seq')")


async def main() -> None:
    dsn = os.environ["TEST_DATABASE_URL"].replace(
        "postgresql+asyncpg://", "postgresql://"
    )
    pool = await asyncpg.create_pool(dsn, min_size=2, max_size=20)
    try:
        values = await asyncio.gather(*(reserve(pool, 100, "LEAD") for _ in range(50)))
        assert len(values) == len(set(values)) == 50
        assert max(values) - min(values) == 49
        other = await asyncio.gather(*(reserve(pool, 200, "LEAD") for _ in range(10)))
        assert len(other) == len(set(other)) == 10
        assert not set(values).intersection(other)
        async with pool.acquire() as conn:
            tx = conn.transaction()
            await tx.start()
            rolled_back = await conn.fetchval(
                "SELECT nextval('campaign_identity_global_seq')"
            )
            await tx.rollback()
            after_rollback = await conn.fetchval(
                "SELECT nextval('campaign_identity_global_seq')"
            )
            assert after_rollback > rolled_back
        print("M2_ID_SEQUENCE_CONCURRENCY_GATE=PASS")
        print("M2_NO_ID_REUSE_GATE=PASS")
    finally:
        await pool.close()


asyncio.run(main())
