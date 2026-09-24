"""Real PostgreSQL concurrency proof for inclusive campaign ranges."""

import asyncio
import os
import uuid

import asyncpg


RUN_ID = "concurrency-" + uuid.uuid4().hex
INSERT = """
INSERT INTO {table}
(id,campaign_id,campaign_number,allocation_public_id,extension_start,
 extension_end,created_by,policy_hash,source_change_id)
VALUES($1,$2,$3,$4,$5,$6,'concurrency-test',$7,$8)
"""


def require(condition: bool, message: str) -> None:
    """Keep this deployment gate effective even when Python runs with -O."""
    if not condition:
        raise RuntimeError(message)


async def insert(pool, table, name, number, start, end, delay=0):
    async with pool.acquire() as connection:
        transaction = connection.transaction()
        await transaction.start()
        try:
            await connection.execute(
                INSERT.format(table=table),
                uuid.uuid4(),
                f"{RUN_ID}-{name}",
                number,
                f"ALLOC-{RUN_ID}-{name}",
                start,
                end,
                "c" * 64,
                RUN_ID,
            )
            await asyncio.sleep(delay)
            await transaction.commit()
            return "PASS"
        except (
            asyncpg.DeadlockDetectedError,
            asyncpg.ExclusionViolationError,
        ):
            await transaction.rollback()
            return "OVERLAP"


async def create_scratch_schema(database_url: str) -> str:
    connection = await asyncpg.connect(database_url)
    schema = "concurrency_" + uuid.uuid4().hex
    try:
        await connection.execute(f'CREATE SCHEMA "{schema}"')
        await connection.execute(
            f'CREATE TABLE "{schema}".campaign_extension_allocation '
            "(LIKE public.campaign_extension_allocation INCLUDING ALL)"
        )
    except Exception:
        await connection.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        raise
    finally:
        await connection.close()
    return schema


async def drop_scratch_schema(database_url: str, schema: str) -> None:
    connection = await asyncpg.connect(database_url)
    try:
        await connection.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
    finally:
        await connection.close()


async def find_test_bases(pool, table):
    """Choose a free extension band and unique campaign numbers for this run."""
    async with pool.acquire() as connection:
        extension_base = None
        for candidate in range(6100, 9201, 100):
            occupied = await connection.fetchval(
                f"""
                SELECT EXISTS (
                    SELECT 1
                    FROM {table}
                    WHERE extension_range && int4range($1, $2, '[]')
                )
                """,
                candidate,
                candidate + 799,
            )
            if not occupied:
                extension_base = candidate
                break
        if extension_base is None:
            raise RuntimeError("no free extension range available for concurrency test")
        max_number = await connection.fetchval(
            f"SELECT COALESCE(MAX(campaign_number), 0) FROM {table}"
        )
    number_base = ((int(max_number) // 100) + 1) * 100
    return extension_base, number_base


async def main():
    database_url = os.environ["TEST_DATABASE_URL"]
    if "diag" not in database_url and "rehearsal" not in database_url:
        raise RuntimeError("concurrency proof requires an isolated test database")
    schema = await create_scratch_schema(database_url)
    table = f'"{schema}".campaign_extension_allocation'

    async def configure_connection(connection):
        await connection.execute(f'SET search_path TO "{schema}", public')

    pool = await asyncpg.create_pool(database_url, init=configure_connection)
    try:
        extension_base, number_base = await find_test_bases(pool, table)

        exact = await asyncio.gather(
            insert(
                pool,
                table,
                "EXACT1",
                number_base,
                extension_base,
                extension_base + 99,
                0.1,
            ),
            insert(
                pool,
                table,
                "EXACT2",
                number_base + 100,
                extension_base,
                extension_base + 99,
            ),
        )
        require(sorted(exact) == ["OVERLAP", "PASS"], "exact overlap was accepted")

        partial = await asyncio.gather(
            insert(
                pool,
                table,
                "PART1",
                number_base + 200,
                extension_base + 100,
                extension_base + 199,
                0.1,
            ),
            insert(
                pool,
                table,
                "PART2",
                number_base + 300,
                extension_base + 199,
                extension_base + 298,
            ),
        )
        require(
            sorted(partial) == ["OVERLAP", "PASS"],
            "partial overlap was accepted",
        )

        contained = await asyncio.gather(
            insert(
                pool,
                table,
                "OUTER",
                number_base + 400,
                extension_base + 300,
                extension_base + 399,
                0.1,
            ),
            insert(
                pool,
                table,
                "INNER",
                number_base + 500,
                extension_base + 320,
                extension_base + 330,
            ),
        )
        require(
            sorted(contained) == ["OVERLAP", "PASS"],
            "contained overlap was accepted",
        )

        adjacent = await asyncio.gather(
            insert(
                pool,
                table,
                "ADJ1",
                number_base + 600,
                extension_base + 400,
                extension_base + 499,
                0.1,
            ),
            insert(
                pool,
                table,
                "ADJ2",
                number_base + 700,
                extension_base + 500,
                extension_base + 599,
            ),
        )
        require(adjacent == ["PASS", "PASS"], "adjacent ranges were rejected")

        many = await asyncio.gather(
            *[
                insert(
                    pool,
                    table,
                    f"BLOCK{offset}",
                    number_base + 800 + (offset * 100),
                    extension_base + 600 + (offset * 10),
                    extension_base + 609 + (offset * 10),
                )
                for offset in range(5)
            ]
        )
        require(many == ["PASS"] * 5, "disjoint concurrent ranges were rejected")

        async with pool.acquire() as connection:
            transaction = connection.transaction()
            await transaction.start()
            await connection.execute(
                INSERT.format(table=table),
                uuid.uuid4(),
                f"{RUN_ID}-ROLLBACK",
                number_base + 1300,
                f"ALLOC-{RUN_ID}-ROLLBACK",
                extension_base + 700,
                extension_base + 799,
                "c" * 64,
                RUN_ID,
            )
            await transaction.rollback()

        require(
            await insert(
                pool,
                table,
                "AFTERROLLBACK",
                number_base + 1400,
                extension_base + 700,
                extension_base + 799,
            )
            == "PASS",
            "rolled-back range was not released",
        )
        async with pool.acquire() as connection:
            await connection.execute(
                f"UPDATE {table} SET allocation_status='RETIRED' WHERE campaign_id=$1",
                f"{RUN_ID}-AFTERROLLBACK",
            )
        require(
            await insert(
                pool,
                table,
                "REUSE",
                number_base + 1500,
                extension_base + 700,
                extension_base + 799,
            )
            == "OVERLAP",
            "retired range was incorrectly reusable",
        )
        async with pool.acquire() as connection:
            require(
                await connection.fetchval(
                    f"SELECT count(*) FROM {table} WHERE source_change_id=$1",
                    RUN_ID,
                )
                == 11,
                "unexpected persisted row count",
            )
        print("CONCURRENT_OVERLAP_GATE=PASS")
        print("CONCURRENT_ADJACENT_GATE=PASS")
        print("RACE_CONDITION_GATE=PASS")
        print("TRANSACTION_ROLLBACK_GATE=PASS")
        print("RETIRED_RANGE_NON_REUSE_GATE=PASS")
    finally:
        await pool.close()
        await drop_scratch_schema(database_url, schema)


if __name__ == "__main__":
    asyncio.run(main())
