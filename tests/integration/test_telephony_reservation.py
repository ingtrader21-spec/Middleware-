import asyncio
import hashlib
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


def test_database_prevents_concurrent_duplicate_extension_and_employee():
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("requires an explicitly provisioned disposable database")
    assert "diag" in database_url or "rehearsal" in database_url
    asyncio.run(_scenario(database_url))


async def _scenario(database_url: str):
    engine = create_async_engine(database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            await session.execute(text("TRUNCATE telephony_extension_reservation"))
            pool_id = await session.scalar(
                text(
                    "SELECT id FROM telephony_extension_pool "
                    "WHERE code='transportation-intro-sales'"
                )
            )
            assert pool_id
            await session.commit()

        async def reserve(attempt: int):
            async with factory() as session:
                try:
                    await session.execute(
                        text(
                            "INSERT INTO telephony_extension_reservation "
                            "(id,extension,employee_id,request_id,pool_id,state,"
                            "idempotency_hash,evidence_hash,reserved_at,expires_at) "
                            "VALUES (:id,6110,:employee,:request,:pool,'RESERVED',"
                            ":key,:evidence,:now,:expires)"
                        ),
                        {
                            "id": uuid4(),
                            "employee": f"employee-{attempt}",
                            "request": f"request-{attempt}",
                            "pool": pool_id,
                            "key": hashlib.sha256(
                                f"key-{attempt}".encode()
                            ).hexdigest(),
                            "evidence": "e" * 64,
                            "now": datetime.now(timezone.utc),
                            "expires": datetime.now(timezone.utc)
                            + timedelta(minutes=15),
                        },
                    )
                    await session.commit()
                    return True
                except IntegrityError:
                    await session.rollback()
                    return False

        results = await asyncio.gather(*(reserve(i) for i in range(20)))
        assert results.count(True) == 1
        async with factory() as session:
            assert (
                await session.scalar(
                    text(
                        "SELECT count(*) FROM telephony_extension_reservation "
                        "WHERE extension=6110 AND state='RESERVED'"
                    )
                )
                == 1
            )
    finally:
        await engine.dispose()
