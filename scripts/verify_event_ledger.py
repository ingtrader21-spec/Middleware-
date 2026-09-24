#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

import asyncpg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.storage import EventLedgerIntegrityError, PostgresInboxStore  # noqa: E402


async def verify(tenant_id: str | None) -> int:
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise SystemExit("DATABASE_URL is required")
    pool = await asyncpg.create_pool(
        database_url,
        min_size=1,
        max_size=2,
        command_timeout=30,
    )
    try:
        store = PostgresInboxStore(pool)
        await store.verify_schema()
        counts = await store.verify_event_ledger(tenant_id)
    except EventLedgerIntegrityError as exc:
        print(f"EVENT_LEDGER_INTEGRITY=FAIL REASON={exc}")
        return 1
    finally:
        await pool.close()
    print(
        "EVENT_LEDGER_INTEGRITY=PASS "
        f"TENANTS={len(counts)} ENTRIES={sum(counts.values())}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the immutable per-tenant event hash chains",
    )
    parser.add_argument("--tenant-id")
    args = parser.parse_args()
    return asyncio.run(verify(args.tenant_id))


if __name__ == "__main__":
    raise SystemExit(main())
