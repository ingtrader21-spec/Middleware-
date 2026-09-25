from __future__ import annotations

from uuid import uuid4

import pytest

from app.db.session import TENANT_CONTEXT_GUC, set_transaction_tenant_context


class _RecordingSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []

    async def execute(self, statement, params):
        self.calls.append((str(statement), params))


@pytest.mark.asyncio
async def test_sets_transaction_local_postgres_context() -> None:
    session = _RecordingSession()
    tenant_id = str(uuid4())

    normalized = await set_transaction_tenant_context(session, tenant_id)  # type: ignore[arg-type]

    assert normalized == tenant_id
    assert len(session.calls) == 1
    sql, params = session.calls[0]
    assert "set_config" in sql
    assert params == {
        "setting_name": "app.tenant_id",
        "tenant_id": tenant_id,
    }


@pytest.mark.asyncio
async def test_rejects_missing_or_invalid_tenant_context_before_sql() -> None:
    session = _RecordingSession()

    for invalid in ("", "   ", "tenant-a", "not-a-uuid"):
        with pytest.raises(ValueError):
            await set_transaction_tenant_context(session, invalid)  # type: ignore[arg-type]

    assert session.calls == []
