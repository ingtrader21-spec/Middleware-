from __future__ import annotations

from uuid import uuid4

import pytest

from app.api.v1.ai_console import Tenant, tenant_db_session


class RecordingSession:
    def __init__(self) -> None:
        self.info: dict[str, str] = {}
        self.calls: list[tuple[str, dict[str, str]]] = []

    async def execute(self, statement, params):
        self.calls.append((str(statement), params))


@pytest.mark.asyncio
async def test_ai_tenant_db_session_binds_verified_organization() -> None:
    organization_id = uuid4()
    subject = Tenant(
        organization_id=organization_id,
        workspace_id=uuid4(),
        user_id="user-1",
        roles=frozenset({"codestra_ai_user"}),
    )
    session = RecordingSession()

    dependency = tenant_db_session(subject=subject, db=session)  # type: ignore[arg-type]
    yielded = await anext(dependency)
    assert yielded is session
    assert session.info["codestra.tenant_id"] == str(organization_id)
    assert "set_config" in session.calls[0][0]
    await dependency.aclose()
