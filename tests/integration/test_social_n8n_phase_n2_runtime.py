import asyncio
import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import settings
from app.workers.postly_polling import poll_account
from app.workers.social_n8n_delivery import reconcile_terminal, stage_pending


DATABASE_URL = os.getenv("TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="TEST_DATABASE_URL is required"
)


class FakePostly:
    def __init__(self, account_ref: str, provider_post_id: str):
        self.account_ref = account_ref
        self.provider_post_id = provider_post_id
        self.calls = 0

    async def list_posts(self, **kwargs):
        self.calls += 1
        return {
            "posts": [
                {
                    "id": self.provider_post_id,
                    "status": "published",
                    "updatedAt": "2026-08-09T00:00:00Z",
                    "integrations": [{"id": self.account_ref}],
                }
            ]
        }


def test_poll_dedupe_delivery_bridge_and_terminal_recovery(monkeypatch):
    monkeypatch.setattr(settings, "social_n8n_events_enabled", True)
    monkeypatch.setattr(settings, "social_n8n_delivery_batch_size", 8)
    monkeypatch.setattr(settings, "social_n8n_delivery_lease_seconds", 60)

    async def scenario():
        engine = create_async_engine(DATABASE_URL)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        tenant_id = uuid4()
        account_id = uuid4()
        post_id = uuid4()
        account_ref = f"postly-account-{account_id}"
        provider_post_id = f"postly-post-{post_id}"
        now = datetime(2026, 8, 9, tzinfo=UTC)
        async with factory() as session:
            await session.execute(
                text(
                    """INSERT INTO social_accounts
                    (id,tenant_id,provider,provider_account_id,network,
                     external_profile_name,external_profile_id,connection_state,capabilities,metadata)
                    VALUES (:id,:tenant,'postly',:external,'other','synthetic',:external,
                    'connected','[]'::jsonb,'{"classification":"STAGING_SAFE"}'::jsonb)"""
                ),
                {"id": account_id, "tenant": tenant_id, "external": account_ref},
            )
            await session.execute(
                text(
                    """INSERT INTO social_posts
                    (id,tenant_id,provider,provider_post_id,status,content,metadata)
                    VALUES (:id,:tenant,'postly',:provider,'PUBLISHED',
                    '{"text":"synthetic"}'::jsonb,'{}'::jsonb)"""
                ),
                {"id": post_id, "tenant": tenant_id, "provider": provider_post_id},
            )
            await session.execute(
                text(
                    """INSERT INTO n8n_workflow_registry
                    (registry_id,workflow_code,workflow_version,n8n_workflow_id,
                     event_types,tenant_scope,enabled,timeout_seconds,retry_policy,
                     result_contract,owner,webhook_path)
                    VALUES (:id,'CDST_SOCIAL_EVENT_ROUTER','1',:workflow,
                    '["social.post.published"]'::jsonb,CAST(:tenants AS jsonb),true,600,
                    CAST(:retry AS jsonb),'codestra.n8n.result.v1','social-platform',
                    '/webhook/codestra-social-router-v1')"""
                ),
                {
                    "id": uuid4(),
                    "workflow": f"social-router-{tenant_id}",
                    "tenants": f'["{tenant_id}"]',
                    "retry": '{"max_attempts":5}',
                },
            )
            await session.commit()
            account = {
                "id": account_id,
                "tenant_id": tenant_id,
                "provider_account_id": account_ref,
            }
            client = FakePostly(account_ref, provider_post_id)
            assert await poll_account(session, client, account, now=now) == 1
            assert await poll_account(session, client, account, now=now) == 0
            assert client.calls == 2
            assert await session.scalar(
                text(
                    "SELECT count(*) FROM social_poll_observations WHERE account_id=:account"
                ),
                {"account": account_id},
            ) == 1
            assert await session.scalar(
                text(
                    "SELECT count(*) FROM integration_delivery d JOIN integration_event e "
                    "ON e.id=d.event_id WHERE e.entity_key=:entity"
                ),
                {"entity": f"social:{post_id}"},
            ) == 1
            assert await stage_pending(session) == 1
            execution_id = await session.scalar(
                text(
                    "SELECT execution_id FROM social_n8n_delivery_execution m "
                    "JOIN integration_delivery d ON d.id=m.delivery_id "
                    "JOIN integration_event e ON e.id=d.event_id WHERE e.entity_key=:entity"
                ),
                {"entity": f"social:{post_id}"},
            )
            assert execution_id is not None
            await session.execute(
                text(
                    "UPDATE n8n_runtime_execution SET status='COMPLETED' "
                    "WHERE execution_id=:execution"
                ),
                {"execution": execution_id},
            )
            await session.commit()
            assert await reconcile_terminal(session) == 1
            assert await session.scalar(
                text(
                    "SELECT d.status FROM integration_delivery d "
                    "JOIN social_n8n_delivery_execution m ON m.delivery_id=d.id "
                    "WHERE m.execution_id=:execution"
                ),
                {"execution": execution_id},
            ) == "delivered"
        await engine.dispose()

    asyncio.run(scenario())
