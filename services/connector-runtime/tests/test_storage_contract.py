from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations" / "versions" / "20260828_0001_connector_runtime.py"


def test_migration_is_reversible_and_contains_required_controls() -> None:
    text = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "connector_idempotency_keys",
        "connector_webhook_event_keys",
        "connector_webhook_inbox",
        "connector_operations",
        "connector_dead_letters",
        "connector_outbox",
        "connector_audit_log",
        "FORCE ROW LEVEL SECURITY",
        "DROP SCHEMA IF EXISTS connector_sdk CASCADE",
    ):
        assert marker in text


@pytest.fixture(scope="session")
def database_urls() -> tuple[str, str]:
    admin = os.getenv("ADMIN_DATABASE_URL")
    app = os.getenv("APP_DATABASE_URL")
    if not admin or not app:
        pytest.skip("ADMIN_DATABASE_URL and APP_DATABASE_URL are required")
    return (
        admin.replace("postgresql+psycopg://", "postgresql://"),
        app.replace("postgresql+psycopg://", "postgresql://"),
    )


def _connect(url: str):
    import psycopg

    return psycopg.connect(url, autocommit=False)


def _seed(admin_url: str) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    suffix = uuid.uuid4().hex[:12]
    connector_id = f"test-{suffix}"
    version = "1.0.0"
    digest = "sha256:" + hashlib.sha256(connector_id.encode()).hexdigest()
    installation_id = uuid.uuid4()
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    manifest = json.dumps(
        {"enabled_by_default": False, "direct_n8n_access": False}
    )
    with _connect(admin_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO connector_sdk.connector_manifests
                    (connector_id, version, manifest_digest, manifest, created_by_subject)
                VALUES (%s, %s, %s, %s::jsonb, %s)
                """,
                (connector_id, version, digest, manifest, "storage-ci"),
            )
            cur.execute(
                """
                INSERT INTO connector_sdk.connector_installations
                    (installation_id, connector_id, environment, cell,
                     current_version, current_manifest_digest, state)
                VALUES (%s, %s, 'staging', 'core-communications', %s, %s,
                        'INSTALLED_DISABLED')
                """,
                (installation_id, connector_id, version, digest),
            )
        conn.commit()
    return installation_id, tenant_a, tenant_b


def _insert_connection(
    app_url: str, tenant_id: uuid.UUID, installation_id: uuid.UUID
) -> uuid.UUID:
    connection_id = uuid.uuid4()
    account_hash = hashlib.sha256(str(connection_id).encode()).hexdigest()
    with _connect(app_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT set_config('codestra.tenant_id', %s, true)",
                (str(tenant_id),),
            )
            cur.execute(
                """
                INSERT INTO connector_sdk.connector_connections
                    (connection_id, tenant_id, installation_id,
                     provider_account_hash, state)
                VALUES (%s, %s, %s, %s, 'READY')
                """,
                (connection_id, tenant_id, installation_id, account_hash),
            )
        conn.commit()
    return connection_id


@pytest.mark.postgres
def test_rls_denies_cross_tenant_rows(
    database_urls: tuple[str, str]
) -> None:
    admin_url, app_url = database_urls
    installation_id, tenant_a, tenant_b = _seed(admin_url)
    _insert_connection(app_url, tenant_a, installation_id)
    _insert_connection(app_url, tenant_b, installation_id)
    with _connect(app_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT set_config('codestra.tenant_id', %s, true)",
                (str(tenant_a),),
            )
            cur.execute(
                "SELECT tenant_id FROM connector_sdk.connector_connections"
            )
            assert cur.fetchall() == [(tenant_a,)]


@pytest.mark.postgres
def test_concurrent_idempotency_claim_has_one_winner(
    database_urls: tuple[str, str]
) -> None:
    admin_url, app_url = database_urls
    _, tenant_id, _ = _seed(admin_url)
    barrier = threading.Barrier(16)

    def claim(_: int) -> bool:
        with _connect(app_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT set_config('codestra.tenant_id', %s, true)",
                    (str(tenant_id),),
                )
                barrier.wait()
                cur.execute(
                    """
                    INSERT INTO connector_sdk.connector_idempotency_keys
                        (tenant_id, scope, idempotency_key, request_sha256)
                    VALUES (%s, 'test', 'same-key', %s)
                    ON CONFLICT DO NOTHING RETURNING 1
                    """,
                    (tenant_id, "b" * 64),
                )
                won = cur.fetchone() is not None
            conn.commit()
            return won

    with ThreadPoolExecutor(max_workers=16) as pool:
        assert sum(pool.map(claim, range(16))) == 1


@pytest.mark.postgres
def test_webhook_replay_key_is_atomic(
    database_urls: tuple[str, str]
) -> None:
    admin_url, app_url = database_urls
    installation_id, tenant_id, _ = _seed(admin_url)
    connection_id = _insert_connection(app_url, tenant_id, installation_id)
    webhook_id = uuid.uuid4()
    with _connect(app_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT set_config('codestra.tenant_id', %s, true)",
                (str(tenant_id),),
            )
            cur.execute(
                """
                INSERT INTO connector_sdk.connector_webhook_endpoints
                    (webhook_id, tenant_id, connection_id, endpoint_key,
                     route_template, public_path, secret_reference_current, state)
                VALUES (%s, %s, %s, 'events', '/v1/webhooks/test/events',
                        %s, 'TEST_SECRET', 'ACTIVE')
                """,
                (
                    webhook_id,
                    tenant_id,
                    connection_id,
                    f"/v1/webhooks/test/events/{webhook_id}",
                ),
            )
        conn.commit()

    barrier = threading.Barrier(20)

    def claim(_: int) -> bool:
        with _connect(app_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT set_config('codestra.tenant_id', %s, true)",
                    (str(tenant_id),),
                )
                barrier.wait()
                cur.execute(
                    """
                    INSERT INTO connector_sdk.connector_webhook_event_keys
                        (tenant_id, webhook_id, event_id, body_sha256, expires_at)
                    VALUES (%s, %s, 'evt-1', %s, now() + interval '7 days')
                    ON CONFLICT DO NOTHING RETURNING 1
                    """,
                    (tenant_id, webhook_id, "c" * 64),
                )
                won = cur.fetchone() is not None
            conn.commit()
            return won

    with ThreadPoolExecutor(max_workers=20) as pool:
        assert sum(pool.map(claim, range(20))) == 1
