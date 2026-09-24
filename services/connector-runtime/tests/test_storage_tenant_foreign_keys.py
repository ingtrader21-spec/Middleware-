from __future__ import annotations

import hashlib
import json
import os
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

pytestmark = pytest.mark.postgres


def _admin_engine():
    return create_engine(
        os.environ["ADMIN_DATABASE_URL"],
        future=True,
        pool_pre_ping=True,
    )


def _seed_parent(connection, *, tenant_id: uuid.UUID) -> tuple[uuid.UUID, uuid.UUID]:
    connector_id = "tenant-fk-" + uuid.uuid4().hex[:8]
    installation_id = uuid.uuid4()
    connection_id = uuid.uuid4()
    manifest = {
        "manifest_version": "1.0",
        "connector_id": connector_id,
        "display_name": "Tenant FK Test",
        "version": "1.0.0",
        "enabled_by_default": False,
        "direct_n8n_access": False,
    }
    digest = "sha256:" + hashlib.sha256(
        json.dumps(manifest, sort_keys=True).encode()
    ).hexdigest()
    provider_hash = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    connection.execute(
        text(
            """
            INSERT INTO connector_sdk.connector_manifests
              (connector_id, version, manifest_digest, manifest, created_by_subject)
            VALUES (:connector_id, '1.0.0', :digest, CAST(:manifest AS jsonb), 'test')
            """
        ),
        {
            "connector_id": connector_id,
            "digest": digest,
            "manifest": json.dumps(manifest),
        },
    )
    connection.execute(
        text(
            """
            INSERT INTO connector_sdk.connector_installations
              (installation_id, connector_id, environment, cell, current_version,
               current_manifest_digest, state)
            VALUES (:installation_id, :connector_id, 'staging',
                    'core-communications', '1.0.0', :digest, 'INSTALLED_DISABLED')
            """
        ),
        {
            "installation_id": installation_id,
            "connector_id": connector_id,
            "digest": digest,
        },
    )
    connection.execute(
        text(
            """
            INSERT INTO connector_sdk.connector_connections
              (connection_id, tenant_id, installation_id, provider_account_hash, state)
            VALUES (:connection_id, :tenant_id, :installation_id, :provider_hash, 'READY')
            """
        ),
        {
            "connection_id": connection_id,
            "tenant_id": tenant_id,
            "installation_id": installation_id,
            "provider_hash": provider_hash,
        },
    )
    return installation_id, connection_id


def test_endpoint_cannot_reference_another_tenants_connection() -> None:
    engine = _admin_engine()
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    with engine.begin() as connection:
        _, connection_id = _seed_parent(connection, tenant_id=tenant_a)
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    """
                    INSERT INTO connector_sdk.connector_webhook_endpoints
                      (webhook_id, tenant_id, connection_id, endpoint_key,
                       route_template, public_path, secret_reference_current, state)
                    VALUES (:webhook_id, :tenant_id, :connection_id, 'events',
                            '/v1/webhooks/test/events', :public_path,
                            'WEBHOOK_TEST_SECRET', 'DISABLED')
                    """
                ),
                {
                    "webhook_id": uuid.uuid4(),
                    "tenant_id": tenant_b,
                    "connection_id": connection_id,
                    "public_path": "/v1/webhooks/test/events/" + uuid.uuid4().hex,
                },
            )
    engine.dispose()


def test_replay_inbox_and_operation_require_tenant_matching_parents() -> None:
    engine = _admin_engine()
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    with engine.begin() as connection:
        _, connection_id = _seed_parent(connection, tenant_id=tenant_a)
        webhook_id = uuid.uuid4()
        connection.execute(
            text(
                """
                INSERT INTO connector_sdk.connector_webhook_endpoints
                  (webhook_id, tenant_id, connection_id, endpoint_key,
                   route_template, public_path, secret_reference_current, state)
                VALUES (:webhook_id, :tenant_id, :connection_id, 'events',
                        '/v1/webhooks/test/events', :public_path,
                        'WEBHOOK_TEST_SECRET', 'DISABLED')
                """
            ),
            {
                "webhook_id": webhook_id,
                "tenant_id": tenant_a,
                "connection_id": connection_id,
                "public_path": "/v1/webhooks/test/events/" + uuid.uuid4().hex,
            },
        )

        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    """
                    INSERT INTO connector_sdk.connector_webhook_event_keys
                      (tenant_id, webhook_id, event_id, body_sha256, expires_at)
                    VALUES (:tenant_id, :webhook_id, 'evt-cross-tenant', :digest,
                            now() + interval '7 days')
                    """
                ),
                {
                    "tenant_id": tenant_b,
                    "webhook_id": webhook_id,
                    "digest": "a" * 64,
                },
            )
        connection.rollback()

    # Each expected integrity failure aborts a PostgreSQL transaction, so use
    # fresh transactions for the remaining child-table checks.
    with engine.begin() as connection:
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    """
                    INSERT INTO connector_sdk.connector_webhook_inbox
                      (inbox_id, tenant_id, webhook_id, connector_id, endpoint_key,
                       event_id, body_sha256, encrypted_body_reference,
                       signature_version, verification_state, processing_state,
                       correlation_id)
                    VALUES (:inbox_id, :tenant_id, :webhook_id, 'test', 'events',
                            'evt-inbox-cross', :digest, 'blob:1', 'v1',
                            'VERIFIED', 'PENDING', :correlation_id)
                    """
                ),
                {
                    "inbox_id": uuid.uuid4(),
                    "tenant_id": tenant_b,
                    "webhook_id": webhook_id,
                    "digest": "b" * 64,
                    "correlation_id": uuid.uuid4(),
                },
            )

    with engine.begin() as connection:
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    """
                    INSERT INTO connector_sdk.connector_operations
                      (operation_id, tenant_id, connection_id, command_id,
                       command_type, idempotency_key, request_sha256,
                       capability, state)
                    VALUES (:operation_id, :tenant_id, :connection_id, :command_id,
                            'test.command.v1', :idempotency_key, :digest,
                            'NONE', 'ACCEPTED')
                    """
                ),
                {
                    "operation_id": uuid.uuid4(),
                    "tenant_id": tenant_b,
                    "connection_id": connection_id,
                    "command_id": uuid.uuid4(),
                    "idempotency_key": "cross-tenant-" + uuid.uuid4().hex,
                    "digest": "c" * 64,
                },
            )
    engine.dispose()
