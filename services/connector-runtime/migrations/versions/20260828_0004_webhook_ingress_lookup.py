"""Maintain and resolve the secret-free webhook ingress route index.

Revision ID: 20260828_0004
Revises: 20260828_0003
"""
from __future__ import annotations

from alembic import op

revision = "20260828_0004"
down_revision = "20260828_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION connector_sdk.sync_webhook_route()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, connector_sdk
        AS $$
        DECLARE
            resolved_connector_id text;
        BEGIN
            SELECT i.connector_id
              INTO STRICT resolved_connector_id
              FROM connector_sdk.connector_connections c
              JOIN connector_sdk.connector_installations i
                ON i.installation_id = c.installation_id
             WHERE c.tenant_id = NEW.tenant_id
               AND c.connection_id = NEW.connection_id;

            INSERT INTO connector_sdk.connector_webhook_routes
              (webhook_id, tenant_id, connector_id, endpoint_key, public_path)
            VALUES
              (NEW.webhook_id, NEW.tenant_id, resolved_connector_id,
               NEW.endpoint_key, NEW.public_path)
            ON CONFLICT (webhook_id) DO UPDATE
                  SET tenant_id = EXCLUDED.tenant_id,
                      connector_id = EXCLUDED.connector_id,
                      endpoint_key = EXCLUDED.endpoint_key,
                      public_path = EXCLUDED.public_path;
            RETURN NEW;
        END;
        $$;

        CREATE TRIGGER connector_webhook_routes_sync
        AFTER INSERT OR UPDATE OF tenant_id, connection_id, endpoint_key, public_path
        ON connector_sdk.connector_webhook_endpoints
        FOR EACH ROW EXECUTE FUNCTION connector_sdk.sync_webhook_route();

        INSERT INTO connector_sdk.connector_webhook_routes
          (webhook_id, tenant_id, connector_id, endpoint_key, public_path)
        SELECT w.webhook_id, w.tenant_id, i.connector_id,
               w.endpoint_key, w.public_path
          FROM connector_sdk.connector_webhook_endpoints w
          JOIN connector_sdk.connector_connections c
            ON c.tenant_id = w.tenant_id
           AND c.connection_id = w.connection_id
          JOIN connector_sdk.connector_installations i
            ON i.installation_id = c.installation_id
        ON CONFLICT (webhook_id) DO UPDATE
              SET tenant_id = EXCLUDED.tenant_id,
                  connector_id = EXCLUDED.connector_id,
                  endpoint_key = EXCLUDED.endpoint_key,
                  public_path = EXCLUDED.public_path;

        CREATE OR REPLACE FUNCTION connector_sdk.resolve_webhook_ingress(
            requested_webhook_id uuid
        )
        RETURNS TABLE (
            tenant_id uuid,
            webhook_id uuid,
            connection_id uuid,
            connector_id text,
            endpoint_key text,
            public_path text,
            webhook_state text,
            installation_state text,
            secret_reference_current text,
            secret_reference_previous text,
            previous_secret_valid_until timestamptz,
            external_account_reference text,
            manifest jsonb
        )
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, connector_sdk
        AS $$
            SELECT r.tenant_id,
                   r.webhook_id,
                   w.connection_id,
                   r.connector_id,
                   r.endpoint_key,
                   r.public_path,
                   w.state AS webhook_state,
                   i.state AS installation_state,
                   w.secret_reference_current,
                   w.secret_reference_previous,
                   w.previous_secret_valid_until,
                   c.external_account_reference,
                   m.manifest
              FROM connector_sdk.connector_webhook_routes r
              JOIN connector_sdk.connector_webhook_endpoints w
                ON w.tenant_id = r.tenant_id
               AND w.webhook_id = r.webhook_id
              JOIN connector_sdk.connector_connections c
                ON c.tenant_id = w.tenant_id
               AND c.connection_id = w.connection_id
              JOIN connector_sdk.connector_installations i
                ON i.installation_id = c.installation_id
               AND i.connector_id = r.connector_id
              JOIN connector_sdk.connector_manifests m
                ON m.connector_id = i.connector_id
               AND m.version = i.current_version
               AND m.manifest_digest = i.current_manifest_digest
             WHERE r.webhook_id = requested_webhook_id
        $$;

        COMMENT ON FUNCTION connector_sdk.resolve_webhook_ingress(uuid) IS
          'Returns secret references and tenant context, never secret values, for signed webhook verification';
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP FUNCTION IF EXISTS connector_sdk.resolve_webhook_ingress(uuid);
        DROP TRIGGER IF EXISTS connector_webhook_routes_sync
          ON connector_sdk.connector_webhook_endpoints;
        DROP FUNCTION IF EXISTS connector_sdk.sync_webhook_route();
        """
    )
