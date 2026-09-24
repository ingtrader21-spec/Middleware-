"""Bind tenant-owned connector rows to tenant-matching parents.

Revision ID: 20260828_0002
Revises: 20260828_0001
"""
from __future__ import annotations

from alembic import op

revision = "20260828_0002"
down_revision = "20260828_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE connector_sdk.connector_connections
          ADD CONSTRAINT connector_connections_tenant_connection_key
          UNIQUE (tenant_id, connection_id);

        ALTER TABLE connector_sdk.connector_webhook_endpoints
          ADD CONSTRAINT connector_webhook_endpoints_tenant_webhook_key
          UNIQUE (tenant_id, webhook_id);

        ALTER TABLE connector_sdk.connector_webhook_endpoints
          DROP CONSTRAINT connector_webhook_endpoints_connection_id_fkey;
        ALTER TABLE connector_sdk.connector_webhook_endpoints
          ADD CONSTRAINT connector_webhook_endpoints_tenant_connection_fkey
          FOREIGN KEY (tenant_id, connection_id)
          REFERENCES connector_sdk.connector_connections
            (tenant_id, connection_id);

        ALTER TABLE connector_sdk.connector_webhook_event_keys
          DROP CONSTRAINT connector_webhook_event_keys_webhook_id_fkey;
        ALTER TABLE connector_sdk.connector_webhook_event_keys
          ADD CONSTRAINT connector_webhook_event_keys_tenant_webhook_fkey
          FOREIGN KEY (tenant_id, webhook_id)
          REFERENCES connector_sdk.connector_webhook_endpoints
            (tenant_id, webhook_id);

        ALTER TABLE connector_sdk.connector_webhook_inbox
          DROP CONSTRAINT connector_webhook_inbox_webhook_id_fkey;
        ALTER TABLE connector_sdk.connector_webhook_inbox
          ADD CONSTRAINT connector_webhook_inbox_tenant_webhook_fkey
          FOREIGN KEY (tenant_id, webhook_id)
          REFERENCES connector_sdk.connector_webhook_endpoints
            (tenant_id, webhook_id);

        ALTER TABLE connector_sdk.connector_operations
          DROP CONSTRAINT connector_operations_connection_id_fkey;
        ALTER TABLE connector_sdk.connector_operations
          ADD CONSTRAINT connector_operations_tenant_connection_fkey
          FOREIGN KEY (tenant_id, connection_id)
          REFERENCES connector_sdk.connector_connections
            (tenant_id, connection_id);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE connector_sdk.connector_operations
          DROP CONSTRAINT connector_operations_tenant_connection_fkey;
        ALTER TABLE connector_sdk.connector_operations
          ADD CONSTRAINT connector_operations_connection_id_fkey
          FOREIGN KEY (connection_id)
          REFERENCES connector_sdk.connector_connections (connection_id);

        ALTER TABLE connector_sdk.connector_webhook_inbox
          DROP CONSTRAINT connector_webhook_inbox_tenant_webhook_fkey;
        ALTER TABLE connector_sdk.connector_webhook_inbox
          ADD CONSTRAINT connector_webhook_inbox_webhook_id_fkey
          FOREIGN KEY (webhook_id)
          REFERENCES connector_sdk.connector_webhook_endpoints (webhook_id);

        ALTER TABLE connector_sdk.connector_webhook_event_keys
          DROP CONSTRAINT connector_webhook_event_keys_tenant_webhook_fkey;
        ALTER TABLE connector_sdk.connector_webhook_event_keys
          ADD CONSTRAINT connector_webhook_event_keys_webhook_id_fkey
          FOREIGN KEY (webhook_id)
          REFERENCES connector_sdk.connector_webhook_endpoints (webhook_id);

        ALTER TABLE connector_sdk.connector_webhook_endpoints
          DROP CONSTRAINT connector_webhook_endpoints_tenant_connection_fkey;
        ALTER TABLE connector_sdk.connector_webhook_endpoints
          ADD CONSTRAINT connector_webhook_endpoints_connection_id_fkey
          FOREIGN KEY (connection_id)
          REFERENCES connector_sdk.connector_connections (connection_id);

        ALTER TABLE connector_sdk.connector_webhook_endpoints
          DROP CONSTRAINT connector_webhook_endpoints_tenant_webhook_key;
        ALTER TABLE connector_sdk.connector_connections
          DROP CONSTRAINT connector_connections_tenant_connection_key;
        """
    )
