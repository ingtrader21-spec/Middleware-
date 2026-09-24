"""Add safe public webhook route lookup for the management API.

Revision ID: 20260828_0003
Revises: 20260828_0002
"""
from __future__ import annotations

from alembic import op

revision = "20260828_0003"
down_revision = "20260828_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE connector_sdk.connector_webhook_routes (
            webhook_id uuid PRIMARY KEY,
            tenant_id uuid NOT NULL,
            connector_id text NOT NULL,
            endpoint_key text NOT NULL,
            public_path text NOT NULL UNIQUE,
            created_at timestamptz NOT NULL DEFAULT now(),
            FOREIGN KEY (tenant_id, webhook_id)
                REFERENCES connector_sdk.connector_webhook_endpoints
                    (tenant_id, webhook_id)
                ON DELETE CASCADE,
            CHECK (connector_id ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
            CHECK (endpoint_key ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
            CHECK (public_path LIKE '/v1/webhooks/%')
        );

        COMMENT ON TABLE connector_sdk.connector_webhook_routes IS
          'Secret-free route-to-tenant index used only to establish RLS context for signed webhook ingress';
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TABLE IF EXISTS connector_sdk.connector_webhook_routes"
    )
