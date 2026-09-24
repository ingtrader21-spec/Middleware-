"""Persist the complete BREERO-to-Odoo event envelope.

Revision ID: 0046_breero_complete_envelope
Revises: 0045_merge_breero_odoo
"""

from alembic import op

revision = "0046_breero_complete_envelope"
down_revision = "0045_merge_breero_odoo"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Ingress has remained disabled. Refuse to invent missing contract values if
    # that invariant is ever violated on a target database.
    op.execute("""DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM breero_event_receipt) THEN
        RAISE EXCEPTION 'BREERO receipts exist; complete-envelope migration requires adjudication';
      END IF;
    END $$""")
    op.execute("""ALTER TABLE breero_event_receipt
      ADD COLUMN schema_version integer NOT NULL,
      ADD COLUMN occurred_at timestamptz NOT NULL,
      ADD COLUMN idempotency_key text NOT NULL,
      ADD COLUMN source text NOT NULL,
      ADD CONSTRAINT ck_breero_schema_version CHECK (schema_version = 1),
      ADD CONSTRAINT ck_breero_source CHECK (source = 'breero'),
      ADD CONSTRAINT ck_breero_idempotency_key CHECK (length(idempotency_key) BETWEEN 1 AND 255)""")


def downgrade() -> None:
    op.execute("""ALTER TABLE breero_event_receipt
      DROP COLUMN source,
      DROP COLUMN idempotency_key,
      DROP COLUMN occurred_at,
      DROP COLUMN schema_version""")
