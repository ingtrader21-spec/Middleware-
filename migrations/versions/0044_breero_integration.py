"""BREERO durable ingress, Odoo outbox, audit and reconciliation.

Revision ID: 0044_breero_integration
Revises: 0043_scraper_durable_inbox
"""
from alembic import op

revision = "0044_breero_integration"
down_revision = "0043_scraper_durable_inbox"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE breero_event_receipt (
      public_id text PRIMARY KEY, event_id uuid NOT NULL, event_type text NOT NULL,
      aggregate_id uuid NOT NULL, aggregate_version integer NOT NULL,
      identity text NOT NULL, tenant text NOT NULL, environment text NOT NULL, scope text NOT NULL,
      payload_hash char(64) NOT NULL, idempotency_key_hash char(64) NOT NULL, payload jsonb NOT NULL,
      status text NOT NULL, route_key text NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(identity,event_id), UNIQUE(identity,idempotency_key_hash),
      CHECK (event_type IN ('breero.service_request.created','breero.contact_request.created','breero.provider_interest.created','breero.lead_dispute.created')),
      CHECK (status IN ('queued','processing','retry_wait','delivered','dead_letter')),
      CHECK (aggregate_version > 0))""")
    op.execute("""CREATE TABLE breero_odoo_outbox (
      id uuid PRIMARY KEY, receipt_public_id text NOT NULL UNIQUE REFERENCES breero_event_receipt(public_id) ON DELETE RESTRICT,
      status text NOT NULL, attempts integer NOT NULL DEFAULT 0, next_attempt_at timestamptz,
      lease_token uuid, lease_expires_at timestamptz, last_safe_error text, odoo_model text, odoo_record_id bigint,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      CHECK (attempts >= 0), CHECK (status IN ('pending','leased','retry_wait','delivered','dead_letter')))""")
    op.execute("CREATE INDEX ix_breero_outbox_claim ON breero_odoo_outbox(status,next_attempt_at,lease_expires_at)")
    op.execute("""CREATE TABLE breero_replay_nonce (
      identity text NOT NULL, nonce_hash char(64) NOT NULL, expires_at timestamptz NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(identity,nonce_hash))""")
    op.execute("""CREATE TABLE breero_integration_audit (
      id bigserial PRIMARY KEY, receipt_public_id text REFERENCES breero_event_receipt(public_id) ON DELETE RESTRICT,
      action text NOT NULL, outcome text NOT NULL, safe_detail text, occurred_at timestamptz NOT NULL DEFAULT now())""")
    op.execute("""CREATE TABLE breero_reconciliation_run (
      id uuid PRIMARY KEY, environment text NOT NULL, started_at timestamptz NOT NULL DEFAULT now(),
      completed_at timestamptz, receipt_count integer NOT NULL DEFAULT 0, outbox_count integer NOT NULL DEFAULT 0,
      delivered_count integer NOT NULL DEFAULT 0, gap_count integer NOT NULL DEFAULT 0, evidence jsonb NOT NULL DEFAULT '{}'::jsonb)""")


def downgrade() -> None:
    op.execute("DROP TABLE breero_reconciliation_run, breero_integration_audit, breero_replay_nonce, breero_odoo_outbox, breero_event_receipt")
