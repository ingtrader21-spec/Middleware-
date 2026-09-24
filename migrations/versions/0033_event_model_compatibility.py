"""Expand legacy event inbox compatibility without removing either model.

Revision ID: 0033_event_model_compatibility
Revises: 0032_website_gateway_registry
"""

from alembic import op


revision = "0033_event_model_compatibility"
down_revision = "0032_website_gateway_registry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE event_inbox ADD COLUMN organization_id varchar(128)")
    op.execute("ALTER TABLE event_inbox ADD COLUMN schema_version varchar(16)")
    op.execute("ALTER TABLE event_inbox ADD COLUMN idempotency_key varchar(255)")
    op.execute("ALTER TABLE event_inbox ADD COLUMN payload_hash char(64)")
    op.execute("ALTER TABLE event_inbox ADD COLUMN delivery_state varchar(24)")
    op.execute("ALTER TABLE event_inbox ADD COLUMN retry_count integer")
    op.execute("""UPDATE event_inbox SET
      organization_id=COALESCE(NULLIF(payload->>'organization_id',''),'legacy-unassigned'),
      schema_version=COALESCE(NULLIF(payload->>'schema_version',''),'legacy-1.0'),
      idempotency_key=encode(sha256(event_id::bytea),'hex'),
      payload_hash=encode(sha256(payload::text::bytea),'hex'),
      delivery_state=COALESCE(NULLIF(status,''),'accepted'),
      retry_count=COALESCE((
        SELECT MAX(o.attempts) FROM outbox_event o
        WHERE o.correlation_id=event_inbox.correlation_id
      ),0)
      WHERE organization_id IS NULL OR schema_version IS NULL OR idempotency_key IS NULL
         OR payload_hash IS NULL OR delivery_state IS NULL OR retry_count IS NULL""")
    # Expansion fields intentionally remain nullable during the application
    # rollback window. The 0031 writer only knows the legacy columns, so making
    # these fields mandatory would prevent a safe application rollback.
    op.execute("ALTER TABLE event_inbox ALTER COLUMN retry_count SET DEFAULT 0")
    op.execute("CREATE INDEX ix_event_inbox_org_state ON event_inbox(organization_id,delivery_state,created_at)")
    op.execute("""CREATE TABLE event_model_bridge (
      id bigserial PRIMARY KEY,
      event_id varchar(128) NOT NULL UNIQUE,
      event_inbox_id uuid NOT NULL UNIQUE REFERENCES event_inbox(id) ON DELETE RESTRICT,
      integration_event_id bigint NOT NULL UNIQUE REFERENCES integration_event(id) ON DELETE RESTRICT,
      organization_id varchar(128) NOT NULL,
      compatibility_state varchar(24) NOT NULL DEFAULT 'dual_read',
      created_at timestamptz NOT NULL DEFAULT now(),
      CHECK (compatibility_state IN ('backfilled','dual_read','dual_write','canonical'))
    )""")
    op.execute("""INSERT INTO integration_event
      (idempotency_key,event_type,schema_version,original_event_id,source_system,
       correlation_id,payload_json,payload_hash,state,created_at)
      SELECT i.idempotency_key,i.event_type,i.schema_version,i.event_id,i.source,
             i.correlation_id,i.payload,i.payload_hash,i.delivery_state,i.created_at
      FROM event_inbox i
      WHERE NOT EXISTS (
        SELECT 1 FROM integration_event e WHERE e.original_event_id=i.event_id
      )""")
    op.execute("""INSERT INTO event_model_bridge
      (event_id,event_inbox_id,integration_event_id,organization_id,compatibility_state)
      SELECT i.event_id,i.id,e.id,i.organization_id,'backfilled'
      FROM event_inbox i JOIN integration_event e ON e.original_event_id=i.event_id
      ON CONFLICT (event_id) DO NOTHING""")


def downgrade() -> None:
    op.execute("DROP TABLE event_model_bridge")
    op.execute("DROP INDEX ix_event_inbox_org_state")
    op.execute("ALTER TABLE event_inbox DROP COLUMN retry_count")
    op.execute("ALTER TABLE event_inbox DROP COLUMN delivery_state")
    op.execute("ALTER TABLE event_inbox DROP COLUMN payload_hash")
    op.execute("ALTER TABLE event_inbox DROP COLUMN idempotency_key")
    op.execute("ALTER TABLE event_inbox DROP COLUMN schema_version")
    op.execute("ALTER TABLE event_inbox DROP COLUMN organization_id")
