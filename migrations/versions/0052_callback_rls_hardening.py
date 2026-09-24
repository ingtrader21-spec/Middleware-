"""Callback tenant RLS, popup acknowledgements, and delivery message binding.

Revision ID: 0052_callback_rls_hardening
Revises: 0051_callback_management
"""

from alembic import op

revision = "0052_callback_rls_hardening"
down_revision = "0051_callback_management"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE callback_record ADD COLUMN assigned_user_id varchar(128)")
    op.execute(
        "ALTER TABLE callback_record ADD COLUMN context_json jsonb NOT NULL DEFAULT '{}'::jsonb"
    )
    op.execute("ALTER TABLE callback_delivery ADD COLUMN message_id uuid")
    op.execute("""CREATE TABLE callback_popup_ack (
      callback_id uuid NOT NULL REFERENCES callback_record(id) ON DELETE RESTRICT,
      callback_version integer NOT NULL, agent_id varchar(128) NOT NULL,
      browser_session_id varchar(128) NOT NULL, status varchar(32) NOT NULL,
      acknowledged_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY(callback_id,callback_version))""")
    for table in (
        "callback_record",
        "callback_event",
        "callback_delivery",
        "callback_popup_ack",
    ):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    callback_scope = """tenant_id = NULLIF(current_setting('app.tenant_id', true),'')
      AND campaign_id = ANY(string_to_array(NULLIF(current_setting('app.campaign_ids', true),''), ','))
      AND (NULLIF(current_setting('app.role', true),'') IN
             ('service','scheduler','supervisor','campaign_manager','call_center_admin','owner','qa')
           OR assigned_agent_id = NULLIF(current_setting('app.actor_id', true),'')
           OR assigned_user_id = NULLIF(current_setting('app.actor_id', true),'')
           OR assigned_team_id = ANY(string_to_array(NULLIF(current_setting('app.team_ids', true),''), ',')))"""
    op.execute(f"""CREATE POLICY callback_record_scope ON callback_record
      USING ({callback_scope}) WITH CHECK ({callback_scope})""")
    op.execute("""CREATE POLICY callback_event_tenant ON callback_event
      USING (tenant_id = NULLIF(current_setting('app.tenant_id', true),''))
      WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true),''))""")
    op.execute("""CREATE POLICY callback_delivery_tenant ON callback_delivery USING (
      EXISTS (SELECT 1 FROM callback_record r WHERE r.id=callback_delivery.callback_id
        AND r.tenant_id=NULLIF(current_setting('app.tenant_id',true),''))) WITH CHECK (
      EXISTS (SELECT 1 FROM callback_record r WHERE r.id=callback_delivery.callback_id
        AND r.tenant_id=NULLIF(current_setting('app.tenant_id',true),'')))""")
    op.execute("""CREATE POLICY callback_popup_ack_tenant ON callback_popup_ack USING (
      EXISTS (SELECT 1 FROM callback_record r WHERE r.id=callback_popup_ack.callback_id
        AND r.tenant_id=NULLIF(current_setting('app.tenant_id',true),''))) WITH CHECK (
      EXISTS (SELECT 1 FROM callback_record r WHERE r.id=callback_popup_ack.callback_id
        AND r.tenant_id=NULLIF(current_setting('app.tenant_id',true),'')))""")
    op.execute("""DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mw_integration_api') THEN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mw_integration_api' AND rolbypassrls) THEN
        RAISE EXCEPTION 'mw_integration_api must be NOBYPASSRLS before callback migration';
      END IF;
      GRANT SELECT,INSERT,UPDATE ON callback_popup_ack TO mw_integration_api;
    END IF; END $$""")


def downgrade() -> None:
    op.execute("DROP POLICY callback_popup_ack_tenant ON callback_popup_ack")
    op.execute("DROP POLICY callback_delivery_tenant ON callback_delivery")
    op.execute("DROP POLICY callback_event_tenant ON callback_event")
    op.execute("DROP POLICY callback_record_scope ON callback_record")
    for table in (
        "callback_popup_ack",
        "callback_delivery",
        "callback_event",
        "callback_record",
    ):
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP TABLE callback_popup_ack")
    op.execute("ALTER TABLE callback_delivery DROP COLUMN message_id")
    op.execute("ALTER TABLE callback_record DROP COLUMN context_json")
    op.execute("ALTER TABLE callback_record DROP COLUMN assigned_user_id")
