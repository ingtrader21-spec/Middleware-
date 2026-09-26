"""Make inherited tenant identity explicit on durable child tables.

Revision ID: 0068_explicit_tenant_child_columns
Revises: 0067_service_catalog_monitoring_state
"""

from alembic import op

revision = "0068_explicit_tenant_child_columns"
down_revision = "0067_service_catalog_monitoring_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Parent composite keys allow children to prove tenant and parent belong
    # to the same tenant instead of relying only on application joins.
    op.execute(
        "ALTER TABLE agent_provisioning_request "
        "ADD CONSTRAINT uq_agent_provisioning_request_tenant_id "
        "UNIQUE (tenant_id, id)"
    )
    op.execute(
        "ALTER TABLE callback_record "
        "ADD CONSTRAINT uq_callback_record_tenant_id UNIQUE (tenant_id, id)"
    )

    op.execute("ALTER TABLE agent_provisioning_step ADD COLUMN tenant_id text")
    op.execute(
        "UPDATE agent_provisioning_step s SET tenant_id=r.tenant_id "
        "FROM agent_provisioning_request r WHERE r.id=s.request_id"
    )
    op.execute(
        "ALTER TABLE agent_provisioning_step ALTER COLUMN tenant_id SET NOT NULL"
    )
    op.execute(
        "ALTER TABLE agent_provisioning_step "
        "ADD CONSTRAINT fk_agent_provisioning_step_tenant_request "
        "FOREIGN KEY (tenant_id, request_id) "
        "REFERENCES agent_provisioning_request(tenant_id, id) ON DELETE RESTRICT"
    )
    op.execute(
        "CREATE INDEX ix_agent_provisioning_step_tenant_request "
        "ON agent_provisioning_step(tenant_id, request_id, system, attempt)"
    )

    op.execute("ALTER TABLE agent_provisioning_audit ADD COLUMN tenant_id text")
    op.execute(
        "UPDATE agent_provisioning_audit a SET tenant_id=r.tenant_id "
        "FROM agent_provisioning_request r WHERE r.id=a.request_id"
    )
    op.execute(
        "ALTER TABLE agent_provisioning_audit ALTER COLUMN tenant_id SET NOT NULL"
    )
    op.execute(
        "ALTER TABLE agent_provisioning_audit "
        "ADD CONSTRAINT fk_agent_provisioning_audit_tenant_request "
        "FOREIGN KEY (tenant_id, request_id) "
        "REFERENCES agent_provisioning_request(tenant_id, id) ON DELETE RESTRICT"
    )
    op.execute(
        "CREATE INDEX ix_agent_provisioning_audit_tenant_request "
        "ON agent_provisioning_audit(tenant_id, request_id, created_at)"
    )

    op.execute(
        "ALTER TABLE callback_delivery ADD COLUMN tenant_id varchar(128)"
    )
    op.execute(
        "UPDATE callback_delivery d SET tenant_id=r.tenant_id "
        "FROM callback_record r WHERE r.id=d.callback_id"
    )
    op.execute(
        "ALTER TABLE callback_delivery ALTER COLUMN tenant_id SET NOT NULL"
    )
    op.execute(
        "ALTER TABLE callback_delivery "
        "ADD CONSTRAINT fk_callback_delivery_tenant_callback "
        "FOREIGN KEY (tenant_id, callback_id) "
        "REFERENCES callback_record(tenant_id, id) ON DELETE RESTRICT"
    )
    op.execute(
        "CREATE INDEX ix_callback_delivery_tenant_retry "
        "ON callback_delivery(tenant_id, status, next_attempt_at)"
    )

    op.execute(
        "ALTER TABLE callback_popup_ack ADD COLUMN tenant_id varchar(128)"
    )
    op.execute(
        "UPDATE callback_popup_ack a SET tenant_id=r.tenant_id "
        "FROM callback_record r WHERE r.id=a.callback_id"
    )
    op.execute(
        "ALTER TABLE callback_popup_ack ALTER COLUMN tenant_id SET NOT NULL"
    )
    op.execute(
        "ALTER TABLE callback_popup_ack "
        "ADD CONSTRAINT fk_callback_popup_ack_tenant_callback "
        "FOREIGN KEY (tenant_id, callback_id) "
        "REFERENCES callback_record(tenant_id, id) ON DELETE RESTRICT"
    )
    op.execute(
        "CREATE INDEX ix_callback_popup_ack_tenant_callback "
        "ON callback_popup_ack(tenant_id, callback_id, callback_version)"
    )

    # Replace parent-join RLS checks with direct transaction-local tenant checks
    # now that each child row carries its own explicit tenant identity.
    op.execute("DROP POLICY callback_delivery_tenant ON callback_delivery")
    op.execute(
        """CREATE POLICY callback_delivery_tenant ON callback_delivery
        USING (tenant_id = NULLIF(current_setting('app.tenant_id', true),''))
        WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true),''))"""
    )
    op.execute("DROP POLICY callback_popup_ack_tenant ON callback_popup_ack")
    op.execute(
        """CREATE POLICY callback_popup_ack_tenant ON callback_popup_ack
        USING (tenant_id = NULLIF(current_setting('app.tenant_id', true),''))
        WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true),''))"""
    )


def downgrade() -> None:
    op.execute("DROP POLICY callback_popup_ack_tenant ON callback_popup_ack")
    op.execute(
        """CREATE POLICY callback_popup_ack_tenant ON callback_popup_ack USING (
        EXISTS (SELECT 1 FROM callback_record r WHERE r.id=callback_popup_ack.callback_id
          AND r.tenant_id=NULLIF(current_setting('app.tenant_id',true),''))) WITH CHECK (
        EXISTS (SELECT 1 FROM callback_record r WHERE r.id=callback_popup_ack.callback_id
          AND r.tenant_id=NULLIF(current_setting('app.tenant_id',true),'')))"""
    )
    op.execute("DROP POLICY callback_delivery_tenant ON callback_delivery")
    op.execute(
        """CREATE POLICY callback_delivery_tenant ON callback_delivery USING (
        EXISTS (SELECT 1 FROM callback_record r WHERE r.id=callback_delivery.callback_id
          AND r.tenant_id=NULLIF(current_setting('app.tenant_id',true),''))) WITH CHECK (
        EXISTS (SELECT 1 FROM callback_record r WHERE r.id=callback_delivery.callback_id
          AND r.tenant_id=NULLIF(current_setting('app.tenant_id',true),'')))"""
    )

    op.execute("DROP INDEX ix_callback_popup_ack_tenant_callback")
    op.execute(
        "ALTER TABLE callback_popup_ack "
        "DROP CONSTRAINT fk_callback_popup_ack_tenant_callback"
    )
    op.execute("ALTER TABLE callback_popup_ack DROP COLUMN tenant_id")

    op.execute("DROP INDEX ix_callback_delivery_tenant_retry")
    op.execute(
        "ALTER TABLE callback_delivery "
        "DROP CONSTRAINT fk_callback_delivery_tenant_callback"
    )
    op.execute("ALTER TABLE callback_delivery DROP COLUMN tenant_id")

    op.execute("DROP INDEX ix_agent_provisioning_audit_tenant_request")
    op.execute(
        "ALTER TABLE agent_provisioning_audit "
        "DROP CONSTRAINT fk_agent_provisioning_audit_tenant_request"
    )
    op.execute("ALTER TABLE agent_provisioning_audit DROP COLUMN tenant_id")

    op.execute("DROP INDEX ix_agent_provisioning_step_tenant_request")
    op.execute(
        "ALTER TABLE agent_provisioning_step "
        "DROP CONSTRAINT fk_agent_provisioning_step_tenant_request"
    )
    op.execute("ALTER TABLE agent_provisioning_step DROP COLUMN tenant_id")

    op.execute(
        "ALTER TABLE callback_record "
        "DROP CONSTRAINT uq_callback_record_tenant_id"
    )
    op.execute(
        "ALTER TABLE agent_provisioning_request "
        "DROP CONSTRAINT uq_agent_provisioning_request_tenant_id"
    )
