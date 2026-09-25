"""Durable Section 6 agent lifecycle state.
Revision ID: 0068_agent_provisioning_lifecycle
Revises: 0067_service_catalog_monitoring_state
"""
from alembic import op
revision='0068_agent_provisioning_lifecycle'; down_revision='0067_service_catalog_monitoring_state'; branch_labels=None; depends_on=None

def upgrade():
 op.execute("""CREATE TABLE agent_provisioning_repair_intent (id uuid PRIMARY KEY, request_id uuid NOT NULL REFERENCES agent_provisioning_request(id) ON DELETE RESTRICT, drift_class text NOT NULL, proposed_action text NOT NULL, state text NOT NULL DEFAULT 'PROPOSED', effect_class text NOT NULL DEFAULT 'provider_mutation', authorized_by text, result_code text, created_at timestamptz NOT NULL DEFAULT now(), executed_at timestamptz, CONSTRAINT ck_agent_repair_state CHECK(state IN('PROPOSED','AUTHORIZED','EXECUTING','SUCCEEDED','FAILED','CANCELLED')))""")
 op.execute("CREATE INDEX ix_agent_repair_request ON agent_provisioning_repair_intent(request_id,created_at DESC)")
 op.execute("""CREATE TABLE agent_webrtc_session (id uuid PRIMARY KEY, request_id uuid NOT NULL REFERENCES agent_provisioning_request(id) ON DELETE RESTRICT, tenant_id text NOT NULL, employee_id text NOT NULL, campaign_id text NOT NULL, extension text NOT NULL, provider_reference text, state text NOT NULL DEFAULT 'ISSUED', issued_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL, revoked_at timestamptz, correlation_id text NOT NULL, CONSTRAINT ck_agent_webrtc_state CHECK(state IN('ISSUED','REGISTERING','REGISTERED','EXPIRED','REVOKED','FAILED')))""")
 op.execute("CREATE UNIQUE INDEX uq_agent_webrtc_active_device ON agent_webrtc_session(tenant_id,employee_id) WHERE state IN('ISSUED','REGISTERING','REGISTERED')")

def downgrade():
 op.execute('DROP TABLE agent_webrtc_session')
 op.execute('DROP TABLE agent_provisioning_repair_intent')
