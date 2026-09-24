"""Create Connector Runtime v1 storage.

Revision ID: 20260828_0001
Revises: None
"""
from __future__ import annotations

from alembic import op

revision = "20260828_0001"
down_revision = None
branch_labels = ("connector_runtime",)
depends_on = None

UP_SQL = r'''
CREATE SCHEMA IF NOT EXISTS connector_sdk;
CREATE OR REPLACE FUNCTION connector_sdk.touch_versioned_row() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at=now(); NEW.resource_version=OLD.resource_version+1; RETURN NEW; END; $$;
CREATE OR REPLACE FUNCTION connector_sdk.reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'append-only table % cannot be modified', TG_TABLE_NAME USING ERRCODE='55000'; END; $$;

CREATE TABLE connector_sdk.connector_manifests (
 connector_id text NOT NULL, version text NOT NULL, manifest_digest text NOT NULL,
 manifest jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), created_by_subject text NOT NULL,
 PRIMARY KEY(connector_id,version), UNIQUE(connector_id,version,manifest_digest),
 CHECK(connector_id ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
 CHECK(version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$'),
 CHECK(manifest_digest ~ '^sha256:[a-f0-9]{64}$'), CHECK(jsonb_typeof(manifest)='object'),
 CHECK((manifest->>'enabled_by_default')::boolean IS FALSE), CHECK((manifest->>'direct_n8n_access')::boolean IS FALSE));

CREATE TABLE connector_sdk.connector_installations (
 installation_id uuid PRIMARY KEY, connector_id text NOT NULL, environment text NOT NULL, cell text NOT NULL,
 current_version text NOT NULL, current_manifest_digest text NOT NULL, state text NOT NULL,
 resource_version bigint NOT NULL DEFAULT 1, activated_at timestamptz, suspended_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(connector_id,environment),
 FOREIGN KEY(connector_id,current_version,current_manifest_digest)
  REFERENCES connector_sdk.connector_manifests(connector_id,version,manifest_digest),
 CHECK(environment IN('development','staging','production')),
 CHECK(cell IN('core-communications','beyvra-financial','telephony-private')),
 CHECK(state IN('DECLARED','VALIDATED','INSTALLED_DISABLED','ACTIVE','SUSPENDED','FAILED')),
 CHECK(current_manifest_digest ~ '^sha256:[a-f0-9]{64}$'), CHECK(resource_version>0));
CREATE TRIGGER connector_installations_touch BEFORE UPDATE ON connector_sdk.connector_installations
 FOR EACH ROW EXECUTE FUNCTION connector_sdk.touch_versioned_row();

CREATE TABLE connector_sdk.connector_connections (
 connection_id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
 installation_id uuid NOT NULL REFERENCES connector_sdk.connector_installations(installation_id),
 external_account_reference text, provider_account_hash text NOT NULL,
 configuration jsonb NOT NULL DEFAULT '{}'::jsonb, secret_references jsonb NOT NULL DEFAULT '[]'::jsonb,
 state text NOT NULL, resource_version bigint NOT NULL DEFAULT 1,
 last_tested_at timestamptz, last_test_code text, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,installation_id,provider_account_hash), CHECK(provider_account_hash ~ '^[a-f0-9]{64}$'),
 CHECK(jsonb_typeof(configuration)='object'), CHECK(jsonb_typeof(secret_references)='array'),
 CHECK(state IN('PENDING','READY','DEGRADED','DISABLED','FAILED')), CHECK(resource_version>0));
CREATE TRIGGER connector_connections_touch BEFORE UPDATE ON connector_sdk.connector_connections
 FOR EACH ROW EXECUTE FUNCTION connector_sdk.touch_versioned_row();

CREATE TABLE connector_sdk.connector_webhook_endpoints (
 webhook_id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
 connection_id uuid NOT NULL REFERENCES connector_sdk.connector_connections(connection_id),
 endpoint_key text NOT NULL, route_template text NOT NULL, public_path text NOT NULL UNIQUE,
 secret_reference_current text NOT NULL, secret_reference_previous text, previous_secret_valid_until timestamptz,
 state text NOT NULL, resource_version bigint NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(connection_id,endpoint_key), CHECK(endpoint_key ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
 CHECK(route_template LIKE '/v1/webhooks/%' OR route_template LIKE '/internal/v1/adapters/%'),
 CHECK(public_path LIKE '/v1/webhooks/%' OR public_path LIKE '/internal/v1/adapters/%'),
 CHECK(state IN('DISABLED','ACTIVE','SUSPENDED','FAILED')), CHECK(resource_version>0));
CREATE TRIGGER connector_webhook_endpoints_touch BEFORE UPDATE ON connector_sdk.connector_webhook_endpoints
 FOR EACH ROW EXECUTE FUNCTION connector_sdk.touch_versioned_row();

CREATE TABLE connector_sdk.connector_webhook_event_keys (
 tenant_id uuid NOT NULL, webhook_id uuid NOT NULL REFERENCES connector_sdk.connector_webhook_endpoints(webhook_id),
 event_id text NOT NULL, body_sha256 text NOT NULL, first_received_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 PRIMARY KEY(webhook_id,event_id), CHECK(length(event_id) BETWEEN 1 AND 256),
 CHECK(body_sha256 ~ '^[a-f0-9]{64}$'), CHECK(expires_at>first_received_at));

CREATE TABLE connector_sdk.connector_webhook_inbox (
 inbox_id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
 webhook_id uuid NOT NULL REFERENCES connector_sdk.connector_webhook_endpoints(webhook_id),
 connector_id text NOT NULL, endpoint_key text NOT NULL, event_id text NOT NULL, body_sha256 text NOT NULL,
 encrypted_body_reference text NOT NULL, signature_version text NOT NULL,
 verification_state text NOT NULL, processing_state text NOT NULL, correlation_id uuid NOT NULL, traceparent text,
 received_at timestamptz NOT NULL DEFAULT now(), verified_at timestamptz, processed_at timestamptz, error_code text,
 UNIQUE(webhook_id,event_id), CHECK(body_sha256 ~ '^[a-f0-9]{64}$'),
 CHECK(verification_state IN('PENDING','VERIFIED','REJECTED','SEMANTIC_CONFLICT')),
 CHECK(processing_state IN('PENDING','NORMALIZED','OUTBOXED','COMPLETED','FAILED','DEAD_LETTER')));

CREATE TABLE connector_sdk.connector_idempotency_keys (
 tenant_id uuid NOT NULL, scope text NOT NULL, idempotency_key text NOT NULL, request_sha256 text NOT NULL,
 operation_id uuid, response_status integer, response_body jsonb,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL DEFAULT(now()+interval '7 days'),
 PRIMARY KEY(tenant_id,scope,idempotency_key), CHECK(length(idempotency_key) BETWEEN 8 AND 180),
 CHECK(request_sha256 ~ '^[a-f0-9]{64}$'), CHECK(response_status IS NULL OR response_status BETWEEN 100 AND 599),
 CHECK(response_body IS NULL OR jsonb_typeof(response_body)='object'));

CREATE TABLE connector_sdk.connector_operations (
 operation_id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
 connection_id uuid NOT NULL REFERENCES connector_sdk.connector_connections(connection_id),
 command_id uuid NOT NULL, command_type text NOT NULL, idempotency_key text NOT NULL, request_sha256 text NOT NULL,
 capability text NOT NULL, state text NOT NULL, provider_reference text, resource_version bigint NOT NULL DEFAULT 1,
 safe_result jsonb NOT NULL DEFAULT '{}'::jsonb, error_code text, submitted_at timestamptz, reconciled_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,connection_id,idempotency_key), UNIQUE(tenant_id,command_id),
 CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 CHECK(state IN('ACCEPTED','BLOCKED','SUBMITTED','UNKNOWN','COMPLETED','FAILED','CANCELLED')),
 CHECK(resource_version>0), CHECK(jsonb_typeof(safe_result)='object'));
CREATE TRIGGER connector_operations_touch BEFORE UPDATE ON connector_sdk.connector_operations
 FOR EACH ROW EXECUTE FUNCTION connector_sdk.touch_versioned_row();

CREATE TABLE connector_sdk.connector_dead_letters (
 dead_letter_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, aggregate_type text NOT NULL, aggregate_id uuid NOT NULL,
 reason_code text NOT NULL, safe_summary jsonb NOT NULL DEFAULT '{}'::jsonb, original_fingerprint text NOT NULL,
 replay_classification text NOT NULL, state text NOT NULL DEFAULT 'OPEN', resource_version bigint NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK(jsonb_typeof(safe_summary)='object'), CHECK(original_fingerprint ~ '^sha256:[a-f0-9]{64}$'),
 CHECK(replay_classification IN('SAFE','REQUIRES_APPROVAL','UNSAFE')),
 CHECK(state IN('OPEN','APPROVED','REPLAY_SCHEDULED','RESOLVED','REJECTED')));
CREATE TRIGGER connector_dead_letters_touch BEFORE UPDATE ON connector_sdk.connector_dead_letters
 FOR EACH ROW EXECUTE FUNCTION connector_sdk.touch_versioned_row();

CREATE TABLE connector_sdk.connector_outbox (
 outbox_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, aggregate_type text NOT NULL, aggregate_id uuid NOT NULL,
 event_type text NOT NULL, event_version integer NOT NULL, payload jsonb NOT NULL, correlation_id uuid NOT NULL,
 causation_id text NOT NULL, traceparent text, available_at timestamptz NOT NULL DEFAULT now(),
 lease_owner text, lease_expires_at timestamptz, attempt_count integer NOT NULL DEFAULT 0,
 delivered_at timestamptz, last_error_code text, created_at timestamptz NOT NULL DEFAULT now(),
 CHECK(event_version>0), CHECK(attempt_count>=0), CHECK(jsonb_typeof(payload)='object'));

CREATE TABLE connector_sdk.connector_audit_log (
 audit_id uuid PRIMARY KEY, tenant_id uuid, actor_subject text NOT NULL, actor_type text NOT NULL,
 action text NOT NULL, resource_type text NOT NULL, resource_id text NOT NULL, correlation_id uuid NOT NULL,
 request_id text, source_ip inet, user_agent text, safe_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
 created_at timestamptz NOT NULL DEFAULT now(), CHECK(actor_type IN('human','service','system')),
 CHECK(jsonb_typeof(safe_metadata)='object'));
CREATE TRIGGER connector_audit_immutable BEFORE UPDATE OR DELETE ON connector_sdk.connector_audit_log
 FOR EACH ROW EXECUTE FUNCTION connector_sdk.reject_mutation();

CREATE INDEX connector_connections_tenant_state_idx ON connector_sdk.connector_connections(tenant_id,state);
CREATE INDEX connector_webhook_event_expiry_idx ON connector_sdk.connector_webhook_event_keys(expires_at);
CREATE INDEX connector_webhook_inbox_pending_idx ON connector_sdk.connector_webhook_inbox(processing_state,received_at) WHERE processing_state IN('PENDING','FAILED');
CREATE INDEX connector_idempotency_expiry_idx ON connector_sdk.connector_idempotency_keys(expires_at);
CREATE INDEX connector_operations_tenant_state_idx ON connector_sdk.connector_operations(tenant_id,state,created_at);
CREATE INDEX connector_dead_letters_open_idx ON connector_sdk.connector_dead_letters(tenant_id,state,created_at) WHERE state IN('OPEN','APPROVED','REPLAY_SCHEDULED');
CREATE INDEX connector_outbox_available_idx ON connector_sdk.connector_outbox(available_at,created_at) WHERE delivered_at IS NULL;
CREATE INDEX connector_audit_tenant_created_idx ON connector_sdk.connector_audit_log(tenant_id,created_at DESC);

ALTER TABLE connector_sdk.connector_connections ENABLE ROW LEVEL SECURITY; ALTER TABLE connector_sdk.connector_connections FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_webhook_endpoints ENABLE ROW LEVEL SECURITY; ALTER TABLE connector_sdk.connector_webhook_endpoints FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_webhook_event_keys ENABLE ROW LEVEL SECURITY; ALTER TABLE connector_sdk.connector_webhook_event_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_webhook_inbox ENABLE ROW LEVEL SECURITY; ALTER TABLE connector_sdk.connector_webhook_inbox FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_idempotency_keys ENABLE ROW LEVEL SECURITY; ALTER TABLE connector_sdk.connector_idempotency_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_operations ENABLE ROW LEVEL SECURITY; ALTER TABLE connector_sdk.connector_operations FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_dead_letters ENABLE ROW LEVEL SECURITY; ALTER TABLE connector_sdk.connector_dead_letters FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_outbox ENABLE ROW LEVEL SECURITY; ALTER TABLE connector_sdk.connector_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_audit_log ENABLE ROW LEVEL SECURITY; ALTER TABLE connector_sdk.connector_audit_log FORCE ROW LEVEL SECURITY;

CREATE POLICY connector_connections_tenant_policy ON connector_sdk.connector_connections USING(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid);
CREATE POLICY connector_webhook_endpoints_tenant_policy ON connector_sdk.connector_webhook_endpoints USING(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid);
CREATE POLICY connector_webhook_event_keys_tenant_policy ON connector_sdk.connector_webhook_event_keys USING(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid);
CREATE POLICY connector_webhook_inbox_tenant_policy ON connector_sdk.connector_webhook_inbox USING(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid);
CREATE POLICY connector_idempotency_tenant_policy ON connector_sdk.connector_idempotency_keys USING(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid);
CREATE POLICY connector_operations_tenant_policy ON connector_sdk.connector_operations USING(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid);
CREATE POLICY connector_dead_letters_tenant_policy ON connector_sdk.connector_dead_letters USING(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid);
CREATE POLICY connector_outbox_tenant_policy ON connector_sdk.connector_outbox USING(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid);
CREATE POLICY connector_audit_tenant_policy ON connector_sdk.connector_audit_log USING(tenant_id IS NULL OR tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid) WITH CHECK(tenant_id IS NULL OR tenant_id=NULLIF(current_setting('codestra.tenant_id',true),'')::uuid);
'''


def upgrade() -> None:
    op.execute(UP_SQL)


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS connector_sdk CASCADE")
