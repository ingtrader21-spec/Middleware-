"""Add the reusable website registry and durable public intake boundary.

Revision ID: 0032_website_gateway_registry
Revises: 0031_social_provider_callbacks
"""

from alembic import op


revision = "0032_website_gateway_registry"
down_revision = "0031_social_provider_callbacks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE website_site (
      id uuid PRIMARY KEY, site_id varchar(64) NOT NULL UNIQUE,
      site_slug varchar(64) NOT NULL UNIQUE, display_name varchar(128) NOT NULL,
      organization_id varchar(128) NOT NULL, approved_domains jsonb NOT NULL DEFAULT '[]',
      allowed_cors_origins jsonb NOT NULL DEFAULT '[]', environment varchar(24) NOT NULL,
      status varchar(24) NOT NULL DEFAULT 'pending_verification',
      credential_scopes jsonb NOT NULL DEFAULT '[]', rate_limit_policy jsonb NOT NULL DEFAULT '{}',
      routing_profile jsonb NOT NULL DEFAULT '{}', default_language varchar(8) NOT NULL DEFAULT 'en',
      default_country varchar(2), odoo_mapping jsonb NOT NULL DEFAULT '{}',
      vicidial_mapping jsonb NOT NULL DEFAULT '{}', n8n_workflow_routing jsonb NOT NULL DEFAULT '{}',
      webhook_subscriptions jsonb NOT NULL DEFAULT '[]', kill_switch boolean NOT NULL DEFAULT true,
      owner_ref varchar(128), created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      CHECK (status IN ('pending_verification','active','disabled','revoked')),
      CHECK (environment IN ('test','staging','production'))
    )""")
    op.execute("CREATE INDEX ix_website_site_org ON website_site(organization_id, status)")
    op.execute("""CREATE TABLE website_site_credential (
      id uuid PRIMARY KEY, site_pk uuid NOT NULL REFERENCES website_site(id) ON DELETE RESTRICT,
      key_id varchar(64) NOT NULL UNIQUE, secret_hash char(64) NOT NULL,
      credential_fingerprint char(16) NOT NULL, scopes jsonb NOT NULL,
      environment varchar(24) NOT NULL, organization_id varchar(128) NOT NULL,
      status varchar(16) NOT NULL DEFAULT 'active', expires_at timestamptz,
      rotated_from uuid REFERENCES website_site_credential(id) ON DELETE RESTRICT,
      created_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz,
      last_used_at timestamptz,
      CHECK (status IN ('active','rotating','revoked','expired'))
    )""")
    op.execute("CREATE INDEX ix_website_credential_site ON website_site_credential(site_pk, status)")
    op.execute("""CREATE TABLE website_submission (
      id uuid PRIMARY KEY, submission_id varchar(72) NOT NULL UNIQUE,
      external_submission_id varchar(128) NOT NULL, site_pk uuid NOT NULL REFERENCES website_site(id),
      organization_id varchar(128) NOT NULL, form_type varchar(40) NOT NULL,
      payload jsonb NOT NULL, encrypted_payload bytea NOT NULL,
      payload_sha256 char(64) NOT NULL,
      idempotency_key varchar(128) NOT NULL, correlation_id varchar(128) NOT NULL,
      consent boolean NOT NULL, consent_timestamp timestamptz,
      privacy_policy_version varchar(64), state varchar(32) NOT NULL DEFAULT 'accepted',
      odoo_reference varchar(128), created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(site_pk, idempotency_key), UNIQUE(site_pk, external_submission_id),
      CHECK (state IN ('accepted','automation_queued','automation_completed','odoo_mocked','delivery_failed','dead_letter'))
    )""")
    op.execute("CREATE INDEX ix_website_submission_org_created ON website_submission(organization_id, created_at)")
    op.execute("""CREATE TABLE website_delivery (
      id uuid PRIMARY KEY, submission_pk uuid NOT NULL REFERENCES website_submission(id) ON DELETE RESTRICT,
      organization_id varchar(128) NOT NULL, target varchar(24) NOT NULL,
      binding_key varchar(128) NOT NULL, state varchar(32) NOT NULL DEFAULT 'blocked',
      attempt_count integer NOT NULL DEFAULT 0, max_attempts integer NOT NULL DEFAULT 5,
      next_attempt_at timestamptz, lease_owner varchar(128), lease_expires_at timestamptz,
      last_error_code varchar(64), response_reference varchar(128),
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(submission_pk,target,binding_key),
      CHECK (target IN ('n8n','odoo','vicidial','webhook')),
      CHECK (state IN ('blocked','queued','leased','succeeded','retry_wait','dead_letter','cancelled')),
      CHECK (attempt_count >= 0 AND max_attempts BETWEEN 1 AND 10)
    )""")
    op.execute("CREATE INDEX ix_website_delivery_queue ON website_delivery(target,state,next_attempt_at,created_at)")
    op.execute("""CREATE TABLE managed_webhook_subscription (
      id uuid PRIMARY KEY, public_id varchar(72) NOT NULL UNIQUE,
      organization_id varchar(128) NOT NULL, site_pk uuid REFERENCES website_site(id) ON DELETE RESTRICT,
      destination_url text NOT NULL, event_categories jsonb NOT NULL,
      encrypted_secret bytea NOT NULL, key_version integer NOT NULL,
      previous_encrypted_secret bytea, previous_key_expires_at timestamptz,
      secret_fingerprint char(16) NOT NULL, status varchar(16) NOT NULL DEFAULT 'disabled',
      rate_limit_per_minute integer NOT NULL DEFAULT 30,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      CHECK (status IN ('disabled','active','rotating','revoked')),
      CHECK (rate_limit_per_minute BETWEEN 1 AND 600)
    )""")
    op.execute("CREATE INDEX ix_managed_webhook_org ON managed_webhook_subscription(organization_id,status)")
    op.execute("""CREATE TABLE managed_webhook_delivery (
      id uuid PRIMARY KEY, subscription_id uuid NOT NULL REFERENCES managed_webhook_subscription(id) ON DELETE RESTRICT,
      organization_id varchar(128) NOT NULL, event_id varchar(128) NOT NULL,
      event_category varchar(64) NOT NULL, event_version varchar(16) NOT NULL DEFAULT '1.0',
      encrypted_payload bytea, payload_sha256 char(64) NOT NULL,
      state varchar(24) NOT NULL DEFAULT 'blocked', attempt_count integer NOT NULL DEFAULT 0,
      max_attempts integer NOT NULL DEFAULT 5, next_attempt_at timestamptz,
      lease_owner varchar(128), lease_expires_at timestamptz, last_error_code varchar(64),
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(subscription_id,event_id),
      CHECK (state IN ('blocked','queued','leased','succeeded','retry_wait','dead_letter','cancelled')),
      CHECK (attempt_count >= 0 AND max_attempts BETWEEN 1 AND 10)
    )""")
    op.execute("CREATE INDEX ix_managed_webhook_delivery_queue ON managed_webhook_delivery(state,next_attempt_at,created_at)")
    op.execute("""CREATE TABLE managed_webhook_attempt (
      id bigserial PRIMARY KEY,
      delivery_id uuid NOT NULL REFERENCES managed_webhook_delivery(id) ON DELETE RESTRICT,
      attempt_number integer NOT NULL, outcome varchar(32) NOT NULL,
      http_status integer, error_code varchar(64), duration_ms integer NOT NULL,
      response_bytes integer NOT NULL DEFAULT 0, occurred_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(delivery_id,attempt_number),
      CHECK (outcome IN ('succeeded','temporary_failure','permanent_failure','timeout','tls_failure','blocked')),
      CHECK (duration_ms >= 0 AND response_bytes >= 0)
    )""")
    op.execute("""CREATE TABLE website_rate_limit_bucket (
      site_pk uuid NOT NULL REFERENCES website_site(id) ON DELETE CASCADE,
      dimension varchar(24) NOT NULL, subject_hash char(64) NOT NULL,
      window_started_at timestamptz NOT NULL, request_count integer NOT NULL,
      PRIMARY KEY(site_pk, dimension, subject_hash, window_started_at),
      CHECK (request_count >= 1)
    )""")
    op.execute("""CREATE TABLE website_audit_record (
      id bigserial PRIMARY KEY, site_pk uuid REFERENCES website_site(id) ON DELETE RESTRICT,
      organization_id varchar(128) NOT NULL, action varchar(64) NOT NULL,
      actor_ref varchar(128) NOT NULL, correlation_id varchar(128) NOT NULL,
      safe_details jsonb NOT NULL DEFAULT '{}', occurred_at timestamptz NOT NULL DEFAULT now()
    )""")
    op.execute("CREATE INDEX ix_website_audit_site ON website_audit_record(site_pk, occurred_at)")
    op.execute("""CREATE OR REPLACE FUNCTION deny_website_audit_mutation() RETURNS trigger AS $$
      BEGIN RAISE EXCEPTION 'website audit records are append-only'; END; $$ LANGUAGE plpgsql""")
    op.execute("""CREATE TRIGGER website_audit_append_only BEFORE UPDATE OR DELETE
      ON website_audit_record FOR EACH ROW EXECUTE FUNCTION deny_website_audit_mutation()""")
    op.execute("""INSERT INTO website_site
      (id,site_id,site_slug,display_name,organization_id,environment,status,kill_switch)
      VALUES
      ('00000000-0000-4000-8000-000000000001','SITE-CODESTRA','codestra-co','Codestra.co','UNVERIFIED','staging','pending_verification',true),
      ('00000000-0000-4000-8000-000000000002','SITE-SOCIAL-CODESTRA','social-codestra-co','Social.codestra.co','UNVERIFIED','staging','pending_verification',true),
      ('00000000-0000-4000-8000-000000000003','SITE-MOY-LOGISTICS','moy-logistics','Moy Logistics','UNVERIFIED','staging','pending_verification',true),
      ('00000000-0000-4000-8000-000000000004','SITE-MONEYBEE','moneybee','MoneyBee','UNVERIFIED','staging','pending_verification',true),
      ('00000000-0000-4000-8000-000000000005','SITE-SENIOR-CITIZEN-PRODUCTS','senior-citizen-products','Senior Citizen Products','UNVERIFIED','staging','pending_verification',true),
      ('00000000-0000-4000-8000-000000000006','SITE-CALDERON-FARM','calderon-farm','Calderon Farm','UNVERIFIED','staging','pending_verification',true)""")


def downgrade() -> None:
    op.execute("DROP TRIGGER website_audit_append_only ON website_audit_record")
    op.execute("DROP FUNCTION deny_website_audit_mutation()")
    op.execute("DROP TABLE website_audit_record")
    op.execute("DROP TABLE website_rate_limit_bucket")
    op.execute("DROP TABLE managed_webhook_attempt")
    op.execute("DROP TABLE managed_webhook_delivery")
    op.execute("DROP TABLE managed_webhook_subscription")
    op.execute("DROP TABLE website_delivery")
    op.execute("DROP TABLE website_submission")
    op.execute("DROP TABLE website_site_credential")
    op.execute("DROP TABLE website_site")
