"""Service catalog monitoring state: expected vs observed release identity and secret references.

Revision ID: 0067_service_catalog_monitoring_state
Revises: 0066_reconcile_odoo_campaign_scope

Extends ``platform_services`` (the canonical operational catalog) with the
monitoring descriptor the integrated monitoring design proposes: deployment,
host and instance identity; public/private origins; separate liveness and
readiness paths; per-signal collection profiles; Prometheus/Blackbox target
and Grafana dashboard bindings; expected versus observed Git SHA, image
digest, configuration digest and migration head; ``monitoring_state``; and
the last observation and certification timestamps.

``secret_references`` holds OpenBao secret *references* only (provider,
environment, service, path, class, version, identity, rotation and hashed
lease metadata). No column ever holds a secret value; the application layer
rejects value-bearing keys before a row is written.

``platform_service_monitoring_audit`` records every monitoring-state
transition with the evidence hash that justified it. Downgrade removes the
columns and the audit table only when the audit table is empty, so recorded
certification evidence is never destroyed by an application rollback.
"""

from alembic import op

revision = "0067_service_catalog_monitoring_state"
down_revision = "0066_reconcile_odoo_campaign_scope"
branch_labels = None
depends_on = None

MONITORING_STATES = (
    "unregistered",
    "registered",
    "pending",
    "applying",
    "synced",
    "drifted",
    "failed",
    "unknown",
    "certified",
)

COLUMNS = (
    ("deployment_id", "text"),
    ("host_id", "text"),
    ("instance_id", "text"),
    ("public_origin", "text"),
    ("private_origin", "text"),
    ("liveness_path", "text"),
    ("readiness_path", "text"),
    ("metrics_profile", "text"),
    ("logs_profile", "text"),
    ("traces_profile", "text"),
    ("prometheus_target_id", "text"),
    ("blackbox_target_id", "text"),
    ("grafana_dashboard_ids", "jsonb NOT NULL DEFAULT '[]'::jsonb"),
    ("expected_git_sha", "char(40)"),
    ("observed_git_sha", "char(40)"),
    ("expected_image_digest", "text"),
    ("observed_image_digest", "text"),
    ("expected_config_digest", "text"),
    ("observed_config_digest", "text"),
    ("expected_migration_head", "text"),
    ("observed_migration_head", "text"),
    ("secret_references", "jsonb NOT NULL DEFAULT '[]'::jsonb"),
    ("monitoring_state", "text NOT NULL DEFAULT 'unregistered'"),
    ("monitoring_state_reason", "text"),
    ("last_observed_at", "timestamptz"),
    ("last_observation_source", "text"),
    ("last_certified_at", "timestamptz"),
    ("last_certified_by", "text"),
)


def upgrade() -> None:
    for name, definition in COLUMNS:
        op.execute(f"ALTER TABLE platform_services ADD COLUMN {name} {definition}")
    states = ",".join(f"'{state}'" for state in MONITORING_STATES)
    op.execute(
        "ALTER TABLE platform_services ADD CONSTRAINT ck_platform_service_monitoring_state "
        f"CHECK (monitoring_state IN ({states}))"
    )
    op.execute(
        "ALTER TABLE platform_services ADD CONSTRAINT ck_platform_service_secret_references "
        "CHECK (jsonb_typeof(secret_references) = 'array')"
    )
    op.execute(
        "ALTER TABLE platform_services ADD CONSTRAINT ck_platform_service_dashboard_ids "
        "CHECK (jsonb_typeof(grafana_dashboard_ids) = 'array')"
    )
    op.execute("""CREATE TABLE platform_service_monitoring_audit (
      id uuid PRIMARY KEY,
      service_id uuid NOT NULL REFERENCES platform_services(id) ON DELETE RESTRICT,
      from_state text NOT NULL, to_state text NOT NULL,
      reason text NOT NULL, actor text NOT NULL, correlation_id text NOT NULL,
      evidence_hash char(64) NOT NULL, created_at timestamptz NOT NULL
    )""")
    op.execute(
        "CREATE INDEX ix_platform_service_monitoring_audit_service "
        "ON platform_service_monitoring_audit(service_id, created_at)"
    )
    op.execute(
        "CREATE INDEX ix_platform_services_monitoring_state "
        "ON platform_services(monitoring_state, last_observed_at)"
    )


def downgrade() -> None:
    op.execute("""DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM platform_service_monitoring_audit) THEN
        RAISE EXCEPTION 'platform_service_monitoring_audit holds certification evidence; downgrade refused';
      END IF;
    END $$""")
    op.execute("DROP INDEX IF EXISTS ix_platform_services_monitoring_state")
    op.execute("DROP TABLE platform_service_monitoring_audit")
    op.execute(
        "ALTER TABLE platform_services DROP CONSTRAINT ck_platform_service_dashboard_ids"
    )
    op.execute(
        "ALTER TABLE platform_services DROP CONSTRAINT ck_platform_service_secret_references"
    )
    op.execute(
        "ALTER TABLE platform_services DROP CONSTRAINT ck_platform_service_monitoring_state"
    )
    for name, _definition in reversed(COLUMNS):
        op.execute(f"ALTER TABLE platform_services DROP COLUMN {name}")
