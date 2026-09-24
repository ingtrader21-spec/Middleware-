"""Separate Odoo campaign control from n8n automation results.

Revision ID: 0066_reconcile_odoo_campaign_scope
Revises: 0065_lifecycle_outcome_state

Contract source: contracts/odoo/campaign-control.v1.json. ``ROUTES`` below is
a static snapshot of that catalog's ``registered_by == "0066"`` operations and
``CATALOG_SHA256`` pins the catalog's canonical hash; tests assert exact parity
so the catalog cannot drift from what this revision seeded. Alembic never
reads the JSON file at upgrade time.

- Retires the 0054 ``odoo.campaign_actions.apply`` route by kill switch. Its
  Odoo path collided with Odoo's own campaign lifecycle command route. The
  0054 rows are neither rewritten nor removed, and ``downgrade`` never
  re-enables them.
- Registers ``odoo.automation_results.apply`` (n8n CRM actions),
  ``odoo.provider_activities.create`` (VICIdial/Telnexa projection),
  ``odoo.campaign.actual_state.write`` (saga readback) and the two
  campaign-control reads.
- Creates ``odoo_campaign_saga``: exactly one saga per accepted Odoo
  campaign-control outbox event.

Binding policy: staging reads unscoped; staging writes bound to TEST_SYN only;
production reads unscoped; production writes ``kill_switch=true`` until a
separate reviewed activation revision.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0066_reconcile_odoo_campaign_scope"
down_revision = "0065_lifecycle_outcome_state"
branch_labels = None
depends_on = None

CATALOG_PATH = "contracts/odoo/campaign-control.v1.json"
CATALOG_SHA256 = "874711f3a8c38bfb2c69169d5f7c1717897d48419ce60bf5649a899f023e1e03"
LEGACY_0054_ENDPOINT_VERSION_ID = "54000000-0000-4000-8000-000000000023"

# (endpoint_id, operation, endpoint_key, method, path, scope, kind, request_schema)
ROUTES = (
    ("66000000-0000-4000-8000-000000000011", "automation_results.apply", "odoo.automation_results.apply", "POST", "/api/v1/integration/automation-results", "odoo.integration.automation_results.write", "write", "internal://odoo/automation-results/v1"),
    ("66000000-0000-4000-8000-000000000012", "provider_activities.create", "odoo.provider_activities.create", "POST", "/api/v1/integration/provider-activities", "odoo.integration.provider_activities.write", "write", "internal://odoo/provider-activities/v1"),
    ("66000000-0000-4000-8000-000000000013", "campaign.actual_state.write", "odoo.campaign.actual_state.write", "POST", "/api/v1/integration/campaigns/actual-state", "odoo.campaign.actual_state.write", "write", "internal://odoo/campaigns/actual-state/v1"),
    ("66000000-0000-4000-8000-000000000014", "campaigns.read", "odoo.campaigns.read", "POST", "/api/v1/integration/campaigns/read", "odoo.campaign.control.read", "read", "internal://odoo/campaigns/read/v1"),
    ("66000000-0000-4000-8000-000000000015", "desired_state.read", "odoo.desired_state.read", "POST", "/api/v1/integration/desired-state/read", "odoo.campaign.control.read", "read", "internal://odoo/desired-state/read/v1"),
)

TEST_SYN_BINDING = ("TEST_SYN_TENANT", "TEST_SYN", "TEST_SYN")

ENVIRONMENTS = (
    # environment, base_url, credential, audience, tls_profile, version_prefix, configuration_version, write_kill_switch, write_binding
    ("staging", "http://odoo19-staging:8069", "secret://staging/odoo-results-client", "codestra-odoo-integration", "staging-internal", 66, 1, False, TEST_SYN_BINDING),
    ("production", "https://odoo.internal.codestra.agency", "secret://production/odoo-results-client", "codestra-odoo", "production-internal-ca", 67, 2, True, ("", "", "")),
)


def _insert_routes(environment, base_url, credential, audience, tls_profile, version_prefix, configuration_version, write_kill_switch, write_binding):
    connection = op.get_bind()
    for index, (endpoint_id, _operation, endpoint_key, method, path, scope, kind, schema_reference) in enumerate(ROUTES, start=1):
        is_write = kind == "write"
        endpoint_version_id = f"66000000-0000-4000-{version_prefix:04d}-{index:012d}"
        binding_id = f"66000000-0000-5000-{version_prefix:04d}-{index:012d}"
        schema_id = f"66000000-0000-6000-0000-{index:012d}"
        checksum = f"sha256:{version_prefix:02x}" + "0" * 62
        connection.execute(sa.text(
            """
            INSERT INTO integration_endpoint(endpoint_id,service_id,endpoint_key,api_version)
            SELECT CAST(:endpoint_id AS uuid), service_id, :endpoint_key, 'v1'
              FROM integration_service
             WHERE service_key='odoo'
            ON CONFLICT (service_id,endpoint_key,api_version) DO NOTHING
            """),
            {"endpoint_id": endpoint_id, "endpoint_key": endpoint_key},
        )
        connection.execute(sa.text(
            """
            INSERT INTO integration_schema_version
              (schema_version_id,service_key,endpoint_key,api_version,
               schema_reference,checksum,enabled)
            VALUES
              (CAST(:schema_id AS uuid),'odoo',:endpoint_key,'v1',
               :schema_reference,:checksum,true)
            ON CONFLICT (service_key,endpoint_key,api_version)
            DO UPDATE SET enabled=true, schema_reference=EXCLUDED.schema_reference,
                          checksum=EXCLUDED.checksum
            """),
            {
                "schema_id": schema_id,
                "endpoint_key": endpoint_key,
                "schema_reference": schema_reference,
                "checksum": checksum,
            },
        )
        connection.execute(sa.text(
            """
            INSERT INTO integration_endpoint_version
              (endpoint_version_id,endpoint_id,configuration_version,base_url,
               path_template,http_method,content_type,authentication_mode,
               required_audience,required_scopes,credential_reference_id,
               tls_profile_id,timeout_ms,connection_timeout_ms,rate_limit_per_minute,
               concurrency_limit,idempotency_required,retry_class,retry_limit,
               redirects_allowed,target_attestation_required,stale_read_safe,enabled,
               kill_switch,configuration_checksum,effective_at,created_by,approved_by)
            VALUES
              (CAST(:version_id AS uuid),
               CAST(:endpoint_id AS uuid),:configuration_version,:base_url,:path,:method,
               'application/json','oauth2_client_secret',:audience,
               jsonb_build_array(CAST(:scope AS text)),:credential,:tls_profile,
               10000,3000,60,4,:idempotency,
               'BOUNDED_TRANSIENT_RETRY',3,false,false,:stale,true,:kill_switch,
               :checksum,now(),'campaign-crm-control-plane','protected-review-required')
            ON CONFLICT (endpoint_id,configuration_version) DO NOTHING
            """),
            {
                "version_id": endpoint_version_id,
                "endpoint_id": endpoint_id,
                "configuration_version": configuration_version,
                "base_url": base_url,
                "path": path,
                "method": method,
                "audience": audience,
                "scope": scope,
                "credential": credential,
                "tls_profile": tls_profile,
                "idempotency": is_write,
                "stale": not is_write,
                "kill_switch": is_write and write_kill_switch,
                "checksum": checksum,
            },
        )
        organization, business_unit, campaign = write_binding if is_write else ("", "", "")
        connection.execute(sa.text(
            """
            INSERT INTO integration_route_binding
              (binding_id,endpoint_version_id,environment,
               organization_scope,business_unit_scope,campaign_scope)
            VALUES (CAST(:binding_id AS uuid),CAST(:version_id AS uuid),:environment,
                    :organization,:business_unit,:campaign)
            ON CONFLICT DO NOTHING
            """),
            {
                "binding_id": binding_id,
                "version_id": endpoint_version_id,
                "environment": environment,
                "organization": organization,
                "business_unit": business_unit,
                "campaign": campaign,
            },
        )


def upgrade() -> None:
    # This revision id is 34 characters; Alembic creates
    # public.alembic_version.version_num as VARCHAR(32) and stamps the id after
    # upgrade() returns, in the same transaction. Widen the column first so the
    # stamp fits. Idempotent, never shrunk on downgrade, touches no business
    # table. Every earlier revision id fits either width.
    op.execute(
        """
        ALTER TABLE public.alembic_version
        ALTER COLUMN version_num TYPE VARCHAR(64)
        """
    )
    # Retire, never rewrite: the 0054 campaign-actions route is kill-switched.
    op.execute(
        f"""
        UPDATE integration_endpoint_version
           SET kill_switch = true
         WHERE endpoint_version_id = '{LEGACY_0054_ENDPOINT_VERSION_ID}'
        """
    )
    op.create_table(
        "odoo_campaign_saga",
        sa.Column("saga_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("integration_event_id", sa.BigInteger(), sa.ForeignKey("integration_event.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("event_uuid", sa.String(128), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("operation", sa.String(32), nullable=False),
        sa.Column("command_id", sa.String(128), nullable=False),
        sa.Column("organization_public_id", sa.String(128), nullable=False),
        sa.Column("business_unit_public_id", sa.String(128), nullable=False),
        sa.Column("campaign_public_id", sa.String(128), nullable=False),
        sa.Column("configuration_version", sa.Integer(), nullable=False),
        sa.Column("manifest_ref", sa.String(256), nullable=False),
        sa.Column("manifest_hash", sa.String(80), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reserved_at", sa.DateTime(timezone=True)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_class", sa.String(64)),
        sa.Column("effective_state", sa.String(32)),
        sa.Column("evidence_json", postgresql.JSONB()),
        sa.Column("observed_at", sa.DateTime(timezone=True)),
        sa.Column("readback_idempotency_key", sa.String(160)),
        sa.Column("readback_attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("readback_id", sa.String(128)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("integration_event_id", name="uq_odoo_campaign_saga_event"),
        sa.CheckConstraint(
            "status IN ('PENDING','RESERVED','RETRY','COMPLETED','DEAD_LETTER')",
            name="ck_odoo_campaign_saga_status",
        ),
        sa.CheckConstraint(
            "effective_state IS NULL OR effective_state IN "
            "('unknown','absent','provisioned_disabled','synthetic_tested','active','disabled')",
            name="ck_odoo_campaign_saga_effective_state",
        ),
    )
    op.create_index("ix_odoo_campaign_saga_claim", "odoo_campaign_saga", ["status", "next_attempt_at"])
    for environment in ENVIRONMENTS:
        _insert_routes(*environment)


def downgrade() -> None:
    # The 0054 route stays kill-switched on purpose: downgrading this revision
    # must never silently re-expose the colliding campaign-actions path.
    # Saga history is evidence; refuse a destructive downgrade while any exists.
    remaining = op.get_bind().execute(sa.text("SELECT count(*) FROM odoo_campaign_saga")).scalar()
    if remaining:
        raise RuntimeError(
            f"refusing downgrade: {remaining} odoo_campaign_saga rows would be destroyed; "
            "archive them through a reviewed change first"
        )
    op.execute("DELETE FROM integration_route_binding WHERE binding_id::text LIKE '66000000-%'")
    op.execute("DELETE FROM integration_endpoint_version WHERE endpoint_version_id::text LIKE '66000000-%'")
    op.execute("DELETE FROM integration_schema_version WHERE schema_version_id::text LIKE '66000000-%'")
    op.execute("DELETE FROM integration_endpoint WHERE endpoint_id::text LIKE '66000000-%'")
    op.drop_index("ix_odoo_campaign_saga_claim", table_name="odoo_campaign_saga")
    op.drop_table("odoo_campaign_saga")
