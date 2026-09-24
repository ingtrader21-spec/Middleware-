"""Register the Kyyow observability write/read routes in the Odoo registry.

Revision ID: 0061_kyyow_observability_odoo
Revises: 0060_agent_provisioning
"""

from alembic import op
import sqlalchemy as sa


revision = "0061_kyyow_observability_odoo"
down_revision = "0060_agent_provisioning"
branch_labels = None
depends_on = None


ROUTES = (
    ("61000000-0000-4000-8000-000000000011", "odoo.observability.kpis.create", "kpis.create", "POST", "/api/v1/integration/observability/kpis", "odoo.observability.kpis.write", False),
    ("61000000-0000-4000-8000-000000000012", "odoo.observability.incidents.upsert", "incidents.upsert", "POST", "/api/v1/integration/observability/incidents", "odoo.observability.incidents.write", False),
    ("61000000-0000-4000-8000-000000000013", "odoo.observability.kpis.read", "kpis.read", "GET", "/api/v1/integration/observability/kpis", "odoo.observability.read", True),
    ("61000000-0000-4000-8000-000000000014", "odoo.observability.incidents.read", "incidents.read", "GET", "/api/v1/integration/observability/incidents", "odoo.observability.read", True),
    ("61000000-0000-4000-8000-000000000015", "odoo.observability.sync.read", "sync.read", "GET", "/api/v1/integration/observability/sync-status", "odoo.observability.read", True),
)


def _insert_routes(environment, base_url, credential, audience, tls_profile, version_prefix, configuration_version):
    connection = op.get_bind()
    for index, (endpoint_id, endpoint_key, _short_name, method, path, scope, stale_read_safe) in enumerate(ROUTES, start=1):
        endpoint_version_id = f"61000000-0000-4000-{version_prefix:04d}-{index:012d}"
        binding_id = f"61000000-0000-5000-{version_prefix:04d}-{index:012d}"
        schema_id = f"61000000-0000-6000-0000-{index:012d}"
        checksum = f"sha256:{version_prefix:02x}" + "0" * 62
        connection.execute(sa.text(
            """
            INSERT INTO integration_endpoint(endpoint_id,service_id,endpoint_key,api_version)
            SELECT CAST(:endpoint_id AS uuid), service_id, :endpoint_key, 'v1'
              FROM integration_service
             WHERE service_key='odoo'
            ON CONFLICT (service_id,endpoint_key,api_version) DO NOTHING
            """),
            {
                "endpoint_id": endpoint_id,
                "endpoint_key": endpoint_key,
            },
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
                "schema_reference": f"internal://odoo/observability/{_short_name}/v1",
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
               'BOUNDED_TRANSIENT_RETRY',3,false,false,:stale,true,false,
               :checksum,now(),'kyyow-observability','protected-review-required')
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
                "idempotency": not stale_read_safe,
                "stale": stale_read_safe,
                "checksum": checksum,
            },
        )
        connection.execute(sa.text(
            """
            INSERT INTO integration_route_binding
              (binding_id,endpoint_version_id,environment,
               organization_scope,business_unit_scope,campaign_scope)
            VALUES (CAST(:binding_id AS uuid),CAST(:version_id AS uuid),:environment,'','','')
            ON CONFLICT DO NOTHING
            """),
            {
                "binding_id": binding_id,
                "version_id": endpoint_version_id,
                "environment": environment,
            },
        )


def upgrade() -> None:
    # This pre-release migration introduces direct projection deliveries.
    # Preserve exactly-one-source enforcement while admitting the new source.
    op.drop_constraint("ck_odoo_result_delivery_one_source", "odoo_result_delivery", type_="check")
    op.create_check_constraint("ck_odoo_result_delivery_one_source", "odoo_result_delivery",
        "num_nonnulls(acknowledgement_id, runtime_result_id, integration_event_id) = 1")
    op.create_check_constraint("ck_odoo_result_delivery_standard_payload", "odoo_result_delivery",
        "(integration_event_id IS NULL) = (standard_result_json IS NULL)")
    op.execute(
        """
        INSERT INTO integration_service(service_id,service_key,display_name,enabled)
        VALUES ('61000000-0000-0000-0000-000000000010','odoo','Odoo',true)
        ON CONFLICT (service_key) DO UPDATE SET enabled=true
        """
    )
    op.execute(
        """
        INSERT INTO integration_credential_reference
          (credential_reference_id,reference_key,provider,enabled)
        VALUES
          ('61000000-0000-0000-0000-000000000011',
           'secret://staging/odoo-results-client','docker-secret',true),
          ('61000000-0000-0000-0000-000000000012',
           'secret://production/odoo-results-client','docker-secret',true)
        ON CONFLICT (reference_key) DO UPDATE SET enabled=true
        """
    )
    _insert_routes(
        "staging",
        "http://odoo19-staging:8069",
        "secret://staging/odoo-results-client",
        "codestra-odoo-integration",
        "staging-internal",
        61,
        1,
    )
    _insert_routes(
        "production",
        "https://odoo.internal.codestra.agency",
        "secret://production/odoo-results-client",
        "codestra-odoo",
        "production-internal-ca",
        62,
        2,
    )


def downgrade() -> None:
    # Reject rollback if projection-only deliveries still need this schema.
    op.drop_constraint("ck_odoo_result_delivery_standard_payload", "odoo_result_delivery", type_="check")
    op.drop_constraint("ck_odoo_result_delivery_one_source", "odoo_result_delivery", type_="check")
    op.create_check_constraint("ck_odoo_result_delivery_one_source", "odoo_result_delivery",
        "(acknowledgement_id IS NOT NULL) <> (runtime_result_id IS NOT NULL)")
    op.execute(
        """
        DELETE FROM integration_route_binding
         WHERE endpoint_version_id IN (
           SELECT endpoint_version_id FROM integration_endpoint_version
            WHERE endpoint_id IN (
              SELECT endpoint_id FROM integration_endpoint
               WHERE endpoint_key LIKE 'odoo.observability.%'
            )
         )
        """
    )
    op.execute(
        """
        DELETE FROM integration_endpoint_version
         WHERE endpoint_id IN (
           SELECT endpoint_id FROM integration_endpoint
            WHERE endpoint_key LIKE 'odoo.observability.%'
         )
        """
    )
    op.execute(
        """
        DELETE FROM integration_schema_version
         WHERE endpoint_key LIKE 'odoo.observability.%'
        """
    )
    op.execute(
        """
        DELETE FROM integration_endpoint
         WHERE endpoint_key LIKE 'odoo.observability.%'
        """
    )
