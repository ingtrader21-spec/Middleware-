"""Register private production identity and Odoo result routes.

Revision ID: 0050_production_odoo_results
Revises: 0049_merge_external_agent
"""

from alembic import op


revision = "0050_production_odoo_results"
down_revision = "0049_merge_external_agent"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    INSERT INTO integration_credential_reference
      (credential_reference_id,reference_key,provider,enabled)
    VALUES ('49000000-0000-4000-8000-000000000001',
            'secret://production/odoo-results-client','docker-secret',true)
    ON CONFLICT (reference_key) DO UPDATE SET enabled=true
    """)
    op.execute("""
    INSERT INTO integration_endpoint_version
      (endpoint_version_id,endpoint_id,configuration_version,base_url,path_template,http_method,
       content_type,authentication_mode,required_audience,required_scopes,credential_reference_id,
       tls_profile_id,timeout_ms,connection_timeout_ms,rate_limit_per_minute,concurrency_limit,
       idempotency_required,retry_class,retry_limit,redirects_allowed,target_attestation_required,
       stale_read_safe,enabled,kill_switch,configuration_checksum,effective_at,created_by,approved_by)
    VALUES
      ('49000000-0000-4000-8000-000000000013','43000000-0000-4000-8000-000000000011',2,
       'http://keycloak:8080','/realms/codestra/protocol/openid-connect/token','POST',
       'application/x-www-form-urlencoded','client_secret','codestra-odoo','["odoo.integration.results.write"]'::jsonb,
       'secret://production/odoo-results-client','production-identity-internal',10000,3000,60,4,true,
       'BOUNDED_TRANSIENT_RETRY',3,false,false,false,true,false,
       'sha256:822d7e0e9073dca54cf035903f0f226ef65d2d40157971e5ac16a2aa289c49a0',now(),'result-contract-remediation','protected-review-required'),
      ('49000000-0000-4000-8000-000000000023','43000000-0000-4000-8000-000000000021',2,
       'https://odoo.internal.codestra.agency','/api/v1/integration/results','POST',
       'application/json','oauth2_client_secret','codestra-odoo','["odoo.integration.results.write"]'::jsonb,
       'secret://production/odoo-results-client','production-internal-ca',10000,3000,60,2,true,
       'BOUNDED_TRANSIENT_RETRY',3,false,false,false,true,false,
       'sha256:4b2088f7f268eb54bcfa8256a08759910f5a36bdbdb9e02ba0605928688bc325',now(),'result-contract-remediation','protected-review-required')
    ON CONFLICT (endpoint_id,configuration_version) DO NOTHING
    """)
    op.execute("""
    INSERT INTO integration_route_binding
      (binding_id,endpoint_version_id,environment,organization_scope,business_unit_scope,campaign_scope)
    VALUES
      ('49000000-0000-4000-8000-000000000014','49000000-0000-4000-8000-000000000013','production','','',''),
      ('49000000-0000-4000-8000-000000000024','49000000-0000-4000-8000-000000000023','production','ORG-CODESTRA','BU-400-COD','CMP-400-COD')
    ON CONFLICT DO NOTHING
    """)


def downgrade() -> None:
    op.execute("DELETE FROM integration_route_binding WHERE binding_id::text LIKE '49000000-%'")
    op.execute("DELETE FROM integration_endpoint_version WHERE endpoint_version_id::text LIKE '49000000-%'")
    op.execute("DELETE FROM integration_credential_reference WHERE credential_reference_id::text LIKE '49000000-%'")
