"""Register least-privilege staging identity and Odoo result routes.

Revision ID: 0043_staging_odoo_routes
Revises: 0042_merge_gateway_trust
"""

from alembic import op


revision = "0043_staging_odoo_routes"
down_revision = "0042_merge_gateway_trust"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Fixed identifiers make the migration idempotent and auditable. These
    # routes are staging-only and never create a production binding.
    op.execute("""
    INSERT INTO integration_credential_reference
      (credential_reference_id,reference_key,provider,enabled)
    VALUES ('43000000-0000-4000-8000-000000000001',
            'secret://staging/odoo-results-client','docker-secret',true)
    ON CONFLICT (reference_key) DO UPDATE SET enabled=true
    """)
    op.execute("""
    INSERT INTO integration_service(service_id,service_key,display_name,enabled)
    VALUES
      ('43000000-0000-4000-8000-000000000010','identity','Staging Identity',true),
      ('43000000-0000-4000-8000-000000000020','odoo','Staging Odoo',true)
    ON CONFLICT (service_key) DO UPDATE SET enabled=true
    """)
    op.execute("""
    INSERT INTO integration_endpoint(endpoint_id,service_id,endpoint_key,api_version)
    VALUES
      ('43000000-0000-4000-8000-000000000011','43000000-0000-4000-8000-000000000010','oauth.token','v1'),
      ('43000000-0000-4000-8000-000000000021','43000000-0000-4000-8000-000000000020','odoo.results.create','v1')
    ON CONFLICT (service_id,endpoint_key,api_version) DO NOTHING
    """)
    op.execute("""
    INSERT INTO integration_schema_version
      (schema_version_id,service_key,endpoint_key,api_version,schema_reference,checksum,enabled)
    VALUES
      ('43000000-0000-4000-8000-000000000012','identity','oauth.token','v1','internal://identity/oauth-token/v1','sha256:0000000000000000000000000000000000000000000000000000000000000043',true),
      ('43000000-0000-4000-8000-000000000022','odoo','odoo.results.create','v1','internal://odoo/results-create/v1','sha256:0000000000000000000000000000000000000000000000000000000000000043',true)
    ON CONFLICT (service_key,endpoint_key,api_version) DO UPDATE SET enabled=true
    """)
    op.execute("""
    INSERT INTO integration_endpoint_version
      (endpoint_version_id,endpoint_id,configuration_version,base_url,path_template,http_method,
       content_type,authentication_mode,required_audience,required_scopes,credential_reference_id,
       tls_profile_id,timeout_ms,connection_timeout_ms,rate_limit_per_minute,concurrency_limit,
       idempotency_required,retry_class,retry_limit,redirects_allowed,target_attestation_required,
       stale_read_safe,enabled,kill_switch,configuration_checksum,effective_at,created_by,approved_by)
    VALUES
      ('43000000-0000-4000-8000-000000000013','43000000-0000-4000-8000-000000000011',1,
       'http://keycloak-staging:8080','/realms/codestra/protocol/openid-connect/token','POST',
       'application/x-www-form-urlencoded','client_secret','codestra-odoo-integration','["service.attest"]'::jsonb,
       'secret://staging/odoo-results-client','staging-internal',10000,3000,60,4,true,
       'BOUNDED_TRANSIENT_RETRY',3,false,false,false,true,false,
       'sha256:0000000000000000000000000000000000000000000000000000000000000043',now(),'r1-remediation','approved-pr-24'),
      ('43000000-0000-4000-8000-000000000023','43000000-0000-4000-8000-000000000021',1,
       'http://odoo19-staging:8069','/api/v1/integration/results','POST','application/json','oauth2_client_secret',
       'codestra-odoo-integration','["odoo.integration.results.write"]'::jsonb,
       'secret://staging/odoo-results-client','staging-internal',10000,3000,60,2,true,
       'BOUNDED_TRANSIENT_RETRY',3,false,false,false,true,false,
       'sha256:0000000000000000000000000000000000000000000000000000000000000043',now(),'r1-remediation','approved-pr-24')
    ON CONFLICT (endpoint_id,configuration_version) DO NOTHING
    """)
    op.execute("""
    INSERT INTO integration_route_binding(binding_id,endpoint_version_id,environment)
    VALUES
      ('43000000-0000-4000-8000-000000000014','43000000-0000-4000-8000-000000000013','staging'),
      ('43000000-0000-4000-8000-000000000024','43000000-0000-4000-8000-000000000023','staging')
    ON CONFLICT DO NOTHING
    """)


def downgrade() -> None:
    op.execute("DELETE FROM integration_route_binding WHERE binding_id::text LIKE '43000000-%'")
    op.execute("DELETE FROM integration_endpoint_version WHERE endpoint_version_id::text LIKE '43000000-%'")
    op.execute("DELETE FROM integration_schema_version WHERE schema_version_id::text LIKE '43000000-%'")
    op.execute("DELETE FROM integration_endpoint WHERE endpoint_id::text LIKE '43000000-%'")
    op.execute("DELETE FROM integration_service WHERE service_id::text LIKE '43000000-%'")
    op.execute("DELETE FROM integration_credential_reference WHERE credential_reference_id::text LIKE '43000000-%'")
