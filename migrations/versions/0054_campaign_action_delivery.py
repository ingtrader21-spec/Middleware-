"""Add durable campaign action delivery and exact production routes.

Revision ID: 0054_campaign_actions
Revises: 0053_callback_worker_grants
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0054_campaign_actions"
down_revision = "0053_callback_worker_grants"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "odoo_result_delivery",
        sa.Column("integration_event_id", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "odoo_result_delivery",
        sa.Column("standard_result_json", postgresql.JSONB(), nullable=True),
    )
    op.create_foreign_key(
        "fk_odoo_result_delivery_integration_event",
        "odoo_result_delivery", "integration_event",
        ["integration_event_id"], ["id"], ondelete="RESTRICT",
    )
    op.create_unique_constraint(
        "uq_odoo_result_delivery_integration_event",
        "odoo_result_delivery", ["integration_event_id"],
    )
    op.execute("""
    INSERT INTO integration_endpoint(endpoint_id,service_id,endpoint_key,api_version)
    SELECT '54000000-0000-4000-8000-000000000021', service_id,
           'odoo.campaign_actions.apply','v1'
      FROM integration_service WHERE service_key='odoo'
    ON CONFLICT (service_id,endpoint_key,api_version) DO NOTHING
    """)
    op.execute("""
    INSERT INTO integration_schema_version
      (schema_version_id,service_key,endpoint_key,api_version,schema_reference,checksum,enabled)
    VALUES ('54000000-0000-4000-8000-000000000022','odoo',
      'odoo.campaign_actions.apply','v1','internal://odoo/campaign-actions/v1',
      'sha256:77177c5a9e728f5173c9530c8fc7fc38c88ac26db576f19401ab0bc00a1f80a3',true)
    ON CONFLICT (service_key,endpoint_key,api_version) DO UPDATE SET enabled=true
    """)
    op.execute("""
    INSERT INTO integration_endpoint_version
      (endpoint_version_id,endpoint_id,configuration_version,base_url,path_template,http_method,
       content_type,authentication_mode,required_audience,required_scopes,credential_reference_id,
       tls_profile_id,timeout_ms,connection_timeout_ms,rate_limit_per_minute,concurrency_limit,
       idempotency_required,retry_class,retry_limit,redirects_allowed,target_attestation_required,
       stale_read_safe,enabled,kill_switch,configuration_checksum,effective_at,created_by,approved_by)
    VALUES ('54000000-0000-4000-8000-000000000023','54000000-0000-4000-8000-000000000021',1,
      'https://odoo.internal.codestra.agency','/api/v1/integration/campaign-actions','POST',
      'application/json','oauth2_client_secret','codestra-odoo',
      '["odoo.campaign.actions.apply"]'::jsonb,'secret://production/odoo-results-client',
      'production-internal-ca',10000,3000,60,2,true,'BOUNDED_TRANSIENT_RETRY',3,false,false,
      false,true,false,'sha256:77177c5a9e728f5173c9530c8fc7fc38c88ac26db576f19401ab0bc00a1f80a3',
      now(),'campaign-crm-control-plane','protected-review-required')
    ON CONFLICT (endpoint_id,configuration_version) DO NOTHING
    """)
    bindings = (
        ("01", "MOY", "MOY-SHIPPER-OUT"),
        ("02", "COD", "COD-WEB-OUT"),
        ("03", "MBL", "MBL-NEW-LOAN-OUT"),
        ("04", "SCP", "SCP-PRODUCT-OUT"),
        ("05", "SRP", "SRP-STUDENT-OUT"),
    )
    for suffix, business_unit, campaign in bindings:
        op.execute(sa.text("""
        INSERT INTO integration_route_binding
          (binding_id,endpoint_version_id,environment,organization_scope,
           business_unit_scope,campaign_scope)
        VALUES (CAST(:binding AS uuid),'54000000-0000-4000-8000-000000000023',
          'production','ORG-CODESTRA',:business_unit,:campaign)
        ON CONFLICT DO NOTHING
        """).bindparams(
            binding=f"54000000-0000-4000-8000-0000000000{suffix}",
            business_unit=business_unit,
            campaign=campaign,
        ))


def downgrade() -> None:
    op.execute("DELETE FROM integration_route_binding WHERE binding_id::text LIKE '54000000-%'")
    op.execute("DELETE FROM integration_endpoint_version WHERE endpoint_version_id='54000000-0000-4000-8000-000000000023'")
    op.execute("DELETE FROM integration_schema_version WHERE schema_version_id='54000000-0000-4000-8000-000000000022'")
    op.execute("DELETE FROM integration_endpoint WHERE endpoint_id='54000000-0000-4000-8000-000000000021'")
    op.drop_constraint("uq_odoo_result_delivery_integration_event", "odoo_result_delivery", type_="unique")
    op.drop_constraint("fk_odoo_result_delivery_integration_event", "odoo_result_delivery", type_="foreignkey")
    op.drop_column("odoo_result_delivery", "standard_result_json")
    op.drop_column("odoo_result_delivery", "integration_event_id")
