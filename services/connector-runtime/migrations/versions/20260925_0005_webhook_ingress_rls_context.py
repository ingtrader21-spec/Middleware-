"""Resolve public webhook ingress by establishing tenant RLS context safely.

Revision ID: 20260925_0005
Revises: 20260828_0004
"""
from alembic import op
revision='20260925_0005'; down_revision='20260828_0004'; branch_labels=None; depends_on=None

def upgrade():
 op.execute(r'''
 CREATE OR REPLACE FUNCTION connector_sdk.sync_webhook_route() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,connector_sdk AS $$ DECLARE resolved_connector_id text; BEGIN PERFORM set_config('codestra.tenant_id', NEW.tenant_id::text, true); SELECT i.connector_id INTO STRICT resolved_connector_id FROM connector_sdk.connector_connections c JOIN connector_sdk.connector_installations i ON i.installation_id=c.installation_id WHERE c.tenant_id=NEW.tenant_id AND c.connection_id=NEW.connection_id; INSERT INTO connector_sdk.connector_webhook_routes(webhook_id,tenant_id,connector_id,endpoint_key,public_path) VALUES(NEW.webhook_id,NEW.tenant_id,resolved_connector_id,NEW.endpoint_key,NEW.public_path) ON CONFLICT(webhook_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id,connector_id=EXCLUDED.connector_id,endpoint_key=EXCLUDED.endpoint_key,public_path=EXCLUDED.public_path; RETURN NEW; END $$;
 CREATE OR REPLACE FUNCTION connector_sdk.resolve_webhook_ingress(requested_webhook_id uuid)
 RETURNS TABLE (tenant_id uuid, webhook_id uuid, connection_id uuid, connector_id text, endpoint_key text, public_path text, webhook_state text, installation_state text, secret_reference_current text, secret_reference_previous text, previous_secret_valid_until timestamptz, external_account_reference text, manifest jsonb)
 LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,connector_sdk AS $$
 DECLARE resolved_tenant uuid;
 BEGIN
   SELECT r.tenant_id INTO resolved_tenant FROM connector_sdk.connector_webhook_routes r WHERE r.webhook_id=requested_webhook_id;
   IF resolved_tenant IS NULL THEN RETURN; END IF;
   PERFORM set_config('codestra.tenant_id', resolved_tenant::text, true);
   RETURN QUERY
   SELECT r.tenant_id,r.webhook_id,w.connection_id,r.connector_id,r.endpoint_key,r.public_path,w.state,i.state,w.secret_reference_current,w.secret_reference_previous,w.previous_secret_valid_until,c.external_account_reference,m.manifest
   FROM connector_sdk.connector_webhook_routes r
   JOIN connector_sdk.connector_webhook_endpoints w ON w.tenant_id=r.tenant_id AND w.webhook_id=r.webhook_id
   JOIN connector_sdk.connector_connections c ON c.tenant_id=w.tenant_id AND c.connection_id=w.connection_id
   JOIN connector_sdk.connector_installations i ON i.installation_id=c.installation_id AND i.connector_id=r.connector_id
   JOIN connector_sdk.connector_manifests m ON m.connector_id=i.connector_id AND m.version=i.current_version AND m.manifest_digest=i.current_manifest_digest
   WHERE r.webhook_id=requested_webhook_id;
 END $$;
 REVOKE ALL ON FUNCTION connector_sdk.resolve_webhook_ingress(uuid) FROM PUBLIC;
 GRANT EXECUTE ON FUNCTION connector_sdk.resolve_webhook_ingress(uuid) TO CURRENT_USER;
 ''')

def downgrade():
 op.execute('DROP FUNCTION IF EXISTS connector_sdk.resolve_webhook_ingress(uuid)')