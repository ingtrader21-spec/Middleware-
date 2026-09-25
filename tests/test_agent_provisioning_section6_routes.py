from pathlib import Path

def test_section6_canonical_lifecycle_routes_present():
 source=(Path(__file__).resolve().parents[1]/"app/api/v1/agent_provisioning.py").read_text()
 for route in ('/requests/{request_id}/history','/{request_id}/sync','/{request_id}/disable','/{request_id}/readback','/reserve-extension'):
  assert route in source

def test_no_section6_501_or_notimplemented():
 source=(Path(__file__).resolve().parents[1]/"app/api/v1/agent_provisioning.py").read_text()
 assert 'status_code=501' not in source and 'NotImplementedError' not in source

def test_section6_lifecycle_migration_is_restart_safe():
 from pathlib import Path
 source=(Path(__file__).resolve().parents[1]/'migrations/versions/0068_agent_provisioning_lifecycle.py').read_text()
 assert 'agent_provisioning_repair_intent' in source
 assert 'agent_webrtc_session' in source
 assert 'uq_agent_webrtc_active_device' in source

def test_section6_extension_and_webrtc_routes_present():
 from pathlib import Path
 source=(Path(__file__).resolve().parents[1]/'app/api/v1/agent_provisioning.py').read_text()
 for route in ('/adopt-extension','/{request_id}/release-extension','/webrtc/tickets','/{request_id}/webrtc/revoke'):
  assert route in source
 assert 'WEBRTC_SESSION_ALREADY_ACTIVE' in source
 assert 'EFFECT_DISABLED' in source


def test_section6_rls_successor_is_canonical_and_fail_closed():
    root = Path(__file__).resolve().parents[1]
    migration = (root / "migrations/versions/0069_agent_provisioning_rls.py").read_text()
    assert 'revision = "0069_agent_provisioning_rls"' in migration
    assert 'down_revision = "0068_agent_provisioning_lifecycle"' in migration
    for table in (
        "agent_provisioning_request",
        "agent_provisioning_step",
        "agent_provisioning_audit",
        "agent_provisioning_repair_intent",
        "agent_webrtc_session",
    ):
        assert table in migration
    assert "ENABLE ROW LEVEL SECURITY" in migration
    assert "FORCE ROW LEVEL SECURITY" in migration
    assert "current_setting('app.tenant_ids', true)" in migration
    assert "mw_integration_api must be NOBYPASSRLS" in migration


def test_section6_api_binds_verified_tenant_set_to_rls_transaction():
    source = (
        Path(__file__).resolve().parents[1]
        / "app/api/v1/agent_provisioning.py"
    ).read_text()
    assert "SELECT set_config('app.tenant_ids', :tenant_ids, true)" in source
    assert "json.dumps(sorted(principal.tenant_ids)" in source
    assert source.count("await _set_provisioning_rls_context(session, principal)") >= 10
