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
