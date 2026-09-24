from pathlib import Path


def test_external_webhook_migration_is_authoritative_source():
    source = Path("migrations/versions/0047_external_webhook_ingestion.py").read_text()
    assert 'revision = "0047_external_webhooks"' in source
    assert 'down_revision = "0046_breero_complete_envelope"' in source


def test_single_merge_head_includes_agent_and_external_branches():
    source = Path("migrations/versions/0049_merge_external_agent_heads.py").read_text()
    assert 'revision = "0049_merge_external_agent"' in source
    assert '("0047_external_webhooks", "0048_agent_call_realtime")' in source
