from pathlib import Path


def test_runtime_migration_is_forward_safe_and_reversible():
    text = Path("migrations/versions/0034_n8n_redis_runtime.py").read_text()
    assert 'down_revision = "0033_tts_job_runtime"' in text
    assert "n8n_workflow_registry" in text
    assert "n8n_runtime_execution" in text
    assert "n8n_runtime_result" in text
    assert "n8n_runtime_nonce" in text
    assert "def downgrade()" in text
    assert (
        "DROP TABLE"
        not in text.split("def upgrade()", 1)[1].split("def downgrade()", 1)[0]
    )
