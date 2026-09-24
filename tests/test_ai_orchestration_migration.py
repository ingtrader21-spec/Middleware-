from pathlib import Path


MIGRATION = Path("migrations/versions/0031_ai_orchestration_v1.py")


def test_downgrade_preserves_orchestration_jobs_with_deterministic_legacy_links() -> None:
    source = MIGRATION.read_text()
    downgrade = source.split("def downgrade() -> None:", 1)[1]

    assert "ai-orchestration-rollback-conversation:" in downgrade
    assert "ai-orchestration-rollback-message:" in downgrade
    assert "WHERE conversation_id IS NULL" in downgrade
    assert "WHERE request_message_id IS NULL" in downgrade
    assert "ALTER COLUMN request_message_id SET NOT NULL" in downgrade
    assert "ALTER COLUMN conversation_id SET NOT NULL" in downgrade


def test_downgrade_fail_closes_states_unknown_to_legacy_workers() -> None:
    source = MIGRATION.read_text()
    downgrade = source.split("def downgrade() -> None:", 1)[1]

    assert "WHEN state IN ('queued','available') THEN 'queued'" in downgrade
    assert "WHEN state IN ('leased','running') THEN 'leased'" in downgrade
    assert "WHEN state IN ('completed','approved') THEN 'completed'" in downgrade
    assert "ELSE 'dead_letter' END" in downgrade
