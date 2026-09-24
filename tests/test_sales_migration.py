from pathlib import Path


def test_sales_migration_is_forward_safe_reversible_and_has_tenant_constraints():
    text = Path("migrations/versions/0034_sales_lead_foundation.py").read_text()
    assert 'down_revision = "0033_tts_job_runtime"' in text
    for table in (
        "sales_lead_candidate",
        "sales_identity_resolution",
        "sales_duplicate_review",
        "sales_verification_job",
        "sales_verification_result",
        "sales_idempotency",
        "sales_webhook_nonce",
        "sales_provider_call_audit",
    ):
        assert f'"{table}"' in text
        assert f'op.drop_table("{table}")' in text
    assert "uq_sales_idempotency_scope" in text
    assert "DROP COLUMN" not in text.upper() and "DELETE FROM" not in text.upper()
