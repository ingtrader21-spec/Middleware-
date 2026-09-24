from importlib import import_module
from pathlib import Path


def test_scraper_inbox_migration_is_linear_and_has_all_required_states() -> None:
    migration = import_module("migrations.versions.0043_scraper_durable_inbox")
    assert migration.down_revision == "0042_merge_gateway_trust"
    assert set(migration.STATES) == {
        "received",
        "eligible",
        "rejected",
        "queued",
        "processing",
        "retry_wait",
        "delivered",
        "dead_letter",
    }


def test_scraper_inbox_stores_hashes_and_refs_but_not_raw_payload() -> None:
    source = Path("migrations/versions/0043_scraper_durable_inbox.py").read_text()
    assert "payload_hash" in source
    assert "idempotency_key_hash" in source
    assert "odoo_result_reference" in source
    assert "n8n_result_reference" in source
    assert 'sa.Column("payload"' not in source
