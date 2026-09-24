import json
from pathlib import Path

from scripts.audit_release_endpoints import configured_upstreams, source_audit


def test_public_route_contract_matches_application() -> None:
    contract = json.loads(Path("deploy/public-api-route-contract.json").read_text())
    shared = [row for row in contract["routes"] if row["classification"] == "shared_edge"]
    assert len(source_audit()) == 1 + len(shared) + 2


def test_route_contract_uses_exact_listener_and_no_secrets() -> None:
    contract = json.loads(Path("deploy/public-api-route-contract.json").read_text())
    assert contract["listener_port"] == 8095
    assert "password" not in json.dumps(contract).lower()


def test_configured_upstream_inventory_redacts_urls(monkeypatch) -> None:
    monkeypatch.setattr(
        "scripts.audit_release_endpoints.settings.database_url",
        "postgresql+asyncpg://user:secret@database.internal:5432/app",
    )
    rows = configured_upstreams()
    assert ("database_url", "database.internal", 5432) in rows
    assert all("secret" not in repr(row) for row in rows)
