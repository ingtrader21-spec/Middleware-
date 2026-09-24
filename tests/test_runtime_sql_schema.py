"""Catalog-signature regressions; real DDL corruption cases live in integration."""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path
from typing import Any

import pytest

from scripts import runtime_sql_schema as schema
from scripts.production_migration_authority import validate_authority

ROOT = Path(__file__).resolve().parents[1]


class ReadOnlyTransaction:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        self.conn.in_transaction = True

    async def __aexit__(self, *args):
        self.conn.in_transaction = False


class Catalog:
    def __init__(self, structures):
        self.structures = structures
        self.statements: list[str] = []
        self.in_transaction = False
        self.transaction_options = None

    def transaction(self, **kwargs):
        self.transaction_options = kwargs
        return ReadOnlyTransaction(self)

    async def execute(self, query):
        assert self.in_transaction
        assert query == "SET LOCAL search_path = pg_catalog"
        self.statements.append(query)

    async def fetch(self, query, names):
        assert self.in_transaction
        assert query == schema.CATALOG_SQL
        self.statements.append(query)
        return [
            dict(table_name=name, structure=json.dumps(self.structures[name]))
            for name in names
            if name in self.structures
        ]


@pytest.fixture
def catalog(monkeypatch):
    structure = {
        "kind": "r",
        "persistence": "p",
        "row_security": False,
        "force_row_security": False,
        "columns": [
            {
                "name": "tenant_id",
                "type": "text",
                "not_null": True,
                "default": None,
                "identity": "",
                "generated": "",
                "collation": "pg_catalog.default",
            }
        ],
        "constraints": [
            {
                "name": "key",
                "type": "p",
                "definition": "PRIMARY KEY (tenant_id)",
                "validated": True,
                "deferrable": False,
                "deferred": False,
            }
        ],
        "indexes": [
            {"name": "key", "definition": "CREATE UNIQUE INDEX key ...", "valid": True}
        ],
        "triggers": [
            {
                "name": "immutable",
                "enabled": "O",
                "definition": "BEFORE UPDATE",
                "function": "RAISE EXCEPTION",
            }
        ],
        "internal_triggers": [{"enabled": "O", "constraint": "fk"}],
        "policies": [],
        "sequences": [{"increment": 1, "cycle": False}],
    }
    expected = {"middleware_automation_jobs": schema.structure_digest(structure)}
    monkeypatch.setattr(schema, "load_contract", lambda root, digest: expected)
    return Catalog({"middleware_automation_jobs": copy.deepcopy(structure)})


def verify(conn):
    asyncio.run(schema.verify_sql_schema(conn, ROOT))


def test_valid_structure_uses_catalog_only_readonly_snapshot(catalog):
    verify(catalog)
    assert catalog.transaction_options == {
        "isolation": "repeatable_read",
        "readonly": True,
    }
    assert catalog.statements == [
        "SET LOCAL search_path = pg_catalog",
        schema.CATALOG_SQL,
    ]
    assert not catalog.in_transaction


@pytest.mark.parametrize(
    "section",
    [
        "columns",
        "constraints",
        "indexes",
        "triggers",
        "internal_triggers",
        "sequences",
    ],
)
def test_missing_required_schema_object_is_rejected(catalog, section):
    catalog.structures["middleware_automation_jobs"][section] = []
    with pytest.raises(schema.SchemaDriftError, match="structure mismatch"):
        verify(catalog)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("type", "integer"),
        ("not_null", False),
        ("default", "42"),
        ("identity", "a"),
        ("generated", "s"),
        ("collation", "public.changed"),
    ],
)
def test_column_signature_drift_is_rejected(catalog, field, value):
    catalog.structures["middleware_automation_jobs"]["columns"][0][field] = value
    with pytest.raises(schema.SchemaDriftError, match="structure mismatch"):
        verify(catalog)


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("constraints", "validated", False),
        ("constraints", "definition", "CHECK (true)"),
        ("constraints", "deferred", True),
        ("indexes", "valid", False),
        ("indexes", "definition", "CREATE INDEX nonunique ..."),
        ("triggers", "enabled", "D"),
        ("triggers", "function", "RETURN NEW"),
        ("internal_triggers", "enabled", "D"),
        ("sequences", "increment", -1),
    ],
)
def test_enforcement_drift_is_rejected(catalog, section, field, value):
    catalog.structures["middleware_automation_jobs"][section][0][field] = value
    with pytest.raises(schema.SchemaDriftError, match="structure mismatch"):
        verify(catalog)


def test_missing_public_table_does_not_pass(catalog):
    catalog.structures.clear()
    with pytest.raises(schema.SchemaDriftError, match="missing from public"):
        verify(catalog)


def test_unrelated_tables_are_not_inspected(catalog):
    catalog.structures["unrelated_customer_records"] = {"private": "not returned"}
    verify(catalog)


def test_checked_contract_covers_source_and_exact_migration_history():
    _, _, digest = validate_authority(ROOT)
    contract = schema.load_contract(ROOT, digest)
    assert set(contract) == set(schema.managed_tables(ROOT))
    assert "middleware_automation_jobs" in contract
    assert "middleware_commands" in contract
    assert "middleware_automation_schema_migrations" in contract
    assert len(schema.campaign_tables(ROOT)) == 6
    assert set(schema.campaign_tables(ROOT)).issubset(contract)
    assert set(schema.monitoring_tables(ROOT)) == {
        "monitoring_resources",
        "monitoring_operations",
        "monitoring_events",
    }
    assert set(schema.monitoring_tables(ROOT)).issubset(contract)


@pytest.mark.parametrize("namespace", ["campaign", "monitoring"])
@pytest.mark.parametrize(
    "declaration",
    [
        "op.create_table('unrelated_table')",
        "op.create_table(table_name)",
        "",
    ],
)
def test_alembic_namespace_rejects_unproved_tables(tmp_path, namespace, declaration):
    path = (
        tmp_path / "migrations/versions" / schema.ALEMBIC_CATALOG_MIGRATIONS[namespace]
    )
    path.parent.mkdir(parents=True)
    path.write_text(declaration)
    with pytest.raises(schema.SchemaDriftError):
        schema.alembic_tables(tmp_path, namespace)


def test_monitoring_baseline_covers_exact_source_ddl():
    evidence = json.loads(
        (
            ROOT / "docs/production/evidence/monitoring-schema-0059-baseline.json"
        ).read_text()
    )
    contract = json.loads((ROOT / schema.CONTRACT_PATH).read_text())
    rows = {row["table_name"]: row for row in evidence["rows"]}
    assert set(rows) == set(schema.monitoring_tables(ROOT))
    for name, row in rows.items():
        assert (
            schema.structure_digest(json.loads(row["structure"]))
            == contract["tables"][name]
        )


@pytest.mark.parametrize(
    "change", ["missing_table", "extra_table", "bad_hash", "history", "version"]
)
def test_invalid_contract_rejected_before_catalog_access(tmp_path, monkeypatch, change):
    path = tmp_path / "contract.json"
    document: dict[str, Any] = {
        "schema_version": 1,
        "migration_history_sha256": "expected",
        "tables": {"middleware_jobs": "sha256:" + "a" * 64},
    }
    if change == "missing_table":
        document["tables"] = {}
    elif change == "extra_table":
        document["tables"]["extra"] = "sha256:" + "b" * 64
    elif change == "bad_hash":
        document["tables"]["middleware_jobs"] = "not-a-hash"
    elif change == "history":
        document["migration_history_sha256"] = "old"
    else:
        document["schema_version"] = 2
    path.write_text(json.dumps(document))
    monkeypatch.setattr(schema, "CONTRACT_PATH", "contract.json")
    monkeypatch.setattr(schema, "managed_tables", lambda root: ("middleware_jobs",))
    with pytest.raises(schema.SchemaDriftError):
        schema.load_contract(tmp_path, "expected")


def test_runtime_image_packages_schema_verifier():
    source = (ROOT / "Dockerfile.runtime").read_text()
    assert "scripts/runtime_sql_schema.py ./scripts/runtime_sql_schema.py" in source


def test_runner_checks_contract_before_opening_database():
    source = (
        (ROOT / "scripts/migrate_runtime.py").read_text().split("async def main(", 1)[1]
    )
    assert source.index("load_contract(ROOT, history_digest)") < source.index(
        "asyncpg.connect("
    )
