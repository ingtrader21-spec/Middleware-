from pathlib import Path

import yaml


def test_postgres_exporter_uses_canonical_database_target() -> None:
    compose = yaml.safe_load(Path(__file__).with_name("compose.yaml").read_text())
    uri = compose["services"]["postgres-exporter"]["environment"]["DATA_SOURCE_URI"]
    assert uri == "codestra-postgres-1:5432/postgres?sslmode=disable"
    assert not uri.startswith("postgres:")
