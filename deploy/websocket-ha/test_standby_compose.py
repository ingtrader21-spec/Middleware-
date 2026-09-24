from pathlib import Path

import yaml


COMPOSE = yaml.safe_load(Path(__file__).with_name("compose.standby.yaml").read_text())


def test_standby_database_and_gateway_match_primary_runtime_policy() -> None:
    services = COMPOSE["services"]
    assert services["postgres"]["restart"] == "unless-stopped"
    health = services["gateway"]["healthcheck"]
    assert health["interval"] == "15s"
    assert health["timeout"] == "3s"
    assert health["retries"] == 3
    assert health["start_period"] == "10s"


def test_standby_has_no_staging_or_public_edge_dependency() -> None:
    rendered = Path(__file__).with_name("compose.standby.yaml").read_text().lower()
    assert "staging" not in rendered
    assert "codestra_edge" not in rendered
    gateway = COMPOSE["services"]["gateway"]
    assert gateway["environment"]["INTERNAL_EVENT_SOURCE_HEALTH_URL"] == "http://middleware:8095/health"
    assert gateway["ports"] == ["127.0.0.1:31882:8080"]


def test_database_alias_and_secret_references_are_explicit() -> None:
    postgres = COMPOSE["services"]["postgres"]
    assert "codestra-websocket-gateway-postgres-1" in postgres["networks"]["backend"]["aliases"]
    assert postgres["environment"]["POSTGRES_PASSWORD_FILE"] == "/run/secrets/postgres_password"
    assert COMPOSE["services"]["gateway"]["environment"]["DATABASE_URL_FILE"] == "/run/secrets/database_url"
