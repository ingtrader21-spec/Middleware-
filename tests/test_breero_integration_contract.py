import json
from pathlib import Path

from app.api.v1.breero import ALLOWED_EVENTS, BreeroEvent, PATH
from app.core.config import Settings


def test_exact_cross_repository_schemas_are_tracked():
    event = json.loads(Path("schemas/breero-middleware-event-v1.json").read_text())
    ack = json.loads(Path("schemas/breero-middleware-ack-v1.json").read_text())
    assert set(event["properties"]["event_type"]["enum"]) == set(ALLOWED_EVENTS)
    assert ack["properties"]["status"]["enum"] == ["queued", "delivered", "replayed"]


def test_event_model_rejects_extra_fields_and_non_uuid_values():
    value = {
        "event_id": "00000000-0000-4000-8000-000000000001",
        "event_type": "breero.contact_request.created",
        "schema_version": 1,
        "aggregate_id": "00000000-0000-4000-8000-000000000002",
        "aggregate_version": 1,
        "occurred_at": "2026-08-13T00:00:00Z",
        "idempotency_key": "canary-1",
        "source": "breero",
        "payload": {},
    }
    assert BreeroEvent.model_validate(value).event_type in ALLOWED_EVENTS
    value["generic_odoo_model"] = "res.users"
    try:
        BreeroEvent.model_validate(value)
    except ValueError:
        pass
    else:
        raise AssertionError("generic Odoo operations must be rejected")


def test_fail_closed_defaults_and_private_proxy_contract():
    config = Settings()
    assert config.breero_ingress_enabled is False
    assert config.breero_odoo_delivery_enabled is False
    source = Path("deploy/breero/Caddyfile.private-route").read_text()
    assert PATH in source
    assert "remote_ip 10.40.0.3" in source
    assert "header_up -X-Codestra-Verified-Source-IP" in source
    listener = Path("deploy/readiness/Caddyfile.private-vicidial-ingress").read_text()
    compose = Path("deploy/readiness/compose.private-vicidial-ingress.yaml").read_text()
    assert "import /etc/caddy/snippets/breero-private-route" in listener
    assert "/etc/caddy/snippets/breero-private-route:ro" in compose
    identities = json.loads(Path("deploy/breero/identities.example.json").read_text())
    assert identities and all(item["enabled"] is False for item in identities.values())
    assert all("secret" not in item for item in identities.values())


def test_migration_has_durable_non_destructive_tables():
    migration = Path("migrations/versions/0044_breero_integration.py").read_text()
    for table in (
        "breero_event_receipt",
        "breero_odoo_outbox",
        "breero_replay_nonce",
        "breero_integration_audit",
        "breero_reconciliation_run",
    ):
        assert table in migration
    assert "ON DELETE RESTRICT" in migration
