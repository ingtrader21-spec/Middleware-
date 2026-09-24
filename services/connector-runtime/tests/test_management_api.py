from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from codestra_connector_runtime.api.app import create_app
from codestra_connector_runtime.api.auth import Principal, principal_dependency
from codestra_connector_runtime.api.config import get_settings
from middleware.connector_sdk import manifest_digest

pytestmark = pytest.mark.postgres

ROOT = Path(__file__).resolve().parents[3]
MANIFESTS = ROOT / "connectors" / "manifests"


def _principal(tenant_id: UUID) -> Principal:
    return Principal(
        subject="api-test-subject",
        issuer="https://auth.codestra.co/realms/codestra",
        client_id="connector-management-api",
        tenant_ids=frozenset({tenant_id}),
        scopes=frozenset(
            {
                "connector.catalog.read",
                "connector.manifest.read",
                "connector.manifest.validate",
                "connector.install.request",
                "connector.upgrade.request",
                "connector.disable.request",
                "connector.connection.test",
                "connector.health.read",
                "integration.connection.read",
                "integration.connection.write",
                "connector.webhook.read",
                "connector.webhook.write",
                "connector.webhook.rotate",
                "connector.webhook.delivery.read",
                "connector.webhook.replay.request",
            }
        ),
        claims={},
    )


def _manifest() -> dict[str, object]:
    raw = json.loads(
        (MANIFESTS / "klyrow-email.connector.json").read_text()
    )
    suffix = uuid.uuid4().hex[:10]
    raw["connector_id"] = f"api-test-{suffix}"
    raw["display_name"] = f"API Test {suffix}"
    raw["repository"] = f"appolon1908-hue/api-test-{suffix}"
    raw["runtime_binding"]["base_url"] = f"https://api-test-{suffix}.internal.invalid"
    raw["authentication"]["scopes"] = [
        f"connector.api-test-{suffix}.command",
        f"connector.api-test-{suffix}.read",
    ]
    raw["authentication"]["secret_references"] = [
        f"CONNECTOR_API_TEST_{suffix.upper()}_CLIENT_SECRET",
        f"CONNECTOR_API_TEST_{suffix.upper()}_MTLS_CERT",
    ]
    raw["commands"][0]["prefix"] = f"apitest{suffix}."
    raw["events"] = [
        {
            "event_type": f"apitest{suffix}.record.changed.v1",
            "direction": "inbound",
        }
    ]
    raw["webhooks"] = [
        {
            "endpoint_key": "provider-events",
            "route_path": f"/v1/webhooks/apitest{suffix}/provider",
            "signature_algorithm": "hmac-sha256",
            "signature_header": "X-Test-Signature",
            "timestamp_header": "X-Test-Timestamp",
            "event_id_header": "X-Test-Event-Id",
            "maximum_clock_skew_seconds": 300,
            "maximum_body_bytes": 1048576,
            "acknowledgement_deadline_seconds": 5,
            "replay_retention_seconds": 604800,
            "secret_reference": "WEBHOOK_TEST_SECRET",
        }
    ]
    raw["workflow_families"] = [f"product.apitest{suffix}"]
    raw["metadata"]["owner"] = raw["connector_id"]
    return raw


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tenant_id = uuid.uuid4()
    key_file = tmp_path / "body-key"
    key_file.write_bytes(b"b" * 32)
    monkeypatch.setenv("CONNECTOR_RUNTIME_DATABASE_URL", os.environ["ADMIN_DATABASE_URL"])
    monkeypatch.setenv("CONNECTOR_RUNTIME_CURSOR_HMAC_KEY", "c" * 48)
    monkeypatch.setenv("CONNECTOR_RUNTIME_BODY_ENCRYPTION_KEY_FILE", str(key_file))
    monkeypatch.setenv("CONNECTOR_RUNTIME_WEBHOOK_BODY_ROOT", str(tmp_path / "bodies"))
    monkeypatch.setenv("CONNECTOR_RUNTIME_CONNECTOR_INSTALL_ENABLED", "true")
    monkeypatch.setenv("CONNECTOR_RUNTIME_WEBHOOK_INGRESS_ENABLED", "true")
    monkeypatch.setenv("WEBHOOK_TEST_SECRET", "s" * 48)
    get_settings.cache_clear()
    app = create_app()

    async def override_principal() -> Principal:
        return _principal(tenant_id)

    app.dependency_overrides[principal_dependency] = override_principal
    with TestClient(app) as test_client:
        yield test_client, app, tenant_id, tmp_path
    get_settings.cache_clear()


def test_connector_connection_and_webhook_lifecycle(client) -> None:
    test_client, app, tenant_id, _ = client
    manifest = _manifest()
    digest = manifest_digest(manifest)

    validation = test_client.post(
        "/v1/connectors/validate",
        json={"manifest": manifest},
    )
    assert validation.status_code == 200, validation.text
    assert validation.json()["data"]["manifest_digest"] == digest

    headers = {"Idempotency-Key": "install-" + uuid.uuid4().hex}
    installed = test_client.post(
        "/v1/connectors/install",
        json={"manifest": manifest, "expected_manifest_digest": digest},
        headers=headers,
    )
    assert installed.status_code == 202, installed.text
    replay = test_client.post(
        "/v1/connectors/install",
        json={"manifest": manifest, "expected_manifest_digest": digest},
        headers=headers,
    )
    assert replay.status_code == 202
    assert replay.json() == installed.json()

    connector_id = str(manifest["connector_id"])
    connector = test_client.get(f"/v1/connectors/{connector_id}")
    assert connector.status_code == 200
    assert connector.headers["etag"] == '"v1"'
    assert connector.json()["data"]["state"] == "INSTALLED_DISABLED"

    connection_response = test_client.post(
        "/v1/integrations/connections",
        json={
            "connector_id": connector_id,
            "external_account_reference": "provider-account-1",
            "configuration": {"region": "test"},
            "secret_references": ["CONNECTOR_TEST_SECRET"],
        },
        headers={"Idempotency-Key": "connection-" + uuid.uuid4().hex},
    )
    assert connection_response.status_code == 202, connection_response.text

    with app.state.database.session(tenant_id) as session:
        connection_id = session.execute(
            text(
                """
                SELECT c.connection_id
                  FROM connector_sdk.connector_connections c
                  JOIN connector_sdk.connector_installations i
                    ON i.installation_id=c.installation_id
                 WHERE c.tenant_id=:tenant_id AND i.connector_id=:connector_id
                """
            ),
            {"tenant_id": tenant_id, "connector_id": connector_id},
        ).scalar_one()

    fetched_connection = test_client.get(
        f"/v1/integrations/connections/{connection_id}"
    )
    assert fetched_connection.status_code == 200
    assert fetched_connection.headers["etag"] == '"v1"'

    webhook_response = test_client.post(
        f"/v1/integrations/connections/{connection_id}/webhooks",
        json={
            "endpoint_key": "provider-events",
            "secret_reference_current": "WEBHOOK_TEST_SECRET",
        },
        headers={"Idempotency-Key": "webhook-" + uuid.uuid4().hex},
    )
    assert webhook_response.status_code == 202, webhook_response.text

    with app.state.database.session(tenant_id) as session:
        webhook_id = session.execute(
            text(
                """
                SELECT webhook_id
                  FROM connector_sdk.connector_webhook_endpoints
                 WHERE tenant_id=:tenant_id AND connection_id=:connection_id
                """
            ),
            {"tenant_id": tenant_id, "connection_id": connection_id},
        ).scalar_one()

    fetched_webhook = test_client.get(f"/v1/webhooks/{webhook_id}")
    assert fetched_webhook.status_code == 200
    assert fetched_webhook.headers["etag"] == '"v1"'
    assert fetched_webhook.json()["data"]["state"] == "DISABLED"


def test_management_body_limit_is_enforced_before_json_parsing(client) -> None:
    test_client, app, _, _ = client
    app.state.settings.maximum_management_body_bytes = 1024
    oversized = test_client.post(
        "/v1/connectors/validate",
        content=b"{" + (b"x" * 1024) + b"}",
        headers={"Content-Type": "application/json"},
    )
    assert oversized.status_code == 413
    assert oversized.json()["code"] == "MANAGEMENT_BODY_TOO_LARGE"


def test_signed_webhook_is_durable_before_202_and_replay_safe(client) -> None:
    test_client, app, tenant_id, tmp_path = client
    manifest = _manifest()
    connector_id = str(manifest["connector_id"])
    digest = manifest_digest(manifest)
    assert test_client.post(
        "/v1/connectors/install",
        json={"manifest": manifest, "expected_manifest_digest": digest},
        headers={"Idempotency-Key": "install-" + uuid.uuid4().hex},
    ).status_code == 202
    assert test_client.post(
        "/v1/integrations/connections",
        json={
            "connector_id": connector_id,
            "external_account_reference": "provider-account-2",
            "configuration": {},
            "secret_references": ["CONNECTOR_TEST_SECRET"],
        },
        headers={"Idempotency-Key": "connection-" + uuid.uuid4().hex},
    ).status_code == 202

    with app.state.database.session(tenant_id) as session:
        connection_id = session.execute(
            text(
                """
                SELECT c.connection_id
                  FROM connector_sdk.connector_connections c
                  JOIN connector_sdk.connector_installations i
                    ON i.installation_id=c.installation_id
                 WHERE c.tenant_id=:tenant_id AND i.connector_id=:connector_id
                """
            ),
            {"tenant_id": tenant_id, "connector_id": connector_id},
        ).scalar_one()
    assert test_client.post(
        f"/v1/integrations/connections/{connection_id}/webhooks",
        json={
            "endpoint_key": "provider-events",
            "secret_reference_current": "WEBHOOK_TEST_SECRET",
        },
        headers={"Idempotency-Key": "webhook-" + uuid.uuid4().hex},
    ).status_code == 202

    with app.state.database.session(tenant_id) as session:
        row = session.execute(
            text(
                """
                SELECT webhook_id
                  FROM connector_sdk.connector_webhook_endpoints
                 WHERE tenant_id=:tenant_id AND connection_id=:connection_id
                """
            ),
            {"tenant_id": tenant_id, "connection_id": connection_id},
        ).one()
        webhook_id = row.webhook_id
        session.execute(
            text(
                """
                UPDATE connector_sdk.connector_installations
                   SET state='ACTIVE'
                 WHERE connector_id=:connector_id
                   AND environment='development'
                """
            ),
            {"connector_id": connector_id},
        )
        session.execute(
            text(
                """
                UPDATE connector_sdk.connector_connections
                   SET state='READY'
                 WHERE tenant_id=:tenant_id AND connection_id=:connection_id
                """
            ),
            {"tenant_id": tenant_id, "connection_id": connection_id},
        )
        session.execute(
            text(
                """
                UPDATE connector_sdk.connector_webhook_endpoints
                   SET state='ACTIVE'
                 WHERE tenant_id=:tenant_id AND webhook_id=:webhook_id
                """
            ),
            {"tenant_id": tenant_id, "webhook_id": webhook_id},
        )

    event_id = "evt-api-durable"
    now = int(time.time())
    body = json.dumps({"provider_account": "provider-account-2", "value": 1}).encode()
    signature = hmac.new(
        ("s" * 48).encode(),
        str(now).encode() + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    webhook_path = f"/v1/webhooks/{connector_id}/provider-events/{webhook_id}"
    webhook_headers = {
        "Content-Type": "application/json",
        "X-Test-Signature": "v1=" + signature,
        "X-Test-Timestamp": str(now),
        "X-Test-Event-Id": event_id,
    }
    accepted = test_client.post(webhook_path, content=body, headers=webhook_headers)
    assert accepted.status_code == 202, accepted.text
    assert accepted.json()["data"]["duplicate"] is False
    inbox_id = accepted.json()["data"]["inbox_id"]

    with app.state.database.session(tenant_id) as session:
        inbox = session.execute(
            text(
                """
                SELECT processing_state, encrypted_body_reference
                  FROM connector_sdk.connector_webhook_inbox
                 WHERE tenant_id=:tenant_id AND inbox_id=:inbox_id
                """
            ),
            {"tenant_id": tenant_id, "inbox_id": inbox_id},
        ).mappings().one()
        outbox_count = session.execute(
            text(
                """
                SELECT count(*) FROM connector_sdk.connector_outbox
                 WHERE tenant_id=:tenant_id
                   AND aggregate_id=:inbox_id
                   AND event_type='connector.webhook.accepted.v1'
                """
            ),
            {"tenant_id": tenant_id, "inbox_id": inbox_id},
        ).scalar_one()
    assert inbox["processing_state"] == "PENDING"
    assert outbox_count == 1
    encrypted_path = tmp_path / "bodies" / inbox["encrypted_body_reference"].removeprefix("file:")
    assert encrypted_path.is_file()
    assert body not in encrypted_path.read_bytes()

    duplicate = test_client.post(webhook_path, content=body, headers=webhook_headers)
    assert duplicate.status_code == 202
    assert duplicate.json()["data"]["duplicate"] is True
    assert duplicate.json()["data"]["inbox_id"] == inbox_id

    concurrent_event = "evt-api-concurrent-first"
    concurrent_headers = dict(webhook_headers)
    concurrent_headers["X-Test-Event-Id"] = concurrent_event
    concurrent_headers["X-Test-Signature"] = "v1=" + hmac.new(
        ("s" * 48).encode(),
        str(now).encode() + b"." + body,
        hashlib.sha256,
    ).hexdigest()

    def deliver_once(_index: int):
        return test_client.post(
            webhook_path,
            content=body,
            headers=concurrent_headers,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        concurrent = list(executor.map(deliver_once, range(8)))
    assert {response.status_code for response in concurrent} == {202}
    concurrent_payloads = [response.json()["data"] for response in concurrent]
    assert sum(not payload["duplicate"] for payload in concurrent_payloads) == 1
    assert len({payload["inbox_id"] for payload in concurrent_payloads}) == 1

    changed_body = body + b" "
    changed_signature = hmac.new(
        ("s" * 48).encode(),
        str(now).encode() + b"." + changed_body,
        hashlib.sha256,
    ).hexdigest()
    changed_headers = dict(webhook_headers)
    changed_headers["X-Test-Signature"] = "v1=" + changed_signature
    conflict = test_client.post(
        webhook_path,
        content=changed_body,
        headers=changed_headers,
    )
    assert conflict.status_code == 409
    assert conflict.json()["code"] == "WEBHOOK_SEMANTIC_CONFLICT"
    encrypted_files = list((tmp_path / "bodies").rglob("*.bin"))
    assert encrypted_path in encrypted_files
    assert len(encrypted_files) == 2


def test_cross_tenant_connection_read_is_denied(client) -> None:
    test_client, app, tenant_id, _ = client
    manifest = _manifest()
    connector_id = str(manifest["connector_id"])
    digest = manifest_digest(manifest)
    assert test_client.post(
        "/v1/connectors/install",
        json={"manifest": manifest, "expected_manifest_digest": digest},
        headers={"Idempotency-Key": "install-" + uuid.uuid4().hex},
    ).status_code == 202
    assert test_client.post(
        "/v1/integrations/connections",
        json={"connector_id": connector_id, "configuration": {}, "secret_references": []},
        headers={"Idempotency-Key": "connection-" + uuid.uuid4().hex},
    ).status_code == 202
    with app.state.database.session(tenant_id) as session:
        connection_id = session.execute(
            text(
                "SELECT connection_id FROM connector_sdk.connector_connections WHERE tenant_id=:tenant_id"
            ),
            {"tenant_id": tenant_id},
        ).scalar_one()

    other_tenant = uuid.uuid4()

    async def other_principal() -> Principal:
        return _principal(other_tenant)

    app.dependency_overrides[principal_dependency] = other_principal
    denied = test_client.get(f"/v1/integrations/connections/{connection_id}")
    assert denied.status_code == 404
