from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.v1 import webphone
from app.core.config import settings
from app.main import app


HEADERS = {
    "X-Webphone-Gateway": "caddy-basic-auth",
    "X-Webphone-User": "preprod",
    "Origin": "https://phone.codestra.agency",
    "X-Forwarded-Proto": "https",
    "Sec-Fetch-Site": "same-origin",
}

MODERN_HEADERS = {
    "Authorization": "Bearer browser-token",
    "Origin": "https://phone.codestra.agency",
    "X-Forwarded-Proto": "https",
    "Sec-Fetch-Site": "same-origin",
}


def payload():
    return {
        "campaign_id": "TEST_SYN",
        "endpoint": "6101",
        "browser_session_id": str(uuid4()),
    }


def test_desktop_response_rejects_non_string_role():
    value = {
        "session_id": "00000000-0000-4000-8000-000000000001",
        "browser_session_binding": "00000000-0000-4000-8000-000000000002",
        "temporary_sip_authorization_username": "6101",
        "temporary_sip_credential": "short-lived",
        "endpoint": 6101,
        "sip_uri": "sip:6101@dialer.codestra.agency",
        "approved_wss_url": "wss://wss.codestra.agency:8089/ws",
        "temporary_turn_username": "turn-user",
        "temporary_turn_credential": "turn-credential",
        "approved_turn_url": "turns:dialer.codestra.agency:5349?transport=tcp",
        "expiration": "2099-01-01T00:00:00+00:00",
        "campaign": "TEST_SYN",
        "role": 7,
    }
    with pytest.raises(webphone.HTTPException) as invalid:
        webphone._desktop_response(value)
    assert invalid.value.status_code == 503


def test_deployed_default_is_fail_closed(monkeypatch):
    monkeypatch.setattr(settings, "webphone_staging_provisioning_enabled", False)
    monkeypatch.setattr(settings, "webphone_keycloak_enabled", False)
    response = TestClient(app).post(
        "/webphone-api/v1/provision", headers=HEADERS, json=payload()
    )
    assert response.status_code == 503


def test_gateway_identity_and_origin_are_required(monkeypatch):
    monkeypatch.setattr(settings, "webphone_staging_provisioning_enabled", True)
    monkeypatch.setattr(settings, "webphone_keycloak_enabled", False)
    for key in HEADERS:
        headers = {**HEADERS}
        headers.pop(key)
        response = TestClient(app).post(
            "/webphone-api/v1/provision", headers=headers, json=payload()
        )
        assert response.status_code == 403


def test_issue_returns_bounded_memory_only_contract(monkeypatch):
    monkeypatch.setattr(settings, "webphone_staging_provisioning_enabled", True)
    monkeypatch.setattr(settings, "webphone_keycloak_enabled", False)
    monkeypatch.setattr(webphone, "SESSIONS", webphone.SessionRegistry())

    async def endpoint_request(method, path, request_id, idempotency_key, body=None):
        assert method == "POST"
        assert path == "/v1/endpoint/6101/issue"
        assert body["endpoint"] == "6101"
        return {
            "status": "issued",
            "endpoint": "6101",
            "turn": {
                "urls": ["turns:dialer.codestra.agency:5349?transport=tcp"],
                "username": "temporary",
                "credential": "memory-only",
            },
        }

    monkeypatch.setattr(webphone, "endpoint_request", endpoint_request)
    response = TestClient(app).post(
        "/webphone-api/v1/provision", headers=HEADERS, json=payload()
    )
    assert response.status_code == 200
    value = response.json()
    assert value["campaign_id"] == "TEST_SYN"
    assert value["endpoint"] == "6101"
    assert value["permitted_call_scope"] == ["6000"]
    assert value["environment"] == "STAGING"
    assert value["websocket_url"].startswith("wss://")
    assert value["ice_servers"][0]["urls"][0].startswith("turns:")
    assert datetime.fromisoformat(
        value["expires_at"].replace("Z", "+00:00")
    ) <= datetime.now(timezone.utc) + timedelta(seconds=301)


def test_legacy_provisioning_route_is_retired_in_keycloak_mode(monkeypatch):
    monkeypatch.setattr(settings, "webphone_staging_provisioning_enabled", True)
    monkeypatch.setattr(settings, "webphone_keycloak_enabled", True)
    response = TestClient(app).post(
        "/webphone-api/v1/provision", headers=HEADERS, json=payload()
    )
    assert response.status_code == 410
    assert response.json() == {"detail": "legacy provisioning route disabled"}


def test_invalid_scope_and_browser_session_are_rejected(monkeypatch):
    monkeypatch.setattr(settings, "webphone_staging_provisioning_enabled", True)
    monkeypatch.setattr(settings, "webphone_keycloak_enabled", True)
    client = TestClient(app)
    invalid = payload()
    invalid["campaign_id"] = "PRODUCTION"
    assert (
        client.post(
            "/webphone-api/v1/provision", headers=HEADERS, json=invalid
        ).status_code
        == 410
    )


def _explicit_identity(monkeypatch) -> None:
    # The browser facade only trusts an explicitly configured identity authority.
    monkeypatch.setattr(settings, "keycloak_issuer", "https://auth-staging.codestra.co/realms/codestra")
    monkeypatch.setattr(settings, "keycloak_audience", "middleware-api")
    monkeypatch.setattr(
        settings,
        "keycloak_jwks_url",
        "https://auth-staging.codestra.co/realms/codestra/protocol/openid-connect/certs",
    )
    monkeypatch.setattr(settings, "keycloak_authorized_parties", "codestra-agent-desktop")


def test_keycloak_gateway_proxies_only_validated_identity(monkeypatch):
    monkeypatch.setattr(settings, "webphone_staging_provisioning_enabled", True)
    monkeypatch.setattr(settings, "webphone_keycloak_enabled", True)
    _explicit_identity(monkeypatch)
    monkeypatch.setattr(
        webphone.KeycloakValidator,
        "validate",
        lambda self, token: {
            "sub": "keycloak-subject",
            "typ": "ID",
            "azp": "codestra-agent-desktop",
            "realm_access": {"roles": ["codestra_agent"]},
        },
    )
    monkeypatch.setattr(
        webphone,
        "_keycloak_user",
        lambda subject, *_client: __import__("asyncio").sleep(
            0,
            result={
                "enabled": True,
                "username": "agent-6102",
                "attributes": {
                    "employee_id": ["EMP-1"],
                    "odoo_employee_id": ["ODOO-1"],
                    "vicidial_username": ["agent-6102"],
                    "company_id": ["COMP-1"],
                    "business_unit_id": ["BU-1"],
                    "department_id": ["DEPT-1"],
                    "team_id": ["TEAM-1"],
                    "supervisor_id": ["SUP-1"],
                    "agent_desktop_roles": ["agent"],
                    "lifecycle_state": ["active"],
                    "role_template": ["AGENT"],
                    "campaign_ids": ["TEST_SYN"],
                },
            },
        ),
    )
    monkeypatch.setattr(
        webphone,
        "_odoo_identity",
        lambda employee_id, _client=None, campaign_id=None, endpoint=None: __import__(
            "asyncio"
        ).sleep(
            0,
            result={
                "employee_id": "EMP-1",
                "odoo_employee_id": "ODOO-1",
                "keycloak_subject": "keycloak-subject",
                "endpoint": "6101",
                "vicidial_username": "agent-6102",
                "campaign_ids": ["TEST_SYN"],
                "role_template": "AGENT",
            },
        ),
    )
    calls = []

    async def provisioning_call(_request, method, path, body=None, query=None):
        calls.append((method, path, body, query))
        return {
            "session_id": "00000000-0000-4000-8000-000000000001",
            "temporary_sip_authorization_username": "6101",
            "temporary_sip_credential": "short-lived",
            "endpoint": 6101,
            "sip_uri": "sip:6101@dialer.codestra.agency",
            "approved_wss_url": "wss://wss.codestra.agency:8089/ws",
            "temporary_turn_username": "turn-user",
            "temporary_turn_credential": "turn-credential",
            "approved_turn_url": "turns:dialer.codestra.agency:5349?transport=tcp",
            "expiration": "2099-01-01T00:00:00+00:00",
            "campaign": "TEST_SYN",
            "role": "AGENT",
            "employee_identity": "EMP-1",
            "browser_session_binding": "00000000-0000-4000-8000-000000000002",
        }

    monkeypatch.setattr(webphone, "_provisioning_call", provisioning_call)
    response = TestClient(app).post(
        "/webphone-api/v1/session",
        headers=MODERN_HEADERS,
        json={
            "campaign_id": "TEST_SYN",
            "endpoint": "6101",
            "browser_session_id": str(uuid4()),
        },
    )
    assert response.status_code == 200
    assert response.json()["ephemeral_password"] == "short-lived"
    assert calls[0][0:2] == ("POST", "/session")
    assert calls[0][2]["keycloak_subject"] == "keycloak-subject"
    assert calls[0][2]["employee_id"] == "EMP-1"


def test_keycloak_gateway_denies_wrong_campaign_and_missing_origin(monkeypatch):
    monkeypatch.setattr(settings, "webphone_staging_provisioning_enabled", True)
    monkeypatch.setattr(settings, "webphone_keycloak_enabled", True)
    _explicit_identity(monkeypatch)
    monkeypatch.setattr(
        webphone.KeycloakValidator,
        "validate",
        lambda self, token: {
            "sub": "subject",
            "typ": "ID",
            "azp": "codestra-agent-desktop",
            "realm_access": {"roles": ["codestra_agent"]},
        },
    )
    monkeypatch.setattr(
        webphone,
        "_keycloak_user",
        lambda subject, *_client: __import__("asyncio").sleep(
            0,
            result={
                "enabled": True,
                "username": "agent",
                "attributes": {
                    "employee_id": ["EMP-1"],
                    "company_id": ["COMP-1"],
                    "business_unit_id": ["BU-1"],
                    "department_id": ["DEPT-1"],
                    "team_id": ["TEAM-1"],
                    "supervisor_id": ["SUP-1"],
                    "agent_desktop_roles": ["agent"],
                    "lifecycle_state": ["active"],
                    "role_template": ["AGENT"],
                    "campaign_ids": ["TEST_SYN"],
                },
            },
        ),
    )
    monkeypatch.setattr(
        webphone,
        "_odoo_identity",
        lambda employee_id, _client=None, campaign_id=None, endpoint=None: __import__(
            "asyncio"
        ).sleep(
            0,
            result={
                "employee_id": "EMP-1",
                "odoo_employee_id": "EMP-1",
                "keycloak_subject": "subject",
                "endpoint": "6101",
                "vicidial_username": "agent",
                "campaign_ids": ["TEST_SYN"],
                "role_template": "AGENT",
            },
        ),
    )
    client = TestClient(app)
    missing_origin = client.post(
        "/webphone-api/v1/session",
        headers={"Authorization": "Bearer browser-token"},
        json={
            "campaign_id": "TEST_SYN",
            "endpoint": "6101",
            "browser_session_id": str(uuid4()),
        },
    )
    assert missing_origin.status_code == 403
    wrong_campaign = client.post(
        "/webphone-api/v1/session",
        headers=MODERN_HEADERS,
        json={
            "campaign_id": "OTHER",
            "endpoint": "6101",
            "browser_session_id": str(uuid4()),
        },
    )
    assert wrong_campaign.status_code == 403
    invalid = payload()
    invalid["browser_session_id"] = "not-a-uuid"
    assert (
        client.post(
            "/webphone-api/v1/provision", headers=HEADERS, json=invalid
        ).status_code
        == 410
    )
