from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from app.api.v1.booking import repository
from app.entrypoints.integration_api import app
from app.core.config import settings


client = TestClient(app)


# CI intentionally has no runtime secret. Configure only this in-process test
# client with a synthetic value; no deployment credential is loaded or logged.
settings.middleware_secret = "synthetic-booking-test-secret-32-characters"


def auth():
    return {"Authorization": f"Bearer {settings.middleware_secret}"}


def payload(tenant=None, customer=None):
    return {
        "tenant_id": str(tenant or uuid4()),
        "customer_id": str(customer or uuid4()),
        "service_code": "HOME_CLEANING",
        "address": "100 Synthetic Test Avenue",
        "country_code": "DO",
        "timezone": "America/Santo_Domingo",
        "requested_start": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
        "notes": "Synthetic staging request",
        "consent": True,
        "dnc": False,
    }


def setup_function():
    repository._records.clear()
    repository._keys.clear()


def test_catalog_is_real_and_staging_safe():
    response = client.get("/api/v1/booking/services", headers=auth())
    assert response.status_code == 200
    assert len(response.json()["services"]) >= 4
    assert response.json()["external_delivery"] is False


def test_success_idempotency_duplicate_and_cross_tenant():
    body = payload()
    headers = {**auth(), "Idempotency-Key": "synthetic-success-1"}
    first = client.post("/api/v1/booking/requests", json=body, headers=headers)
    assert first.status_code == 201
    replay = client.post("/api/v1/booking/requests", json=body, headers=headers)
    assert replay.status_code == 200
    assert replay.headers["X-Idempotent-Replay"] == "true"
    duplicate = client.post("/api/v1/booking/requests", json=body, headers={**auth(), "Idempotency-Key": "synthetic-success-2"})
    assert duplicate.status_code == 409
    appointment_id = first.json()["id"]
    denied = client.get(f"/api/v1/booking/appointments/{appointment_id}", params={"tenant_id": str(uuid4()), "customer_id": body["customer_id"]}, headers=auth())
    assert denied.status_code == 404


def test_validation_dnc_reschedule_and_cancel():
    invalid = payload()
    invalid["address"] = "x"
    assert client.post("/api/v1/booking/requests", json=invalid, headers={**auth(), "Idempotency-Key": "invalid"}).status_code == 422
    blocked = payload()
    blocked["dnc"] = True
    assert client.post("/api/v1/booking/requests", json=blocked, headers={**auth(), "Idempotency-Key": "dnc"}).status_code == 409
    body = payload()
    created = client.post("/api/v1/booking/requests", json=body, headers={**auth(), "Idempotency-Key": "lifecycle"})
    appointment_id = created.json()["id"]
    change = {"tenant_id": body["tenant_id"], "customer_id": body["customer_id"], "requested_start": (datetime.now(UTC) + timedelta(days=3)).isoformat(), "reason": "Synthetic reschedule"}
    assert client.post(f"/api/v1/booking/appointments/{appointment_id}/reschedule", json=change, headers=auth()).json()["state"] == "rescheduled"
    assert client.post(f"/api/v1/booking/appointments/{appointment_id}/cancel", json={**change, "reason": "Synthetic cancellation"}, headers=auth()).json()["state"] == "cancelled"


def test_missing_and_malformed_authorization_are_rejected():
    assert client.get("/api/v1/booking/services").status_code == 401
    assert client.get("/api/v1/booking/services", headers={"Authorization": "Bearer malformed"}).status_code == 401
