from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.api.v1 import recordings as recording_api
from app.core.config import settings
from app.main import app
from app.recording.domain import ObjectHead
from app.recording.odoo import AcknowledgingOdooClient
from app.recording.security import ReplayGuard
from app.recording.service import RecordingService
from app.recording.storage import MemoryObjectStorage

SHA = "a" * 64


@pytest.fixture(autouse=True)
def isolated_recording_api(monkeypatch):
    service = RecordingService(MemoryObjectStorage(), AcknowledgingOdooClient())
    monkeypatch.setattr(recording_api, "recording_service", service)
    monkeypatch.setattr(recording_api, "exporter_replay_guard", ReplayGuard())
    monkeypatch.setattr(settings, "middleware_secret", "test-middleware-secret")
    return service


def reservation_payload(**updates):
    payload = {
        "contract_version": "1.0",
        "idempotency_key": "c" * 64,
        "recording": {
            "contract_version": "1.0",
            "vicidial_recording_id": "9001",
            "vicidial_call_id": "call-contract",
            "asterisk_uniqueid": "asterisk-contract",
            "campaign_key": "SYNTHETIC",
            "agent_key": "agent-contract",
            "started_at": "2026-07-31T00:00:00Z",
            "duration_seconds": 1.25,
            "format": "mp3",
            "codec": "mp3",
            "channels": 1,
            "sample_rate_hz": 8000,
            "file_size_bytes": 123,
            "sha256": SHA,
            "environment": "staging",
            "retention_class": "synthetic_test",
        },
    }
    payload["recording"].update(updates)
    return payload


def exporter_headers(nonce: str):
    return {
        "X-TLS-Client-Identity": "codestra-recording-exporter-server-b",
        "X-Certificate-Environment": "staging",
        "X-Certificate-Role": "recording-exporter",
        "X-Audience": "codestra-recording-api",
        "X-TLS-Client-Not-After": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        "X-TLS-Client-Revoked": "false",
        "X-Request-Nonce": nonce,
        "X-Request-Timestamp": str(int(datetime.now(UTC).timestamp())),
    }


def test_exporter_mtls_is_required_and_middleware_assigns_uid():
    client = TestClient(app)
    assert (
        client.post(
            "/api/v1/recordings/reservations", json=reservation_payload()
        ).status_code
        == 401
    )
    response = client.post(
        "/api/v1/recordings/reservations",
        json=reservation_payload(),
        headers=exporter_headers("reservation-contract-nonce"),
    )
    assert response.status_code == 201
    body = response.json()
    assert body["contract_version"] == "1.0"
    assert body["recording_uid"].startswith("REC-")
    assert "recording_uid" not in reservation_payload()["recording"]


def test_reservation_is_deterministic_and_replay_is_rejected():
    client = TestClient(app)
    first = client.post(
        "/api/v1/recordings/reservations",
        json=reservation_payload(),
        headers=exporter_headers("deterministic-first"),
    )
    second = client.post(
        "/api/v1/recordings/reservations",
        json=reservation_payload(),
        headers=exporter_headers("deterministic-second"),
    )
    assert first.status_code == second.status_code == 201
    assert first.json() == second.json()
    replay_headers = exporter_headers("replayed-nonce")
    accepted = client.post(
        "/api/v1/recordings/reservations",
        json={**reservation_payload(), "idempotency_key": "d" * 64},
        headers=replay_headers,
    )
    rejected = client.post(
        "/api/v1/recordings/reservations",
        json={**reservation_payload(), "idempotency_key": "e" * 64},
        headers=replay_headers,
    )
    assert accepted.status_code == 201
    assert rejected.status_code == 401


def test_health_and_service_identity_contract():
    client = TestClient(app)
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code in {200, 503}
    identity = client.get("/.well-known/codestra-service")
    assert identity.status_code == 200
    assert identity.json()["hostname"] == "api.staging.internal.codestra.agency"
    assert identity.json()["tls_sni_required"] is True


def bearer_headers(environment="staging"):
    return {
        "Authorization": "Bearer test-middleware-secret",
        "X-Codestra-Environment": environment,
    }


def complete_payload(service, recording_uid):
    recording = service.get(recording_uid)
    return {
        "contract_version": "1.0",
        "recording_uid": recording_uid,
        "idempotency_key": recording.idempotency_key,
        "environment": recording.environment,
        "campaign_key": recording.campaign_key,
        "sha256": recording.sha256,
        "file_size_bytes": recording.file_size_bytes,
        "format": recording.format,
        "duration_seconds": recording.duration_seconds,
    }


def bind_object(service, recording_uid):
    recording = service.get(recording_uid)
    service.storage.objects[(recording.opaque_object_identifier, "v-http")] = (
        ObjectHead(
            size_bytes=recording.file_size_bytes,
            content_type=recording.content_type,
            checksum_sha256=recording.sha256,
            version_id="v-http",
            metadata={
                "environment": recording.environment,
                "campaign_key": recording.campaign_key,
                "recording_uid": recording.recording_uid,
                "idempotency_key": recording.idempotency_key,
            },
        )
    )


def test_all_six_routes_auth_environment_schema_idempotency_and_failures(
    isolated_recording_api,
):
    service = isolated_recording_api
    client = TestClient(app)

    reservation_path = "/api/v1/recordings/reservations"
    assert client.post(reservation_path, json=reservation_payload()).status_code == 401
    wrong_environment = client.post(
        reservation_path,
        json=reservation_payload(environment="production"),
        headers=exporter_headers("wrong-environment"),
    )
    assert wrong_environment.status_code == 403
    malformed = reservation_payload()
    malformed["recording"]["unexpected"] = True
    assert (
        client.post(
            reservation_path,
            json=malformed,
            headers=exporter_headers("malformed-reservation"),
        ).status_code
        == 422
    )

    first = client.post(
        reservation_path,
        json=reservation_payload(),
        headers=exporter_headers("http-reserve-first"),
    )
    duplicate = client.post(
        reservation_path,
        json=reservation_payload(),
        headers=exporter_headers("http-reserve-second"),
    )
    assert first.status_code == duplicate.status_code == 201
    assert first.json() == duplicate.json()
    recording_api.ReservationResponse.model_validate(first.json())
    recording_uid = first.json()["recording_uid"]

    complete_path = f"/api/v1/recordings/{recording_uid}/complete"
    assert (
        client.post(
            complete_path, json=complete_payload(service, recording_uid)
        ).status_code
        == 401
    )
    bind_object(service, recording_uid)
    completed = client.post(
        complete_path,
        json=complete_payload(service, recording_uid),
        headers=exporter_headers("http-complete-first"),
    )
    completed_duplicate = client.post(
        complete_path,
        json=complete_payload(service, recording_uid),
        headers=exporter_headers("http-complete-second"),
    )
    assert completed.status_code == completed_duplicate.status_code == 200
    assert completed.json()["duplicate"] is False
    assert completed_duplicate.json()["duplicate"] is True
    recording_api.RecordingMutationResponse.model_validate(completed.json())

    status_path = f"/api/v1/recordings/{recording_uid}"
    assert client.get(status_path).status_code == 401
    assert (
        client.get(
            status_path, headers={"X-Codestra-Environment": "staging"}
        ).status_code
        == 401
    )
    assert (
        client.get(
            status_path,
            headers={
                "Authorization": "Bearer wrong",
                "X-Codestra-Environment": "staging",
            },
        ).status_code
        == 401
    )
    assert (
        client.get(status_path, headers=bearer_headers("production")).status_code == 403
    )
    status = client.get(status_path, headers=bearer_headers())
    assert status.status_code == 200
    recording_api.RecordingStateResponse.model_validate(status.json())

    playback_path = f"{status_path}/playback-url"
    playback_request = {
        "requester_type": "odoo",
        "user_level": 9,
        "campaign_authorized": True,
        "group_authorized": False,
        "ttl_seconds": 120,
    }
    assert client.post(playback_path, json=playback_request).status_code == 401
    assert (
        client.post(
            playback_path,
            json=playback_request,
            headers={
                "X-Codestra-Environment": "staging",
                "X-Service-Identity": "codestra-odoo",
            },
        ).status_code
        == 401
    )
    denied = client.post(
        playback_path,
        json=playback_request,
        headers={
            **bearer_headers(),
            "X-Service-Identity": "unapproved-service",
        },
    )
    assert denied.status_code == 403
    playback = client.post(
        playback_path,
        json=playback_request,
        headers={**bearer_headers(), "X-Service-Identity": "codestra-odoo"},
    )
    assert playback.status_code == 200
    assert playback.headers["cache-control"] == "no-store"
    recording_api.PlaybackResponse.model_validate(playback.json())

    automation_path = f"{status_path}/automation-result"
    automation_payload = {
        "idempotency_key": "automation-http-idempotency",
        "result": {"transcription_status": "submitted"},
    }
    assert client.post(automation_path, json=automation_payload).status_code == 401
    assert (
        client.post(
            automation_path,
            json=automation_payload,
            headers={"X-Codestra-Environment": "staging"},
        ).status_code
        == 401
    )
    automation = client.post(
        automation_path, json=automation_payload, headers=bearer_headers()
    )
    automation_duplicate = client.post(
        automation_path, json=automation_payload, headers=bearer_headers()
    )
    assert automation.status_code == automation_duplicate.status_code == 200
    assert automation.json()["duplicate"] is False
    assert automation_duplicate.json()["duplicate"] is True
    recording_api.AutomationResultResponse.model_validate(automation.json())

    failed_reservation = reservation_payload(vicidial_recording_id="9002")
    failed_reservation["idempotency_key"] = "d" * 64
    failed = client.post(
        reservation_path,
        json=failed_reservation,
        headers=exporter_headers("http-failure-reservation"),
    )
    failed_uid = failed.json()["recording_uid"]
    failure_path = f"/api/v1/recordings/{failed_uid}/failure"
    failure_headers = {
        **exporter_headers("http-failure"),
        "Idempotency-Key": service.get(failed_uid).idempotency_key,
    }
    assert client.post(failure_path, json={"code": "EXPORT_FAILED"}).status_code == 401
    failure = client.post(
        failure_path,
        json={"code": "EXPORT_FAILED"},
        headers=failure_headers,
    )
    assert failure.status_code == 200
    assert failure.json()["state"] == "FAILED"
    duplicate_headers = {
        **exporter_headers("http-failure-duplicate"),
        "Idempotency-Key": service.get(failed_uid).idempotency_key,
    }
    duplicate_failure = client.post(
        failure_path,
        json={"code": "EXPORT_FAILED"},
        headers=duplicate_headers,
    )
    assert duplicate_failure.status_code == 200
    assert duplicate_failure.json()["duplicate"] is True
    recording_api.RecordingMutationResponse.model_validate(failure.json())
    assert (
        client.post(
            "/api/v1/recordings/REC-" + "f" * 32 + "/failure",
            json={"code": "EXPORT_FAILED"},
            headers={
                **exporter_headers("http-not-found"),
                "Idempotency-Key": "d" * 64,
            },
        ).status_code
        == 404
    )


def test_all_six_openapi_operations_declare_response_models():
    schema = app.openapi()
    operations = (
        ("post", "/api/v1/recordings/reservations"),
        ("post", "/api/v1/recordings/{recording_uid}/complete"),
        ("post", "/api/v1/recordings/{recording_uid}/failure"),
        ("get", "/api/v1/recordings/{recording_uid}"),
        ("post", "/api/v1/recordings/{recording_uid}/playback-url"),
        ("post", "/api/v1/recordings/{recording_uid}/automation-result"),
    )
    expected_refs = {
        "ReservationResponse",
        "RecordingMutationResponse",
        "RecordingStateResponse",
        "PlaybackResponse",
        "AutomationResultResponse",
    }
    observed_refs = set()
    for method, path in operations:
        responses = schema["paths"][path][method]["responses"]
        success = responses["201" if path.endswith("/reservations") else "200"]
        response_schema = success["content"]["application/json"]["schema"]
        assert "$ref" in response_schema
        observed_refs.add(response_schema["$ref"].rsplit("/", 1)[-1])
    assert observed_refs == expected_refs
