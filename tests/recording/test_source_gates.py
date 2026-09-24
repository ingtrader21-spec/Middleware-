import hashlib
import json
from pathlib import Path

from app.core.config import Settings

ROOT = Path(__file__).resolve().parents[2]
STORAGE = ROOT / "deploy" / "recording-storage"


def test_contract_and_n8n_inactive_schema():
    manifest = json.loads(
        (ROOT / "schemas/recording/contract-manifest-v1.json").read_text()
    )
    assert manifest["contract_version"] == "1.0"
    assert manifest["source_pull_request"] == 20
    assert manifest["source_head"] == "ae92b95240a5ff638837121bc2773545bfbf6fdc"
    for name, expected in manifest["schemas"].items():
        assert (
            hashlib.sha256((ROOT / "schemas/recording" / name).read_bytes()).hexdigest()
            == expected
        )
    workflow = json.loads((STORAGE / "n8n/recording-postprocess-v1.json").read_text())
    assert workflow["active"] is False
    assert workflow["meta"]["binding_enabled_default"] is False
    for action in (
        "email_actions",
        "sms_actions",
        "whatsapp_actions",
        "calendar_actions",
        "appointment_actions",
        "crm_lead_actions",
    ):
        assert workflow["meta"][action] is False
    projection = json.loads(
        (ROOT / "schemas/recording/recording-n8n-event-v1.json").read_text()
    )
    expected = {
        "contract_version",
        "event_id",
        "event_type",
        "occurred_at",
        "environment",
        "recording_uid",
        "call_uid",
        "campaign_key",
        "duration_seconds",
        "sha256",
        "object_version_id",
        "retention_class",
    }
    assert set(projection["required"]) == expected
    assert set(projection["properties"]) == expected
    assert projection["additionalProperties"] is False


def test_storage_private_lock_versioning_encryption_and_kms_gate():
    compose = (STORAGE / "compose.yaml").read_text()
    bootstrap = (STORAGE / "bucket-bootstrap/bootstrap.sh").read_text()
    assert "ports:" not in compose
    assert "internal: true" in compose
    assert "@sha256:" in compose
    assert "--with-lock" in bootstrap
    assert "version enable" in bootstrap
    assert "encrypt set sse-s3" in bootstrap
    assert "retention set --default GOVERNANCE" in bootstrap
    assert "PRODUCTION_KMS_PROVIDER" in bootstrap


def test_all_dangerous_switches_are_disabled():
    settings = Settings()
    assert settings.retention_worker_enabled is True
    assert settings.retention_delete_enabled is False
    assert settings.export_upload_enabled is False
    assert settings.odoo_recording_write_enabled is False
    assert settings.n8n_recording_workflow_enabled is False
    assert settings.n8n_recording_binding_enabled is False
    assert settings.n8n_recording_workflow_active is False
    assert settings.recording_playback_url_ttl_seconds <= 120


def test_n8n_projection_is_optional_and_not_in_critical_path():
    service = (ROOT / "app/recording/service.py").read_text()
    workflow = json.loads((STORAGE / "n8n/recording-postprocess-v1.json").read_text())
    assert workflow["active"] is False
    assert workflow["meta"]["binding_enabled_default"] is False
    assert "_n8n_projection" in service
    assert "self.outbox.append(self._n8n_projection(recording))" in service
    assert service.index("RecordingState.ODOO_LINKED") < service.index(
        "self.outbox.append(self._n8n_projection(recording))"
    )


def test_state_retry_and_rollback_documentation_exists():
    state = ROOT / "docs/recording/EXPORTER-MIDDLEWARE-STATE-MAPPING.md"
    retry = ROOT / "docs/recording/RETRYABILITY-CONTRACT.md"
    rollback = STORAGE / "ROLLBACK.md"
    assert state.is_file() and retry.is_file() and rollback.is_file()
    assert "SERVER_VERIFIED" in state.read_text()
    assert "ODOO_LINKED" in state.read_text()
    retry_text = retry.read_text().lower()
    assert "deterministic idempotency key" in retry_text
    assert "at most three transport attempts" in retry_text
    assert "`quarantined`" in retry_text
    assert "never delete" in rollback.read_text().lower()


def test_no_customer_identifiers_or_public_recording_urls():
    relevant = [
        *ROOT.glob("app/recording/*.py"),
        *ROOT.glob("deploy/recording-storage/**/*"),
    ]
    text = "\n".join(
        p.read_text(errors="ignore") for p in relevant if p.is_file()
    ).lower()
    assert '"telephone_number":' not in text
    assert '"customer_name":' not in text
    assert "public-read" not in text


def test_internal_hostname_tls_and_health_contract():
    candidate = (STORAGE / "tls/Caddyfile.candidate").read_text()
    assert "api.staging.internal.codestra.agency" in candidate
    assert "mode require_and_verify" in candidate
    assert "/health/live" in candidate and "/health/ready" in candidate
    assert "10.40.0.1 {" not in candidate


def test_all_six_routes_require_explicit_response_models_and_authentication():
    source = (ROOT / "app/api/v1/recordings.py").read_text()
    assert source.count("response_model=") == 6
    assert source.count("Depends(require_exporter_mtls)") == 3
    assert source.count("Depends(require_internal_service_auth)") == 3
    assert "hmac.compare_digest(authorization, expected)" in source
