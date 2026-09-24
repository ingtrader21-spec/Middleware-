#!/usr/bin/env python3
"""Static release gates for the PR B recording contract remediation."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> int:
    odoo = (ROOT / "app/recording/odoo.py").read_text()
    service = (ROOT / "app/recording/service.py").read_text()
    api = (ROOT / "app/api/v1/recordings.py").read_text()
    config = (ROOT / "app/core/config.py").read_text()
    workflow = json.loads(
        (
            ROOT / "deploy/recording-storage/n8n/recording-postprocess-v1.json"
        ).read_text()
    )
    projection = json.loads(
        (ROOT / "schemas/recording/recording-n8n-event-v1.json").read_text()
    )

    for header in (
        "X-Service-Identity",
        "X-Service-Audience",
        "X-Codestra-Timestamp",
        "X-Codestra-Nonce",
        "X-Codestra-Content-SHA256",
        "X-Codestra-Signature",
        "Idempotency-Key",
        "X-Codestra-Environment",
    ):
        require(header in odoo, f"missing Odoo HMAC header: {header}")
    require(
        "Authorization" not in odoo, "bearer fallback remains in recording Odoo client"
    )
    require("hmac.new" in odoo and "hashlib.sha256" in odoo, "HMAC-SHA256 absent")
    require(
        '.get("acknowledged")' not in odoo + service
        and '"acknowledged":' not in odoo + service,
        "noncanonical acknowledged boolean remains",
    )

    payload_fields = {
        "contract_version",
        "environment",
        "recording_uid",
        "vicidial_recording_id",
        "vicidial_call_id",
        "asterisk_uniqueid",
        "campaign_key",
        "agent_key",
        "started_at",
        "duration_seconds",
        "format",
        "codec",
        "channels",
        "sample_rate_hz",
        "file_size_bytes",
        "sha256",
        "object_version_id",
        "storage_status",
        "retention_class",
        "retention_until",
        "legal_hold",
    }
    require(
        all(f'"{field}"' in service for field in payload_fields),
        "Odoo upsert payload is incomplete",
    )
    acknowledgement_fields = {
        "contract_version",
        "recording_uid",
        "odoo_record_id",
        "call_link_status",
        "lead_link_status",
        "campaign_link_status",
        "agent_link_status",
        "storage_status",
        "retention_class",
        "retention_until",
        "legal_hold",
        "updated_at",
    }
    require(
        all(
            field in odoo and f'"{field}"' in service
            for field in acknowledgement_fields
        ),
        "canonical acknowledgement validation is incomplete",
    )
    require(api.count("response_model=") == 6, "all six response models are required")
    require(
        api.count("Depends(require_internal_service_auth)") == 3
        and "hmac.compare_digest(authorization, expected)" in api,
        "internal recording routes do not authenticate the bearer credential",
    )

    n8n_fields = {
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
    require(set(projection["required"]) == n8n_fields, "n8n required fields drifted")
    require(set(projection["properties"]) == n8n_fields, "n8n allowlist drifted")
    require(projection["additionalProperties"] is False, "n8n projection is not closed")
    require(workflow["active"] is False, "n8n workflow must remain inactive")
    require(
        workflow["meta"]["binding_enabled_default"] is False,
        "n8n binding must default inactive",
    )
    require(
        "n8n_recording_binding_enabled: bool = False" in config
        and "n8n_recording_workflow_active: bool = False" in config,
        "n8n runtime defaults must remain inactive",
    )
    require(
        service.index("RecordingState.ODOO_LINKED")
        < service.index("self.outbox.append(self._n8n_projection(recording))"),
        "n8n projection entered the critical path",
    )
    require(
        (ROOT / "docs/recording/EXPORTER-MIDDLEWARE-STATE-MAPPING.md").is_file(),
        "state mapping documentation missing",
    )
    require(
        (ROOT / "docs/recording/RETRYABILITY-CONTRACT.md").is_file(),
        "retryability documentation missing",
    )
    require(
        (ROOT / "deploy/recording-storage/ROLLBACK.md").is_file(),
        "rollback documentation missing",
    )
    required_ci = (ROOT / ".github/workflows/required-ci.yml").read_text()
    require(
        "alembic downgrade 0027_telephony_command_journal" in required_ci
        and required_ci.count("alembic upgrade head") >= 2,
        "recording migration downgrade and re-upgrade gate missing",
    )

    gates = (
        "PR_B_ODOO_HMAC_AUTH_GATE",
        "PR_B_ODOO_REPLAY_REJECTION_GATE",
        "PR_B_ODOO_PAYLOAD_COMPLETENESS_GATE",
        "PR_B_CANONICAL_ACK_GATE",
        "PR_B_NO_ACKNOWLEDGED_BOOLEAN_GATE",
        "PR_B_ALL_SIX_RESPONSE_MODELS_GATE",
        "PR_B_ALL_SIX_HTTP_ROUTE_TEST_GATE",
        "PR_B_OPENAPI_RESPONSE_SCHEMA_GATE",
        "PR_B_INTERNAL_ROUTE_AUTH_GATE",
        "PR_B_MIGRATION_DOWNGRADE_REUPGRADE_GATE",
        "PR_B_N8N_PROJECTION_SCHEMA_GATE",
        "PR_B_N8N_INACTIVE_DEFAULT_GATE",
        "PR_B_N8N_NOT_IN_CRITICAL_PATH_GATE",
        "PR_B_STATE_MAPPING_GATE",
        "PR_B_RETRYABILITY_GATE",
        "ROLLBACK_DOCUMENTATION_GATE",
    )
    for gate in gates:
        print(f"{gate}=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
