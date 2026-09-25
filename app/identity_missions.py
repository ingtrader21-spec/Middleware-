"""Closed, reference-only FACE-ID mission contracts; no runtime activation."""

import math
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

REF = {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$"}
TIME = {"type": "string", "format": "date-time", "maxLength": 40}


def closed(properties: dict[str, Any], optional: tuple[str, ...] = ()) -> dict:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [key for key in properties if key not in optional],
        "properties": properties,
    }


MISSION_COMMANDS = {
    "face-id.access.evaluate.v1": (
        "FACE_ID_ACCESS_EVALUATE",
        closed(
            {
                "subject_ref": REF,
                "zone_ref": REF,
                "occurred_at": TIME,
                "visitor_pass_ref": REF,
            },
            ("visitor_pass_ref",),
        ),
    ),
    **{
        f"face-id.presence.{direction}.v1": (
            "FACE_ID_PRESENCE_EVENT",
            closed(
                dict.fromkeys(
                    ("event_ref", "camera_ref", "zone_ref", "subject_ref"), REF
                )
            ),
        )
        for direction in ("enter", "exit")
    },
    "camera-gateway.ptz.move.v1": (
        "CAMERA_PTZ",
        closed(
            {
                "camera_ref": REF,
                "pan": {"type": "number", "minimum": -1, "maximum": 1},
                "tilt": {"type": "number", "minimum": -1, "maximum": 1},
                "zoom": {"type": "number", "minimum": 0, "maximum": 1},
                "duration_ms": {"type": "integer", "minimum": 100, "maximum": 2000},
            }
        ),
    ),
    "camera-gateway.ptz.stop.v1": ("CAMERA_PTZ", closed({"camera_ref": REF})),
}

MISSION_COMMANDS.update(
    {
        "face-id.watchlist.membership.update.v1": (
            "FACE_ID_WATCHLIST_REFERENCE",
            closed(
                {
                    "watchlist_ref": REF,
                    "subject_ref": REF,
                    "action": {"enum": ["add", "remove"]},
                    "decision_ref": REF,
                }
            ),
        ),
        "face-id.enrollment.quality.review.v1": (
            "FACE_ID_ENROLLMENT_REVIEW",
            closed(
                {
                    "session_ref": REF,
                    "quality_evidence_ref": REF,
                    "decision": {"enum": ["accept", "reject", "needs_review"]},
                }
            ),
        ),
        "face-id.duplicate.review.resolve.v1": (
            "FACE_ID_ENROLLMENT_REVIEW",
            closed(
                {
                    "review_ref": REF,
                    "candidate_subject_ref": REF,
                    "evidence_ref": REF,
                    "resolution": {"enum": ["distinct", "same_subject_candidate", "needs_review"]},
                }
            ),
        ),
        "camera-gateway.event.normalize.v1": (
            "CAMERA_EVENT_NORMALIZATION",
            closed(
                {
                    "event_ref": REF,
                    "camera_ref": REF,
                    "event_kind": {"enum": ["motion", "scene_change", "tamper", "health"]},
                    "observed_at": TIME,
                    "source_version": REF,
                    "heuristic": {"type": "boolean"},
                }
            ),
        ),
        "camera-gateway.maintenance.update.v1": (
            "CAMERA_MAINTENANCE_METADATA",
            closed(
                {
                    "camera_ref": REF,
                    "enabled": {"type": "boolean"},
                    "reason_ref": REF,
                },
                ("reason_ref",),
            ),
        ),
    }
)


# Only sanitized, closed results can enter the operation evidence ledger.
MISSION_RESULTS = {
    "face-id.access.evaluate.v1": closed(
        {
            "decision_ref": REF,
            "decision": {"enum": ["allow", "deny", "indeterminate"]},
            "policy_ref": REF,
            "evaluated_at": TIME,
            "door_effect": {"const": False},
        },
        ("policy_ref",),
    ),
    **{
        f"face-id.presence.{direction}.v1": closed({"event_ref": REF})
        for direction in ("enter", "exit")
    },
    **{
        f"camera-gateway.ptz.{action}.v1": closed(
            {
                "camera_ref": REF,
                "motion_state": {"const": "stopped"},
                "stop_reason": {
                    "enum": ["explicit_stop", "duration_elapsed", "failsafe"]
                },
            }
        )
        for action in ("move", "stop")
    },
}

MISSION_RESULTS.update(
    {
        "face-id.watchlist.membership.update.v1": closed(
            {
                "watchlist_ref": REF,
                "subject_ref": REF,
                "membership_ref": REF,
                "state": {"enum": ["present", "absent"]},
                "audit_ref": REF,
            }
        ),
        "face-id.enrollment.quality.review.v1": closed(
            {
                "session_ref": REF,
                "review_ref": REF,
                "decision": {"enum": ["accept", "reject", "needs_review"]},
                "audit_ref": REF,
                "identity_asserted": {"const": False},
            }
        ),
        "face-id.duplicate.review.resolve.v1": closed(
            {
                "review_ref": REF,
                "resolution_ref": REF,
                "resolution": {"enum": ["distinct", "same_subject_candidate", "needs_review"]},
                "audit_ref": REF,
                "auto_merged": {"const": False},
                "identity_asserted": {"const": False},
            }
        ),
        "camera-gateway.event.normalize.v1": closed(
            {
                "event_ref": REF,
                "camera_ref": REF,
                "normalized_event_ref": REF,
                "stored_raw_frame": {"const": False},
            }
        ),
        "camera-gateway.maintenance.update.v1": closed(
            {
                "camera_ref": REF,
                "enabled": {"type": "boolean"},
                "reason_ref": {"anyOf": [REF, {"type": "null"}]},
                "changed_at": TIME,
            },
            ("reason_ref",),
        ),
    }
)


READBACKS: dict[str, dict[str, Any]] = {
    name: {
        "service_id": "postgresql",
        "method": "GET",
        "path": f"/internal/v1/observability/{name}",
        "scope": "connector.postgresql.read",
        "state": "PROPOSED_NOT_IMPLEMENTED",
        "schema": closed(
            {
                "tenant_id": REF,
                "database_ref": REF,
                "observed_at": TIME,
                "status": {"enum": ["ready", "not_ready", "unknown"]},
                "evidence_refs": {
                    "type": "array",
                    "maxItems": 100,
                    "uniqueItems": True,
                    "items": REF,
                },
            }
        ),
    }
    for name in (
        "backup-catalog",
        "restore-rehearsal",
        "tls-security",
        "replication-recovery",
    )
}


# Nullable checks distinguish missing evidence from a measured failure.
for _name, _checks in {
    "backup-catalog": ("catalog_available", "encrypted", "offsite_verified"),
    "restore-rehearsal": (
        "isolated_target",
        "restore_verified",
        "application_verified",
    ),
    "tls-security": ("tls_required", "certificate_valid", "least_privilege_verified"),
    "replication-recovery": (
        "replication_healthy",
        "recovery_tested",
        "rpo_met",
        "rto_met",
    ),
}.items():
    _schema = READBACKS[_name]["schema"]
    _schema["required"].append("checks")
    _schema["properties"]["checks"] = closed(
        {key: {"type": ["boolean", "null"]} for key in _checks}
    )
    _schema["allOf"] = [
        {
            "if": {"properties": {"status": {"const": "ready"}}},
            "then": {
                "properties": {
                    "checks": closed({key: {"const": True} for key in _checks}),
                    "evidence_refs": {"minItems": 1},
                }
            },
        }
    ]


for _name, _checks in {
    "pitr-readiness": ("wal_archiving", "base_backup_recent", "recovery_target_supported"),
    "capacity-status": ("storage_within_threshold", "growth_sample_recent", "disk_free_known"),
    "maintenance-health": ("autovacuum_healthy", "analyze_recent", "checkpoint_healthy"),
    "failover-rehearsal": ("rehearsal_completed", "integrity_verified", "rto_recorded"),
}.items():
    READBACKS[_name] = {
        "service_id": "postgresql",
        "method": "GET",
        "path": f"/internal/v1/observability/{_name}",
        "scope": "connector.postgresql.read",
        "state": "IMPLEMENTED_READ_ONLY",
        "schema": closed(
            {
                "tenant_id": REF,
                "database_ref": REF,
                "observed_at": TIME,
                "status": {"enum": ["ready", "not_ready", "unknown"]},
                "evidence_refs": {
                    "type": "array",
                    "maxItems": 100,
                    "uniqueItems": True,
                    "items": REF,
                },
                "checks": closed({key: {"type": ["boolean", "null"]} for key in _checks}),
            }
        ),
    }
    _schema = READBACKS[_name]["schema"]
    _schema["allOf"] = [
        {
            "if": {"properties": {"status": {"const": "ready"}}},
            "then": {
                "properties": {
                    "checks": closed({key: {"const": True} for key in _checks}),
                    "evidence_refs": {"minItems": 1},
                }
            },
        }
    ]


VERSION = {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"}
HEX64 = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
NULL_TIME = {"type": ["string", "null"], "format": "date-time", "maxLength": 40}
NULL_REF = {"type": ["string", "null"], "pattern": r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$"}

SERVICE_READBACKS: dict[str, dict[str, Any]] = {
    "camera-contract-version": {
        "service_id": "camera-gateway",
        "method": "GET",
        "path": "/v1/contract-version",
        "scope": "connector.camera-gateway.read",
        "resource_param": None,
        "state": "IMPLEMENTED_READ_ONLY",
        "schema": closed(
            {
                "service": {"const": "camera-gateway"},
                "service_version": VERSION,
                "api_version": {"const": "v1"},
                "contract_revision": {"const": "camera-gateway.missions-11-22.v1"},
                "capability_sha256": HEX64,
                "middleware_authority": {"const": True},
            }
        ),
    },
    "camera-configuration-snapshot": {
        "service_id": "camera-gateway",
        "method": "GET",
        "path": "/v1/cameras/{camera_ref}/configuration-snapshot",
        "scope": "connector.camera-gateway.read",
        "resource_param": "camera_ref",
        "state": "IMPLEMENTED_READ_ONLY",
        "schema": closed(
            {
                "camera_id": REF,
                "observed_at": TIME,
                "config_sha256": HEX64,
                "enabled": {"type": "boolean"},
                "vendor": VERSION,
                "rtsp_transport": {"enum": ["tcp", "udp"]},
                "onvif_enabled": {"type": "boolean"},
                "credential_ref_present": {"type": "boolean"},
                "labels_count": {"type": "integer", "minimum": 0, "maximum": 32},
            }
        ),
    },
    "camera-connectivity-evidence": {
        "service_id": "camera-gateway",
        "method": "GET",
        "path": "/v1/cameras/{camera_ref}/connectivity-evidence",
        "scope": "connector.camera-gateway.read",
        "resource_param": "camera_ref",
        "state": "IMPLEMENTED_READ_ONLY",
        "schema": closed(
            {
                "camera_id": REF,
                "observed_at": TIME,
                "status": {"enum": ["unknown", "online", "offline", "auth_failed", "error"]},
                "last_success_at": NULL_TIME,
                "last_error_code": {"type": ["string", "null"], "maxLength": 128},
                "recent_event_count": {"type": "integer", "minimum": 0, "maximum": 200},
            }
        ),
    },
    "camera-stream-quality": {
        "service_id": "camera-gateway",
        "method": "GET",
        "path": "/v1/cameras/{camera_ref}/stream-quality",
        "scope": "connector.camera-gateway.read",
        "resource_param": "camera_ref",
        "state": "IMPLEMENTED_READ_ONLY",
        "schema": closed(
            {
                "camera_id": REF,
                "observed_at": TIME,
                "status": {"enum": ["known", "unknown"]},
                "codec": {"type": ["string", "null"], "maxLength": 64},
                "width": {"type": ["integer", "null"], "minimum": 1},
                "height": {"type": ["integer", "null"], "minimum": 1},
                "fps": {"type": ["number", "null"], "minimum": 0},
                "last_frame_at": NULL_TIME,
                "stale": {"type": "boolean"},
            }
        ),
    },
    "camera-maintenance-state": {
        "service_id": "camera-gateway",
        "method": "GET",
        "path": "/v1/cameras/{camera_ref}/maintenance",
        "scope": "connector.camera-gateway.read",
        "resource_param": "camera_ref",
        "state": "IMPLEMENTED_READ_ONLY",
        "schema": closed(
            {
                "camera_id": REF,
                "enabled": {"type": "boolean"},
                "reason_ref": NULL_REF,
                "changed_at": NULL_TIME,
            }
        ),
    },
    "camera-inventory-search": {
        "service_id": "camera-gateway",
        "method": "GET",
        "path": "/v1/camera-inventory/search",
        "scope": "connector.camera-gateway.read",
        "resource_param": None,
        "state": "IMPLEMENTED_READ_ONLY",
        "schema": closed(
            {
                "items": {
                    "type": "array",
                    "maxItems": 200,
                    "uniqueItems": True,
                    "items": REF,
                },
                "total": {"type": "integer", "minimum": 0, "maximum": 200},
            }
        ),
    },
    "camera-compatibility": {
        "service_id": "camera-gateway",
        "method": "GET",
        "path": "/v1/cameras/{camera_ref}/compatibility",
        "scope": "connector.camera-gateway.read",
        "resource_param": "camera_ref",
        "state": "IMPLEMENTED_READ_ONLY",
        "schema": closed(
            {
                "camera_id": REF,
                "compatible": {"type": "boolean"},
                "checks": {
                    "type": "object",
                    "additionalProperties": {"type": "boolean"},
                    "maxProperties": 32,
                },
                "warnings": {
                    "type": "array",
                    "maxItems": 32,
                    "items": VERSION,
                },
            }
        ),
    },
    "camera-event-page": {
        "service_id": "camera-gateway",
        "method": "GET",
        "path": "/v1/cameras/{camera_ref}/events/page",
        "scope": "connector.camera-gateway.read",
        "resource_param": "camera_ref",
        "state": "IMPLEMENTED_READ_ONLY",
        "schema": closed(
            {
                "items": {
                    "type": "array",
                    "maxItems": 200,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "id",
                            "camera_id",
                            "observed_at",
                            "kind",
                            "source",
                            "source_version",
                            "heuristic",
                            "confidence_kind",
                            "signal",
                        ],
                        "properties": {
                            "id": {"type": "integer", "minimum": 1},
                            "camera_id": REF,
                            "observed_at": TIME,
                            "kind": {"enum": ["motion", "scene_change", "tamper", "health"]},
                            "source": {"enum": ["gateway_health", "frame_delta", "camera_native"]},
                            "source_version": VERSION,
                            "heuristic": {"type": "boolean"},
                            "confidence_kind": {"enum": ["heuristic", "observed"]},
                            "score": {"type": ["number", "null"], "minimum": 0, "maximum": 1},
                            "signal": {"type": "string", "minLength": 1, "maxLength": 128},
                        },
                    },
                },
                "next_offset": {"type": ["integer", "null"], "minimum": 0},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                "offset": {"type": "integer", "minimum": 0},
            }
        ),
    },
    "camera-health-slo": {
        "service_id": "camera-gateway",
        "method": "GET",
        "path": "/v1/cameras/{camera_ref}/health/slo",
        "scope": "connector.camera-gateway.read",
        "resource_param": "camera_ref",
        "state": "IMPLEMENTED_READ_ONLY",
        "schema": closed(
            {
                "camera_id": REF,
                "observed_at": TIME,
                "health_fresh": {"type": "boolean"},
                "frame_fresh": {"type": "boolean"},
                "last_success_at": NULL_TIME,
                "last_frame_at": NULL_TIME,
                "status": {"enum": ["healthy", "degraded", "unknown"]},
            }
        ),
    },
    "camera-secret-reference-health": {
        "service_id": "camera-gateway",
        "method": "GET",
        "path": "/v1/cameras/{camera_ref}/credentials/reference-health",
        "scope": "connector.camera-gateway.read",
        "resource_param": "camera_ref",
        "state": "IMPLEMENTED_READ_ONLY",
        "schema": closed(
            {
                "camera_id": REF,
                "configured": {"type": "boolean"},
                "scheme": {"type": ["string", "null"], "enum": ["openbao", None]},
                "fingerprint": {"type": ["string", "null"], "pattern": r"^[0-9a-f]{16}$"},
                "reference_valid": {"type": "boolean"},
                "last_successful_auth": NULL_TIME,
            }
        ),
    },
    "camera-retention-policy": {
        "service_id": "camera-gateway",
        "method": "GET",
        "path": "/v1/cameras/{camera_ref}/retention-policy",
        "scope": "connector.camera-gateway.read",
        "resource_param": "camera_ref",
        "state": "IMPLEMENTED_READ_ONLY",
        "schema": closed(
            {
                "camera_id": REF,
                "clip_retention_s": {"type": "integer", "minimum": 1},
                "rolling_buffer_retention_s": {"type": "integer", "minimum": 1},
                "health_event_limit": {"type": "integer", "minimum": 1},
                "normalized_event_limit": {"type": "integer", "minimum": 1},
                "raw_frames_persisted": {"const": False},
            }
        ),
    },
    "camera-diagnostics": {
        "service_id": "camera-gateway",
        "method": "GET",
        "path": "/v1/cameras/{camera_ref}/diagnostics",
        "scope": "connector.camera-gateway.read",
        "resource_param": "camera_ref",
        "state": "IMPLEMENTED_READ_ONLY",
        "schema": closed(
            {
                "camera_id": REF,
                "observed_at": TIME,
                "health_status": {"enum": ["unknown", "online", "offline", "auth_failed", "error"]},
                "inventory_stale": {"type": "boolean"},
                "credentials_configured": {"type": "boolean"},
                "rolling_buffer_enabled": {"type": "boolean"},
                "maintenance_enabled": {"type": "boolean"},
                "clock_drift_ms": {"type": ["integer", "null"]},
                "secrets_exposed": {"const": False},
            }
        ),
    },
}


def validate_schema(schema: dict, value: Any) -> None:
    def finite(item: Any) -> bool:
        if isinstance(item, float):
            return math.isfinite(item)
        if isinstance(item, dict):
            return all(finite(v) for v in item.values())
        if isinstance(item, list):
            return all(finite(v) for v in item)
        return True

    if not finite(value):
        raise ValueError("identity mission contract invalid")
    try:
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
    except ValidationError:
        # Never echo invalid payloads, SQL, credentials or biometrics in errors.
        raise ValueError("identity mission contract invalid") from None


def authorize_mission(command_type: str, scopes: tuple[str, ...]) -> bool:
    """Additional least-privilege scope; ordinary kernel policy still applies."""
    mission = MISSION_COMMANDS.get(command_type)
    return mission is None or (
        "platform.command" in scopes
        and {
            "FACE_ID_ACCESS_EVALUATE": "face-id.access.evaluate",
            "FACE_ID_PRESENCE_EVENT": "face-id.presence.write",
            "FACE_ID_WATCHLIST_REFERENCE": "face-id.watchlist.write",
            "FACE_ID_ENROLLMENT_REVIEW": "face-id.enrollment.review",
            "CAMERA_PTZ": "camera-gateway.ptz.control",
            "CAMERA_EVENT_NORMALIZATION": "camera-gateway.events.write",
            "CAMERA_MAINTENANCE_METADATA": "camera-gateway.maintenance.write",
        }[mission[0]]
        in scopes
    )


def validate_event_idempotency(command_type: str, payload: dict, key: str) -> None:
    if command_type in {"face-id.presence.enter.v1", "face-id.presence.exit.v1"}:
        if key != "presence:" + payload["event_ref"]:
            raise ValueError("presence idempotency key must be presence:<event_ref>")
    elif command_type == "face-id.watchlist.membership.update.v1":
        expected = "watchlist:" + payload["watchlist_ref"] + ":" + payload["subject_ref"] + ":" + payload["action"]
        if key != expected:
            raise ValueError("watchlist idempotency key invalid")
    elif command_type == "face-id.enrollment.quality.review.v1":
        if key != "enrollment-review:" + payload["session_ref"]:
            raise ValueError("enrollment review idempotency key invalid")
    elif command_type == "face-id.duplicate.review.resolve.v1":
        if key != "duplicate-review:" + payload["review_ref"]:
            raise ValueError("duplicate review idempotency key invalid")
    elif command_type == "camera-gateway.event.normalize.v1":
        if key != "camera-event:" + payload["event_ref"]:
            raise ValueError("camera event idempotency key invalid")
    elif command_type == "camera-gateway.maintenance.update.v1":
        expected = "camera-maintenance:" + payload["camera_ref"] + ":" + (
            "enabled" if payload["enabled"] else "disabled"
        )
        if key != expected:
            raise ValueError("camera maintenance idempotency key invalid")
