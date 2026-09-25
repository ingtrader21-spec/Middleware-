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
            "CAMERA_PTZ": "camera-gateway.ptz.control",
        }[mission[0]]
        in scopes
    )


def validate_event_idempotency(command_type: str, payload: dict, key: str) -> None:
    if command_type in {"face-id.presence.enter.v1", "face-id.presence.exit.v1"}:
        if key != "presence:" + payload["event_ref"]:
            raise ValueError("presence idempotency key must be presence:<event_ref>")
