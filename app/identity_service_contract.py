"""Reference-only commands for independently owned identity infrastructure."""

import re
from typing import Any

# Explicit API commands, never arbitrary SQL, URLs, camera streams or biometrics.
SERVICE_COMMANDS = {
    "face-id": (
        "FACE_ID_VERIFY",
        "face-id.verify.v1",
        frozenset({"subject_ref", "capture_ref", "liveness_ref"}),
    ),
    "face-liveness": (
        "FACE_LIVENESS_VERIFY",
        "face-liveness.verify.v1",
        frozenset({"capture_ref", "challenge_ref"}),
    ),
    "camera-gateway": (
        "CAMERA_CAPTURE",
        "camera-gateway.capture.v1",
        frozenset({"camera_ref", "consent_ref"}),
    ),
    "postgresql": (
        "POSTGRESQL_BACKUP",
        "postgresql.backup.v1",
        frozenset({"database_ref", "backup_policy_ref"}),
    ),
}
REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")


def validate_service_command(
    command_type: str, target: str, capability: str, payload: dict[str, Any]
) -> None:
    family = command_type.split(".", 1)[0]
    if family not in SERVICE_COMMANDS and target not in SERVICE_COMMANDS:
        return
    expected = SERVICE_COMMANDS.get(target)
    if expected is None:
        raise ValueError("service command target mismatch")
    expected_capability, expected_type, fields = expected
    if (
        command_type != expected_type
        or capability != expected_capability
        or set(payload) != fields
    ):
        raise ValueError("unsupported service command or payload fields")
    if any(
        not isinstance(v, str) or not REFERENCE.fullmatch(v) for v in payload.values()
    ):
        raise ValueError("service payload requires bounded opaque references")


# Verified GitHub repository identities on 2026-09-24; no broad owner exception.
SERVICE_REPOSITORIES = {
    "face-id": "ingtrader21-spec/FACE-ID",
    "face-liveness": "ingtrader21-spec/Codestra-Face-Liveness",
    "camera-gateway": "ingtrader21-spec/Codestra-Camera-Gateway",
    "postgresql": "ingtrader21-spec/Codestra-PostgreSQL",
}
