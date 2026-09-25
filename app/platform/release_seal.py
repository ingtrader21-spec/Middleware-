from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HASH64 = re.compile(r"^[0-9a-f]{64}$")


class ReleaseSealError(ValueError):
    pass


@dataclass(frozen=True)
class ReleaseSeal:
    source_sha: str
    image_digest: str
    schema_head: str
    production_go: str
    provider_effects: int
    production_effects: int


def validate_release_seal(packet: dict[str, Any]) -> ReleaseSeal:
    source_sha = str(packet.get("protected_source_sha") or "")
    image_digest = str(packet.get("image_digest") or "")
    schema_head = str(packet.get("alembic_head") or "")

    if SHA40.fullmatch(source_sha) is None:
        raise ReleaseSealError("protected_source_sha must be a 40-char lowercase git SHA")
    if DIGEST.fullmatch(image_digest) is None:
        raise ReleaseSealError("image_digest must be immutable sha256")
    if schema_head != "0067":
        raise ReleaseSealError("alembic_head must be 0067")

    for field in ("sbom_sha256", "trivy_sha256", "grype_sha256", "provenance_sha256"):
        if HASH64.fullmatch(str(packet.get(field) or "")) is None:
            raise ReleaseSealError(f"{field} must be a sha256 hex digest")

    if packet.get("cosign_verified") is not True:
        raise ReleaseSealError("Cosign verification must pass")
    if not str(packet.get("cosign_identity") or "").strip():
        raise ReleaseSealError("Cosign identity is required")
    issuer = str(packet.get("cosign_issuer") or "")
    if not issuer.startswith("https://"):
        raise ReleaseSealError("Cosign issuer must be an https issuer")

    if packet.get("vulnerability_policy_passed") is not True:
        raise ReleaseSealError("vulnerability policy must pass")
    if packet.get("backup_verified") is not True:
        raise ReleaseSealError("backup verification must pass")
    if packet.get("restore_rehearsal_passed") is not True:
        raise ReleaseSealError("restore rehearsal must pass")
    if packet.get("rollback_rehearsal_passed") is not True:
        raise ReleaseSealError("rollback rehearsal must pass")

    if packet.get("provider_effects") != 0:
        raise ReleaseSealError("provider_effects must remain 0")
    if packet.get("production_effects") != 0:
        raise ReleaseSealError("production_effects must remain 0")
    if packet.get("production_go") != "NO":
        raise ReleaseSealError("production_go must remain NO during release seal")

    return ReleaseSeal(
        source_sha=source_sha,
        image_digest=image_digest,
        schema_head=schema_head,
        production_go="NO",
        provider_effects=0,
        production_effects=0,
    )
