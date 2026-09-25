"""Fail-closed release-candidate / backup / restore / rollback / seal certification.

This module is pure evaluation: it never deploys, signs, backs up, restores,
rolls back, or mutates anything. It decides whether a machine-readable
evidence chain is complete and self-consistent:

``release_candidate``
    The exact source commit, image digest and schema head being certified.
``backup``
    A verified, encrypted backup of the source database at that schema head.
``restore_rehearsal``
    A verified restore of that exact backup (bound by id and sha256) into an
    isolated, different database.
``rollback``
    A pinned rollback target (source + image digest) distinct from the
    candidate, rehearsed and not requiring a schema downgrade.
``seal``
    Binds every identifier above plus the sha256 over the canonical JSON of the
    four evidence documents.

Every missing, malformed, unexpected, stale, future-dated or inconsistent
input is a blocker. ``certified`` is true only with zero blockers, and even
then certification never authorizes a production release: that requires a
signed release decision which this service neither produces nor verifies.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

EVIDENCE_KINDS = ("release_candidate", "backup", "restore_rehearsal", "rollback")
ALL_KINDS = (*EVIDENCE_KINDS, "seal")
EVIDENCE_FILES = {kind: f"{kind}.json" for kind in ALL_KINDS}
SCHEMA_IDS = {kind: f"codestra.middleware.release-{kind.replace('_', '-')}.v1" for kind in ALL_KINDS}

REPOSITORY = "ingtrader21-spec/Middleware-"
IMAGE_REPOSITORIES = frozenset({"ghcr.io/ingtrader21-spec/codestra-middleware"})
BACKUP_STORAGE_CLASSES = frozenset({"offsite_encrypted", "onsite_encrypted"})
DEFAULT_MAX_BACKUP_AGE = timedelta(hours=24)
MAX_CLOCK_SKEW = timedelta(minutes=5)
MAX_EVIDENCE_BYTES = 262_144


class InvalidEvidence:
    """Placeholder for an evidence file that exists but is not usable JSON."""

    def __repr__(self) -> str:
        return "InvalidEvidence()"


INVALID_EVIDENCE = InvalidEvidence()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def parse_evidence_json(raw: bytes | str) -> Any:
    """Strict JSON: duplicate keys are rejected rather than last-one-wins."""
    return json.loads(raw, object_pairs_hook=_unique_pairs)


def load_evidence_file(path: Path) -> Any:
    """``None`` when absent; ``INVALID_EVIDENCE`` when unreadable, oversized or not JSON."""
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > MAX_EVIDENCE_BYTES:
            return INVALID_EVIDENCE
        return parse_evidence_json(path.read_bytes())
    except (OSError, UnicodeDecodeError, ValueError):
        return INVALID_EVIDENCE


def load_evidence_dir(root: Path | None) -> dict[str, Any]:
    return {
        kind: load_evidence_file(root / filename) if root is not None else None
        for kind, filename in EVIDENCE_FILES.items()
    }

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_SCHEMA_HEAD = re.compile(r"^[0-9]{4}_[a-z0-9_]{1,120}$")
_DB_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

AUTHORITY = {
    "certification_only": True,
    "deployment_authorized": False,
    "release_signing_performed": False,
    "backup_execution_supported": False,
    "restore_execution_supported": False,
    "rollback_execution_supported": False,
    "production_effects": 0,
    "provider_effects": 0,
}

# field -> validator name; every field is required and no other field is allowed.
_FIELDS: dict[str, dict[str, str]] = {
    "release_candidate": {
        "schema": "schema",
        "candidate_id": "id",
        "repository": "repository",
        "source_sha": "sha40",
        "image_repository": "image_repository",
        "image_digest": "digest",
        "schema_head": "schema_head",
        "sbom_sha256": "sha256",
        "provenance_sha256": "sha256",
        "created_utc": "timestamp",
    },
    "backup": {
        "schema": "schema",
        "backup_id": "id",
        "source_database": "db_name",
        "schema_head": "schema_head",
        "sha256": "sha256",
        "size_bytes": "positive_int",
        "encrypted": "true",
        "storage_class": "storage_class",
        "verified": "true",
        "started_utc": "timestamp",
        "completed_utc": "timestamp",
    },
    "restore_rehearsal": {
        "schema": "schema",
        "rehearsal_id": "id",
        "backup_id": "id",
        "backup_sha256": "sha256",
        "target_database": "db_name",
        "isolated": "true",
        "restored_schema_head": "schema_head",
        "integrity_checks_passed": "true",
        "verified": "true",
        "rto_seconds": "non_negative_int",
        "started_utc": "timestamp",
        "completed_utc": "timestamp",
    },
    "rollback": {
        "schema": "schema",
        "rollback_id": "id",
        "candidate_id": "id",
        "rollback_source_sha": "sha40",
        "rollback_image_digest": "digest",
        "rollback_schema_head": "schema_head",
        "schema_downgrade_required": "false",
        "config_backup_sha256": "sha256",
        "rehearsed": "true",
        "verified": "true",
        "rehearsed_utc": "timestamp",
    },
    "seal": {
        "schema": "schema",
        "seal_id": "id",
        "candidate_id": "id",
        "source_sha": "sha40",
        "image_digest": "digest",
        "schema_head": "schema_head",
        "backup_id": "id",
        "rehearsal_id": "id",
        "rollback_id": "id",
        "evidence_sha256": "sha256",
        "sealed_utc": "timestamp",
    },
}


def _blocker(kind: str, code: str, field: str | None = None) -> dict[str, str]:
    item = {"kind": kind, "code": code}
    if field is not None:
        item["field"] = field
    return item


def parse_utc(value: Any) -> datetime | None:
    """An RFC 3339 timestamp that is explicitly UTC (``Z`` or ``+00:00``)."""
    if not isinstance(value, str) or not value.endswith(("Z", "+00:00")):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.utcoffset() != timedelta(0):
        return None
    return parsed.astimezone(UTC)


def _valid(rule: str, kind: str, value: Any) -> bool:
    if rule == "schema":
        return value == SCHEMA_IDS[kind]
    if rule == "true":
        return value is True
    if rule == "false":
        return value is False
    if rule in {"positive_int", "non_negative_int"}:
        if isinstance(value, bool) or not isinstance(value, int):
            return False
        return value > 0 if rule == "positive_int" else value >= 0
    if rule == "timestamp":
        return parse_utc(value) is not None
    if not isinstance(value, str):
        return False
    return {
        "id": lambda: bool(_ID.fullmatch(value)),
        "sha40": lambda: bool(_SHA40.fullmatch(value)),
        "sha256": lambda: bool(_SHA256.fullmatch(value)),
        "digest": lambda: bool(_DIGEST.fullmatch(value)),
        "schema_head": lambda: bool(_SCHEMA_HEAD.fullmatch(value)),
        "db_name": lambda: bool(_DB_NAME.fullmatch(value)),
        "repository": lambda: value == REPOSITORY,
        "image_repository": lambda: value in IMAGE_REPOSITORIES,
        "storage_class": lambda: value in BACKUP_STORAGE_CLASSES,
    }[rule]()


def validate_document(kind: str, document: Any, *, now: datetime) -> list[dict[str, str]]:
    """Structural blockers for one evidence document (strict, closed schema)."""
    if document is None:
        return [_blocker(kind, "evidence_missing")]
    if isinstance(document, InvalidEvidence):
        return [_blocker(kind, "evidence_unreadable")]
    if not isinstance(document, Mapping):
        return [_blocker(kind, "evidence_not_object")]
    fields = _FIELDS[kind]
    blockers = [
        _blocker(kind, "unexpected_field", str(name))
        for name in sorted(map(str, document))
        if name not in fields
    ]
    for name, rule in fields.items():
        if name not in document:
            blockers.append(_blocker(kind, "field_missing", name))
        elif not _valid(rule, kind, document[name]):
            blockers.append(_blocker(kind, "field_invalid", name))
        elif rule == "timestamp" and parse_utc(document[name]) > now + MAX_CLOCK_SKEW:  # type: ignore[operator]
            blockers.append(_blocker(kind, "timestamp_in_future", name))
    return blockers


def canonical_sha256(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def evidence_sha256(bundle: Mapping[str, Any]) -> str:
    """The digest a seal must carry: canonical JSON of the four evidence documents."""
    return canonical_sha256({kind: bundle.get(kind) for kind in EVIDENCE_KINDS})


def _ts(document: Mapping[str, Any], field: str) -> datetime:
    parsed = parse_utc(document[field])
    assert parsed is not None  # only called on structurally valid documents
    return parsed


# Each gate is checked against the documents it binds to; a gate whose
# dependencies are not structurally valid is unverifiable and fails closed.
DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "release_candidate": (),
    "backup": ("release_candidate",),
    "restore_rehearsal": ("backup",),
    "rollback": ("release_candidate",),
    "seal": EVIDENCE_KINDS,
}


def _chain_blockers(
    kind: str,
    bundle: Mapping[str, Any],
    *,
    now: datetime,
    expected_schema_head: str | None,
    max_backup_age: timedelta,
) -> list[dict[str, str]]:
    rc = bundle["release_candidate"]
    blockers: list[dict[str, str]] = []

    def check(ok: bool, code: str, field: str) -> None:
        if not ok:
            blockers.append(_blocker(kind, code, field))

    if kind == "release_candidate" and expected_schema_head is not None:
        check(rc["schema_head"] == expected_schema_head, "schema_head_not_expected", "schema_head")
    elif kind == "backup":
        backup = bundle["backup"]
        check(backup["schema_head"] == rc["schema_head"], "schema_head_mismatch", "schema_head")
        check(_ts(backup, "started_utc") <= _ts(backup, "completed_utc"), "timestamps_out_of_order", "completed_utc")
        check(now - _ts(backup, "completed_utc") <= max_backup_age, "backup_stale", "completed_utc")
    elif kind == "restore_rehearsal":
        backup = bundle["backup"]
        restore = bundle["restore_rehearsal"]
        check(restore["backup_id"] == backup["backup_id"], "backup_id_mismatch", "backup_id")
        check(restore["backup_sha256"] == backup["sha256"], "backup_sha256_mismatch", "backup_sha256")
        check(restore["target_database"] != backup["source_database"], "target_not_isolated", "target_database")
        check(restore["restored_schema_head"] == backup["schema_head"], "schema_head_mismatch", "restored_schema_head")
        check(_ts(restore, "started_utc") <= _ts(restore, "completed_utc"), "timestamps_out_of_order", "completed_utc")
        check(_ts(restore, "started_utc") >= _ts(backup, "completed_utc"), "rehearsal_precedes_backup", "started_utc")
    elif kind == "rollback":
        rollback = bundle["rollback"]
        check(rollback["candidate_id"] == rc["candidate_id"], "candidate_id_mismatch", "candidate_id")
        check(rollback["rollback_source_sha"] != rc["source_sha"], "rollback_target_is_candidate", "rollback_source_sha")
        check(rollback["rollback_image_digest"] != rc["image_digest"], "rollback_target_is_candidate", "rollback_image_digest")
        check(_ts(rollback, "rehearsed_utc") >= _ts(rc, "created_utc"), "rehearsal_precedes_candidate", "rehearsed_utc")
    elif kind == "seal":
        blockers.extend(_seal_blockers(bundle))
    return blockers


def _seal_blockers(bundle: Mapping[str, Any]) -> list[dict[str, str]]:
    rc = bundle["release_candidate"]
    seal = bundle["seal"]
    expected = {
        "candidate_id": rc["candidate_id"],
        "source_sha": rc["source_sha"],
        "image_digest": rc["image_digest"],
        "schema_head": rc["schema_head"],
        "backup_id": bundle["backup"]["backup_id"],
        "rehearsal_id": bundle["restore_rehearsal"]["rehearsal_id"],
        "rollback_id": bundle["rollback"]["rollback_id"],
        "evidence_sha256": evidence_sha256(bundle),
    }
    blockers = [
        _blocker("seal", "binding_mismatch", field)
        for field, value in expected.items()
        if seal[field] != value
    ]
    sealed = _ts(seal, "sealed_utc")
    latest = max(
        _ts(rc, "created_utc"),
        _ts(bundle["backup"], "completed_utc"),
        _ts(bundle["restore_rehearsal"], "completed_utc"),
        _ts(bundle["rollback"], "rehearsed_utc"),
    )
    if sealed < latest:
        blockers.append(_blocker("seal", "sealed_before_evidence", "sealed_utc"))
    return blockers


def evaluate(
    bundle: Mapping[str, Any],
    *,
    now: datetime | None = None,
    expected_schema_head: str | None = None,
    max_backup_age: timedelta = DEFAULT_MAX_BACKUP_AGE,
) -> dict[str, Any]:
    """Evaluate a full evidence bundle; the result is always machine-readable."""
    now = now or datetime.now(UTC)
    blockers: list[dict[str, str]] = [
        _blocker("bundle", "unexpected_field", str(name))
        for name in sorted(map(str, bundle))
        if name not in ALL_KINDS
    ]
    structural = {kind: validate_document(kind, bundle.get(kind), now=now) for kind in ALL_KINDS}
    for kind in ALL_KINDS:
        blockers.extend(structural[kind])
    evidence_valid = not any(structural[kind] for kind in EVIDENCE_KINDS)
    for kind in ALL_KINDS:
        if structural[kind]:
            continue
        if any(structural[dependency] for dependency in DEPENDENCIES[kind]):
            blockers.append(_blocker(kind, "chain_unverifiable"))
            continue
        blockers.extend(
            _chain_blockers(
                kind,
                bundle,
                now=now,
                expected_schema_head=expected_schema_head,
                max_backup_age=max_backup_age,
            )
        )

    def gate(*kinds: str) -> str:
        return "PASS" if not any(item["kind"] in kinds for item in blockers) else "BLOCKED"

    certified = not blockers
    rc = bundle.get("release_candidate") if evidence_valid else None
    return {
        "decision": "CERTIFIED" if certified else "BLOCKED",
        "certified": certified,
        "evaluated_utc": now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "gates": {
            "release_candidate": gate("release_candidate", "bundle"),
            "backup": gate("backup"),
            "restore_rehearsal": gate("restore_rehearsal"),
            "rollback_readiness": gate("rollback"),
            "release_seal": gate("seal"),
        },
        "candidate": (
            {key: rc[key] for key in ("candidate_id", "source_sha", "image_digest", "schema_head")}
            if rc
            else None
        ),
        "evidence_sha256": evidence_sha256(bundle) if evidence_valid else None,
        "blockers": blockers,
        "production_release_authorized": False,
        "authority": dict(AUTHORITY),
    }


def lock_readback(
    candidate: Any,
    *,
    source_sha: str,
    image_digest: str,
    schema_head: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Compare the running process identity with the certified candidate.

    An unknown or malformed runtime identity never matches.
    """
    now = now or datetime.now(UTC)
    candidate_blockers = validate_document("release_candidate", candidate, now=now)
    runtime = {"source_sha": source_sha, "image_digest": image_digest, "schema_head": schema_head}
    runtime_valid = {
        "source_sha": bool(_SHA40.fullmatch(source_sha or "")),
        "image_digest": bool(_DIGEST.fullmatch(image_digest or "")),
        "schema_head": bool(_SCHEMA_HEAD.fullmatch(schema_head or "")),
    }
    matches = {
        field: (
            not candidate_blockers
            and runtime_valid[field]
            and candidate[field] == runtime[field]
        )
        for field in runtime
    }
    locked = all(matches.values())
    return {
        "locked": locked,
        "status": "LOCKED" if locked else "MISMATCH" if not candidate_blockers else "CANDIDATE_INVALID",
        "runtime": runtime,
        "runtime_identity_valid": runtime_valid,
        "candidate": (
            {key: candidate[key] for key in ("candidate_id", "source_sha", "image_digest", "schema_head")}
            if not candidate_blockers
            else None
        ),
        "source_matches": matches["source_sha"],
        "image_matches": matches["image_digest"],
        "schema_matches": matches["schema_head"],
        "blockers": candidate_blockers,
    }


_RULE_SCHEMAS: dict[str, dict[str, Any]] = {
    "id": {"type": "string", "pattern": _ID.pattern},
    "sha40": {"type": "string", "pattern": _SHA40.pattern},
    "sha256": {"type": "string", "pattern": _SHA256.pattern},
    "digest": {"type": "string", "pattern": _DIGEST.pattern},
    "schema_head": {"type": "string", "pattern": _SCHEMA_HEAD.pattern},
    "db_name": {"type": "string", "pattern": _DB_NAME.pattern},
    "repository": {"const": REPOSITORY},
    "image_repository": {"enum": sorted(IMAGE_REPOSITORIES)},
    "storage_class": {"enum": sorted(BACKUP_STORAGE_CLASSES)},
    "true": {"const": True},
    "false": {"const": False},
    "positive_int": {"type": "integer", "minimum": 1},
    "non_negative_int": {"type": "integer", "minimum": 0},
    "timestamp": {"type": "string", "format": "date-time", "pattern": "(Z|\\+00:00)$"},
}


def json_schema() -> dict[str, Any]:
    """The closed JSON Schema for every evidence document, derived from ``_FIELDS``."""
    definitions = {
        kind: {
            "type": "object",
            "additionalProperties": False,
            "required": list(fields),
            "properties": {
                name: {"const": SCHEMA_IDS[kind]} if rule == "schema" else dict(_RULE_SCHEMAS[rule])
                for name, rule in fields.items()
            },
        }
        for kind, fields in _FIELDS.items()
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://codestra.internal/schemas/release-certification-evidence.v1.json",
        "title": "Codestra Middleware release certification evidence bundle v1",
        "description": (
            "Certification only: a CERTIFIED decision never authorizes deployment, "
            "signing, backup, restore or rollback execution."
        ),
        "type": "object",
        "additionalProperties": False,
        "required": list(ALL_KINDS),
        "properties": {kind: {"$ref": f"#/$defs/{kind}"} for kind in ALL_KINDS},
        "$defs": definitions,
    }
