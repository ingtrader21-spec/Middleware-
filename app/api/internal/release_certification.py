"""Private fail-closed release certification API.

Reads machine-readable release-candidate, backup, restore-rehearsal, rollback
and seal evidence from ``RELEASE_CERTIFICATION_EVIDENCE_DIR`` and evaluates it
with :mod:`app.release_certification`. No handler deploys, signs, backs up,
restores, rolls back, writes evidence, or reaches a provider; the POST
``/evaluate`` route computes a decision over a submitted bundle and persists
nothing. The surface is edge-denied under ``/internal/*``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from app import release_certification as certification
from app.api_inputs import authorization_header
from app.control_plane_auth import caller_for_authorization

router = APIRouter(prefix="/internal/v1/release", tags=["internal-release-certification"])

READ_SCOPE = "platform.release.read"
VERIFY_SCOPE = "platform.release.verify"


def _runtime(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None or getattr(runtime, "settings", None) is None:
        raise HTTPException(503, "release certification runtime unavailable")
    return runtime


async def _authorize(request: Request, required_scope: str) -> str:
    runtime = _runtime(request)
    authorization = authorization_header(request)
    caller = caller_for_authorization(authorization)
    await runtime.tokens.verify(
        authorization,
        expected_client_id=caller.client_id,
        required_scope=required_scope,
    )
    return caller.client_id


def _setting(request: Request, name: str, default: Any) -> Any:
    return getattr(_runtime(request).settings, name, default)


def _evidence_root(request: Request) -> Path | None:
    root = str(_setting(request, "release_certification_evidence_dir", "") or "").strip()
    return Path(root) if root else None


def _bundle(request: Request) -> dict[str, Any]:
    return certification.load_evidence_dir(_evidence_root(request))


def _evaluate(request: Request, bundle: dict[str, Any]) -> dict[str, Any]:
    hours = int(_setting(request, "release_certification_max_backup_age_hours", 24))
    expected_head = str(_setting(request, "schema_head", "") or "") or None
    return certification.evaluate(
        bundle,
        now=datetime.now(UTC),
        expected_schema_head=expected_head,
        max_backup_age=timedelta(hours=max(hours, 1)),
    )


def _kind_view(result: dict[str, Any], bundle: dict[str, Any], kind: str, gate: str) -> dict[str, Any]:
    document: Any = bundle.get(kind)
    blockers = [item for item in result["blockers"] if item["kind"] == kind]
    structurally_valid = not certification.validate_document(
        kind, document, now=datetime.now(UTC)
    )
    return {
        "kind": kind,
        "available": document is not None,
        "status": result["gates"][gate],
        # Only a document that passed the closed schema is echoed back, so an
        # evidence file can never smuggle unexpected fields through the API.
        "evidence": dict(document) if structurally_valid else None,
        "blockers": blockers,
        "authority": result["authority"],
    }


@router.get("/certification")
async def certification_status(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    root = _evidence_root(request)
    result = _evaluate(request, _bundle(request))
    result["evidence_source"] = "directory" if root is not None else "unconfigured"
    return result


@router.post("/certification/evaluate")
async def evaluate_bundle(request: Request) -> dict[str, Any]:
    await _authorize(request, VERIFY_SCOPE)
    raw = await request.body()
    if len(raw) > certification.MAX_EVIDENCE_BYTES * len(certification.ALL_KINDS):
        raise HTTPException(413, "evidence bundle too large")
    try:
        body = certification.parse_evidence_json(raw)
    except (UnicodeDecodeError, ValueError):
        raise HTTPException(400, "evidence bundle must be a JSON object without duplicate keys") from None
    if not isinstance(body, dict):
        raise HTTPException(400, "evidence bundle must be a JSON object without duplicate keys")
    result = _evaluate(request, body)
    result["evidence_source"] = "request"
    result["persisted"] = False
    return result


@router.get("/candidate")
async def release_candidate(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    bundle = _bundle(request)
    return _kind_view(_evaluate(request, bundle), bundle, "release_candidate", "release_candidate")


@router.get("/lock")
async def release_lock(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    readback = certification.lock_readback(
        _bundle(request)["release_candidate"],
        source_sha=str(_setting(request, "source_sha", "") or ""),
        image_digest=str(_setting(request, "image_digest", "") or ""),
        schema_head=str(_setting(request, "schema_head", "") or ""),
    )
    readback["authority"] = dict(certification.AUTHORITY)
    return readback


@router.get("/backups/latest")
async def latest_backup(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    bundle = _bundle(request)
    return _kind_view(_evaluate(request, bundle), bundle, "backup", "backup")


@router.get("/restore-rehearsals/latest")
async def latest_restore_rehearsal(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    bundle = _bundle(request)
    return _kind_view(_evaluate(request, bundle), bundle, "restore_rehearsal", "restore_rehearsal")


@router.get("/rollback/readiness")
async def rollback_readiness(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    bundle = _bundle(request)
    view = _kind_view(_evaluate(request, bundle), bundle, "rollback", "rollback_readiness")
    view["ready"] = view["status"] == "PASS"
    return view


@router.get("/seal")
async def release_seal(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    bundle = _bundle(request)
    result = _evaluate(request, bundle)
    view = _kind_view(result, bundle, "seal", "release_seal")
    view["expected_evidence_sha256"] = result["evidence_sha256"]
    view["sealed"] = view["status"] == "PASS"
    view["signature_verified"] = False
    return view
