import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import release_certification as certification
from app.api.internal import release_certification as release_api

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
HEAD = "0067_service_catalog_monitoring_state"
SOURCE = "a" * 40
DIGEST = "sha256:" + "b" * 64
ROLLBACK_SOURCE = "c" * 40
ROLLBACK_DIGEST = "sha256:" + "d" * 64


def _bundle() -> dict:
    bundle = {
        "release_candidate": {
            "schema": "codestra.middleware.release-release-candidate.v1",
            "candidate_id": "rc-2026-09-25.1",
            "repository": "ingtrader21-spec/Middleware-",
            "source_sha": SOURCE,
            "image_repository": "ghcr.io/ingtrader21-spec/codestra-middleware",
            "image_digest": DIGEST,
            "schema_head": HEAD,
            "sbom_sha256": "1" * 64,
            "provenance_sha256": "2" * 64,
            "created_utc": "2026-09-25T08:00:00Z",
        },
        "backup": {
            "schema": "codestra.middleware.release-backup.v1",
            "backup_id": "backup-2026-09-25.1",
            "source_database": "middleware_staging",
            "schema_head": HEAD,
            "sha256": "3" * 64,
            "size_bytes": 1048576,
            "encrypted": True,
            "storage_class": "offsite_encrypted",
            "verified": True,
            "started_utc": "2026-09-25T09:00:00Z",
            "completed_utc": "2026-09-25T09:10:00Z",
        },
        "restore_rehearsal": {
            "schema": "codestra.middleware.release-restore-rehearsal.v1",
            "rehearsal_id": "restore-2026-09-25.1",
            "backup_id": "backup-2026-09-25.1",
            "backup_sha256": "3" * 64,
            "target_database": "middleware_restore_rehearsal",
            "isolated": True,
            "restored_schema_head": HEAD,
            "integrity_checks_passed": True,
            "verified": True,
            "rto_seconds": 540,
            "started_utc": "2026-09-25T09:20:00Z",
            "completed_utc": "2026-09-25T09:29:00Z",
        },
        "rollback": {
            "schema": "codestra.middleware.release-rollback.v1",
            "rollback_id": "rollback-2026-09-25.1",
            "candidate_id": "rc-2026-09-25.1",
            "rollback_source_sha": ROLLBACK_SOURCE,
            "rollback_image_digest": ROLLBACK_DIGEST,
            "rollback_schema_head": HEAD,
            "schema_downgrade_required": False,
            "config_backup_sha256": "4" * 64,
            "rehearsed": True,
            "verified": True,
            "rehearsed_utc": "2026-09-25T10:00:00Z",
        },
    }
    bundle["seal"] = {
        "schema": "codestra.middleware.release-seal.v1",
        "seal_id": "seal-2026-09-25.1",
        "candidate_id": "rc-2026-09-25.1",
        "source_sha": SOURCE,
        "image_digest": DIGEST,
        "schema_head": HEAD,
        "backup_id": "backup-2026-09-25.1",
        "rehearsal_id": "restore-2026-09-25.1",
        "rollback_id": "rollback-2026-09-25.1",
        "evidence_sha256": certification.evidence_sha256(bundle),
        "sealed_utc": "2026-09-25T10:30:00Z",
    }
    return bundle


def _codes(result: dict) -> set[tuple[str, str]]:
    return {(item["kind"], item["code"]) for item in result["blockers"]}


def _reseal(bundle: dict) -> dict:
    bundle["seal"]["evidence_sha256"] = certification.evidence_sha256(bundle)
    return bundle


def test_complete_chain_is_certified_but_never_authorizes_release():
    result = certification.evaluate(_bundle(), now=NOW, expected_schema_head=HEAD)
    assert result["decision"] == "CERTIFIED"
    assert result["certified"] is True
    assert result["blockers"] == []
    assert set(result["gates"].values()) == {"PASS"}
    assert result["candidate"] == {
        "candidate_id": "rc-2026-09-25.1",
        "source_sha": SOURCE,
        "image_digest": DIGEST,
        "schema_head": HEAD,
    }
    assert result["production_release_authorized"] is False
    assert result["authority"]["deployment_authorized"] is False
    assert result["authority"]["release_signing_performed"] is False
    assert result["authority"]["restore_execution_supported"] is False
    assert result["authority"]["rollback_execution_supported"] is False
    assert result["authority"]["production_effects"] == 0


def test_empty_bundle_fails_closed_on_every_gate():
    result = certification.evaluate({}, now=NOW)
    assert result["certified"] is False
    assert result["decision"] == "BLOCKED"
    assert set(result["gates"].values()) == {"BLOCKED"}
    assert {code for _kind, code in _codes(result)} == {"evidence_missing"}
    assert result["candidate"] is None
    assert result["evidence_sha256"] is None


@pytest.mark.parametrize(
    ("kind", "field", "value", "code"),
    [
        ("release_candidate", "source_sha", "abc", "field_invalid"),
        ("release_candidate", "image_digest", "latest", "field_invalid"),
        ("release_candidate", "repository", "someone/else", "field_invalid"),
        ("release_candidate", "created_utc", "2026-09-25T08:00:00+02:00", "field_invalid"),
        ("release_candidate", "created_utc", "2026-09-26T08:00:00Z", "timestamp_in_future"),
        ("backup", "encrypted", False, "field_invalid"),
        ("backup", "verified", "true", "field_invalid"),
        ("backup", "size_bytes", 0, "field_invalid"),
        ("backup", "size_bytes", True, "field_invalid"),
        ("backup", "storage_class", "s3://bucket/key", "field_invalid"),
        ("restore_rehearsal", "isolated", False, "field_invalid"),
        ("restore_rehearsal", "integrity_checks_passed", False, "field_invalid"),
        ("rollback", "schema_downgrade_required", True, "field_invalid"),
        ("rollback", "rehearsed", False, "field_invalid"),
        ("seal", "schema", "codestra.middleware.release-seal.v2", "field_invalid"),
    ],
)
def test_structural_violations_block(kind, field, value, code):
    bundle = _bundle()
    bundle[kind][field] = value
    result = certification.evaluate(bundle, now=NOW)
    assert result["certified"] is False
    assert {"kind": kind, "code": code, "field": field} in result["blockers"]


def test_unexpected_and_missing_fields_block_and_are_never_echoed():
    bundle = _bundle()
    bundle["backup"]["storage_uri"] = "s3://secret-bucket/key?token=x"
    del bundle["backup"]["sha256"]
    bundle["extra"] = {}
    result = certification.evaluate(bundle, now=NOW)
    assert ("backup", "unexpected_field") in _codes(result)
    assert ("backup", "field_missing") in _codes(result)
    assert ("bundle", "unexpected_field") in _codes(result)
    assert result["gates"]["release_candidate"] == "BLOCKED"
    # Dependents of the invalid backup are unverifiable, not silently passed.
    assert ("restore_rehearsal", "chain_unverifiable") in _codes(result)
    assert ("seal", "chain_unverifiable") in _codes(result)
    assert "secret-bucket" not in json.dumps(result)


def test_backup_restore_chain_bindings_block():
    bundle = _bundle()
    bundle["restore_rehearsal"]["backup_sha256"] = "9" * 64
    bundle["restore_rehearsal"]["target_database"] = "middleware_staging"
    bundle["restore_rehearsal"]["started_utc"] = "2026-09-25T09:05:00Z"
    result = certification.evaluate(_reseal(bundle), now=NOW)
    assert {
        ("restore_rehearsal", "backup_sha256_mismatch"),
        ("restore_rehearsal", "target_not_isolated"),
        ("restore_rehearsal", "rehearsal_precedes_backup"),
    } <= _codes(result)
    assert result["gates"]["backup"] == "PASS"
    assert result["gates"]["restore_rehearsal"] == "BLOCKED"


def test_stale_backup_and_schema_mismatch_block():
    bundle = _bundle()
    bundle["backup"]["schema_head"] = "0066_previous_head"
    result = certification.evaluate(
        _reseal(bundle), now=NOW + timedelta(days=2), expected_schema_head=HEAD
    )
    assert ("backup", "backup_stale") in _codes(result)
    assert ("backup", "schema_head_mismatch") in _codes(result)
    assert ("restore_rehearsal", "schema_head_mismatch") in _codes(result)


def test_unexpected_runtime_schema_head_blocks_candidate():
    result = certification.evaluate(_bundle(), now=NOW, expected_schema_head="0068_next")
    assert ("release_candidate", "schema_head_not_expected") in _codes(result)


def test_rollback_to_candidate_or_foreign_candidate_blocks():
    bundle = _bundle()
    bundle["rollback"]["rollback_source_sha"] = SOURCE
    bundle["rollback"]["rollback_image_digest"] = DIGEST
    bundle["rollback"]["candidate_id"] = "rc-other"
    result = certification.evaluate(_reseal(bundle), now=NOW)
    assert result["gates"]["rollback_readiness"] == "BLOCKED"
    assert ("rollback", "rollback_target_is_candidate") in _codes(result)
    assert ("rollback", "candidate_id_mismatch") in _codes(result)


def test_seal_detects_tampered_evidence_and_bindings():
    bundle = _bundle()
    bundle["backup"]["size_bytes"] = 2  # evidence changed after sealing
    result = certification.evaluate(bundle, now=NOW)
    assert {"kind": "seal", "code": "binding_mismatch", "field": "evidence_sha256"} in result["blockers"]

    bundle = _bundle()
    bundle["seal"]["image_digest"] = ROLLBACK_DIGEST
    bundle["seal"]["sealed_utc"] = "2026-09-25T09:59:00Z"
    result = certification.evaluate(bundle, now=NOW)
    assert {"kind": "seal", "code": "binding_mismatch", "field": "image_digest"} in result["blockers"]
    assert ("seal", "sealed_before_evidence") in _codes(result)
    assert result["gates"]["release_seal"] == "BLOCKED"
    assert result["gates"]["backup"] == "PASS"


def test_evidence_digest_is_key_order_independent():
    bundle = _bundle()
    reordered = {kind: dict(reversed(list(bundle[kind].items()))) for kind in reversed(list(bundle))}
    assert certification.evidence_sha256(bundle) == certification.evidence_sha256(reordered)


def test_lock_readback_is_exact_and_fails_closed():
    rc = _bundle()["release_candidate"]
    locked = certification.lock_readback(
        rc, source_sha=SOURCE, image_digest=DIGEST, schema_head=HEAD, now=NOW
    )
    assert locked["locked"] is True
    assert locked["status"] == "LOCKED"

    unknown = certification.lock_readback(
        rc, source_sha="unknown", image_digest="unknown", schema_head=HEAD, now=NOW
    )
    assert unknown["locked"] is False
    assert unknown["status"] == "MISMATCH"
    assert unknown["source_matches"] is False
    assert unknown["image_matches"] is False
    assert unknown["schema_matches"] is True
    assert unknown["runtime_identity_valid"]["source_sha"] is False

    missing = certification.lock_readback(
        None, source_sha=SOURCE, image_digest=DIGEST, schema_head=HEAD, now=NOW
    )
    assert missing["status"] == "CANDIDATE_INVALID"
    assert missing["candidate"] is None
    assert missing["locked"] is False


def test_evidence_files_reject_duplicates_oversize_and_garbage(tmp_path):
    (tmp_path / "backup.json").write_text('{"schema": 1, "schema": 2}', encoding="utf-8")
    (tmp_path / "rollback.json").write_text("not json", encoding="utf-8")
    (tmp_path / "seal.json").write_bytes(b" " * (certification.MAX_EVIDENCE_BYTES + 1))
    bundle = certification.load_evidence_dir(tmp_path)
    assert bundle["release_candidate"] is None
    for kind in ("backup", "rollback", "seal"):
        assert bundle[kind] is certification.INVALID_EVIDENCE
    result = certification.evaluate(bundle, now=NOW)
    assert ("backup", "evidence_unreadable") in _codes(result)
    assert ("release_candidate", "evidence_missing") in _codes(result)


def test_committed_json_schema_matches_rules_and_accepts_fixture():
    import jsonschema

    committed = json.loads(
        (ROOT / "schemas/release-certification-evidence.v1.schema.json").read_text(encoding="utf-8")
    )
    assert committed == certification.json_schema()
    jsonschema.Draft202012Validator.check_schema(committed)
    jsonschema.Draft202012Validator(committed).validate(_bundle())
    bad = _bundle()
    bad["backup"]["encrypted"] = False
    assert list(jsonschema.Draft202012Validator(committed).iter_errors(bad))


def test_cli_certifies_directory_and_fails_closed(tmp_path, capsys):
    from scripts import certify_release_candidate as cli

    assert cli.main(["--check-schema"]) == 0
    assert cli.main([str(tmp_path)]) == 2
    assert json.loads(capsys.readouterr().out)["decision"] == "BLOCKED"


class FakeTokens:
    def __init__(self):
        self.scopes = []

    async def verify(self, authorization, *, expected_client_id, required_scope):
        assert authorization == "Bearer test"
        assert expected_client_id == "release-operator"
        self.scopes.append(required_scope)
        return {"azp": expected_client_id, "scope": required_scope, "sub": "test"}


def _client(monkeypatch, evidence_dir="", **identity):
    tokens = FakeTokens()
    settings = SimpleNamespace(
        release_certification_evidence_dir=str(evidence_dir),
        release_certification_max_backup_age_hours=24 * 365 * 10,
        schema_head=HEAD,
        source_sha=identity.get("source_sha", "unknown"),
        image_digest=identity.get("image_digest", "unknown"),
    )
    app = FastAPI()
    app.state.runtime = SimpleNamespace(tokens=tokens, settings=settings)
    app.include_router(release_api.router)
    monkeypatch.setattr(
        release_api,
        "caller_for_authorization",
        lambda _authorization: SimpleNamespace(client_id="release-operator"),
    )
    return TestClient(app), tokens


def _write(tmp_path: Path, bundle: dict) -> Path:
    for kind, document in bundle.items():
        (tmp_path / certification.EVIDENCE_FILES[kind]).write_text(json.dumps(document), encoding="utf-8")
    return tmp_path


HEADERS = {"Authorization": "Bearer test"}


def test_api_unconfigured_evidence_is_blocked(monkeypatch):
    client, tokens = _client(monkeypatch)
    response = client.get("/internal/v1/release/certification", headers=HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "BLOCKED"
    assert body["evidence_source"] == "unconfigured"
    assert body["production_release_authorized"] is False
    assert tokens.scopes == [release_api.READ_SCOPE]

    rollback = client.get("/internal/v1/release/rollback/readiness", headers=HEADERS).json()
    assert rollback["ready"] is False
    assert rollback["available"] is False
    seal = client.get("/internal/v1/release/seal", headers=HEADERS).json()
    assert seal["sealed"] is False
    assert seal["signature_verified"] is False


def test_api_reads_certified_directory_and_exact_lock(monkeypatch, tmp_path):
    evidence = _write(tmp_path, _bundle())
    client, _tokens = _client(monkeypatch, evidence, source_sha=SOURCE, image_digest=DIGEST)

    status = client.get("/internal/v1/release/certification", headers=HEADERS).json()
    assert status["decision"] == "CERTIFIED"
    assert status["evidence_source"] == "directory"

    candidate = client.get("/internal/v1/release/candidate", headers=HEADERS).json()
    assert candidate["status"] == "PASS"
    assert candidate["evidence"]["source_sha"] == SOURCE
    backup = client.get("/internal/v1/release/backups/latest", headers=HEADERS).json()
    assert backup["status"] == "PASS" and backup["evidence"]["encrypted"] is True
    restore = client.get("/internal/v1/release/restore-rehearsals/latest", headers=HEADERS).json()
    assert restore["status"] == "PASS" and restore["evidence"]["isolated"] is True
    assert client.get("/internal/v1/release/rollback/readiness", headers=HEADERS).json()["ready"] is True
    seal = client.get("/internal/v1/release/seal", headers=HEADERS).json()
    assert seal["sealed"] is True
    assert seal["expected_evidence_sha256"] == seal["evidence"]["evidence_sha256"]

    lock = client.get("/internal/v1/release/lock", headers=HEADERS).json()
    assert lock["locked"] is True
    assert lock["authority"]["deployment_authorized"] is False


def test_api_lock_mismatch_when_runtime_identity_differs(monkeypatch, tmp_path):
    evidence = _write(tmp_path, _bundle())
    client, _tokens = _client(monkeypatch, evidence, source_sha=ROLLBACK_SOURCE, image_digest=DIGEST)
    lock = client.get("/internal/v1/release/lock", headers=HEADERS).json()
    assert lock["locked"] is False
    assert lock["status"] == "MISMATCH"
    assert lock["source_matches"] is False
    assert lock["image_matches"] is True


def test_api_does_not_echo_invalid_evidence(monkeypatch, tmp_path):
    bundle = _bundle()
    bundle["backup"]["storage_uri"] = "s3://secret-bucket/key"
    client, _tokens = _client(monkeypatch, _write(tmp_path, bundle))
    backup = client.get("/internal/v1/release/backups/latest", headers=HEADERS)
    assert backup.status_code == 200
    assert backup.json()["status"] == "BLOCKED"
    assert backup.json()["evidence"] is None
    assert "secret-bucket" not in backup.text


def test_api_evaluate_is_stateless_and_strict(monkeypatch, tmp_path):
    client, tokens = _client(monkeypatch, tmp_path)
    response = client.post("/internal/v1/release/certification/evaluate", headers=HEADERS, json=_bundle())
    assert response.status_code == 200
    assert response.json()["decision"] == "CERTIFIED"
    assert response.json()["persisted"] is False
    assert tokens.scopes == [release_api.VERIFY_SCOPE]
    assert list(tmp_path.iterdir()) == []

    tampered = copy.deepcopy(_bundle())
    tampered["rollback"]["rollback_source_sha"] = SOURCE
    blocked = client.post("/internal/v1/release/certification/evaluate", headers=HEADERS, json=tampered)
    assert blocked.json()["decision"] == "BLOCKED"

    for raw in (b"[]", b"not json", b'{"seal": {}, "seal": {}}'):
        bad = client.post(
            "/internal/v1/release/certification/evaluate",
            headers={**HEADERS, "Content-Type": "application/json"},
            content=raw,
        )
        assert bad.status_code == 400


def test_api_mutation_surfaces_do_not_exist(monkeypatch):
    client, _tokens = _client(monkeypatch)
    for path in (
        "/internal/v1/release/deploy",
        "/internal/v1/release/sign",
        "/internal/v1/release/seal",
        "/internal/v1/release/rollback",
        "/internal/v1/release/rollback/execute",
        "/internal/v1/release/backups",
        "/internal/v1/release/restores",
        "/internal/v1/release/candidate",
    ):
        assert client.post(path, headers=HEADERS).status_code in {404, 405}
    for method in ("put", "patch", "delete"):
        assert getattr(client, method)("/internal/v1/release/certification", headers=HEADERS).status_code == 405


def test_canonical_registry_owns_release_certification_router():
    from app.router_registry import CANONICAL_ROUTERS

    assert release_api.router in CANONICAL_ROUTERS
    methods = {
        (method, route.path)
        for route in release_api.router.routes
        for method in route.methods
    }
    assert {method for method, _path in methods} == {"GET", "POST"}
    assert [path for method, path in methods if method == "POST"] == [
        "/internal/v1/release/certification/evaluate"
    ]
