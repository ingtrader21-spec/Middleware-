from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "scripts/security/validate-production-canary-authorization.py"
SPEC = importlib.util.spec_from_file_location("production_canary", PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
NOW = datetime(2026, 8, 10, 6, 0, tzinfo=timezone.utc)


def request() -> dict:
    return {
        "schema_version": "codestra.production-canary.authorization.v2",
        "middleware_repository": "ingtrader21-spec/Middleware-",
        "pr_number": 183,
        "release_sha": SHA,
        "image_digest": DIGEST,
        "deployment_environment": "production",
        "test_campaign": "TEST_SYN",
        "test_agent": "webtest001",
        "test_extension": "6101",
        "test_lead": 41,
        "test_list": 9001,
        "test_destination": "6000",
        "test_disposition": "CALLBK",
        "minimum_call_count": 5,
        "maximum_call_count": 10,
        "allowed_call_type": "internal_test_only",
        "customer_data_allowed": False,
        "pstn_allowed": False,
        "valid_from": "2026-08-10T06:30:00Z",
        "valid_until": "2026-08-10T07:00:00Z",
        "rollback_authority": "operations-owner",
        "authorized_flags": {"OUTBOX_PROCESSING_ENABLED": True},
    }


def validate(candidate: dict) -> None:
    module.validate(
        candidate,
        repository="ingtrader21-spec/Middleware-",
        pr_number=183,
        release_sha=SHA,
        image_digest=DIGEST,
        now=NOW,
    )


def test_exact_bounded_request_passes() -> None:
    validate(request())


@pytest.mark.parametrize(
    "field,value",
    [
        ("release_sha", "d" * 40),
        ("image_digest", "sha256:" + "d" * 64),
        ("test_campaign", "CUSTOMERS"),
        ("test_destination", "18095550123"),
        ("test_disposition", "SALE"),
        ("minimum_call_count", 4),
        ("maximum_call_count", 11),
        ("allowed_call_type", "external"),
        ("customer_data_allowed", True),
        ("pstn_allowed", True),
    ],
)
def test_identity_and_call_scope_changes_fail_closed(field, value) -> None:
    candidate = request()
    candidate[field] = value
    with pytest.raises(module.ValidationError):
        validate(candidate)


def test_unapproved_feature_flag_fails_closed() -> None:
    candidate = request()
    candidate["authorized_flags"] = {"LIVE_WRITES_ENABLED": True}
    with pytest.raises(module.ValidationError, match="allowlist"):
        validate(candidate)


def test_long_or_expired_window_fails_closed() -> None:
    candidate = request()
    candidate["valid_until"] = "2026-08-10T08:00:01Z"
    with pytest.raises(module.ValidationError, match="too broad"):
        validate(candidate)


def test_unknown_field_fails_closed() -> None:
    candidate = request()
    candidate["bypass"] = True
    with pytest.raises(module.ValidationError, match="fields"):
        validate(candidate)


def test_expired_authorization_fails_closed() -> None:
    candidate = request()
    candidate["valid_from"] = "2026-08-10T05:00:00Z"
    candidate["valid_until"] = "2026-08-10T05:30:00Z"
    with pytest.raises(module.ValidationError, match="execution window"):
        validate(candidate)


def test_workflow_requires_separate_protected_owner_gates() -> None:
    workflow = (ROOT / ".github/workflows/production-canary-authorization.yml").read_text()
    assert "environment: production-release-owner" in workflow
    assert "environment: production-security-owner" in workflow
    assert "needs: [validate, release-owner, security-owner]" in workflow
    assert "id-token: write" in workflow
    assert "github.actor" in workflow
    assert "CODESTRA_RELEASE_OWNER_LOGIN" in workflow
    assert "CODESTRA_SECURITY_OWNER_LOGIN" in workflow
    assert "codestra/required-ci" in workflow
    assert "cosign sign-blob" in workflow
    assert "pull_request_target" not in workflow


def test_workflow_verifies_exact_release_with_authenticated_api() -> None:
    workflow = (ROOT / ".github/workflows/production-canary-authorization.yml").read_text()
    fetch = (ROOT / "scripts/security/fetch-exact-release-commit.sh").read_text()
    assert 'fetch-exact-release-commit.sh "${SHA}" origin' not in workflow
    assert 'compare/${SHA}...${GITHUB_SHA}' in workflow
    assert 'git fetch --no-tags --depth=1 "${remote}" "${release_sha}"' in fetch
    assert "fetch-depth: 0" not in workflow


def _git(path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=path, check=True, text=True, capture_output=True
    )
    return result.stdout.strip()


def _release_repository(tmp_path: Path, marker: str = "release") -> tuple[Path, str, str]:
    source = tmp_path / "source"
    remote = tmp_path / "remote.git"
    checkout = tmp_path / "checkout"
    source.mkdir(parents=True)
    _git(source, "init", "-b", "main")
    _git(source, "config", "user.name", "Codestra Test")
    _git(source, "config", "user.email", "test@example.invalid")
    (source / "release").write_text(f"{marker}\n")
    _git(source, "add", "release")
    _git(source, "commit", "-m", "release")
    release_sha = _git(source, "rev-parse", "HEAD")
    (source / "main").write_text("main\n")
    _git(source, "add", "main")
    _git(source, "commit", "-m", "main")
    main_sha = _git(source, "rev-parse", "HEAD")
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    _git(source, "remote", "add", "origin", str(remote))
    _git(source, "push", "origin", "main")
    subprocess.run(
        ["git", "clone", "--depth=1", "--branch", "main", f"file://{remote}", str(checkout)],
        check=True,
        capture_output=True,
    )
    assert _git(checkout, "rev-parse", "HEAD") == main_sha
    return checkout, release_sha, main_sha


def _fetch_exact(checkout: Path, sha: str, remote: str = "origin") -> subprocess.CompletedProcess[str]:
    if os.name == "nt":
        command = [sys.executable, str(ROOT / "scripts/security/fetch-exact-release-commit.py"), sha, remote]
    else:
        command = [str(ROOT / "scripts/security/fetch-exact-release-commit.sh"), sha, remote]
    return subprocess.run(
        command,
        cwd=checkout,
        text=True,
        capture_output=True,
    )


def test_fetches_valid_non_head_release_sha(tmp_path: Path) -> None:
    checkout, release_sha, main_sha = _release_repository(tmp_path)
    assert release_sha != main_sha
    result = _fetch_exact(checkout, release_sha)
    assert result.returncode == 0
    assert result.stdout.strip() == release_sha


def test_nonexistent_release_sha_fails_closed(tmp_path: Path) -> None:
    checkout, _, _ = _release_repository(tmp_path)
    result = _fetch_exact(checkout, "f" * 40)
    assert result.returncode != 0


def test_malformed_release_sha_fails_closed(tmp_path: Path) -> None:
    checkout, _, _ = _release_repository(tmp_path)
    result = _fetch_exact(checkout, "not-a-sha")
    assert result.returncode == 64


def test_commit_from_wrong_repository_fails_closed(tmp_path: Path) -> None:
    checkout, _, _ = _release_repository(tmp_path / "expected")
    _, foreign_sha, _ = _release_repository(tmp_path / "foreign", "foreign")
    result = _fetch_exact(checkout, foreign_sha)
    assert result.returncode != 0


def test_pr_release_mismatch_fails_closed() -> None:
    candidate = request()
    candidate["release_sha"] = "d" * 40
    with pytest.raises(module.ValidationError, match="identity"):
        validate(candidate)


def test_exact_image_digest_mismatch_fails_closed() -> None:
    candidate = request()
    candidate["image_digest"] = "sha256:" + "d" * 64
    with pytest.raises(module.ValidationError, match="identity"):
        validate(candidate)


def test_workflow_accepts_only_merged_exact_release_and_detached_request() -> None:
    workflow = (ROOT / ".github/workflows/production-canary-authorization.yml").read_text()
    assert 'test "$(jq -r .merged_at pr.json)" != "null"' in workflow
    assert 'test "$(jq -r .head.sha pr.json)" = "${SHA}"' in workflow
    assert 'compare/${SHA}...${GITHUB_SHA}' in workflow
    assert '.merge_base_commit.sha == $sha' in workflow
    assert "request_base64" in workflow
    assert "contents/${PATH_INPUT}?ref=${SHA}" not in workflow
    assert 'test "${{ github.actor }}" != "${{ vars.CODESTRA_RELEASE_OWNER_LOGIN }}"' in workflow
    assert 'test "${{ github.actor }}" != "${{ vars.CODESTRA_SECURITY_OWNER_LOGIN }}"' in workflow
