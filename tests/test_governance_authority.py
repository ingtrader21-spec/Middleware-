import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSIGNMENTS = ROOT / "docs/governance/role-assignments.yaml"
POLICY = ROOT / "docs/governance/release-acceptance-policy.md"
PRODUCTION_AUTHORITY = ROOT / "docs/governance/production-change-authority.md"
ROLLBACK_AUTHORITY = ROOT / "docs/governance/emergency-rollback-authority.md"
REQUIRED_ROLES = {
    "organization_owner",
    "release_owner",
    "security_owner",
    "compliance_owner",
    "operations_owner",
    "rollback_approver",
}
LOGIN_PATTERN = re.compile(r"^[a-z\d](?:[a-z\d]|-(?=[a-z\d])){0,38}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def load_assignments() -> dict[str, object]:
    return json.loads(ASSIGNMENTS.read_text())


def normalized_text(path: Path) -> str:
    return " ".join(path.read_text().split())


def test_evidence_checksum_format() -> None:
    data = load_assignments()
    evidence = data["authority_evidence"]
    assert isinstance(evidence, dict)
    assert SHA256_PATTERN.fullmatch(str(evidence["sha256"]))


def test_required_roles_and_github_login_syntax() -> None:
    data = load_assignments()
    roles = data["roles"]
    assert isinstance(roles, dict)
    assert set(roles) == REQUIRED_ROLES
    assert all(
        LOGIN_PATTERN.fullmatch(login) for logins in roles.values() for login in logins
    )


def test_role_overlap_is_explicitly_authorized() -> None:
    data = load_assignments()
    roles = data["roles"]
    overlap = data["role_overlap"]
    assert isinstance(roles, dict)
    assert isinstance(overlap, dict)
    assert roles["release_owner"] == roles["security_owner"]
    assert overlap["release_owner_security_owner"] is True
    assert overlap["authorized_by"] == "CODESTRA-GOV-RES-2026-001"
    assert overlap["independent_code_review_required"] is True
    assert overlap["separate_role_decisions_required"] is True


def test_unauthorized_acceptance_fails_closed() -> None:
    policy = normalized_text(POLICY)
    assert "Unknown identities" in policy
    assert "fail closed" in policy
    assert "two clearly separated authenticated decisions" in policy


def test_release_source_authorization_is_exact_and_independent() -> None:
    policy = normalized_text(POLICY)
    production = normalized_text(PRODUCTION_AUTHORITY)
    assert "exact source commit" in policy
    assert "independent exact-head review" in policy
    assert "signed immutable artifacts" in production


def test_rollback_authority_is_bounded() -> None:
    rollback = normalized_text(ROLLBACK_AUTHORITY)
    assert "mapped Rollback Approver" in rollback
    assert "last verified fail-closed" in rollback
    assert "does not authorize destructive improvised SQL" in rollback
