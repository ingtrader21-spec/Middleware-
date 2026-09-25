from __future__ import annotations

import copy

import pytest

from app.platform.release_seal import ReleaseSealError, validate_release_seal


def packet() -> dict:
    return {
        "repository": "ingtrader21-spec/Middleware-",
        "protected_ref": "refs/heads/main",
        "protected_source_sha": "a" * 40,
        "image_digest": "sha256:" + "b" * 64,
        "alembic_head": "0067",
        "sbom_sha256": "c" * 64,
        "trivy_sha256": "d" * 64,
        "grype_sha256": "e" * 64,
        "provenance_sha256": "f" * 64,
        "cosign_verified": True,
        "cosign_identity": "https://github.com/ingtrader21-spec/Middleware-/.github/workflows/release.yml@refs/heads/main",
        "cosign_issuer": "https://token.actions.githubusercontent.com",
        "vulnerability_policy_passed": True,
        "backup_verified": True,
        "restore_rehearsal_passed": True,
        "rollback_rehearsal_passed": True,
        "provider_effects": 0,
        "production_effects": 0,
        "production_go": "NO",
    }


def test_complete_release_packet_seals_without_go_live() -> None:
    seal = validate_release_seal(packet())
    assert seal.schema_head == "0067"
    assert seal.provider_effects == 0
    assert seal.production_effects == 0
    assert seal.production_go == "NO"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("alembic_head", "0066", "0067"),
        ("cosign_verified", False, "Cosign"),
        ("vulnerability_policy_passed", False, "vulnerability"),
        ("backup_verified", False, "backup"),
        ("restore_rehearsal_passed", False, "restore"),
        ("rollback_rehearsal_passed", False, "rollback"),
        ("provider_effects", 1, "provider_effects"),
        ("production_effects", 1, "production_effects"),
        ("production_go", "YES", "production_go"),
    ],
)
def test_release_seal_fails_closed(field, value, message) -> None:
    value_packet = copy.deepcopy(packet())
    value_packet[field] = value
    with pytest.raises(ReleaseSealError, match=message):
        validate_release_seal(value_packet)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("repository", "attacker/example", "repository authority"),
        ("protected_ref", "refs/heads/development", "protected_ref"),
        ("protected_source_sha", "A" * 40, "lowercase git SHA"),
        ("image_digest", "sha256:" + "g" * 64, "immutable sha256"),
        ("sbom_sha256", "bad", "sbom_sha256"),
        ("trivy_sha256", "bad", "trivy_sha256"),
        ("grype_sha256", "bad", "grype_sha256"),
        ("provenance_sha256", "bad", "provenance_sha256"),
        ("cosign_identity", "https://github.com/attacker/repo/.github/workflows/release.yml@refs/heads/main", "Cosign identity"),
        ("cosign_issuer", "https://issuer.example", "GitHub Actions OIDC"),
    ],
)
def test_release_authority_and_provenance_are_exact(field, value, message) -> None:
    value_packet = copy.deepcopy(packet())
    value_packet[field] = value
    with pytest.raises(ReleaseSealError, match=message):
        validate_release_seal(value_packet)


def test_missing_release_authority_fields_fail_closed() -> None:
    for field in ("repository", "protected_ref", "cosign_identity", "cosign_issuer"):
        value_packet = copy.deepcopy(packet())
        value_packet.pop(field)
        with pytest.raises(ReleaseSealError):
            validate_release_seal(value_packet)
