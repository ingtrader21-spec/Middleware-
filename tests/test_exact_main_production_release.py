from pathlib import Path


WORKFLOW = Path(".github/workflows/exact-main-production-release.yml")


def source() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_exact_main_identity_and_independent_approval_are_required() -> None:
    value = source()
    assert 'test "$(jq -r .merge_commit_sha pr.json)" = "${SOURCE_SHA}"' in value
    assert '.merge_base_commit.sha == $source' in value
    assert '.state == "APPROVED" and .commit_id == $head' in value
    assert '.context == "codestra/required-ci" and .state == "success"' in value


def test_production_authority_is_signed_and_explicit() -> None:
    value = source()
    assert "security-owner-authority.sigstore.json" in value
    assert 'index("server_a_production_release")' in value
    assert 'index("production_deployment")' in value
    assert 'index("external_delivery_synthetic_only")' in value
    assert ".communications.calls == false" in value
    assert "validate_production_security_owner_authority.py" in value


def test_release_consumes_the_vex_authorized_digest() -> None:
    value = source()
    assert "production-openvex-${SOURCE_SHA}-${VEX_RUN_ID}" in value
    assert 'subject="${IMAGE_REPOSITORY}@${vex_digest}"' in value
    assert "validate-production-openvex.py" in value
    assert 'test "$(jq -er .metadata.image_digest vex/openvex.json)" = "${digest}"' in value


def test_image_is_non_root_scanned_signed_and_pulled_by_digest() -> None:
    value = source()
    assert "USER 10001:10001" in Path("Dockerfile").read_text(encoding="utf-8")
    assert "Run Trivy without suppression" in value
    assert "Run raw Grype without suppression" in value
    assert "Run VEX-applied Grype" in value
    assert "verify-blob" in value
    assert "docker image rm" in value
    assert "docker pull \"${subject}\"" in value
    assert "cosign\" verify-attestation" in value


def test_release_is_separate_from_staging_candidate_workflow() -> None:
    value = source()
    assert "staging-candidate-build-sign.yml" not in value
    assert "exact-main-middleware-production" in value


def test_release_requires_the_klyrow_delivery_migration_head() -> None:
    value = source()
    assert 'alembic heads' in value
    assert '= "0067_service_catalog_monitoring_state"' in value


def test_release_uses_protected_production_environment() -> None:
    value = source()
    assert "environment: production-release" in value
    spec = Path("docs/security/PRODUCTION-RELEASE-ENVIRONMENT.md").read_text()
    assert "`appolon1908-hue`" in spec
    assert "prevent self-review: enabled" in spec
    assert "administrator bypass: disabled" in spec
    assert "protected branches only (`main`)" in spec
    assert "environment secrets: none" in spec
    assert "environment variables: none" in spec
