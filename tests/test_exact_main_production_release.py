"""The exact-main production workflow is a read-only admission verifier.

It used to be a second production publisher (re-tag, push, sign, attest under
its own identity). It now admits or rejects a candidate that the single forward
publisher, ``.github/workflows/release.yml``, already built and signed from the
exact protected-main source, and it keeps every independent control it had:
merged-review identity, signed Security Owner authority, exact-source tests,
VEX, unsuppressed scanners and an isolated runtime smoke test.
"""

from pathlib import Path

import yaml


WORKFLOW = Path(".github/workflows/exact-main-production-release.yml")
PUBLISHER_IDENTITY = "https://github.com/ingtrader21-spec/Middleware-/.github/workflows/release.yml@refs/heads/main"


def source() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def job() -> dict:
    return yaml.safe_load(source())["jobs"]["release"]


def test_exact_main_identity_and_independent_approval_are_required() -> None:
    value = source()
    assert 'test "$(jq -r .merge_commit_sha pr.json)" = "${SOURCE_SHA}"' in value
    assert ".merge_base_commit.sha == $source" in value
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


def test_admission_consumes_the_vex_authorized_digest() -> None:
    value = source()
    assert "production-openvex-${SOURCE_SHA}-${VEX_RUN_ID}" in value
    assert 'subject="${IMAGE_REPOSITORY}@${vex_digest}"' in value
    assert "validate-production-openvex.py" in value
    assert 'digest="$(jq -er .metadata.image_digest vex/openvex.json)"' in value


def test_candidate_must_be_signed_by_the_single_forward_publisher() -> None:
    value = source()
    assert value.count(PUBLISHER_IDENTITY) >= 2
    assert "exact-main-production-release.yml@refs/heads/main" not in value
    assert "sign-middleware-release.yml" not in value
    assert "--type spdxjson" in value
    assert "--type slsaprovenance1" in value
    assert (
        '.predicate.buildDefinition.externalParameters.source.uri | endswith("@" + $sha)'
        in value
    )


def test_verifier_cannot_publish_sign_or_attest() -> None:
    value = source()
    permissions = job()["permissions"]
    assert permissions == {
        "actions": "read",
        "contents": "read",
        "packages": "read",
        "pull-requests": "read",
        "statuses": "read",
    }
    assert "environment" not in job()
    assert "docker push" not in value
    # The only tag it creates is a local, never-pushed scan alias.
    assert 'docker tag "${subject}" "middleware:${SOURCE_SHA}"' in value
    assert '"${IMAGE_REPOSITORY}:${SOURCE_SHA}"' not in value
    assert 'cosign" sign' not in value
    assert 'cosign" attest' not in value
    assert "steps.publish" not in value
    assert "READ-ONLY VERIFIER" in value


def test_image_is_non_root_scanned_and_pulled_by_digest() -> None:
    value = source()
    assert "USER 10001:10001" in Path("Dockerfile").read_text(encoding="utf-8")
    assert "Run Trivy without suppression" in value
    assert "Run raw Grype without suppression" in value
    assert "Run VEX-applied Grype" in value
    assert "verify-blob" in value
    assert "docker image rm" in value
    assert 'docker pull "${subject}"' in value
    assert 'cosign" verify-attestation' in value
    assert "org.opencontainers.image.revision" in value


def test_admission_is_separate_from_staging_candidate_workflow() -> None:
    value = source()
    assert "staging-candidate-build-sign.yml" not in value
    assert "security-owner-staging-candidate" not in value


def test_admission_requires_exactly_one_alembic_head_0067() -> None:
    value = source()
    assert "mapfile -t HEADS < <(alembic heads | awk '{print $1}')" in value
    assert 'test "${#HEADS[@]}" -eq 1' in value
    assert 'test "${HEADS[0]}" = "0069_campaign_recycling_delivery_events"' in value
    assert "0059_integrated_monitoring" not in value
    assert "alembic upgrade head" in value


def test_production_release_environment_is_no_longer_a_release_path() -> None:
    assert "environment: production-release" not in source()
    spec = Path("docs/security/PRODUCTION-RELEASE-ENVIRONMENT.md").read_text(
        encoding="utf-8"
    )
    assert "read-only admission verifier" in spec
    assert ".github/workflows/release.yml" in spec
