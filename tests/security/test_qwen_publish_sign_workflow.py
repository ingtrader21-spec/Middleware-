import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/publish-sign-qwen-auth-verifier.yml"
TEXT = WORKFLOW.read_text()

IMAGE_DIGEST = "sha256:cc7e2457fdd69fdd1bf766831f8f86396495b47e377e86b2d9df1d4fb5432390"
VEX_SHA256 = "2437e123ca8f6b6a27425ead83cba8526b4dd35fab1f2a755fe84be2e3e87e0a"
SBOM_SHA256 = "1c97030914f94412bfba5d6a0178d96d26f2cc04339de3679008bd9d76868138"
GOVERNANCE_HEAD = "461399573993e3a878412d788f3dd8404385cdcb"


def test_dispatch_only_and_separate_concurrency_group():
    assert "on:\n  workflow_dispatch:\n" in TEXT
    for forbidden_trigger in ("pull_request:", "push:", "schedule:"):
        assert forbidden_trigger not in TEXT
    assert "group: publish-sign-qwen-auth-verifier-cc7e2457fdd69fdd" in TEXT
    assert "cancel-in-progress: false" in TEXT


def test_exact_subject_and_evidence_are_hard_bound_without_inputs():
    expected_lines = (
        "IMAGE_REPOSITORY: ghcr.io/codestra-srl/qwen-auth-verifier",
        f"IMAGE_DIGEST: {IMAGE_DIGEST}",
        "OCI_ARCHIVE_PATH: /opt/codestra-jit-input/qwen-auth-verifier-cc7e2457fdd69fdd.oci.tar",
        "ORAS_VERSION: 1.3.2",
        "ORAS_ARCHIVE_SHA256: 9229ccc6d17bb282039ad4a69abb16dcb887a5bce567c075d731d9b3c7ad8eaf",
        "ORAS_SIGNING_KEY_FINGERPRINT: 2DA461D13B0C27845EDFA77FE462A3894CBAAA47",  # gitleaks:allow
        "ORAS_GIT_COMMIT: fe425992fdfdf300a1cfb380bc4271b3e1a3d3db",
        f"VEX_SHA256: {VEX_SHA256}",
        f"SBOM_SHA256: {SBOM_SHA256}",
        f"GOVERNANCE_HEAD: {GOVERNANCE_HEAD}",
        "CANDIDATE_COMMIT: 68dd9585e766f27a97a51329cf08f1f355445026",
        "OCI_MANIFEST_MEDIA_TYPE: application/vnd.oci.image.manifest.v1+json",
        "SECURITY_OWNER_RECORD_SHA256: 56cb87aa6d48dd935f1ce11c9a6ebe8d013b8254a4faf9889069deaecfce2352",
    )
    for line in expected_lines:
        assert line in TEXT


def test_governance_ref_is_validated_by_exact_api_fetch_not_shallow_git_history():
    assert 'contents/${path}?ref=${GOVERNANCE_HEAD}' in TEXT
    assert 'fetch_exact "${VEX_PATH}" final-openvex.json' in TEXT
    assert 'fetch_exact "${SECURITY_OWNER_RECORD_PATH}" security-owner-record.json' in TEXT
    assert "git cat-file" not in TEXT


def test_protected_environment_runner_and_permissions():
    assert "permissions: {}" in TEXT
    assert "environment: security-owner-signing" in TEXT
    assert "runs-on:\n      group: qwen-artifact-publishers" in TEXT
    assert "labels: codestra-qwen-artifact-publisher" in TEXT
    assert "contents: read\n      packages: write\n      id-token: write\n      attestations: write" in TEXT
    assert "contents: read\n      packages: read" in TEXT


def test_all_third_party_actions_are_immutable_sha_pinned():
    uses = re.findall(r"^\s+uses:\s+(\S+)\s*$", TEXT, flags=re.MULTILINE)
    assert uses
    for action in uses:
        assert "@" in action
        revision = action.rsplit("@", 1)[1]
        assert len(revision) == 40
        assert set(revision) <= set("0123456789abcdef")


def test_workflow_publishes_existing_artifact_without_build_or_deployment():
    forbidden = (
        "docker ",
        "docker.",
        "build-push-action",
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "containerd.sock",
        "kubectl",
        "systemctl",
        "docker compose",
        "deployment_performed",
    )
    lowered = TEXT.lower()
    for token in forbidden:
        assert token not in lowered
    assert "skopeo" not in lowered
    assert '"${ORAS_BIN}" cp --no-tty --from-oci-layout' in TEXT
    assert '"${OCI_ARCHIVE_PATH}@${IMAGE_DIGEST}" "${target}"' in TEXT


def test_oras_copy_preserves_the_complete_index_and_digest():
    copy_block = TEXT.split('"${ORAS_BIN}" cp', 1)[1].split("registry_digest=", 1)[0]
    assert "--from-oci-layout" in copy_block
    assert '"${OCI_ARCHIVE_PATH}@${IMAGE_DIGEST}"' in copy_block
    assert '"${ORAS_BIN}" resolve' in TEXT
    assert 'test "${registry_digest}" = "${IMAGE_DIGEST}"' in TEXT
    assert 'test "sha256:${remote_digest}" = "${IMAGE_DIGEST}"' in TEXT


def test_single_platform_manifest_is_selected_and_hash_verified():
    assert 'select(.mediaType == "application/vnd.oci.image.manifest.v1+json")' in TEXT
    assert 'jq -r .mediaType)" = "${OCI_MANIFEST_MEDIA_TYPE}"' in TEXT
    assert 'sha256sum | cut -d\' \' -f1)" = "${IMAGE_DIGEST#sha256:}"' in TEXT


def test_oras_release_signature_checksum_and_archive_are_verified():
    assert "oras_1.3.2_linux_amd64.tar.gz" in TEXT
    assert "oras_1.3.2_checksums.txt" in TEXT
    assert "oras_1.3.2_checksums.txt.asc" in TEXT
    assert "https://raw.githubusercontent.com/oras-project/oras/v1.3.2/KEYS" in TEXT
    assert 'gpg --batch --homedir "${ORAS_TMP_DIR}/gnupg" --status-fd 1' in TEXT
    assert 'test "${signer_fingerprint}" = "${ORAS_SIGNING_KEY_FINGERPRINT}"' in TEXT
    assert "sha256sum --check --strict" in TEXT
    assert "PurePosixPath" in TEXT
    assert 'if {member.name for member in members} != {"LICENSE", "oras"}' in TEXT
    assert 'raise SystemExit("unsafe ORAS archive path")' in TEXT
    assert 'raise SystemExit("non-regular ORAS archive member")' in TEXT
    assert 'raise SystemExit("unexpected ORAS executable member")' in TEXT


def test_registry_auth_is_password_stdin_only_and_always_removed():
    assert '"${ORAS_BIN}" login' in TEXT
    assert "--password-stdin ghcr.io" in TEXT
    assert "--password " not in TEXT
    assert "--password=${GH_TOKEN}" not in TEXT
    assert 'echo "${GH_TOKEN}"' not in TEXT
    assert TEXT.count('printf \'%s\' "${GH_TOKEN}"') == 2
    assert "if: ${{ always() }}" in TEXT
    assert TEXT.count('rm -- "${REGISTRY_AUTH_FILE}"') == 2
    assert TEXT.count('test ! -e "${REGISTRY_AUTH_FILE}"') == 2


def test_exact_daemonless_destination_and_archive_are_enforced():
    assert "target=\"${IMAGE_REPOSITORY}:${PUBLISH_TAG}\"" in TEXT
    assert "IMAGE_REPOSITORY: ghcr.io/codestra-srl/qwen-auth-verifier" in TEXT
    assert "OCI_ARCHIVE_PATH: /opt/codestra-jit-input/" in TEXT
    assert 'test -x "${ORAS_BIN}"' in TEXT
    assert 'test ! -w "${OCI_ARCHIVE_PATH}"' in TEXT
    assert 'test ! -e "${ORAS_TMP_DIR}"' in TEXT


def test_temporary_paths_are_initialized_only_at_runner_runtime():
    assert "${{ runner.temp }}" not in TEXT
    assert TEXT.count('test -n "${RUNNER_TEMP}"') == 2
    assert '"${RUNNER_TEMP}" >> "${GITHUB_ENV}"' in TEXT
    assert "Initialize run-scoped temporary paths" in TEXT
    assert "Initialize independent run-scoped temporary paths" in TEXT


def test_signature_attestations_and_independent_verification_are_exact():
    assert "cosign sign --yes" in TEXT
    for predicate_type in (
        "cyclonedx",
        "https://slsa.dev/provenance/v1",
        "openvex",
    ):
        assert f"--type {predicate_type}" in TEXT or '--type "${type}"' in TEXT
    assert "--type slsaprovenance" not in TEXT
    assert 'output_name="${type##*/}"' in TEXT
    verification_job = TEXT.split("  independently-verify:\n", 1)[1].split(
        "    runs-on: ubuntu-latest", 1
    )[0]
    assert "needs: publish-sign" in verification_job
    assert "RUNTIME_MUTATION_DISABLED=true" in verification_job
    assert "if: ${{ false }}" in verification_job
    assert "--certificate-identity \"${EXPECTED_IDENTITY}\"" in TEXT
    assert "--certificate-oidc-issuer \"${EXPECTED_ISSUER}\"" in TEXT
    assert (
        "EXPECTED_IDENTITY: https://github.com/appolon1908-hue/Middleware-/"
        ".github/workflows/publish-sign-qwen-auth-verifier.yml@refs/heads/main"
        in TEXT
    )
    assert "EXPECTED_ISSUER: https://token.actions.githubusercontent.com" in TEXT


def test_attestation_discovery_retry_is_bounded_and_fails_closed():
    assert "for attempt in 1 2 3 4 5 6; do" in TEXT
    assert 'if [[ "${attempt}" -lt 6 ]]; then' in TEXT
    assert "sleep 5" in TEXT
    assert 'test "${verified}" = true' in TEXT
    assert '"${output_name}-verification.json.tmp"' in TEXT


def test_multiple_verified_attestations_require_an_exact_predicate_match():
    assert "while IFS= read -r payload; do" in TEXT
    assert ".subject[0].digest.sha256" in TEXT
    assert 'matches=$((matches + 1))' in TEXT
    assert 'test "${matches}" -ge 1' in TEXT
    assert "v1-verified-predicate.json" in TEXT


def test_existing_middleware_signing_workflow_is_not_referenced_or_modified():
    assert "sign-middleware-release.yml" not in TEXT
    assert "ghcr.io/ingtrader21-spec/codestra-middleware" not in TEXT
    assert "ghcr.io/appolon1908-hue/codestra-middleware" not in TEXT
