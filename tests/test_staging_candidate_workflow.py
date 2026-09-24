import re
from pathlib import Path

WORKFLOW = Path(".github/workflows/staging-candidate-build-sign.yml")


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_trivy_release_is_explicitly_pinned() -> None:
    workflow = workflow_text()
    version = re.search(r"^  TRIVY_VERSION: (v\d+\.\d+\.\d+)$", workflow, re.MULTILINE)
    checksum = re.search(r"^  TRIVY_SHA256: ([0-9a-f]{64})$", workflow, re.MULTILINE)
    assert version and version.group(1) == "v0.72.0"
    assert checksum and checksum.group(1) == "bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea"
    assert "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/${asset}" in workflow
    assert "trivy_${version}_Linux-64bit.tar.gz" in workflow


def test_trivy_installation_fails_closed() -> None:
    workflow = workflow_text()
    assert "curl --fail --location --proto '=https' --tlsv1.2" in workflow
    assert 'echo "${TRIVY_SHA256}  ${RUNNER_TEMP}/trivy.tar.gz" | sha256sum -c -' in workflow
    assert 'tar -xzf "${RUNNER_TEMP}/trivy.tar.gz" -C "${RUNNER_TEMP}" trivy' in workflow
    assert '"${RUNNER_TEMP}/trivy" --version | tee trivy-version.txt' in workflow
    assert "set -euo pipefail" in workflow


def test_trivy_scans_the_exact_digest_without_suppression() -> None:
    workflow = workflow_text()
    assert '"${RUNNER_TEMP}/trivy" image' in workflow
    assert '"${IMAGE_AT_DIGEST}"' in workflow
    assert "--severity HIGH,CRITICAL" in workflow
    assert "--ignore-unfixed=false" in workflow
    assert "--ignorefile" not in workflow
    assert "aquasecurity/trivy-action@" not in workflow


def test_reports_and_evidence_fail_closed_before_upload() -> None:
    workflow = workflow_text()
    validation = workflow.index("- name: Validate complete candidate evidence")
    upload = workflow.index("- name: Upload exact run-scoped candidate evidence")
    assert validation < upload
    for required in (
        "trivy.json",
        "grype.json",
        "candidate.cdx.json",
        "vulnerability-matrix.csv",
        "vulnerability-summary.json",
        "reconcile-helper.sha256",
        "provenance.json",
        "candidate-image-manifest.json",
        "SHA256SUMS",
    ):
        assert required in workflow[validation:upload]
    assert 'test -s "${json_file}"' in workflow[validation:upload]
    assert 'jq -e . "${json_file}"' in workflow[validation:upload]
    assert "sha256sum -c SHA256SUMS" in workflow[validation:upload]
    assert "Reconcile scanner findings" in workflow[:validation]
    schema_validation = workflow.index("python3 scripts/validate_candidate_image_manifest.py")
    assert schema_validation < validation < upload


def test_candidate_manifest_has_explicit_immutable_bindings() -> None:
    workflow = workflow_text()
    generation = workflow.index("- name: Create provenance and immutable evidence manifest")
    validation = workflow.index("- name: Validate complete candidate evidence")
    block = workflow[generation:validation]
    for binding in (
        'company:$company',
        'repository:$repository',
        'pr_number:$pr_number',
        'head_sha:$head_sha',
        'image_repository:$image_repository',
        'image_digest:$image_digest',
        'vulnerability_summary_sha256:$summary',
        'build_run_id:$build_run_id',
        'build_run_attempt:$build_run_attempt',
    ):
        assert binding in block
    assert '--argjson pr_number "${PR_NUMBER}"' in block
    assert "${IMAGE_REPOSITORY}@${digest}" not in block


def test_reconciliation_helper_is_staged_from_protected_workflow_revision() -> None:
    workflow = workflow_text()
    trusted_checkout = workflow.index("- name: Check out trusted reconciliation helper")
    trusted_stage = workflow.index("- name: Stage trusted reconciliation helper outside candidate context")
    candidate_checkout = workflow.index("- name: Check out exact candidate source")
    reconciliation = workflow.index("- name: Reconcile scanner findings")
    assert trusted_checkout < trusted_stage < candidate_checkout < reconciliation
    assert "ref: ${{ github.sha }}" in workflow[trusted_checkout:trusted_stage]
    assert 'test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"' in workflow[trusted_stage:candidate_checkout]
    assert re.search(r"^  RECONCILE_HELPER_SHA256: [0-9a-f]{64}$", workflow, re.MULTILINE)
    assert '"${RUNNER_TEMP}/reconcile_candidate_vulnerabilities.py"' in workflow[reconciliation:]


def test_identity_and_operational_boundaries_remain_enforced() -> None:
    workflow = workflow_text()
    assert workflow.count("id-token: write") == 1

    build_start = workflow.index("  build:")
    sign_start = workflow.index("  sign:")
    build_block = workflow[build_start:sign_start]
    assert "RUNTIME_MUTATION_DISABLED=true" in build_block
    assert "if: ${{ false }}" in build_block
    assert "docker push" in build_block

    sign_block = workflow[sign_start:]
    assert "if: inputs.operation == 'sign' && github.ref == 'refs/heads/main'" in sign_block

    validator = (Path("scripts/validate_security_owner_decision.py")).read_text(encoding="utf-8")
    for boundary in (
        "production_deployment_gate",
        "production_activation_gate",
        "canary_activation_gate",
        "server_b_access_gate",
    ):
        assert f'"{boundary}"' in validator


def test_oci_labels_use_docker_inspect_schema_case() -> None:
    workflow = workflow_text()
    assert '.Config.Labels["org.opencontainers.image.source"]' in workflow
    assert '.Config.Labels["org.opencontainers.image.revision"]' in workflow
    assert ".config.Labels" not in workflow
