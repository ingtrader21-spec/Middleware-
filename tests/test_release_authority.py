"""Static release-authority invariants for ingtrader21-spec/Middleware-.

These tests pin repository invariants that the runtime gates cannot express on
their own: exactly one forward production publisher, the canonical schema head,
exact-byte read-only script pins, literal argument policies, complete trust-table
coverage in the derivation tool, and fail-closed classification of publishing
constructs. They supplement — never replace — the protected launcher, the
production validators, CI gates and release signature verification.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import os
import runpy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "ingtrader21-spec/Middleware-"
VALIDATOR = ROOT / ".codestra" / "validate-production-orchestrator-contract.py"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
CANONICAL_SCHEMA_HEAD = "0069_progressive_tenant_rls"
PUBLISHER_IDENTITY = "https://github.com/ingtrader21-spec/Middleware-/.github/workflows/release.yml@refs/heads/main"


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = (
        module  # dataclasses resolve postponed annotations via sys.modules
    )
    spec.loader.exec_module(module)
    return module


authority = _load("release_authority_under_test", "scripts/release_authority.py")
derive = _load("derive_trust_pins_under_test", "scripts/derive_trust_pins.py")


@pytest.fixture(scope="module")
def validator() -> dict:
    os.environ["GITHUB_REPOSITORY"] = REPOSITORY
    return runpy.run_path(str(VALIDATOR), run_name="release_authority_probe")


@pytest.fixture(scope="module")
def analyses() -> dict:
    return authority.analyze_all()


@pytest.fixture(scope="module")
def classification(analyses: dict) -> dict:
    return authority.classify(analyses)


def sha256_exact(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- single production publisher ---------------------------------------------


def test_exactly_one_middleware_production_publisher(classification: dict) -> None:
    assert classification["problems"] == []
    assert classification["publishers"] == [authority.CANONICAL_RELEASE_WORKFLOW]
    assert authority.production_middleware_publishers() == {
        ".github/workflows/release.yml"
    }


def test_canonical_release_workflow_is_release_yml(classification: dict) -> None:
    forward = authority.forward_authority()["artifactAuthority"]
    assert forward["releaseWorkflow"] == ".github/workflows/release.yml"
    contract = authority.orchestrator_contract()
    assert (
        contract["native_workflows"]["signed_release"]
        == ".github/workflows/release.yml"
    )
    assert (
        classification["roles"][".github/workflows/release.yml"]
        == "CANONICAL_PRODUCTION_PUBLISHER"
    )


def test_canonical_repository_identity() -> None:
    assert (
        authority.forward_authority()["repositoryAuthority"]["repository"] == REPOSITORY
    )
    assert authority.orchestrator_contract()["repository"] == REPOSITORY
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert "github.repository == 'ingtrader21-spec/Middleware-'" in text
    assert 'test "$GITHUB_REPOSITORY" = "ingtrader21-spec/Middleware-"' in text
    live_release = text.split("\n  release:\n", 1)[1]
    assert "https://github.com/appolon1908-hue/Middleware-/" not in live_release
    assert live_release.count(PUBLISHER_IDENTITY) >= 2


def test_release_workflow_identities_are_current(analyses: dict) -> None:
    assert authority.pre_transfer_identity_references(analyses) == []
    for path, role in authority.SUPPORTING_WORKFLOW_ROLES.items():
        if role in {"HISTORICAL_SIGNER", "HISTORICAL_ARTIFACT_VERIFIER"}:
            continue
        text = (ROOT / path).read_text(encoding="utf-8")
        for job in analyses[path].live_jobs:
            assert not job.pre_transfer_identity, (
                f"{path}:{job.name} still names the pre-transfer identity"
            )
        assert "sign-middleware-release.yml@" not in text
        assert "exact-main-production-release.yml@" not in text


# --- GHCR package authority ---------------------------------------------------


CANONICAL_IMAGE_REPOSITORY = "ghcr.io/ingtrader21-spec/codestra-middleware"
PRE_TRANSFER_IMAGE_REPOSITORY = "ghcr.io/appolon1908-hue/codestra-middleware"


def test_canonical_package_is_owned_by_the_repository_owner() -> None:
    """A GitHub Actions installation token can only publish to its own owner's GHCR
    namespace (the 2862af0a release run was denied with "the requested installation
    does not exist" against the pre-transfer package). The single forward publisher,
    the orchestrator contract, the forward authority and the manifest verifier must
    therefore all bind the repository owner's package, and nothing else."""
    assert CANONICAL_IMAGE_REPOSITORY.split("/")[1] == REPOSITORY.split("/")[0]
    assert authority.CANONICAL_IMAGE_REPOSITORY == CANONICAL_IMAGE_REPOSITORY
    assert authority.PRE_TRANSFER_IMAGE_REPOSITORY == PRE_TRANSFER_IMAGE_REPOSITORY
    assert authority.forward_authority()["artifactAuthority"]["imageRepository"] == (
        CANONICAL_IMAGE_REPOSITORY
    )
    assert authority.orchestrator_contract()["artifact_policy"]["image_repositories"] == [
        CANONICAL_IMAGE_REPOSITORY
    ]
    manifest = _load("release_manifest_under_test", "scripts/release_manifest.py")
    assert manifest.IMAGE_REPOSITORY == CANONICAL_IMAGE_REPOSITORY
    assert manifest.HISTORICAL_IMAGE_REPOSITORY == PRE_TRANSFER_IMAGE_REPOSITORY
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    live_release = text.split("\n  release:\n", 1)[1]
    assert f"IMAGE_REPOSITORY: {CANONICAL_IMAGE_REPOSITORY}\n" in live_release
    assert f"{CANONICAL_IMAGE_REPOSITORY}:sha-${{{{ env.SOURCE_SHA }}}}" in live_release
    assert PRE_TRANSFER_IMAGE_REPOSITORY not in live_release


def test_validator_artifact_policy_binds_the_canonical_package(validator: dict) -> None:
    repositories = validator["EXPECTED_ARTIFACT_POLICIES"][REPOSITORY][0]
    assert repositories == (CANONICAL_IMAGE_REPOSITORY,)


def test_no_live_job_names_the_pre_transfer_package(analyses: dict) -> None:
    """Only digest-pinned historical verification may still name the pre-transfer
    package; a live publisher or verifier naming it could never succeed."""
    for path, analysis in analyses.items():
        role = authority.SUPPORTING_WORKFLOW_ROLES.get(path)
        if role in {"HISTORICAL_SIGNER", "HISTORICAL_ARTIFACT_VERIFIER"}:
            continue
        for job in analysis.live_jobs:
            assert not job.pre_transfer_image, (
                f"{path}:{job.name} still names {PRE_TRANSFER_IMAGE_REPOSITORY}"
            )


def test_pre_transfer_package_is_a_bounded_release_surface(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Naming the pre-transfer package is release surface: an unlisted workflow that
    does so is ambiguous, a live bounded job that does so is a problem, the canonical
    publisher may never do so live, and a historical verifier may only pin it by
    digest."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    probe = workflows / "probe-old-package.yml"
    header = "name: probe\non: workflow_dispatch\njobs:\n  verify:\n    runs-on: ubuntu-24.04\n    steps:\n"
    probe.write_text(
        header + f"      - run: docker pull {PRE_TRANSFER_IMAGE_REPOSITORY}@sha256:{'a' * 64}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(authority, "ROOT", tmp_path)
    analysis = authority.analyze_workflow(probe)
    job = analysis.jobs[0]
    assert job.pre_transfer_image and not job.targets_canonical_image
    assert analysis.touches_release_surface
    unlisted = authority.classify({analysis.path: analysis})["problems"]
    assert any("without an explicit bounded role" in problem for problem in unlisted)
    live = authority.check_bounded_role(analysis, "READ_ONLY_VERIFIER")
    assert any(PRE_TRANSFER_IMAGE_REPOSITORY in problem for problem in live)
    assert authority.check_bounded_role(analysis, "HISTORICAL_ARTIFACT_VERIFIER") == []

    probe.write_text(
        header + f"      - run: docker pull {PRE_TRANSFER_IMAGE_REPOSITORY}:latest\n",
        encoding="utf-8",
    )
    unpinned = authority.check_bounded_role(
        authority.analyze_workflow(probe), "HISTORICAL_ARTIFACT_VERIFIER"
    )
    assert any("pin the artifact by digest" in problem for problem in unpinned)

    publisher = workflows / "release.yml"
    publisher.write_text(
        header.replace("verify:", "release:")
        + f"      - run: docker push {PRE_TRANSFER_IMAGE_REPOSITORY}:x\n",
        encoding="utf-8",
    )
    rogue = authority.analyze_workflow(publisher)
    rogue_problems = authority.classify({rogue.path: rogue})["problems"]
    assert any(
        f"live publisher job names {PRE_TRANSFER_IMAGE_REPOSITORY}" in problem
        for problem in rogue_problems
    )


def test_release_schema_head_is_0067() -> None:
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert f"EXPECTED_SCHEMA_HEAD: {CANONICAL_SCHEMA_HEAD}" in text
    assert f"codestra.schema_head={CANONICAL_SCHEMA_HEAD}" in text
    assert 'test "${#HEADS[@]}" -eq 1' in text
    assert 'test "${HEADS[0]}" = "$EXPECTED_SCHEMA_HEAD"' in text
    assert (
        authority.forward_authority()["artifactAuthority"]["requiredSchemaHead"]
        == CANONICAL_SCHEMA_HEAD
    )
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations"))
    assert ScriptDirectory.from_config(config).get_heads() == [CANONICAL_SCHEMA_HEAD]


def test_no_active_release_workflow_requires_0059(analyses: dict) -> None:
    assert authority.retired_schema_references(analyses) == []
    env_example = (
        ROOT / "deploy/observability-alerts/production.env.example"
    ).read_text(encoding="utf-8")
    assert f"SCHEMA_HEAD={CANONICAL_SCHEMA_HEAD}" in env_example
    assert "0059_integrated_monitoring" not in env_example


def test_release_job_is_the_authorized_narrow_mutation(validator: dict) -> None:
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    jobs = validator["workflow_jobs"](text, ".github/workflows/release.yml")
    release = jobs["release"]
    assert validator["job_condition"](release) != "${{ false }}"
    assert "RUNTIME_MUTATION_DISABLED=true" not in release.raw
    pinned = validator["APPROVED_NARROW_MUTATION_SHA256"][REPOSITORY][
        ".github/workflows/release.yml:release"
    ]
    assert pinned == hashlib.sha256(release.raw.encode()).hexdigest()
    assert "github.event_name == 'workflow_run'" in release.raw
    assert (
        "github.event.workflow_run.head_repository.full_name == github.repository"
        in release.raw
    )
    assert "github.event_name == 'workflow_dispatch'" in release.raw
    assert 'test "$protected_head" = "$EXPECTED_SOURCE_SHA"' in release.raw


def test_supporting_release_workflows_are_bounded(
    analyses: dict, classification: dict
) -> None:
    for path, analysis in analyses.items():
        if path == authority.CANONICAL_RELEASE_WORKFLOW:
            continue
        if analysis.touches_release_surface:
            assert path in authority.SUPPORTING_WORKFLOW_ROLES, (
                f"{path} touches the release surface without a role"
            )
            assert (
                authority.check_bounded_role(
                    analysis, authority.SUPPORTING_WORKFLOW_ROLES[path]
                )
                == []
            )
    assert set(authority.SUPPORTING_WORKFLOW_ROLES.values()) <= authority.ROLES
    assert classification["problems"] == []


def test_verification_workflow_cannot_publish(analyses: dict) -> None:
    for path in (
        ".github/workflows/verify-middleware-release.yml",
        ".github/workflows/exact-main-production-release.yml",
    ):
        analysis = analyses[path]
        for job in analysis.live_jobs:
            assert (
                not job.publishes_image and not job.signs_image and not job.signs_blob
            ), path
            assert job.permissions.get("packages") != "write", path
            assert job.permissions.get("id-token") != "write", path
        text = (ROOT / path).read_text(encoding="utf-8")
        assert PUBLISHER_IDENTITY in text
    verify = (ROOT / ".github/workflows/verify-middleware-release.yml").read_text(
        encoding="utf-8"
    )
    assert f"EXPECTED_SIGNER: {PUBLISHER_IDENTITY}" in verify
    assert "for type in spdxjson slsaprovenance1" in verify
    assert not (ROOT / ".github/workflows/sign-middleware-release.yml").exists()


def test_staging_workflow_cannot_become_production_release_authority(
    analyses: dict,
) -> None:
    path = ".github/workflows/staging-candidate-build-sign.yml"
    analysis = analyses[path]
    assert authority.SUPPORTING_WORKFLOW_ROLES[path] == "STAGING_CANDIDATE_ONLY"
    assert "pr_number" in analysis.inputs
    build = next(job for job in analysis.jobs if job.name == "build")
    assert build.disabled and build.publishes_image
    text = (ROOT / path).read_text(encoding="utf-8")
    assert "RUNTIME_MUTATION_DISABLED=true" in text
    assert PUBLISHER_IDENTITY not in text
    assert "release_manifest.py create" not in text
    assert not analysis.is_production_publisher


def test_second_production_publisher_fails_classification(analyses: dict) -> None:
    forged = copy.deepcopy(analyses)
    rogue = copy.deepcopy(analyses[authority.CANONICAL_RELEASE_WORKFLOW])
    rogue.path = ".github/workflows/rogue-release.yml"
    forged[rogue.path] = rogue
    report = authority.classify(forged)
    assert sorted(report["publishers"]) == sorted(
        [authority.CANONICAL_RELEASE_WORKFLOW, rogue.path]
    )
    assert any(
        "production publishers must be exactly" in problem
        for problem in report["problems"]
    )
    assert any(rogue.path in problem for problem in report["problems"])


def test_release_workflow_reintroducing_0059_fails(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    target = workflows / "release.yml"
    target.write_text(
        RELEASE_WORKFLOW.read_text(encoding="utf-8").replace(
            CANONICAL_SCHEMA_HEAD, "0059_integrated_monitoring"
        ),
        encoding="utf-8",
    )
    original_root = authority.ROOT
    authority.ROOT = tmp_path
    try:
        forged = authority.analyze_all(workflows)
        findings = authority.retired_schema_references(forged)
    finally:
        authority.ROOT = original_root
    assert any(
        finding.startswith(".github/workflows/release.yml:release:0059")
        for finding in findings
    )


# --- read-only script pins ---------------------------------------------------


def _read_only_policies(validator: dict) -> dict:
    return validator["APPROVED_READ_ONLY_SCRIPT_INVOCATIONS"][REPOSITORY]


def test_all_read_only_pin_targets_exist(validator: dict) -> None:
    policies = _read_only_policies(validator)
    assert policies
    for relative in policies:
        target = ROOT / relative
        assert target.is_file(), relative
        assert not target.is_symlink(), relative


def test_read_only_script_pins_match_exact_bytes(validator: dict) -> None:
    for relative, (expected_sha, allowed_args) in _read_only_policies(
        validator
    ).items():
        target = ROOT / relative
        assert sha256_exact(target) == expected_sha, relative
        assert isinstance(allowed_args, frozenset)
        assert all(isinstance(args, tuple) for args in allowed_args)


def test_read_only_argument_policies_are_literal(validator: dict) -> None:
    dynamic = validator["dynamic_invocation_token"]
    for relative, (_, allowed_args) in _read_only_policies(validator).items():
        for args in allowed_args:
            assert all(isinstance(token, str) for token in args), relative
            assert not any(dynamic(token) for token in args), (relative, args)


def test_crlf_variant_of_pinned_script_is_denied(validator: dict) -> None:
    relative, (expected_sha, _) = next(iter(_read_only_policies(validator).items()))
    lf_bytes = (ROOT / relative).read_bytes()
    assert b"\r\n" not in lf_bytes
    crlf_sha = hashlib.sha256(lf_bytes.replace(b"\n", b"\r\n")).hexdigest()
    assert crlf_sha != expected_sha


# --- argument smuggling / invocation hardening ----------------------------------


@pytest.mark.parametrize(
    "target, arguments",
    [
        ("scripts/audit_release_endpoints.py", []),
        ("scripts/apply_production_reviewer_access.py", ["--mode", "validate"]),
    ],
)
def test_exact_approved_invocations_are_admitted(
    validator: dict, target: str, arguments: list[str]
) -> None:
    assert (
        validator["approved_read_only_script_invocation"](target, arguments, ROOT)
        is True
    )


@pytest.mark.parametrize(
    "target, arguments",
    [
        ("scripts/audit_release_endpoints.py", ["unexpected"]),
        (
            "scripts/apply_production_reviewer_access.py",
            ["--mode", "validate", "unexpected"],
        ),
        ("scripts/apply_production_reviewer_access.py", ["--mode", "$MODE"]),
        ("scripts/apply_production_reviewer_access.py", ["--mode", "${MODE}"]),
        ("scripts/audit_release_endpoints.py", ["${ARGS}"]),
        ("scripts/audit_release_endpoints.py", ["SUBSTITUTION"]),
        ("scripts/audit_release_endpoints.py", ["`cat args`"]),
        ("scripts/audit_release_endpoints.py", ["@args.txt"]),
        ("scripts/audit_release_endpoints.py", [">", "out.txt"]),
        ("scripts/audit_release_endpoints.py", ["2>&1"]),
        ("scripts/audit_release_endpoints.py", ["*.json"]),
        ("scripts/audit_release_endpoints.py", ["~/args"]),
        ("scripts/apply_production_reviewer_access.py", ["--mode"]),
        ("scripts/apply_production_reviewer_access.py", ["validate", "--mode"]),
        ("scripts/$SCRIPT.py", []),
        ("scripts/SUBSTITUTION", []),
        ("scripts/not-pinned.py", []),
    ],
)
def test_argument_policy_fails_closed(
    validator: dict, target: str, arguments: list[str]
) -> None:
    assert (
        validator["approved_read_only_script_invocation"](target, arguments, ROOT)
        is False
    )


def test_shell_chaining_after_an_approved_invocation_is_still_classified(
    validator: dict,
) -> None:
    workflow = (
        "name: probe\non: workflow_dispatch\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    steps:\n"
        "      - run: python3 scripts/audit_release_endpoints.py; docker push ghcr.io/x/y:1\n"
    )
    assert (
        validator["workflow_has_image_publication"](workflow, "synthetic.yml") is True
    )
    tokens = validator["shell_tokens"](
        "python3 scripts/audit_release_endpoints.py && docker push x"
    )
    assert "&&" in tokens


def test_one_byte_change_in_pinned_script_is_denied(validator: dict) -> None:
    policies = _read_only_policies(validator)
    relative = "scripts/audit_release_endpoints.py"
    expected, allowed = policies[relative]
    tampered = hashlib.sha256(
        (ROOT / relative).read_bytes() + b"\n# tampered\n"
    ).hexdigest()
    try:
        policies[relative] = (tampered, allowed)
        assert (
            validator["approved_read_only_script_invocation"](relative, [], ROOT)
            is False
        )
    finally:
        policies[relative] = (expected, allowed)
    assert validator["approved_read_only_script_invocation"](relative, [], ROOT) is True


def test_changed_allowed_argv_is_denied(validator: dict) -> None:
    policies = _read_only_policies(validator)
    relative = "scripts/apply_production_reviewer_access.py"
    expected, allowed = policies[relative]
    try:
        policies[relative] = (expected, frozenset({("--mode", "apply")}))
        assert (
            validator["approved_read_only_script_invocation"](
                relative, ["--mode", "validate"], ROOT
            )
            is False
        )
    finally:
        policies[relative] = (expected, allowed)


def test_unsafe_working_directory_is_denied(validator: dict, tmp_path: Path) -> None:
    relative = "scripts/audit_release_endpoints.py"
    outside = tmp_path / "scripts"
    outside.mkdir()
    shutil.copy(ROOT / relative, outside / "audit_release_endpoints.py")
    assert (
        validator["approved_read_only_script_invocation"](relative, [], tmp_path)
        is False
    )


def test_symlinked_pinned_script_is_denied(validator: dict, tmp_path: Path) -> None:
    relative = "scripts/audit_release_endpoints.py"
    shadow = ROOT / "tests" / ".release-authority-symlink-probe"
    shadow_scripts = shadow / "scripts"
    shadow_scripts.mkdir(parents=True, exist_ok=True)
    link = shadow_scripts / "audit_release_endpoints.py"
    try:
        try:
            link.symlink_to(ROOT / relative)
        except (OSError, NotImplementedError) as error:
            pytest.skip(f"symlinks unavailable here: {error}")
        assert (
            validator["approved_read_only_script_invocation"](relative, [], shadow)
            is False
        )
    finally:
        shutil.rmtree(shadow, ignore_errors=True)


# --- publication classification is fail-closed ----------------------------------


@pytest.mark.parametrize(
    "run",
    [
        'digest="$(echo x | tr -d \'"\')"\ndocker push "${tag}"\n',
        'docker push "${tag}"\ndigest="$(echo x | tr -d \'"\')"\n',
        'echo "oops\ndocker push x\n',
        "echo 'oops\ndocker push x\n",
        'cmd=docker\n"$cmd" push x\n',
        "oras push ghcr.io/x/y:1 f.txt\n",
        "crane push img.tar ghcr.io/x/y:1\n",
        "crane copy ghcr.io/a ghcr.io/b\n",
        "skopeo copy docker://a docker://b\n",
        "docker buildx build --push -t x .\n",
        "docker buildx imagetools create -t x y\n",
        "podman push x\n",
    ],
)
def test_publication_constructs_are_detected(validator: dict, run: str) -> None:
    assert validator["contains_image_publication"]({"run": run}) is True


@pytest.mark.parametrize(
    "run",
    [
        "docker build -t x .\n",
        'cosign="$RUNNER_TEMP/bin-cosign"\n"${cosign}" verify img\n',
        "docker buildx imagetools inspect x\n",
        "python3 scripts/audit_release_endpoints.py\n",
    ],
)
def test_benign_constructs_are_not_publication(validator: dict, run: str) -> None:
    assert validator["contains_image_publication"]({"run": run}) is False


def test_tokenizer_fallback_preserves_command_boundaries(validator: dict) -> None:
    tokens = validator["shell_tokens"](
        'set -euo pipefail\ndocker push "${tag}"\ndigest="$(echo \'"\')"\n'
    )
    assert "\n" in tokens
    boundaries = [index for index, token in enumerate(tokens) if token == "\n"]
    assert tokens[boundaries[0] + 1 : boundaries[0] + 3] == ["docker", "push"]


def test_publishing_job_must_be_disabled_or_narrowly_approved(validator: dict) -> None:
    live_publisher = (
        "name: probe\non: workflow_dispatch\njobs:\n  publish:\n    runs-on: ubuntu-24.04\n    steps:\n"
        "      - run: docker push ghcr.io/appolon1908-hue/codestra-middleware:x\n"
    )
    with pytest.raises(validator["ContractError"]):
        validator["require_mutating_jobs_disabled"](
            live_publisher, "synthetic-publisher.yml"
        )
    disabled_publisher = (
        "name: probe\non: workflow_dispatch\njobs:\n  publish:\n"
        "    # RUNTIME_MUTATION_DISABLED=true\n    if: ${{ false }}\n    runs-on: ubuntu-24.04\n    steps:\n"
        "      - run: docker push ghcr.io/appolon1908-hue/codestra-middleware:x\n"
    )
    validator["require_mutating_jobs_disabled"](
        disabled_publisher, "synthetic-publisher.yml"
    )


# --- trust derivation coverage ---------------------------------------------------


def test_no_unknown_trust_tables_escape_derivation(validator: dict) -> None:
    os.environ["GITHUB_REPOSITORY"] = REPOSITORY
    release_ns = runpy.run_path(
        str(ROOT / ".codestra" / "validate-release-intent.py"),
        run_name="release_authority_release_probe",
    )
    derivation = derive.Derivation(derive.Source(ROOT, allow_dirty=True))
    derivation.audit_registry("validator", validator)
    derivation.audit_registry("release", release_ns)
    assert derivation.unknown_tables == []
    categories = {
        category for table in derive.REGISTRY.values() for category in table.values()
    }
    assert categories <= {"DERIVED", "STATIC_BY_DESIGN", "STRUCTURAL_EXCEPTION"}
    structural = [
        name
        for table in derive.REGISTRY.values()
        for name, category in table.items()
        if category == "STRUCTURAL_EXCEPTION"
    ]
    assert structural == ["APPROVED_DEFAULT_TEST_DISCOVERY_SOURCE_SHA256"]


def test_unregistered_trust_table_fails_derivation(validator: dict) -> None:
    forged = dict(validator)
    forged["APPROVED_UNREGISTERED_TABLE_SHA256"] = {
        REPOSITORY: {"scripts/run_ci.sh": "0" * 64}
    }
    derivation = derive.Derivation(derive.Source(ROOT, allow_dirty=True))
    derivation.audit_registry("validator", forged)
    assert derivation.unknown_tables == ["validator.APPROVED_UNREGISTERED_TABLE_SHA256"]


def test_trust_derivation_check_passes() -> None:
    if not (ROOT / ".git").exists():
        pytest.skip("trust derivation --check requires Git metadata")

    command = [
        sys.executable,
        str(ROOT / "scripts" / "derive_trust_pins.py"),
        "--check",
        "--root",
        str(ROOT),
    ]
    result = subprocess.run(
        command, capture_output=True, text=True, cwd=ROOT, check=False
    )
    if result.returncode == 2 and "dirty tree" in result.stderr:
        result = subprocess.run(
            command + ["--allow-dirty"],
            capture_output=True,
            text=True,
            cwd=ROOT,
            check=False,
        )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ACTIVE_STALE_AFTER=0" in result.stdout
    assert "STRUCTURAL_EXCEPTION_COUNT=1" in result.stdout
    assert "UNKNOWN_TRUST_TABLES=0" in result.stdout
