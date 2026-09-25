from __future__ import annotations

import importlib.util
import runpy
from pathlib import Path
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / ".codestra/run-trusted-production-orchestrator.py"
ORCHESTRATOR = ROOT / ".codestra/validate-production-orchestrator-contract.py"
GOVERNANCE_VALIDATOR = ROOT / "scripts/validate_repository_governance.py"
GATE = ROOT / ".github/workflows/trusted-production-orchestrator-gate.yml"
PRODUCTION_WORKFLOW = ROOT / ".github/workflows/production-orchestrator-contract.yml"


def load_launcher() -> ModuleType:
    spec = importlib.util.spec_from_file_location("trusted_orchestrator_launcher", LAUNCHER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_governance_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "repository_governance_gate", GOVERNANCE_VALIDATOR
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_gate_runs_only_from_protected_pull_request_target_source() -> None:
    text = GATE.read_text(encoding="utf-8")
    assert "\n  pull_request_target:\n" in text
    assert "\n  pull_request:\n" not in text
    assert "github.event.pull_request.head.repo.full_name == github.repository" in text
    assert "checks: write" not in text
    assert "persist-credentials: false" in text


def test_gate_validates_exact_candidate_without_publishing_a_spoofable_context() -> None:
    text = GATE.read_text(encoding="utf-8")
    assert "EXPECTED_SHA: ${{ github.event.pull_request.head.sha }}" in text
    assert "COMPARISON_SHA: ${{ github.event.pull_request.base.sha }}" in text
    assert "checks.create" not in text
    assert "checks.update" not in text
    assert "continue-on-error" not in text


def test_gate_uses_commit_pinned_actions() -> None:
    text = GATE.read_text(encoding="utf-8")
    assert (
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in text
    )
    assert "actions/github-script@" not in text


def test_launcher_protects_itself_and_evidence_workflow() -> None:
    launcher = load_launcher()
    assert launcher.TRUST_GATE_WORKFLOW_PATH == Path(
        ".github/workflows/trusted-production-orchestrator-gate.yml"
    )
    source = LAUNCHER.read_text(encoding="utf-8")
    assert "require_unchanged_trust_file(LAUNCHER_PATH.relative_to(TRUST_ROOT), root)" in source
    assert "require_unchanged_trust_file(TRUST_GATE_WORKFLOW_PATH, root)" in source


def test_launcher_does_not_allow_replay_of_candidate_controlled_bootstrap() -> None:
    launcher = load_launcher()
    assert launcher.APPROVED_TRUST_WORKFLOW_SHA256 == {
        "5e968a824d9738ac8237dfd677bae1091aaecfe73f3f98d0c6c63f07a503968f"
    }


def test_validator_transition_is_one_way_after_successor_merges() -> None:
    launcher = load_launcher()
    current = launcher.CURRENT_VALIDATOR_SHA256
    successor = launcher.SUCCESSOR_VALIDATOR_SHA256
    transitions = launcher.APPROVED_VALIDATOR_TRANSITIONS

    assert set(transitions[current]) == {current, successor}
    assert set(transitions[successor]) == {successor}
    assert current not in transitions[successor]


def test_trust_file_comparison_rejects_candidate_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher = load_launcher()
    trusted_root = tmp_path / "trusted"
    candidate_root = tmp_path / "candidate"
    relative = Path(".github/workflows/trusted-production-orchestrator-gate.yml")
    trusted_path = trusted_root / relative
    candidate_path = candidate_root / relative
    trusted_path.parent.mkdir(parents=True)
    candidate_path.parent.mkdir(parents=True)
    trusted_path.write_text("trusted\n", encoding="utf-8")
    candidate_path.write_text("changed\n", encoding="utf-8")
    monkeypatch.setattr(launcher, "TRUST_ROOT", trusted_root)

    with pytest.raises(launcher.TrustError, match="protected-base trust file changed"):
        launcher.require_unchanged_trust_file(relative, candidate_root)


def test_safe_file_rejects_a_symlinked_parent_that_escapes_candidate(
    tmp_path: Path,
) -> None:
    launcher = load_launcher()
    candidate_root = tmp_path / "candidate"
    protected_root = tmp_path / "protected"
    candidate_root.mkdir()
    (protected_root / ".codestra").mkdir(parents=True)
    (protected_root / ".codestra" / "validator.py").write_text(
        "protected\n", encoding="utf-8"
    )
    (candidate_root / ".codestra").symlink_to(
        protected_root / ".codestra", target_is_directory=True
    )

    with pytest.raises(launcher.TrustError, match="unsafe trust path"):
        launcher.safe_file(candidate_root, Path(".codestra/validator.py"))


def test_governance_accepts_only_the_exact_gate_workflow() -> None:
    governance = load_governance_validator()
    text = GATE.read_text(encoding="utf-8")

    governance.validate_pull_request_target_workflow(GATE, text)
    with pytest.raises(governance.GovernanceError, match="pull_request_target is forbidden"):
        governance.validate_pull_request_target_workflow(
            GATE,
            text + "\n# candidate gate mutation\n",
        )


def test_governance_accepts_only_the_exact_production_workflow() -> None:
    governance = load_governance_validator()
    text = PRODUCTION_WORKFLOW.read_text(encoding="utf-8")

    governance.validate_pull_request_target_workflow(PRODUCTION_WORKFLOW, text)
    with pytest.raises(governance.GovernanceError, match="pull_request_target is forbidden"):
        governance.validate_pull_request_target_workflow(
            PRODUCTION_WORKFLOW,
            text + "\n# candidate production workflow mutation\n",
        )


def test_governance_requires_independent_ownership_of_every_trust_path() -> None:
    governance = load_governance_validator()
    text = "\n".join(
        [
            "* @appolon1908-hue @kazan555",
            *(
                f"{path} @kazan555"
                for path in sorted(governance.EXPECTED_SECURITY_CODEOWNER_PATHS)
            ),
        ]
    )

    governance.validate_codeowners(text)
    with pytest.raises(
        governance.GovernanceError,
        match="independent security CODEOWNER drift",
    ):
        governance.validate_codeowners(
            text.replace(
                "/.codestra/validate-release-intent.py @kazan555",
                "/.codestra/validate-release-intent.py @appolon1908-hue",
            )
        )


def test_orchestrator_classifies_the_evidence_gate_as_read_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # This unit test validates the repository's protected offline trust
    # contract. Do not let the GitHub runner's current repository owner
    # override the contract repository identity during this pure source test.
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    orchestrator = runpy.run_path(str(ORCHESTRATOR))
    text = GATE.read_text(encoding="utf-8")
    relative = GATE.relative_to(ROOT).as_posix()

    assert orchestrator["workflow_has_runtime_mutation"](text, relative) is False


def test_repaired_candidate_requires_independent_protected_trust_transition(monkeypatch) -> None:
    import hashlib
    launcher = load_launcher()
    repaired = "5ef5fee63f22ed7c9f4c5f65f0f7a90693cc71828d48e239e907402efe3d1742"
    assert hashlib.sha256(ORCHESTRATOR.read_bytes()).hexdigest() == repaired
    # Until the separately reviewed #272 transition reaches protected main,
    # the unchanged launcher must reject this new validator generation.
    if repaired not in launcher.APPROVED_VALIDATOR_TRANSITIONS:
        with pytest.raises(
            launcher.TrustError,
            match="not an approved generation|candidate trust workflow is not approved by protected main",
        ):
            launcher.validate_candidate(ROOT)
    # Simulate only the final approved policy to verify the repaired pair;
    # this does not change the production launcher's approval table. Once
    # protected main lists this generation, verify it under its own
    # steady-state policy; until then only the successor policy can apply.
    steady_state = launcher.APPROVED_VALIDATOR_TRANSITIONS.get(repaired, {}).get(repaired)
    candidate_namespace = runpy.run_path(str(ORCHESTRATOR), run_name="candidate_orchestrator")
    candidate_fingerprint = candidate_namespace["release_validator_security_fingerprint"](
        (ROOT / launcher.RELEASE_VALIDATOR_PATH).read_text(encoding="utf-8")
    )
    policy = steady_state or ("security-fingerprint", candidate_fingerprint)
    monkeypatch.setattr(
        launcher,
        "APPROVED_TRUST_WORKFLOW_SHA256",
        frozenset({launcher.digest(ROOT, launcher.WORKFLOW_PATH)}),
    )
    monkeypatch.setattr(
        launcher,
        "APPROVED_VALIDATOR_TRANSITIONS",
        {repaired: {repaired: policy}},
    )
    assert launcher.validate_candidate(ROOT) == ORCHESTRATOR
