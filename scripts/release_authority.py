#!/usr/bin/env python3
"""Classify every workflow's release authority for ingtrader21-spec/Middleware-.

Exactly one workflow may create a production Middleware image: build or push a
registry image in the canonical image repository *and* give it a production
release identity (keyless-sign the digest or create the canonical release
manifest). Every other workflow that touches the canonical image repository,
publishes any image, or signs anything must carry an explicit bounded role in
``SUPPORTING_WORKFLOW_ROLES`` and satisfy that role's constraints. Ambiguity is
an error, never a pass.

The analysis is deliberately independent of the production validator's shell
tokenizer: it reads the parsed workflow YAML and the raw step text, so a quoting
construct that confuses a lexer cannot hide a publisher.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

CANONICAL_REPOSITORY = "ingtrader21-spec/Middleware-"
PRE_TRANSFER_REPOSITORY = "appolon1908-hue/Middleware-"
CANONICAL_IMAGE_REPOSITORY = "ghcr.io/appolon1908-hue/codestra-middleware"
CANONICAL_RELEASE_WORKFLOW = ".github/workflows/release.yml"
CANONICAL_SCHEMA_HEAD = "0067_service_catalog_monitoring_state"
RETIRED_SCHEMA_HEADS = ("0059_integrated_monitoring",)
PUBLISHER_IDENTITY = f"https://github.com/{CANONICAL_REPOSITORY}/{CANONICAL_RELEASE_WORKFLOW}@refs/heads/main"
FORWARD_AUTHORITY = ROOT / "config" / "middleware-forward-release-authority.v1.json"
ORCHESTRATOR_CONTRACT = ROOT / ".codestra" / "production-orchestrator-contract.v1.json"

# Every workflow that publishes an image, signs, or names the canonical image
# repository must be listed here with the one bounded role it is allowed to
# play. The canonical publisher is the only workflow allowed to be unbounded.
SUPPORTING_WORKFLOW_ROLES: dict[str, str] = {
    ".github/workflows/exact-main-production-release.yml": "READ_ONLY_VERIFIER",
    ".github/workflows/verify-middleware-release.yml": "READ_ONLY_VERIFIER",
    ".github/workflows/production-route-contract.yml": "HISTORICAL_ARTIFACT_VERIFIER",
    ".github/workflows/production-runtime-certification.yml": "READ_ONLY_VERIFIER",
    ".github/workflows/three-component-release-decision.yml": "SECURITY_DECISION_SIGNER_ONLY",
    ".github/workflows/automated-production-promotion.yml": "READ_ONLY_ADMISSION",
    ".github/workflows/staging-candidate-build-sign.yml": "STAGING_CANDIDATE_ONLY",
    ".github/workflows/security-owner-authority-sign.yml": "AUTHORIZATION_SIGNER_ONLY",
    ".github/workflows/security-owner-decision-sign.yml": "SECURITY_DECISION_SIGNER_ONLY",
    ".github/workflows/production-canary-authorization.yml": "AUTHORIZATION_SIGNER_ONLY",
    ".github/workflows/sign-rc3p-openvex.yml": "HISTORICAL_SIGNER",
    ".github/workflows/sign-rc4-lifecycle-openvex.yml": "HISTORICAL_SIGNER",
    ".github/workflows/sign-gateway-canary-rc1.yml": "HISTORICAL_SIGNER",
    ".github/workflows/sign-gateway-forensics-rc3.yml": "HISTORICAL_SIGNER",
    ".github/workflows/sign-gateway-schema-ack-rc2.yml": "HISTORICAL_SIGNER",
    ".github/workflows/sign-gateway-schema1-correlation-safety-rc1.yml": "HISTORICAL_SIGNER",
    ".github/workflows/release-component-candidate.yml": "DISABLED_PUBLISHER",
    ".github/workflows/source-lock-candidate-build.yml": "DISABLED_PUBLISHER",
    ".github/workflows/mirror-codestra-legacy-middleware-images.yml": "DISABLED_PUBLISHER",
    ".github/workflows/publish-sign-qwen-auth-verifier.yml": "DISABLED_PUBLISHER",
    ".github/workflows/middleware-ci.yml": "CI_BUILD_ONLY",
    ".github/workflows/required-ci.yml": "CI_BUILD_ONLY",
    ".github/workflows/release-component-ci.yml": "CI_BUILD_ONLY",
    ".github/workflows/beyvra-email-authority.yml": "CI_BUILD_ONLY",
}
ROLES = {
    "READ_ONLY_VERIFIER",
    "HISTORICAL_ARTIFACT_VERIFIER",
    "READ_ONLY_ADMISSION",
    "STAGING_CANDIDATE_ONLY",
    "AUTHORIZATION_SIGNER_ONLY",
    "SECURITY_DECISION_SIGNER_ONLY",
    "HISTORICAL_SIGNER",
    "DISABLED_PUBLISHER",
    "CI_BUILD_ONLY",
}

PUSH_RUN = re.compile(
    r"\bdocker\s+push\b|\bdocker\s+buildx\s+build\b[^\n]*--push\b|\bimagetools\s+create\b|"
    r"\bcrane\s+(push|copy|tag)\b|\bskopeo\s+copy\b|\boras\s+push\b"
)
SIGN_RUN = re.compile(r"\bcosign(?:\")?\s+(sign|attest)(?!-blob)\b")
BLOB_SIGN_RUN = re.compile(r"\bcosign(?:\")?\s+sign-blob\b")
BUILD_RUN = re.compile(r"\bdocker\s+(buildx\s+)?build\b")
MANIFEST_RUN = re.compile(r"release_manifest\.py\s+create\b")
DISABLED_CONDITIONS = {"${{ false }}", "false"}


class AuthorityError(RuntimeError):
    """Raised when a workflow's release authority is ambiguous."""


@dataclass
class JobAnalysis:
    name: str
    disabled: bool
    permissions: dict[str, str]
    environment: str | None
    targets_canonical_image: bool
    builds_image: bool
    publishes_image: bool
    signs_image: bool
    signs_blob: bool
    creates_release_manifest: bool
    pre_transfer_identity: bool


@dataclass
class WorkflowAnalysis:
    path: str
    triggers: list[str]
    jobs: list[JobAnalysis] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)

    @property
    def live_jobs(self) -> list[JobAnalysis]:
        return [job for job in self.jobs if not job.disabled]

    @property
    def is_production_publisher(self) -> bool:
        return any(
            job.targets_canonical_image
            and (job.publishes_image or job.builds_image)
            and (job.signs_image or job.creates_release_manifest)
            for job in self.live_jobs
        )

    @property
    def touches_release_surface(self) -> bool:
        return any(
            job.targets_canonical_image
            or job.publishes_image
            or job.signs_image
            or job.signs_blob
            for job in self.jobs
        )


def _step_text(step: dict[str, Any]) -> str:
    return yaml.safe_dump(step, sort_keys=True, width=100000)


def _run_text(step: dict[str, Any]) -> str:
    run = step.get("run")
    return run if isinstance(run, str) else ""


def _build_push_action_pushes(step: dict[str, Any]) -> bool:
    uses = step.get("uses")
    if not isinstance(uses, str) or not uses.split("@", 1)[0].strip().lower().endswith(
        "docker/build-push-action"
    ):
        return False
    inputs = step.get("with") if isinstance(step.get("with"), dict) else {}
    push = inputs.get("push", False)
    return push not in (False, "false")


def _build_push_action_builds(step: dict[str, Any]) -> bool:
    uses = step.get("uses")
    return isinstance(uses, str) and uses.split("@", 1)[0].strip().lower().endswith(
        "docker/build-push-action"
    )


def _job_condition(job: dict[str, Any]) -> str:
    condition = job.get("if")
    return str(condition).strip() if condition is not None else ""


def _permissions(job: dict[str, Any], workflow: dict[str, Any]) -> dict[str, str]:
    scoped = job.get("permissions", workflow.get("permissions", {}))
    return (
        {str(k): str(v) for k, v in scoped.items()} if isinstance(scoped, dict) else {}
    )


def analyze_workflow(path: Path) -> WorkflowAnalysis:
    text = path.read_text(encoding="utf-8")
    document = yaml.safe_load(text) or {}
    triggers_raw = document.get("on", document.get(True, {}))
    if isinstance(triggers_raw, dict):
        triggers = sorted(str(k) for k in triggers_raw)
        dispatch = triggers_raw.get("workflow_dispatch") or {}
        inputs = (
            sorted((dispatch.get("inputs") or {}).keys())
            if isinstance(dispatch, dict)
            else []
        )
    elif isinstance(triggers_raw, list):
        triggers, inputs = sorted(str(k) for k in triggers_raw), []
    else:
        triggers, inputs = [str(triggers_raw)], []
    analysis = WorkflowAnalysis(
        path=path.relative_to(ROOT).as_posix(), triggers=triggers, inputs=inputs
    )
    for name, job in (document.get("jobs") or {}).items():
        if not isinstance(job, dict):
            raise AuthorityError(f"{analysis.path}: job {name} is not a mapping")
        steps = [step for step in (job.get("steps") or []) if isinstance(step, dict)]
        job_text = yaml.safe_dump(job, sort_keys=True, width=100000)
        analysis.jobs.append(
            JobAnalysis(
                name=str(name),
                disabled=_job_condition(job) in DISABLED_CONDITIONS,
                permissions=_permissions(job, document),
                environment=(
                    str(job["environment"]["name"])
                    if isinstance(job.get("environment"), dict)
                    else (str(job["environment"]) if job.get("environment") else None)
                ),
                targets_canonical_image=CANONICAL_IMAGE_REPOSITORY in job_text,
                builds_image=any(
                    BUILD_RUN.search(_run_text(s)) or _build_push_action_builds(s)
                    for s in steps
                ),
                publishes_image=any(
                    PUSH_RUN.search(_run_text(s)) or _build_push_action_pushes(s)
                    for s in steps
                ),
                signs_image=any(SIGN_RUN.search(_run_text(s)) for s in steps),
                signs_blob=any(BLOB_SIGN_RUN.search(_run_text(s)) for s in steps),
                creates_release_manifest=any(
                    MANIFEST_RUN.search(_run_text(s)) for s in steps
                ),
                pre_transfer_identity=PRE_TRANSFER_REPOSITORY in job_text,
            )
        )
    return analysis


def analyze_all(workflows: Path = WORKFLOWS) -> dict[str, WorkflowAnalysis]:
    return {
        analysis.path: analysis
        for analysis in (
            analyze_workflow(path) for path in sorted(workflows.glob("*.yml"))
        )
    }


def production_middleware_publishers(
    analyses: dict[str, WorkflowAnalysis] | None = None,
) -> set[str]:
    analyses = analyses if analyses is not None else analyze_all()
    return {
        path for path, analysis in analyses.items() if analysis.is_production_publisher
    }


def _require(condition: bool, message: str, problems: list[str]) -> None:
    if not condition:
        problems.append(message)


def check_bounded_role(analysis: WorkflowAnalysis, role: str) -> list[str]:
    """Return every way ``analysis`` exceeds the constraints of ``role``."""

    problems: list[str] = []
    path = analysis.path
    live = analysis.live_jobs
    writes_packages = any(job.permissions.get("packages") == "write" for job in live)
    writes_id_token = any(job.permissions.get("id-token") == "write" for job in live)
    publishes = any(job.publishes_image for job in live)
    signs_image = any(job.signs_image for job in live)
    signs_blob = any(job.signs_blob for job in live)
    manifest = any(job.creates_release_manifest for job in live)
    pre_transfer_live = any(job.pre_transfer_identity for job in live)

    if role in {
        "READ_ONLY_VERIFIER",
        "READ_ONLY_ADMISSION",
        "HISTORICAL_ARTIFACT_VERIFIER",
    }:
        _require(not writes_packages, f"{path}: {role} grants packages:write", problems)
        _require(not writes_id_token, f"{path}: {role} grants id-token:write", problems)
        _require(not publishes, f"{path}: {role} publishes an image", problems)
        _require(not signs_image and not signs_blob, f"{path}: {role} signs", problems)
        _require(not manifest, f"{path}: {role} creates a release manifest", problems)
        if role == "HISTORICAL_ARTIFACT_VERIFIER":
            # It may name the pre-transfer identity only as the expected label of
            # an immutable, digest-pinned artifact built before the transfer.
            text = (ROOT / path).read_text(encoding="utf-8")
            _require(
                re.search(
                    rf"{re.escape(CANONICAL_IMAGE_REPOSITORY)}@sha256:[0-9a-f]{{64}}",
                    text,
                )
                is not None,
                f"{path}: historical artifact verifier must pin the artifact by digest",
                problems,
            )
    elif role == "STAGING_CANDIDATE_ONLY":
        _require(
            "pr_number" in analysis.inputs,
            f"{path}: staging scope must be a PR candidate",
            problems,
        )
        _require(
            "workflow_run" not in analysis.triggers and "push" not in analysis.triggers,
            f"{path}: staging scope must not run on protected-main events",
            problems,
        )
        _require(
            not manifest,
            f"{path}: staging scope creates the canonical release manifest",
            problems,
        )
        _require(
            all(PUBLISHER_IDENTITY not in job.name for job in live),
            f"{path}: staging scope names the publisher identity",
            problems,
        )
        text = (ROOT / path).read_text(encoding="utf-8")
        _require(
            PUBLISHER_IDENTITY not in text,
            f"{path}: staging scope references the production publisher identity",
            problems,
        )
        _require(
            "candidate" in text.lower(),
            f"{path}: staging scope must be candidate-scoped",
            problems,
        )
    elif role in {"AUTHORIZATION_SIGNER_ONLY", "SECURITY_DECISION_SIGNER_ONLY"}:
        _require(not writes_packages, f"{path}: {role} grants packages:write", problems)
        _require(not publishes, f"{path}: {role} publishes an image", problems)
        _require(not signs_image, f"{path}: {role} signs an image digest", problems)
        _require(not manifest, f"{path}: {role} creates a release manifest", problems)
    elif role == "HISTORICAL_SIGNER":
        text = (ROOT / path).read_text(encoding="utf-8")
        _require(
            f'"{PRE_TRANSFER_REPOSITORY}"' in text
            or f"'{PRE_TRANSFER_REPOSITORY}'" in text,
            f"{path}: historical signer must guard on the pre-transfer repository name (fails closed today)",
            problems,
        )
        _require(
            not publishes, f"{path}: historical signer publishes an image", problems
        )
        _require(
            not manifest,
            f"{path}: historical signer creates a release manifest",
            problems,
        )
    elif role == "DISABLED_PUBLISHER":
        offending = [
            job.name
            for job in analysis.jobs
            if not job.disabled
            and (job.publishes_image or job.signs_image or job.targets_canonical_image)
        ]
        _require(
            not offending,
            f"{path}: DISABLED_PUBLISHER has live publishing jobs {offending}",
            problems,
        )
    elif role == "CI_BUILD_ONLY":
        _require(not publishes, f"{path}: CI build publishes an image", problems)
        _require(
            not signs_image and not signs_blob, f"{path}: CI build signs", problems
        )
        _require(
            not writes_id_token, f"{path}: CI build grants id-token:write", problems
        )
        _require(not manifest, f"{path}: CI build creates a release manifest", problems)
    else:
        problems.append(f"{path}: unknown role {role}")
    if role not in {"HISTORICAL_SIGNER", "HISTORICAL_ARTIFACT_VERIFIER"}:
        _require(
            not pre_transfer_live,
            f"{path}: live job still names {PRE_TRANSFER_REPOSITORY}",
            problems,
        )
    return problems


def classify(analyses: dict[str, WorkflowAnalysis] | None = None) -> dict[str, Any]:
    analyses = analyses if analyses is not None else analyze_all()
    publishers = production_middleware_publishers(analyses)
    problems: list[str] = []
    roles: dict[str, str] = {}
    for path, analysis in analyses.items():
        if path == CANONICAL_RELEASE_WORKFLOW:
            roles[path] = "CANONICAL_PRODUCTION_PUBLISHER"
            continue
        role = SUPPORTING_WORKFLOW_ROLES.get(path)
        if role is None:
            if analysis.touches_release_surface:
                problems.append(
                    f"{path}: touches the release surface without an explicit bounded role"
                )
            else:
                roles[path] = "UNRELATED"
            continue
        if role not in ROLES:
            problems.append(f"{path}: role {role} is not a known bounded role")
            continue
        roles[path] = role
        problems.extend(check_bounded_role(analysis, role))
    for path in SUPPORTING_WORKFLOW_ROLES:
        if path not in analyses:
            problems.append(f"{path}: has a bounded role but no workflow exists")
    if publishers != {CANONICAL_RELEASE_WORKFLOW}:
        problems.append(
            f"production publishers must be exactly {{{CANONICAL_RELEASE_WORKFLOW}}}, found {sorted(publishers)}"
        )
    return {"publishers": sorted(publishers), "roles": roles, "problems": problems}


def retired_schema_references(
    analyses: dict[str, WorkflowAnalysis] | None = None,
) -> list[str]:
    """Live jobs that still name a retired schema head as a release expectation."""

    analyses = analyses if analyses is not None else analyze_all()
    findings: list[str] = []
    for path, analysis in analyses.items():
        document = (
            yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
            if (ROOT / path).is_file()
            else None
        )
        if not isinstance(document, dict):
            continue
        for name, job in (document.get("jobs") or {}).items():
            if not isinstance(job, dict) or _job_condition(job) in DISABLED_CONDITIONS:
                continue
            job_text = yaml.safe_dump(job, sort_keys=True, width=100000)
            for head in RETIRED_SCHEMA_HEADS:
                # A migration file path (…/0059_x.py) is migration-chain history;
                # the bare revision name is a schema-head expectation.
                if re.search(rf"{re.escape(head)}(?!\.py)", job_text):
                    findings.append(f"{path}:{name}:{head}")
    return findings


def pre_transfer_identity_references(
    analyses: dict[str, WorkflowAnalysis] | None = None,
) -> list[str]:
    """Live jobs naming the pre-transfer repository outside a historical role."""

    analyses = analyses if analyses is not None else analyze_all()
    findings: list[str] = []
    for path, analysis in analyses.items():
        role = SUPPORTING_WORKFLOW_ROLES.get(path)
        if role in {"HISTORICAL_SIGNER", "HISTORICAL_ARTIFACT_VERIFIER"}:
            continue
        findings.extend(
            f"{path}:{job.name}"
            for job in analysis.live_jobs
            if job.pre_transfer_identity
        )
    return findings


def forward_authority() -> dict[str, Any]:
    return json.loads(FORWARD_AUTHORITY.read_text(encoding="utf-8"))


def orchestrator_contract() -> dict[str, Any]:
    return json.loads(ORCHESTRATOR_CONTRACT.read_text(encoding="utf-8"))


def main() -> int:
    report = classify()
    print(f"CANONICAL_RELEASE_WORKFLOW={CANONICAL_RELEASE_WORKFLOW}")
    print(f"FINAL_MIDDLEWARE_PRODUCTION_PUBLISHERS={json.dumps(report['publishers'])}")
    print(f"FORWARD_PRODUCTION_RELEASE_PATH_COUNT={len(report['publishers'])}")
    for path, role in sorted(report["roles"].items()):
        if role != "UNRELATED":
            print(f"ROLE {role:32s} {path}")
    retired = retired_schema_references()
    stale_identity = pre_transfer_identity_references()
    for problem in report["problems"]:
        print(f"PROBLEM {problem}")
    for finding in retired:
        print(f"PROBLEM retired schema head in live job: {finding}")
    for finding in stale_identity:
        print(f"PROBLEM pre-transfer identity in live job: {finding}")
    print(f"STALE_FORWARD_SCHEMA_0059_REFERENCES={len(retired)}")
    print(f"STALE_CURRENT_PRE_TRANSFER_IDENTITIES={len(stale_identity)}")
    failed = bool(report["problems"] or retired or stale_identity)
    print(f"SINGLE_FORWARD_RELEASE_PATH={'FAIL' if failed else 'PASS'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
