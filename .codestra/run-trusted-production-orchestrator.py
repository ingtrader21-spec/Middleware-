#!/usr/bin/env python3
"""Run only an independently approved production-contract validator pair.

This launcher is executed from protected-base workflow source. Candidate source
is inert data until its workflow and validator bytes match policies already
approved on protected main. Candidate changes cannot replace this launcher or
the trusted evidence workflow in the same pull request.
"""

from __future__ import annotations

import hashlib
import os
import re
import runpy
import subprocess
import sys
from pathlib import Path


TRUST_ROOT = Path(__file__).resolve().parents[1]
LAUNCHER_PATH = Path(__file__).resolve()
TRUST_GATE_WORKFLOW_PATH = Path(
    ".github/workflows/trusted-production-orchestrator-gate.yml"
)
WORKFLOW_PATH = Path(".github/workflows/production-orchestrator-contract.yml")
ORCHESTRATOR_PATH = Path(".codestra/validate-production-orchestrator-contract.py")
RELEASE_VALIDATOR_PATH = Path(".codestra/validate-release-intent.py")
SHA = re.compile(r"[0-9a-f]{40}")

# The outer key is the exact validator already on protected main; the inner
# key is a candidate generation it may accept. This one-way transition graph
# prevents an older validator from being replayed after its successor merges.
CURRENT_VALIDATOR_SHA256 = (
    "15c35ad11c65b7605d44812e08d45493e31afdea678876b3a44a16d27c1c1a21"
)
SUCCESSOR_VALIDATOR_SHA256 = (
    "a2e58d1c185040b32eb12e3655822570a9045a53e933afca8b4e4f95370ad219"
)
CURRENT_RELEASE_VALIDATOR_SHA256 = (
    "e8b9df096a4069fef1c725460f748fc315f2b6ec091b03254ef7b56c325c7058"
)
CURRENT_RELEASE_SECURITY_FINGERPRINT = (
    "63192fd83f7fc19fa624e2bf26d3b2ccc3941042e4e3c941ba378ff50581e565"
)
SUCCESSOR_RELEASE_SECURITY_FINGERPRINT = (
    "d94351f6d39b406bb7fc3a5b9736e72ff987ef374e264c9844099a7551ce4192"
)
APPROVED_VALIDATOR_TRANSITIONS = {
    CURRENT_VALIDATOR_SHA256: {
        CURRENT_VALIDATOR_SHA256: (
            "security-fingerprint",
            CURRENT_RELEASE_SECURITY_FINGERPRINT,
        ),
        SUCCESSOR_VALIDATOR_SHA256: (
            "security-fingerprint",
            SUCCESSOR_RELEASE_SECURITY_FINGERPRINT,
        ),
    },
    SUCCESSOR_VALIDATOR_SHA256: {
        SUCCESSOR_VALIDATOR_SHA256: (
            "security-fingerprint",
            SUCCESSOR_RELEASE_SECURITY_FINGERPRINT,
        ),
    },
}
APPROVED_TRUST_WORKFLOW_SHA256 = frozenset(
    {
        # Steady state only: the candidate-controlled pull_request generation
        # is intentionally not replayable after this launcher reaches main.
        "5e968a824d9738ac8237dfd677bae1091aaecfe73f3f98d0c6c63f07a503968f",
    }
)


class TrustError(RuntimeError):
    """Raised when candidate source is not anchored by protected main."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TrustError(message)


def safe_file(root: Path, relative: Path) -> Path:
    require(
        not relative.is_absolute() and ".." not in relative.parts,
        f"unsafe trust path: {relative}",
    )
    resolved_root = root.resolve(strict=True)
    candidate = resolved_root
    for part in relative.parts:
        candidate /= part
        require(not candidate.is_symlink(), f"unsafe trust path: {relative}")
    require(candidate.is_file(), f"unsafe trust path: {relative}")
    resolved_candidate = candidate.resolve(strict=True)
    require(
        resolved_candidate.is_relative_to(resolved_root),
        f"trust path escapes checkout: {relative}",
    )
    return candidate


def digest(root: Path, relative: Path) -> str:
    return hashlib.sha256(safe_file(root, relative).read_bytes()).hexdigest()


def require_unchanged_trust_file(relative: Path, candidate_root: Path) -> None:
    require(
        digest(candidate_root, relative) == digest(TRUST_ROOT, relative),
        f"protected-base trust file changed: {relative.as_posix()}",
    )


def candidate_root() -> Path:
    raw = os.environ.get("VALIDATION_ROOT", "")
    require(bool(raw), "VALIDATION_ROOT is required")
    unresolved = Path(raw)
    require(unresolved.is_absolute(), "VALIDATION_ROOT must be absolute")
    require(not unresolved.is_symlink(), "VALIDATION_ROOT cannot be a symlink")
    resolved = unresolved.resolve(strict=True)
    require(resolved.is_dir(), "VALIDATION_ROOT must be a directory")
    return resolved


def validate_exact_checkout(root: Path) -> str:
    expected = os.environ.get("EXPECTED_SHA", "")
    require(SHA.fullmatch(expected) is not None, "EXPECTED_SHA is invalid")
    actual = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    require(actual == expected, "candidate checkout does not match EXPECTED_SHA")
    return expected


def validate_candidate(root: Path) -> Path:
    require(
        digest(root, WORKFLOW_PATH) in APPROVED_TRUST_WORKFLOW_SHA256,
        "candidate trust workflow is not approved by protected main",
    )
    require_unchanged_trust_file(LAUNCHER_PATH.relative_to(TRUST_ROOT), root)
    require_unchanged_trust_file(TRUST_GATE_WORKFLOW_PATH, root)

    orchestrator = safe_file(root, ORCHESTRATOR_PATH)
    release_validator = safe_file(root, RELEASE_VALIDATOR_PATH)
    protected_orchestrator_digest = digest(TRUST_ROOT, ORCHESTRATOR_PATH)
    orchestrator_digest = digest(root, ORCHESTRATOR_PATH)
    release_validator_digest = digest(root, RELEASE_VALIDATOR_PATH)
    allowed_transitions = APPROVED_VALIDATOR_TRANSITIONS.get(
        protected_orchestrator_digest
    )
    require(
        allowed_transitions is not None,
        "protected-base orchestrator validator is not an approved generation",
    )
    assert allowed_transitions is not None
    policy = allowed_transitions.get(orchestrator_digest)
    require(
        policy is not None,
        "candidate orchestrator validator is not approved by protected main",
    )
    assert policy is not None
    mode, expected_release_digest = policy
    if mode == "raw":
        observed_release_digest: object = release_validator_digest
    else:
        require(
            mode == "security-fingerprint",
            "protected-base release-validator policy mode is invalid",
        )
        namespace = runpy.run_path(str(orchestrator), run_name="approved_orchestrator")
        fingerprint = namespace.get("release_validator_security_fingerprint")
        if not callable(fingerprint):
            raise TrustError("approved orchestrator fingerprint is missing")
        observed_release_digest = fingerprint(
            release_validator.read_text(encoding="utf-8")
        )
    require(
        observed_release_digest == expected_release_digest,
        "candidate release validator is not approved by protected main",
    )
    return orchestrator


def main() -> int:
    root = candidate_root()
    validate_exact_checkout(root)
    os.environ["PYTHONSAFEPATH"] = "1"
    orchestrator = validate_candidate(root)
    os.environ.pop("VALIDATION_ROOT", None)
    previous_cwd = Path.cwd()
    previous_argv = sys.argv[:]
    try:
        os.chdir(root)
        sys.argv = [str(orchestrator)]
        try:
            runpy.run_path(str(orchestrator), run_name="__main__")
        except SystemExit as error:
            require(
                error.code in (None, 0),
                "approved production-contract validator failed",
            )
    finally:
        sys.argv = previous_argv
        os.chdir(previous_cwd)
    print("PROTECTED_BASE_VALIDATOR_TRUST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
