#!/usr/bin/env python3
"""Build the post-transfer governance-pin repair for ingtrader21-spec/Infustruction-repo.

Run inside the WSL clone on a branch off main c288723b. Produces:
  1. .codestra/validate-release-intent.py  - repo-specific pin of the post-#126
     production-orchestrator-contract.yml bytes + a normalized binding for this
     repository's orchestrator-validator digest.
  2. .codestra/validate-production-orchestrator-contract.py - the new binding name
     joins the normalized set; Infustruction gets its own release-validator
     security fingerprint.
  3. scripts/validate_release_policy_review.py - post-transfer slug + immutable
     repository ID binding for the pull_request_target review gate.
  4. tests/test_release_policy_review.py - regression guard for (3).
The two digests are derived, not hand-typed, and re-verified at the end.
"""
from __future__ import annotations

import hashlib
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path.cwd()
VRI = ROOT / ".codestra/validate-release-intent.py"
VPO = ROOT / ".codestra/validate-production-orchestrator-contract.py"
RPR = ROOT / "scripts/validate_release_policy_review.py"
TEST = ROOT / "tests/test_release_policy_review.py"
WORKFLOW = ROOT / ".github/workflows/production-orchestrator-contract.yml"

NEW_REPO = "ingtrader21-spec/Infustruction-repo"
OLD_REPO = "appolon1908-hue/Infustruction-repo"
REPO_ID = 1350724865
PLACEHOLDER = "0" * 64


def two_line(digest: str) -> str:
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    return f'(\n    "{digest[:32]}"\n    "{digest[32:]}"\n)'


def must_replace(text: str, old: str, new: str, count: int = 1) -> str:
    assert text.count(old) == count, (old, text.count(old))
    return text.replace(old, new)


def set_two_line_constant(text: str, name: str, digest: str) -> str:
    pattern = re.compile(rf'^{name} = \(\n    "[0-9a-f]{{32}}"\n    "[0-9a-f]{{32}}"\n\)', re.M)
    assert len(pattern.findall(text)) == 1, name
    return pattern.sub(f"{name} = {two_line(digest)}", text)


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------- 1. release-intent validator
workflow_digest = hashlib.sha256(WORKFLOW.read_bytes()).hexdigest()
print("production-orchestrator-contract.yml sha256 =", workflow_digest)

vri = VRI.read_text(encoding="utf-8")
vri = must_replace(
    vri,
    'ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256 = (\n'
    '    "5d5f118c8089a7298cc7439327689f862bf669bad46ec9160a0b5763fa11e869"\n'
    ')\n',
    'ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256 = (\n'
    '    "5d5f118c8089a7298cc7439327689f862bf669bad46ec9160a0b5763fa11e869"\n'
    ')\n'
    '# Infustruction-repo now lives under the ingtrader21-spec owner. Its copy of\n'
    '# the canonical required-check workflow invokes the shared validator with the\n'
    '# mutable GITHUB_REPOSITORY slug unset (PR #126, merge 5b8cdbb8) so the\n'
    '# contract\'s own repository and the immutable GITHUB_REPOSITORY_ID bind the\n'
    '# check. Only the workflow bytes differ; the executable stays the shared one.\n'
    'INFUSTRUCTION_ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256 = (\n'
    f'    "{workflow_digest}"\n'
    ')\n',
)
vri = must_replace(
    vri,
    f'    "{OLD_REPO}": {{\n'
    '        ".github/workflows/production-orchestrator-contract.yml": ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256,\n',
    f'    "{OLD_REPO}": {{\n'
    '        ".github/workflows/production-orchestrator-contract.yml": INFUSTRUCTION_ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256,\n',
)
vri = must_replace(
    vri,
    'SHARED_PRODUCTION_VALIDATOR_SHA256 = (\n'
    '    "6006bbc7850ce7666de926b6cad2585b"\n'
    '    "83d2fce102104543b871530f11115f20"\n'
    ')\n',
    'SHARED_PRODUCTION_VALIDATOR_SHA256 = (\n'
    '    "6006bbc7850ce7666de926b6cad2585b"\n'
    '    "83d2fce102104543b871530f11115f20"\n'
    ')\n'
    '# This repository\'s own orchestrator validator binds this file by an\n'
    '# independent security fingerprint; its digest is a normalized\n'
    '# non-self-referential trust binding like SHARED_PRODUCTION_VALIDATOR_SHA256.\n'
    'INFUSTRUCTION_PRODUCTION_VALIDATOR_SHA256 = ' + two_line(PLACEHOLDER) + '\n',
)
vri = must_replace(
    vri,
    f'    "{OLD_REPO}": {{\n'
    '        ".github/workflows/production-orchestrator-contract.yml": {\n'
    '            ".codestra/validate-production-orchestrator-contract.py": SHARED_PRODUCTION_VALIDATOR_SHA256,\n',
    f'    "{OLD_REPO}": {{\n'
    '        ".github/workflows/production-orchestrator-contract.yml": {\n'
    '            ".codestra/validate-production-orchestrator-contract.py": INFUSTRUCTION_PRODUCTION_VALIDATOR_SHA256,\n',
)
VRI.write_text(vri, encoding="utf-8")

# ---------------------------------------------------------------- 2. orchestrator validator
vpo = VPO.read_text(encoding="utf-8")
vpo = must_replace(
    vpo,
    '        "BACKEND_PRODUCTION_VALIDATOR_SHA256",\n'
    '        "EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256",\n',
    '        "BACKEND_PRODUCTION_VALIDATOR_SHA256",\n'
    '        "INFUSTRUCTION_PRODUCTION_VALIDATOR_SHA256",\n'
    '        "EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256",\n',
)
vpo = must_replace(
    vpo,
    'STANDARD_RELEASE_VALIDATOR_SECURITY_SHA256 = (\n'
    '    "15dbaa6d571a1d1e72c09ca417cc9419"\n'
    '    "8d8f21260babfae5eaedbdd46472b1ec"\n'
    ')\n',
    'STANDARD_RELEASE_VALIDATOR_SECURITY_SHA256 = (\n'
    '    "15dbaa6d571a1d1e72c09ca417cc9419"\n'
    '    "8d8f21260babfae5eaedbdd46472b1ec"\n'
    ')\n'
    '# Infustruction-repo pins its post-transfer required-check workflow bytes in\n'
    '# its release validator, so its security fingerprint diverges from the\n'
    '# standard one shared by the untransferred catalog entries.\n'
    'INFUSTRUCTION_RELEASE_VALIDATOR_SECURITY_SHA256 = ' + two_line(PLACEHOLDER) + '\n',
)
vpo = must_replace(
    vpo,
    f'    "{OLD_REPO}": STANDARD_RELEASE_VALIDATOR_SECURITY_SHA256,\n',
    f'    "{OLD_REPO}": INFUSTRUCTION_RELEASE_VALIDATOR_SECURITY_SHA256,\n',
)
VPO.write_text(vpo, encoding="utf-8")

# ---------------------------------------------------------------- 3. derive the two digests
orchestrator = load(VPO, "orchestrator_candidate")
fingerprint = orchestrator.release_validator_security_fingerprint(VRI.read_text(encoding="utf-8"))
print("release-intent security fingerprint     =", fingerprint)
vpo = set_two_line_constant(VPO.read_text(encoding="utf-8"), "INFUSTRUCTION_RELEASE_VALIDATOR_SECURITY_SHA256", fingerprint)
VPO.write_text(vpo, encoding="utf-8")

orchestrator_digest = hashlib.sha256(VPO.read_bytes()).hexdigest()
print("orchestrator validator sha256           =", orchestrator_digest)
vri = set_two_line_constant(VRI.read_text(encoding="utf-8"), "INFUSTRUCTION_PRODUCTION_VALIDATOR_SHA256", orchestrator_digest)
VRI.write_text(vri, encoding="utf-8")

# The executable digest is a normalized binding: writing it must not move the fingerprint.
orchestrator = load(VPO, "orchestrator_final")
recheck = orchestrator.release_validator_security_fingerprint(VRI.read_text(encoding="utf-8"))
assert recheck == fingerprint, (recheck, fingerprint)
assert hashlib.sha256(VPO.read_bytes()).hexdigest() == orchestrator_digest
print("fingerprint stable after executable pin =", recheck == fingerprint)

# ---------------------------------------------------------------- 4. release policy review binding
rpr = RPR.read_text(encoding="utf-8")
rpr = must_replace(rpr, f'REPOSITORY = "{OLD_REPO}"\n', f'REPOSITORY = "{NEW_REPO}"\n')
rpr = must_replace(
    rpr,
    '    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "workflow repository mismatch")\n',
    '    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "workflow repository mismatch")\n'
    '    require(os.environ.get("GITHUB_REPOSITORY_ID") == str(REPOSITORY_ID),\n'
    '            "workflow repository ID mismatch")\n',
)
RPR.write_text(rpr, encoding="utf-8")

test = TEST.read_text(encoding="utf-8")
test = must_replace(
    test,
    '    def test_invalid_candidate_sha(self):\n',
    '    def test_post_transfer_repository_identity(self):\n'
    '        # The repository moved to the ingtrader21-spec owner; the immutable ID is the authority.\n'
    '        self.assertEqual(policy.REPOSITORY, "ingtrader21-spec/Infustruction-repo")\n'
    '        self.assertEqual(policy.REPOSITORY_ID, 1350724865)\n'
    '        stale = copy.deepcopy(self.pr)\n'
    '        stale["base"]["repo"]["full_name"] = "appolon1908-hue/Infustruction-repo"\n'
    '        with self.assertRaises(policy.ReviewError):\n'
    '            policy.validate_subject(stale, 108, self.base)\n'
    '\n'
    '    def test_invalid_candidate_sha(self):\n',
)
TEST.write_text(test, encoding="utf-8")
print("edits complete")
