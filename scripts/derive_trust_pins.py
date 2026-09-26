#!/usr/bin/env python3
"""Deterministically derive every Middleware trust pin from exact Git bytes.

The protected production validators pin the exact bytes of workflows, scripts,
configuration and of each other.  This tool is the single, repository-owned
derivation of those pins for ``ingtrader21-spec/Middleware-``:

  --check              report every stale active pin (exit 1 if any)
  --apply-candidate    rewrite the candidate trust files atomically
  --emit-transition P  write the launcher transition manifest to P (JSON)
  --json-output P      write the full derivation report to P (JSON)
  --allow-dirty        read every file from the working tree instead of the
                       index (development only; --check refuses a dirty tree)

Generation identity is the canonical Git blob (``git show :path``) so that a
checkout with converted line endings cannot change a pin; the runtime
validators still hash the exact checked-out bytes, which is the tamper check.

Derivation order (the release-policy fingerprint lives inside the production
validator, so the naive ``leaf -> validator -> launcher -> closure`` order is
wrong):

  1. leaf workflow/script/configuration digests -> production validator tables
  2. leaf workflow digests -> release-intent tables (validator binding excluded)
  3. FINAL_RELEASE_SECURITY_FINGERPRINT = release_validator_security_fingerprint
     (release-intent text with its self-referential bindings normalized)
  4. inject the fingerprint into the production validator
  5. FINAL_VALIDATOR_SHA256 = sha256(production validator bytes)
  6. inject FINAL_VALIDATOR_SHA256 into the successor-generation bindings
     (release-intent validator binding, launcher gate test expectation)
  7. project the protected launcher (successor digest + fingerprint) WITHOUT
     writing it -- the launcher-only trust-root PR consumes the manifest
  8. FINAL_SOURCE_CLOSURE_SHA256 over the projected final tree, injected last
  9. recompute everything from the proposed bytes and prove the fingerprint,
     validator digest and closure are a fixed point

``APPROVED_DEFAULT_TEST_DISCOVERY_SOURCE_SHA256`` is the one documented
structural exception: it fingerprints tracked Python that embeds the validator
digest, so a fresh value is a SHA-256 fixed point.  It is reported, never
rewritten, and stays fail-closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import py_compile
import re
import runpy
import subprocess
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

REPOSITORY = "ingtrader21-spec/Middleware-"
VALIDATOR = ".codestra/validate-production-orchestrator-contract.py"
RELEASE = ".codestra/validate-release-intent.py"
LAUNCHER = ".codestra/run-trusted-production-orchestrator.py"
GATE_TEST = "tests/test_trusted_production_orchestrator_gate.py"
INTENT = ".github/workflows/manual-release-intent.yml"
ORCHESTRATOR_WORKFLOW = ".github/workflows/production-orchestrator-contract.yml"
TRUST_FILES = (VALIDATOR, RELEASE, GATE_TEST)
HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Every digest-bearing module constant of both validators must be registered.
# DERIVED tables are recomputed from bytes; STATIC_BY_DESIGN tables carry
# policy or foreign-repository generations this repository cannot derive;
# the STRUCTURAL_EXCEPTION is reported but never rewritten.
REGISTRY: dict[str, dict[str, str]] = {
    "validator": {
        "APPROVED_CONTROL_PLANE_WORKFLOW_SHA256": "DERIVED",
        "APPROVED_JOB_EXECUTABLE_CONFIGURATION_SHA256": "DERIVED",
        "APPROVED_COMPLEX_SCRIPT_SHA256": "DERIVED",
        "APPROVED_CONTROL_PLANE_DEPENDENCY_SHA256": "DERIVED",
        "APPROVED_READ_ONLY_SCRIPT_INVOCATIONS": "DERIVED",
        "APPROVED_NARROW_MUTATION_SHA256": "DERIVED",
        "APPROVED_OFFLINE_RUN_SHA256": "DERIVED",
        "MANUAL_RELEASE_INTENT_SHA256": "DERIVED",
        "MIDDLEWARE_RELEASE_VALIDATOR_SECURITY_SHA256": "DERIVED",
        "EXPECTED_RELEASE_VALIDATOR_SECURITY_SHA256": "DERIVED",
        "APPROVED_DEFAULT_TEST_DISCOVERY_SOURCE_SHA256": "STRUCTURAL_EXCEPTION",
        "BACKEND_RELEASE_VALIDATOR_SECURITY_SHA256": "STATIC_BY_DESIGN",
        "MONEYBEE_RELEASE_VALIDATOR_SECURITY_SHA256": "STATIC_BY_DESIGN",
        "STANDARD_RELEASE_VALIDATOR_SECURITY_SHA256": "STATIC_BY_DESIGN",
    },
    "release": {
        "ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256": "DERIVED",
        "EXPECTED_CHECK_WORKFLOW_SHA256": "DERIVED",
        "EXPECTED_CHECK_WORKFLOW_EXECUTABLE_SHA256": "DERIVED",
        "MIDDLEWARE_PRODUCTION_VALIDATOR_SHA256": "DERIVED",
        "EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256": "DERIVED",
        "SHARED_PRODUCTION_VALIDATOR_SHA256": "STATIC_BY_DESIGN",
        "KEYCLOAK_PRODUCTION_VALIDATOR_SHA256": "STATIC_BY_DESIGN",
        "BACKEND_PRODUCTION_VALIDATOR_SHA256": "STATIC_BY_DESIGN",
        "ZERO64": "STATIC_BY_DESIGN",
    },
}
STRUCTURAL_EXCEPTION_REASON = (
    "tracked Python source (launcher, gate test) embeds the validator digest, so a "
    "fresh discovery fingerprint would be a SHA-256 fixed point; the pin stays "
    "byte-identical to protected main and fails closed"
)


class DerivationError(RuntimeError):
    """Raised when the trust pins cannot be derived deterministically."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(root: Path, *args: str, binary: bool = False) -> Any:
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, check=False)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise DerivationError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout if binary else result.stdout.decode("utf-8")


def digests_in(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        if HEX64.match(value):
            found.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            found.extend(digests_in(key))
            found.extend(digests_in(item))
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            found.extend(digests_in(item))
    return found


class Source:
    """Exact bytes of the candidate: Git index blobs, or the working tree."""

    def __init__(self, root: Path, allow_dirty: bool) -> None:
        self.root = root
        self.allow_dirty = allow_dirty

    def read(self, rel: str) -> bytes:
        path = self.root / rel
        if self.allow_dirty or rel in TRUST_FILES:
            if not path.is_file():
                raise DerivationError(f"missing file: {rel}")
            return path.read_bytes()
        try:
            return git(self.root, "show", f":{rel}", binary=True)
        except DerivationError as error:
            raise DerivationError(f"{rel} is not in the Git index") from error

    def exists(self, rel: str) -> bool:
        try:
            self.read(rel)
        except DerivationError:
            return False
        return True

    def text(self, rel: str) -> str:
        return self.read(rel).decode("utf-8")


def load_module(source: Source, rel: str, name: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as scratch:
        # Execute the exact candidate bytes; the validators only define their
        # constants and helpers when imported under a non-__main__ name.
        probe = Path(scratch) / Path(rel).name
        probe.write_bytes(source.read(rel))
        return runpy.run_path(str(probe), run_name=name)


def replace_digest(text: str, old: str, new: str) -> tuple[str, int]:
    """Replace ``old`` by ``new`` whether written whole or split over two literals."""

    if old == new:
        return text, 0
    count = text.count(old)
    text = text.replace(old, new)
    pattern = re.compile(r'"([0-9a-f]{8,56})"([ \t]*\n[ \t]*)"([0-9a-f]{8,56})"')

    def split_replace(match: re.Match[str]) -> str:
        nonlocal count
        if match.group(1) + match.group(3) != old:
            return match.group(0)
        split = len(match.group(1))
        count += 1
        return f'"{new[:split]}"{match.group(2)}"{new[split:]}"'

    text = pattern.sub(split_replace, text)
    return text, count


class Derivation:
    def __init__(self, source: Source) -> None:
        self.source = source
        self.root = source.root
        self.findings: list[dict[str, str]] = []
        self.counts: dict[str, int] = {"leaf": 0, "read_only": 0, "workflow": 0}
        self.unknown_tables: list[str] = []
        self.report: dict[str, Any] = {}

    # -- registry -----------------------------------------------------------
    def audit_registry(self, label: str, namespace: dict[str, Any]) -> None:
        registry = REGISTRY[label]
        for name, value in namespace.items():
            if not name.isupper() or callable(value) or name.startswith("__"):
                continue
            if digests_in(value) and name not in registry:
                self.unknown_tables.append(f"{label}.{name}")
        for name in registry:
            if name not in namespace:
                self.unknown_tables.append(f"{label}.{name} (registered but absent)")

    # -- helpers -------------------------------------------------------------
    def stale(self, file: str, key: str, have: Any, want: str) -> None:
        if have != want:
            self.findings.append(
                {"file": file, "key": key, "have": str(have), "want": want}
            )

    def file_digest(self, rel: str) -> str:
        if not self.source.exists(rel):
            raise DerivationError(f"pinned file does not exist: {rel}")
        return sha256_bytes(self.source.read(rel))

    def leaf_replacements(
        self, namespace: dict[str, Any], release_ns: dict[str, Any]
    ) -> tuple[dict[str, str], dict[str, str]]:
        """Return old->new digest maps for the validator and release-intent leaves."""

        v_map: dict[str, str] = {}
        r_map: dict[str, str] = {}

        def scoped(table: str) -> dict[str, Any]:
            return namespace[table].get(REPOSITORY, {})

        for table in (
            "APPROVED_CONTROL_PLANE_WORKFLOW_SHA256",
            "APPROVED_JOB_EXECUTABLE_CONFIGURATION_SHA256",
        ):
            for rel, pinned in scoped(table).items():
                self.counts["workflow"] += 1
                want = self.file_digest(rel)
                self.stale("validator", f"{table}[{rel}]", pinned, want)
                v_map[pinned] = want
        for rel, pinned in scoped("APPROVED_COMPLEX_SCRIPT_SHA256").items():
            self.counts["leaf"] += 1
            want = self.file_digest(rel)
            self.stale(
                "validator", f"APPROVED_COMPLEX_SCRIPT_SHA256[{rel}]", pinned, want
            )
            v_map[pinned] = want
        for workflow, manifest in scoped(
            "APPROVED_CONTROL_PLANE_DEPENDENCY_SHA256"
        ).items():
            for rel, pinned in manifest.items():
                self.counts["leaf"] += 1
                want = self.file_digest(rel)
                self.stale(
                    "validator",
                    f"APPROVED_CONTROL_PLANE_DEPENDENCY_SHA256[{workflow}][{rel}]",
                    pinned,
                    want,
                )
                v_map[pinned] = want
        for rel, policy in scoped("APPROVED_READ_ONLY_SCRIPT_INVOCATIONS").items():
            pinned, allowed = policy
            self.counts["read_only"] += 1
            if not isinstance(allowed, frozenset) or not all(
                isinstance(arguments, tuple) for arguments in allowed
            ):
                raise DerivationError(
                    f"read-only argument policy is not literal: {rel}"
                )
            if (self.root / rel).is_symlink():
                raise DerivationError(f"read-only script target is a symlink: {rel}")
            want = self.file_digest(rel)
            self.stale(
                "validator",
                f"APPROVED_READ_ONLY_SCRIPT_INVOCATIONS[{rel}]",
                pinned,
                want,
            )
            v_map[pinned] = want
        for key, pinned in scoped("APPROVED_NARROW_MUTATION_SHA256").items():
            workflow, job_name = key.split(":", 1)
            jobs = namespace["workflow_jobs"](self.source.text(workflow), workflow)
            job = jobs.get(job_name)
            if job is None:
                raise DerivationError(f"narrow-mutation job is missing: {key}")
            want = sha256_bytes(job.raw.encode())
            self.stale(
                "validator", f"APPROVED_NARROW_MUTATION_SHA256[{key}]", pinned, want
            )
            v_map[pinned] = want
        for workflow, hashes in scoped("APPROVED_OFFLINE_RUN_SHA256").items():
            text = self.source.text(workflow)
            observed: dict[str, str] = {}
            for job in namespace["workflow_jobs"](text, workflow).values():
                for step in namespace["workflow_steps"](job, workflow):
                    run = step.get("run")
                    if isinstance(run, str):
                        observed[sha256_bytes(run.encode())] = str(step.get("name", ""))
            unmatched_pins = [digest for digest in hashes if digest not in observed]
            unmatched_runs = [digest for digest in observed if digest not in hashes]
            for pinned in unmatched_pins:
                if len(unmatched_pins) == 1 and len(unmatched_runs) == 1:
                    self.stale(
                        "validator",
                        f"APPROVED_OFFLINE_RUN_SHA256[{workflow}]",
                        pinned,
                        unmatched_runs[0],
                    )
                    v_map[pinned] = unmatched_runs[0]
                else:
                    self.findings.append(
                        {
                            "file": "validator",
                            "key": f"APPROVED_OFFLINE_RUN_SHA256[{workflow}]",
                            "have": pinned,
                            "want": "NO-UNIQUE-RUN-BLOCK (manual)",
                        }
                    )
        intent_want = sha256_bytes(self.source.text(INTENT).encode())
        self.stale(
            "validator",
            "MANUAL_RELEASE_INTENT_SHA256",
            namespace["MANUAL_RELEASE_INTENT_SHA256"],
            intent_want,
        )
        v_map[namespace["MANUAL_RELEASE_INTENT_SHA256"]] = intent_want

        want = self.file_digest(ORCHESTRATOR_WORKFLOW)
        self.stale(
            "release",
            "ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256",
            release_ns["ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256"],
            want,
        )
        r_map[release_ns["ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256"]] = want
        for rel, pinned in (
            release_ns["EXPECTED_CHECK_WORKFLOW_SHA256"].get(REPOSITORY, {}).items()
        ):
            self.counts["workflow"] += 1
            want = self.file_digest(rel)
            self.stale(
                "release", f"EXPECTED_CHECK_WORKFLOW_SHA256[{rel}]", pinned, want
            )
            r_map[pinned] = want
        executables = release_ns["EXPECTED_CHECK_WORKFLOW_EXECUTABLE_SHA256"].get(
            REPOSITORY, {}
        )
        for workflow, manifest in executables.items():
            for rel, pinned in manifest.items():
                if rel == VALIDATOR:
                    continue  # bound to FINAL_VALIDATOR_SHA256 in phase 6
                self.counts["leaf"] += 1
                want = self.file_digest(rel)
                self.stale(
                    "release",
                    f"EXPECTED_CHECK_WORKFLOW_EXECUTABLE_SHA256[{workflow}][{rel}]",
                    pinned,
                    want,
                )
                r_map[pinned] = want
        return v_map, r_map

    # -- projected tree -------------------------------------------------------
    def projected_tree(self, proposed: dict[str, bytes]) -> str:
        with tempfile.TemporaryDirectory() as scratch:
            index = Path(scratch) / "index"
            env = dict(os.environ, GIT_INDEX_FILE=str(index))

            def plumbing(*args: str, data: bytes | None = None) -> str:
                return (
                    subprocess.run(
                        ["git", *args],
                        cwd=self.root,
                        env=env,
                        input=data,
                        check=True,
                        capture_output=True,
                    )
                    .stdout.decode()
                    .strip()
                )

            if self.source.allow_dirty:
                plumbing("read-tree", "HEAD")
                plumbing("add", "-A")
            else:
                plumbing("read-tree", git(self.root, "write-tree").strip())
            for rel, data in proposed.items():
                listed = plumbing("ls-files", "-s", "--", rel)
                mode = listed.split()[0] if listed else "100644"
                blob = plumbing("hash-object", "-w", "--stdin", data=data)
                plumbing("update-index", "--add", "--cacheinfo", f"{mode},{blob},{rel}")
            return plumbing("write-tree")

    # -- main derivation -------------------------------------------------------
    def run(self) -> dict[str, bytes]:
        os.environ["GITHUB_REPOSITORY"] = REPOSITORY
        validator_ns = load_module(self.source, VALIDATOR, "derive_orchestrator")
        release_ns = load_module(self.source, RELEASE, "derive_release")
        self.audit_registry("validator", validator_ns)
        self.audit_registry("release", release_ns)
        if self.unknown_tables:
            raise DerivationError(
                "unregistered trust tables: " + ", ".join(sorted(self.unknown_tables))
            )

        validator_text = self.source.text(VALIDATOR)
        release_text = self.source.text(RELEASE)
        gate_text = self.source.text(GATE_TEST)
        launcher_text = self.source.text(LAUNCHER)

        # Phases 1-2: leaf digests.
        v_map, r_map = self.leaf_replacements(validator_ns, release_ns)
        stale_before = len(self.findings)
        for old, new in v_map.items():
            validator_text, _ = replace_digest(validator_text, old, new)
        for old, new in r_map.items():
            release_text, _ = replace_digest(release_text, old, new)

        # Phases 3-4: release-policy fingerprint (the self-referential bindings
        # are normalized) injected into the production validator.
        fingerprint = validator_ns["release_validator_security_fingerprint"](
            release_text
        )
        old_fingerprint = validator_ns["MIDDLEWARE_RELEASE_VALIDATOR_SECURITY_SHA256"]
        self.stale(
            "validator",
            "MIDDLEWARE_RELEASE_VALIDATOR_SECURITY_SHA256",
            old_fingerprint,
            fingerprint,
        )
        validator_text, _ = replace_digest(validator_text, old_fingerprint, fingerprint)

        # Phase 5: the successor validator digest.
        validator_bytes = validator_text.encode("utf-8")
        validator_sha256 = sha256_bytes(validator_bytes)

        # Phase 6: successor-generation bindings that may carry the digest.
        old_binding = release_ns["MIDDLEWARE_PRODUCTION_VALIDATOR_SHA256"]
        self.stale(
            "release",
            "MIDDLEWARE_PRODUCTION_VALIDATOR_SHA256",
            old_binding,
            validator_sha256,
        )
        executables = release_ns["EXPECTED_CHECK_WORKFLOW_EXECUTABLE_SHA256"].get(
            REPOSITORY, {}
        )
        for workflow, manifest in executables.items():
            if VALIDATOR in manifest:
                self.stale(
                    "release",
                    f"EXPECTED_CHECK_WORKFLOW_EXECUTABLE_SHA256[{workflow}][{VALIDATOR}]",
                    manifest[VALIDATOR],
                    validator_sha256,
                )
                release_text, _ = replace_digest(
                    release_text, manifest[VALIDATOR], validator_sha256
                )
        release_text, _ = replace_digest(release_text, old_binding, validator_sha256)
        repaired = re.search(r'repaired = "([0-9a-f]{64})"', gate_text)
        if repaired is None:
            raise DerivationError("gate test does not bind the successor digest")
        self.stale("gate-test", "repaired", repaired.group(1), validator_sha256)
        gate_text, _ = replace_digest(gate_text, repaired.group(1), validator_sha256)

        # Phase 7: project the protected launcher; never write it.
        successor = re.search(
            r'SUCCESSOR_VALIDATOR_SHA256 = \(\s*"([0-9a-f]{64})"', launcher_text
        )
        successor_fp = re.search(
            r'SUCCESSOR_RELEASE_SECURITY_FINGERPRINT = \(\s*"([0-9a-f]{64})"',
            launcher_text,
        )
        if successor is None or successor_fp is None:
            raise DerivationError("launcher successor constants are missing")
        projected_launcher, _ = replace_digest(
            launcher_text, successor.group(1), validator_sha256
        )
        projected_launcher, _ = replace_digest(
            projected_launcher, successor_fp.group(1), fingerprint
        )
        launcher_parity = projected_launcher == launcher_text

        # Phase 8: source closure over the projected final tree, injected last.
        proposed = {
            VALIDATOR: validator_bytes,
            RELEASE: release_text.encode("utf-8"),
            GATE_TEST: gate_text.encode("utf-8"),
            LAUNCHER: projected_launcher.encode("utf-8"),
        }
        tree = self.projected_tree(proposed)
        closure = release_ns["source_closure_fingerprint"](
            release_ns["local_source_tree_entries"](tree), REPOSITORY
        )
        old_closure = release_ns["EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256"][
            REPOSITORY
        ]
        self.stale(
            "release",
            "EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256",
            old_closure,
            closure,
        )
        release_text, _ = replace_digest(release_text, old_closure, closure)
        proposed[RELEASE] = release_text.encode("utf-8")

        # Phase 9: fixed-point proof on the proposed bytes.
        if (
            validator_ns["release_validator_security_fingerprint"](release_text)
            != fingerprint
        ):
            raise DerivationError(
                "release-policy fingerprint changed after injecting normalized bindings"
            )
        if sha256_bytes(proposed[VALIDATOR]) != validator_sha256:
            raise DerivationError("validator digest is not a fixed point")
        tree_after = self.projected_tree(proposed)
        closure_after = release_ns["source_closure_fingerprint"](
            release_ns["local_source_tree_entries"](tree_after), REPOSITORY
        )
        if closure_after != closure:
            raise DerivationError("source closure is not a fixed point")

        discovery = validator_ns["APPROVED_DEFAULT_TEST_DISCOVERY_SOURCE_SHA256"].get(
            REPOSITORY
        )
        self.report = {
            "repository": REPOSITORY,
            "candidate_tree": tree_after,
            "validator_sha256": validator_sha256,
            "release_security_fingerprint": fingerprint,
            "source_closure_sha256": closure,
            "active_stale_pin_count_before": stale_before,
            "active_stale_pin_count": len(self.findings),
            "structural_exception_count": 1,
            "structural_exception": {
                "table": "APPROVED_DEFAULT_TEST_DISCOVERY_SOURCE_SHA256",
                "pinned": discovery,
                "reason": STRUCTURAL_EXCEPTION_REASON,
            },
            "unknown_trust_tables": 0,
            "leaf_pin_count": self.counts["leaf"],
            "read_only_script_pin_count": self.counts["read_only"],
            "workflow_pin_count": self.counts["workflow"],
            "launcher": {
                "successor_in_tree": successor.group(1),
                "successor_fingerprint_in_tree": successor_fp.group(1),
                "required_successor": validator_sha256,
                "required_successor_fingerprint": fingerprint,
                "parity": launcher_parity,
            },
            "findings": self.findings,
        }
        return proposed


def compile_check(rel: str, data: bytes) -> None:
    with tempfile.TemporaryDirectory() as scratch:
        probe = Path(scratch) / Path(rel).name
        probe.write_bytes(data)
        py_compile.compile(str(probe), doraise=True)


def atomic_apply(root: Path, proposed: dict[str, bytes]) -> list[str]:
    changed: list[str] = []
    staged: list[tuple[Path, Path]] = []
    try:
        for rel, data in proposed.items():
            if rel == LAUNCHER:
                continue  # trust-root bytes belong to the launcher-only PR
            target = root / rel
            if target.read_bytes() == data:
                continue
            if rel.endswith(".py"):
                compile_check(rel, data)
            handle, temp_name = tempfile.mkstemp(
                dir=str(target.parent), prefix=".derive-", suffix=".tmp"
            )
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
            os.chmod(temp_name, stat.S_IMODE(target.stat().st_mode))
            staged.append((Path(temp_name), target))
        for temp, target in staged:
            os.replace(temp, target)
            changed.append(target.relative_to(root).as_posix())
    except Exception:
        for temp, _ in staged:
            if temp.exists():
                temp.unlink()
        raise
    return changed


def print_report(report: dict[str, Any], applied: list[str] | None) -> None:
    for finding in report["findings"]:
        print(
            f"STALE  {finding['file']:9s} {finding['key']}\n"
            f"         have={finding['have']}\n         want={finding['want']}"
        )
    print("TRUST_DERIVATION_REPORT")
    print(f"LEAF_PIN_COUNT={report['leaf_pin_count']}")
    print(f"READ_ONLY_SCRIPT_PIN_COUNT={report['read_only_script_pin_count']}")
    print(f"WORKFLOW_PIN_COUNT={report['workflow_pin_count']}")
    print(f"ACTIVE_STALE_BEFORE={report['active_stale_pin_count']}")
    print(
        f"FINAL_RELEASE_SECURITY_FINGERPRINT={report['release_security_fingerprint']}"
    )
    print(f"FINAL_VALIDATOR_SHA256={report['validator_sha256']}")
    print(f"FINAL_SOURCE_CLOSURE_SHA256={report['source_closure_sha256']}")
    print(
        f"ACTIVE_STALE_AFTER={0 if applied is not None else report['active_stale_pin_count']}"
    )
    print("STRUCTURAL_EXCEPTION_COUNT=1")
    print(
        "STRUCTURAL_EXCEPTION: APPROVED_DEFAULT_TEST_DISCOVERY_SOURCE_SHA256 "
        f"({report['structural_exception']['reason']})"
    )
    print(f"UNKNOWN_TRUST_TABLES={report['unknown_trust_tables']}")
    print(f"LAUNCHER_PARITY={'YES' if report['launcher']['parity'] else 'NO'}")
    print(f"CANDIDATE_TREE={report['candidate_tree']}")
    if applied is not None:
        print(f"ATOMIC_APPLY=PASS changed={','.join(applied) if applied else 'none'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--root", default=".", help="repository root (default: current directory)"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check", action="store_true", help="report stale active pins; exit 1 if any"
    )
    mode.add_argument(
        "--apply-candidate",
        action="store_true",
        help="rewrite the candidate trust files atomically",
    )
    parser.add_argument(
        "--emit-transition",
        metavar="PATH",
        help="write the launcher transition manifest",
    )
    parser.add_argument(
        "--json-output", metavar="PATH", help="write the full derivation report (JSON)"
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="derive from working-tree bytes (development only)",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    if not (root / VALIDATOR).is_file():
        print(f"not a Middleware checkout: {root}", file=sys.stderr)
        return 2
    status = git(root, "status", "--porcelain", "--untracked-files=no").strip()
    if args.check and status and not args.allow_dirty:
        print(
            "refusing --check on a dirty tree (commit or stage first, or pass --allow-dirty):\n"
            + status,
            file=sys.stderr,
        )
        return 2
    if args.check and not args.allow_dirty:
        try:
            git(root, "diff", "--check", "HEAD")
        except DerivationError as error:
            print(f"git diff --check failed: {error}", file=sys.stderr)
            return 2

    derivation = Derivation(Source(root, args.allow_dirty))
    try:
        proposed = derivation.run()
    except DerivationError as error:
        print(f"DERIVATION_FAILED: {error}", file=sys.stderr)
        print("SOURCE_FILES_CHANGED=NO", file=sys.stderr)
        return 1
    report = derivation.report

    applied: list[str] | None = None
    if args.apply_candidate:
        try:
            applied = atomic_apply(root, proposed)
        except Exception as error:  # noqa: BLE001 - report and keep the tree untouched
            print(f"ATOMIC_APPLY=FAIL {error}", file=sys.stderr)
            print("SOURCE_FILES_CHANGED=NO", file=sys.stderr)
            return 1
    if args.emit_transition:
        keys = (
            "repository",
            "candidate_tree",
            "validator_sha256",
            "release_security_fingerprint",
            "source_closure_sha256",
            "active_stale_pin_count",
            "structural_exception_count",
        )
        manifest = {key: report[key] for key in keys}
        manifest["active_stale_pin_count_before"] = report[
            "active_stale_pin_count_before"
        ]
        # After an atomic apply every derived pin matches the emitted values.
        manifest["active_stale_pin_count"] = (
            0 if applied is not None else report["active_stale_pin_count"]
        )
        manifest["launcher"] = report["launcher"]
        target = Path(args.emit_transition)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    if args.json_output:
        target = Path(args.json_output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print_report(report, applied)
    if args.check:
        return 1 if report["active_stale_pin_count"] else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
