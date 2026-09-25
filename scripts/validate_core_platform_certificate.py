#!/usr/bin/env python3
"""Validate the PAS-251 Core Platform production-ready certificate candidate.

The candidate is evidence, not an authorization. It records what was observed on
each component's protected main and in live environments, and derives exactly one
verdict from that record:

* ``READY``   only when every mandatory gate of every core component is ``PASS``
  with cited evidence and the blocker matrix carries no ``OPEN`` blocker;
* ``BLOCKED`` in every other case.

The validator fails closed. It rejects a candidate that declares a verdict the
record does not support, a gate that is not ``PASS`` without a blocker, a ``PASS``
without evidence, an orphan or dangling blocker, a malformed SHA or digest, a
certificate/blocker-matrix hash drift, or anything shaped like a secret. It never
contacts a network or a runtime; it reads only the evidence directory and checks
that cited repository paths exist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIR = ROOT / "docs" / "evidence" / "pas251-core-cert-20260924"
CERTIFICATE_FILE = "certificate-candidate.json"
BLOCKER_FILE = "blocker-matrix.json"
README_FILE = "README.md"

CERTIFICATE_SCHEMA = "codestra.core-platform.production-certificate-candidate.v1"
BLOCKER_SCHEMA = "codestra.core-platform.certificate-blocker-matrix.v1"
CERTIFICATE_ID = "PAS-251-CORE-CERT-01"

REQUIRED_COMPONENTS = ("middleware", "kong", "caddy", "odoo", "keycloak", "openbao")
PLATFORM_SCOPE = "platform"
MANDATORY_GATES = (
    "protected_main",
    "exact_main_ci",
    "independent_review",
    "signed_immutable_artifact",
    "staging_digest_readback",
    "identity_route_matrix",
    "secret_binding",
    "backup_restore",
    "rollback_rehearsal",
    "monitoring_continuity",
)
GATE_STATUSES = ("PASS", "FAIL", "MISSING")
BLOCKER_STATUSES = ("OPEN", "CLEARED")
VERDICTS = ("READY", "BLOCKED")

SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
BLOCKER_ID = re.compile(r"^PAS251-B[0-9]{3}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
URL_PREFIX = "url:https://github.com/ingtrader21-spec/"
REPO_PREFIX = "repo:"
CITABLE_PREFIXES = (REPO_PREFIX, URL_PREFIX)
OBSERVED_PREFIX = "observed:"
SECRET_SHAPED = re.compile(
    r"(hvs\.[A-Za-z0-9_-]{20,}|hvb\.[A-Za-z0-9_-]{20,}|\bs\.[A-Za-z0-9]{24,}\b|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.)"
)
README_HASH_LINE = re.compile(r"CERTIFICATE_CANDIDATE_SHA256=([0-9a-f]{64})")
README_VERDICT_LINE = re.compile(r"^CERTIFICATE=(READY|BLOCKED)$", re.MULTILINE)


class CertificateError(ValueError):
    """Raised when the evidence directory cannot be read as a candidate."""


def canonical_sha256(document: Any) -> str:
    """sha256 over the canonical JSON encoding (sorted keys, no whitespace)."""
    encoded = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CertificateError(f"missing {path.name}") from exc
    except json.JSONDecodeError as exc:
        raise CertificateError(f"{path.name} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise CertificateError(f"{path.name} must be a JSON object")
    return document


def derive_verdict(certificate: dict[str, Any], matrix: dict[str, Any]) -> str:
    """READY iff every mandatory gate is PASS and no blocker is OPEN."""
    components = certificate.get("components")
    if not isinstance(components, list) or not components:
        return "BLOCKED"
    for component in components:
        gates = component.get("gates") if isinstance(component, dict) else None
        if not isinstance(gates, dict):
            return "BLOCKED"
        for gate in MANDATORY_GATES:
            entry = gates.get(gate)
            if not isinstance(entry, dict) or entry.get("status") != "PASS":
                return "BLOCKED"
    blockers = matrix.get("blockers")
    if not isinstance(blockers, list):
        return "BLOCKED"
    if any(not isinstance(b, dict) or b.get("status") != "CLEARED" for b in blockers):
        return "BLOCKED"
    return "READY"


def _check_evidence(
    refs: Any, where: str, repo_root: Path, errors: list[str], *, require_citable: bool
) -> None:
    if not isinstance(refs, list) or not all(isinstance(r, str) and r for r in refs):
        errors.append(f"{where}: evidence must be a list of non-empty strings")
        return
    for ref in refs:
        if ref.startswith(REPO_PREFIX):
            relative = ref[len(REPO_PREFIX) :].split("#", 1)[0]
            candidate = (repo_root / relative).resolve()
            if (
                repo_root.resolve() not in candidate.parents
                and candidate != repo_root.resolve()
            ):
                errors.append(
                    f"{where}: evidence path escapes the repository: {relative}"
                )
            elif not candidate.exists():
                errors.append(
                    f"{where}: cited repository path does not exist: {relative}"
                )
        elif ref.startswith("url:"):
            if not ref.startswith(URL_PREFIX):
                errors.append(
                    f"{where}: evidence URL is outside the canonical owner: {ref}"
                )
        elif not ref.startswith(OBSERVED_PREFIX):
            errors.append(
                f"{where}: evidence must start with repo:, url: or observed: ({ref})"
            )
    if require_citable and not any(r.startswith(CITABLE_PREFIXES) for r in refs):
        errors.append(f"{where}: PASS requires at least one repo: or url: citation")


def _check_component(
    component: Any,
    blockers_by_id: dict[str, dict[str, Any]],
    referenced: set[str],
    repo_root: Path,
    errors: list[str],
) -> str | None:
    if not isinstance(component, dict):
        errors.append("components: every component must be an object")
        return None
    cid = component.get("id")
    where = f"component {cid!r}"
    if cid not in REQUIRED_COMPONENTS:
        errors.append(f"{where}: not a core component")
        return None
    repository = component.get("repository")
    if not isinstance(repository, str) or not REPOSITORY.match(repository):
        errors.append(f"{where}: repository must be owner/name")
    if not isinstance(component.get("protected_main_sha"), str) or not SHA40.match(
        component["protected_main_sha"]
    ):
        errors.append(f"{where}: protected_main_sha must be a lowercase 40-hex SHA")

    artifact = component.get("artifact")
    if not isinstance(artifact, dict):
        errors.append(f"{where}: artifact must be an object")
        artifact = {}
    for key in ("base_image_digests", "release_digests"):
        digests = artifact.get(key, [])
        if not isinstance(digests, list):
            errors.append(f"{where}: artifact.{key} must be a list")
            continue
        for item in digests:
            digest = item.get("digest") if isinstance(item, dict) else None
            if not isinstance(digest, str) or not DIGEST.match(digest):
                errors.append(
                    f"{where}: artifact.{key} entry has a malformed digest: {item!r}"
                )

    gates = component.get("gates")
    if not isinstance(gates, dict):
        errors.append(f"{where}: gates must be an object")
        return cid
    missing = [g for g in MANDATORY_GATES if g not in gates]
    extra = sorted(set(gates) - set(MANDATORY_GATES))
    if missing:
        errors.append(f"{where}: missing mandatory gates {missing}")
    if extra:
        errors.append(f"{where}: unknown gates {extra}")
    for gate in MANDATORY_GATES:
        entry = gates.get(gate)
        gwhere = f"{where} gate {gate}"
        if not isinstance(entry, dict):
            if gate in gates:
                errors.append(f"{gwhere}: must be an object")
            continue
        status = entry.get("status")
        if status not in GATE_STATUSES:
            errors.append(f"{gwhere}: status must be one of {GATE_STATUSES}")
            continue
        ids = entry.get("blockers", [])
        if not isinstance(ids, list):
            errors.append(f"{gwhere}: blockers must be a list")
            ids = []
        _check_evidence(
            entry.get("evidence", []),
            gwhere,
            repo_root,
            errors,
            require_citable=status == "PASS",
        )
        if status == "PASS":
            if ids:
                errors.append(f"{gwhere}: PASS cannot carry blockers")
            if gate == "signed_immutable_artifact" and not artifact.get(
                "release_digests"
            ):
                errors.append(f"{gwhere}: PASS requires a recorded release digest")
            continue
        if not ids:
            errors.append(f"{gwhere}: {status} requires at least one blocker")
        for bid in ids:
            blocker = blockers_by_id.get(bid)
            if blocker is None:
                errors.append(f"{gwhere}: references unknown blocker {bid}")
                continue
            referenced.add(bid)
            if blocker.get("status") != "OPEN":
                errors.append(
                    f"{gwhere}: {status} cites blocker {bid} that is not OPEN"
                )
            if blocker.get("component") not in (cid, PLATFORM_SCOPE):
                errors.append(
                    f"{gwhere}: blocker {bid} belongs to {blocker.get('component')!r}"
                )
            if gate not in blocker.get("gates", []):
                errors.append(f"{gwhere}: blocker {bid} does not list gate {gate}")
    return cid


def validate(
    certificate: dict[str, Any],
    matrix: dict[str, Any],
    readme: str | None,
    repo_root: Path = ROOT,
) -> tuple[list[str], str]:
    """Return (errors, derived_verdict). An empty error list means consistent."""
    errors: list[str] = []
    if certificate.get("schema") != CERTIFICATE_SCHEMA:
        errors.append(f"certificate schema must be {CERTIFICATE_SCHEMA}")
    if certificate.get("certificate_id") != CERTIFICATE_ID:
        errors.append(f"certificate_id must be {CERTIFICATE_ID}")
    if matrix.get("schema") != BLOCKER_SCHEMA:
        errors.append(f"blocker matrix schema must be {BLOCKER_SCHEMA}")
    if matrix.get("certificate_id") != CERTIFICATE_ID:
        errors.append("blocker matrix certificate_id does not match")

    blockers = matrix.get("blockers")
    blockers_by_id: dict[str, dict[str, Any]] = {}
    if not isinstance(blockers, list):
        errors.append("blocker matrix blockers must be a list")
        blockers = []
    for blocker in blockers:
        if not isinstance(blocker, dict):
            errors.append("every blocker must be an object")
            continue
        bid = blocker.get("id")
        bwhere = f"blocker {bid!r}"
        if not isinstance(bid, str) or not BLOCKER_ID.match(bid):
            errors.append(f"{bwhere}: id must match PAS251-Bnnn")
            continue
        if bid in blockers_by_id:
            errors.append(f"{bwhere}: duplicate id")
        blockers_by_id[bid] = blocker
        if blocker.get("component") not in (*REQUIRED_COMPONENTS, PLATFORM_SCOPE):
            errors.append(f"{bwhere}: component must be a core component or platform")
        gates = blocker.get("gates")
        if (
            not isinstance(gates, list)
            or not gates
            or any(g not in MANDATORY_GATES for g in gates)
        ):
            errors.append(
                f"{bwhere}: gates must be a non-empty list of mandatory gates"
            )
        if blocker.get("status") not in BLOCKER_STATUSES:
            errors.append(f"{bwhere}: status must be one of {BLOCKER_STATUSES}")
        if blocker.get("mandatory") is not True:
            errors.append(f"{bwhere}: every certificate blocker is mandatory")
        for key in ("observed", "clear_condition", "owner"):
            if not isinstance(blocker.get(key), str) or not blocker[key].strip():
                errors.append(f"{bwhere}: {key} is required")
        _check_evidence(
            blocker.get("evidence", []), bwhere, repo_root, errors, require_citable=True
        )

    components = certificate.get("components")
    referenced: set[str] = set()
    seen: list[str] = []
    if not isinstance(components, list):
        errors.append("certificate components must be a list")
        components = []
    for component in components:
        cid = _check_component(component, blockers_by_id, referenced, repo_root, errors)
        if cid is not None:
            seen.append(cid)
    if sorted(seen) != sorted(REQUIRED_COMPONENTS) or len(seen) != len(set(seen)):
        errors.append(
            f"components must be exactly {list(REQUIRED_COMPONENTS)} once each (got {seen})"
        )
    orphans = sorted(
        bid
        for bid, b in blockers_by_id.items()
        if b.get("status") == "OPEN" and bid not in referenced
    )
    if orphans:
        errors.append(f"open blockers not cited by any gate: {orphans}")

    bound = certificate.get("blocker_matrix_sha256")
    actual = canonical_sha256(matrix)
    if bound != actual:
        errors.append(
            f"blocker_matrix_sha256 drift: certificate binds {bound}, matrix is {actual}"
        )

    derived = derive_verdict(certificate, matrix)
    declared = certificate.get("certificate")
    if declared not in VERDICTS:
        errors.append(f"certificate must be one of {VERDICTS}")
    elif declared != derived:
        errors.append(
            f"certificate declares {declared} but the evidence derives {derived}"
        )
    if certificate.get("production_mutation") is not False:
        errors.append(
            "production_mutation must be false for a certification-input lane"
        )
    if certificate.get("production_go") is not (derived == "READY"):
        errors.append("production_go must be true only for a READY certificate")

    for name, document in (("certificate", certificate), ("blocker matrix", matrix)):
        if SECRET_SHAPED.search(json.dumps(document)):
            errors.append(f"{name} contains a secret-shaped value")

    if readme is not None:
        match = README_HASH_LINE.search(readme)
        expected = canonical_sha256(certificate)
        if not match or match.group(1) != expected:
            errors.append(f"README must record CERTIFICATE_CANDIDATE_SHA256={expected}")
        verdict_lines = README_VERDICT_LINE.findall(readme)
        if verdict_lines != [declared]:
            errors.append(f"README must state exactly one CERTIFICATE={declared} line")
        if SECRET_SHAPED.search(readme):
            errors.append("README contains a secret-shaped value")
    return errors, derived


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--dir", type=Path, default=DEFAULT_DIR, help="evidence directory"
    )
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    args = parser.parse_args(argv)
    try:
        certificate = load_json(args.dir / CERTIFICATE_FILE)
        matrix = load_json(args.dir / BLOCKER_FILE)
        readme = (args.dir / README_FILE).read_text(encoding="utf-8")
    except (CertificateError, FileNotFoundError) as exc:
        print(f"PAS-251 certificate candidate unreadable: {exc}", file=sys.stderr)
        return 2
    errors, derived = validate(certificate, matrix, readme)
    open_blockers = sorted(
        b["id"]
        for b in matrix.get("blockers", [])
        if isinstance(b, dict) and b.get("status") == "OPEN"
    )
    report = {
        "certificate_id": CERTIFICATE_ID,
        "consistent": not errors,
        "declared": certificate.get("certificate"),
        "derived": derived,
        "certificate_candidate_sha256": canonical_sha256(certificate),
        "blocker_matrix_sha256": canonical_sha256(matrix),
        "open_blockers": open_blockers,
        "errors": errors,
    }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"CERTIFICATE={derived}")
        print(f"CERTIFICATE_CANDIDATE_SHA256={report['certificate_candidate_sha256']}")
        print(f"BLOCKER_MATRIX_SHA256={report['blocker_matrix_sha256']}")
        print(f"OPEN_BLOCKERS={len(open_blockers)}")
        print("CONSISTENT=" + ("yes" if not errors else "no"))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
