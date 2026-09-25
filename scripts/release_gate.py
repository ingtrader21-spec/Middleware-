#!/usr/bin/env python3
"""Evaluate the schema-0067 release-attestation gate and emit machine-readable output.

The gate answers one question for an exact source: is every input the protected
signed-release job needs present, bound to that source, and policy-clean?  It
never signs, pushes, or publishes anything.  Inputs that only an external
authority can supply (the protected main head, the published image digest, the
SBOM and scan produced from that digest, the signed manifest) are reported as
``PENDING_EXTERNAL`` rather than assumed, so the decision is:

  FAIL               at least one check contradicts the release policy (exit 1)
  BLOCKED            no contradiction, but external evidence is missing (exit 2)
  READY_FOR_SIGNING  every input is present and bound to the source (exit 0)

Checks:

  source_binding             HEAD/tree are canonical, the tree is clean, HEAD is
                             the expected source and the protected main head
  alembic_single_head        the Alembic graph is closed, acyclic and has exactly
                             one head equal to the required schema head
  workflow_schema_binding    release.yml probes and annotates that same head
  sbom                       SPDX 2.x document with packages
  vulnerability_policy       no fixable high/critical finding (the scan-action
                             ``severity-cutoff: high`` + ``only-fixed`` policy)
  provenance_predicate       SLSA v1 predicate identical to the release job's
  cosign_inputs              immutable digest in the canonical package, signer
                             identity and OIDC issuer
  release_manifest           canonical manifest bound to source, digest,
                             workspace artifacts, SBOM and scan bytes
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.release_manifest import (  # noqa: E402
    CERTIFICATE_IDENTITY,
    DIGEST,
    IMAGE_REPOSITORY,
    OIDC_ISSUER,
    REPOSITORY,
    SHA40,
    WORKFLOW_PATH,
    ReleaseManifestError,
    canonical_json,
    load_manifest,
    sha256_file,
    validate_manifest,
    verify_workspace,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "codestra.middleware.release-gate.v1"
EXPECTED_SCHEMA_HEAD = "0067_service_catalog_monitoring_state"
MIGRATIONS_RELATIVE = Path("migrations/versions")
PASS = "PASS"
FAIL = "FAIL"
PENDING = "PENDING_EXTERNAL"
CHECK_IDS = (
    "source_binding",
    "alembic_single_head",
    "workflow_schema_binding",
    "sbom",
    "vulnerability_policy",
    "provenance_predicate",
    "cosign_inputs",
    "release_manifest",
)
BLOCKING_SEVERITIES = frozenset({"high", "critical"})
SEVERITY_ORDER = ("critical", "high", "medium", "low", "negligible", "unknown")
SLSA_BUILD_TYPE = (
    "https://codestra.example/buildtypes/exact-main-middleware-production/v1"
)
PLATFORM = "linux/amd64"
PACKAGE_ACCESS_PENDING = "PENDING_OWNER_PACKAGE_ACCESS"


class GateInputError(RuntimeError):
    """A supplied gate input is unreadable or structurally invalid."""


def _check(check_id: str, status: str, detail: str, **evidence: Any) -> dict[str, Any]:
    return {"id": check_id, "status": status, "detail": detail, "evidence": evidence}


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GateInputError(f"{label} cannot be loaded as JSON") from exc


# --------------------------------------------------------------------------- source


def check_source_binding(
    root: Path,
    *,
    expected_source_sha: str | None,
    protected_main_sha: str | None,
) -> dict[str, Any]:
    check_id = "source_binding"
    try:
        head = _git(root, "rev-parse", "HEAD").strip()
        tree = _git(root, "rev-parse", "HEAD^{tree}").strip()
        dirty = [
            line for line in _git(root, "status", "--porcelain").splitlines() if line
        ]
    except (OSError, subprocess.CalledProcessError):
        return _check(check_id, FAIL, "Git source identity cannot be read")
    evidence: dict[str, Any] = {
        "source_sha": head,
        "git_tree_id": tree,
        "worktree_clean": not dirty,
        "expected_source_sha": expected_source_sha,
        "protected_main_sha": protected_main_sha,
    }
    if SHA40.fullmatch(head) is None or SHA40.fullmatch(tree) is None:
        return _check(
            check_id, FAIL, "Git returned a non-canonical source identity", **evidence
        )
    if dirty:
        return _check(
            check_id, FAIL, f"worktree has {len(dirty)} uncommitted path(s)", **evidence
        )
    for label, value in (
        ("expected source SHA", expected_source_sha),
        ("protected main SHA", protected_main_sha),
    ):
        if value is not None and SHA40.fullmatch(value) is None:
            return _check(
                check_id, FAIL, f"{label} is not lowercase 40-character hex", **evidence
            )
    if expected_source_sha is not None and expected_source_sha != head:
        return _check(
            check_id, FAIL, "HEAD is not the expected release source", **evidence
        )
    if protected_main_sha is None:
        return _check(
            check_id,
            PENDING,
            "protected main head was not supplied; only the current protected head may be released",
            **evidence,
        )
    if protected_main_sha != head:
        return _check(
            check_id, FAIL, "HEAD is not the current protected main head", **evidence
        )
    return _check(
        check_id, PASS, "HEAD is the clean, current protected main head", **evidence
    )


# --------------------------------------------------------------------------- alembic


def _literal(module: ast.Module, name: str, path: Path) -> Any:
    for node in module.body:
        targets: list[ast.expr]
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if any(
            isinstance(target, ast.Name) and target.id == name for target in targets
        ):
            if node.value is None:
                return None
            try:
                return ast.literal_eval(node.value)
            except (ValueError, TypeError) as exc:
                raise GateInputError(f"{path.name}: {name} is not a literal") from exc
    raise GateInputError(f"{path.name}: missing {name}")


def alembic_graph(root: Path) -> dict[str, tuple[str, ...]]:
    """Revision -> parents for every migration module, parsed without importing it."""
    graph: dict[str, tuple[str, ...]] = {}
    directory = root / MIGRATIONS_RELATIVE
    paths = sorted(
        path for path in directory.glob("*.py") if path.name != "__init__.py"
    )
    if not paths:
        raise GateInputError("no Alembic migration modules found")
    for path in paths:
        try:
            module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise GateInputError(f"{path.name}: cannot be parsed") from exc
        revision = _literal(module, "revision", path)
        down_revision = _literal(module, "down_revision", path)
        if not isinstance(revision, str) or not revision:
            raise GateInputError(f"{path.name}: revision is invalid")
        if revision in graph:
            raise GateInputError(f"{path.name}: revision {revision} is duplicated")
        if down_revision is None:
            parents: tuple[str, ...] = ()
        elif isinstance(down_revision, str) and down_revision:
            parents = (down_revision,)
        elif (
            isinstance(down_revision, (tuple, list))
            and down_revision
            and all(isinstance(item, str) and item for item in down_revision)
        ):
            parents = tuple(down_revision)
        else:
            raise GateInputError(f"{path.name}: down_revision is invalid")
        graph[revision] = parents
    return graph


def _graph_defects(graph: dict[str, tuple[str, ...]]) -> list[str]:
    defects = [
        f"missing parent {parent} of {revision}"
        for revision, parents in sorted(graph.items())
        for parent in parents
        if parent not in graph
    ]
    roots = sorted(revision for revision, parents in graph.items() if not parents)
    if len(roots) != 1:
        defects.append(f"expected exactly one base revision, found {roots}")
    finished: set[str] = set()
    for start in sorted(graph):
        visiting: set[str] = set()
        stack = [start]
        while stack:
            revision = stack[-1]
            if revision in finished:
                stack.pop()
                continue
            visiting.add(revision)
            pending = [
                parent
                for parent in graph[revision]
                if parent in graph and parent not in finished
            ]
            for parent in pending:
                if parent in visiting:
                    defects.append(f"cycle through {parent}")
                    return defects
            if pending:
                stack.append(pending[0])
            else:
                visiting.discard(revision)
                finished.add(revision)
                stack.pop()
    return defects


def check_alembic_single_head(root: Path, expected_head: str) -> dict[str, Any]:
    check_id = "alembic_single_head"
    try:
        graph = alembic_graph(root)
    except GateInputError as exc:
        return _check(check_id, FAIL, str(exc), expected_head=expected_head)
    parents = {parent for values in graph.values() for parent in values}
    heads = sorted(set(graph) - parents)
    evidence = {
        "expected_head": expected_head,
        "heads": heads,
        "revision_count": len(graph),
        "migrations_path": MIGRATIONS_RELATIVE.as_posix(),
    }
    defects = _graph_defects(graph)
    if defects:
        return _check(check_id, FAIL, "; ".join(defects), **evidence)
    if len(heads) != 1:
        return _check(
            check_id,
            FAIL,
            f"expected exactly one Alembic head, found {len(heads)}",
            **evidence,
        )
    if heads[0] != expected_head:
        return _check(
            check_id,
            FAIL,
            f"Alembic head {heads[0]} is not {expected_head}",
            **evidence,
        )
    return _check(check_id, PASS, f"single Alembic head {expected_head}", **evidence)


def check_workflow_schema_binding(root: Path, expected_head: str) -> dict[str, Any]:
    check_id = "workflow_schema_binding"
    path = root / WORKFLOW_PATH
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return _check(check_id, FAIL, f"{WORKFLOW_PATH} cannot be read")
    probe = sorted(
        set(re.findall(r"^\s*EXPECTED_SCHEMA_HEAD:\s*(\S+)\s*$", text, re.MULTILINE))
    )
    annotation = sorted(set(re.findall(r"codestra\.schema_head=([A-Za-z0-9_]+)", text)))
    evidence = {
        "workflow_path": WORKFLOW_PATH,
        "expected_head": expected_head,
        "probe_expected_heads": probe,
        "signature_annotation_heads": annotation,
    }
    if probe != [expected_head]:
        return _check(
            check_id,
            FAIL,
            "release image probe does not require the schema head",
            **evidence,
        )
    if annotation != [expected_head]:
        return _check(
            check_id,
            FAIL,
            "release signature annotation does not carry the schema head",
            **evidence,
        )
    return _check(
        check_id, PASS, "release job probes and annotates the schema head", **evidence
    )


# --------------------------------------------------------------------------- evidence


def check_sbom(path: Path | None) -> dict[str, Any]:
    check_id = "sbom"
    if path is None:
        return _check(
            check_id, PENDING, "SPDX SBOM of the published digest was not supplied"
        )
    try:
        document = _load_json(path, "SBOM")
        digest = sha256_file(path)
    except (GateInputError, ReleaseManifestError) as exc:
        return _check(check_id, FAIL, str(exc), path=path.name)
    if not isinstance(document, dict):
        return _check(
            check_id, FAIL, "SBOM is not a JSON object", path=path.name, sha256=digest
        )
    version = document.get("spdxVersion")
    packages = document.get("packages")
    evidence = {
        "path": path.name,
        "sha256": digest,
        "spdx_version": version,
        "package_count": len(packages) if isinstance(packages, list) else 0,
        "document_name": document.get("name"),
    }
    if not isinstance(version, str) or re.fullmatch(r"SPDX-2\.\d+", version) is None:
        return _check(
            check_id, FAIL, "SBOM is not an SPDX 2.x JSON document", **evidence
        )
    if (
        not isinstance(document.get("documentNamespace"), str)
        or not document["documentNamespace"]
    ):
        return _check(check_id, FAIL, "SBOM has no documentNamespace", **evidence)
    if not isinstance(packages, list) or not packages:
        return _check(check_id, FAIL, "SBOM lists no packages", **evidence)
    return _check(
        check_id, PASS, f"SPDX SBOM with {len(packages)} package(s)", **evidence
    )


def _severity(match: dict[str, Any]) -> str:
    vulnerability = match.get("vulnerability")
    if not isinstance(vulnerability, dict):
        raise GateInputError("scan match has no vulnerability object")
    severity = str(vulnerability.get("severity") or "unknown").lower()
    return severity if severity in SEVERITY_ORDER else "unknown"


def _fixable(match: dict[str, Any]) -> bool:
    fix = match["vulnerability"].get("fix")
    return isinstance(fix, dict) and fix.get("state") == "fixed"


def check_vulnerability_policy(path: Path | None) -> dict[str, Any]:
    check_id = "vulnerability_policy"
    if path is None:
        return _check(
            check_id, PENDING, "Grype report of the published SBOM was not supplied"
        )
    try:
        report = _load_json(path, "vulnerability report")
        digest = sha256_file(path)
        if not isinstance(report, dict) or not isinstance(report.get("matches"), list):
            raise GateInputError("vulnerability report has no matches list")
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        blocking: list[dict[str, str]] = []
        for match in report["matches"]:
            if not isinstance(match, dict):
                raise GateInputError("vulnerability report match is not an object")
            severity = _severity(match)
            counts[severity] += 1
            if severity in BLOCKING_SEVERITIES and _fixable(match):
                artifact = match.get("artifact")
                if not isinstance(artifact, dict):
                    artifact = {}
                blocking.append(
                    {
                        "id": str(match["vulnerability"].get("id") or ""),
                        "severity": severity,
                        "package": str(artifact.get("name") or ""),
                        "version": str(artifact.get("version") or ""),
                    }
                )
    except (GateInputError, ReleaseManifestError) as exc:
        return _check(check_id, FAIL, str(exc), path=path.name)
    blocking.sort(key=lambda item: (item["severity"], item["id"], item["package"]))
    evidence = {
        "path": path.name,
        "sha256": digest,
        "policy": "fail-high-or-critical-with-fix",
        "severity_counts": counts,
        "blocking_findings": blocking,
    }
    if blocking:
        return _check(
            check_id,
            FAIL,
            f"{len(blocking)} fixable high/critical finding(s)",
            **evidence,
        )
    return _check(check_id, PASS, "no fixable high or critical finding", **evidence)


def provenance_predicate(source_sha: str) -> dict[str, Any]:
    """The SLSA v1 predicate the protected release job attests, byte-for-byte."""
    return {
        "buildDefinition": {
            "buildType": SLSA_BUILD_TYPE,
            "externalParameters": {
                "sourceSha": source_sha,
                "platform": PLATFORM,
            },
            "resolvedDependencies": [
                {
                    "uri": f"git+https://github.com/{REPOSITORY}@{source_sha}",
                    "digest": {"gitCommit": source_sha},
                }
            ],
        },
        "runDetails": {
            "builder": {"id": CERTIFICATE_IDENTITY},
        },
    }


def check_provenance_predicate(source_sha: str | None) -> dict[str, Any]:
    check_id = "provenance_predicate"
    if source_sha is None or SHA40.fullmatch(source_sha) is None:
        return _check(check_id, FAIL, "no canonical source SHA to bind provenance to")
    predicate = provenance_predicate(source_sha)
    return _check(
        check_id,
        PASS,
        "SLSA v1 predicate bound to the exact source and release builder",
        predicate_type="slsaprovenance1",
        builder_id=CERTIFICATE_IDENTITY,
        source_sha=source_sha,
        predicate_sha256="sha256:"
        + hashlib.sha256(canonical_json(predicate)).hexdigest(),
    )


def check_cosign_inputs(image_digest: str | None) -> dict[str, Any]:
    check_id = "cosign_inputs"
    evidence: dict[str, Any] = {
        "image_repository": IMAGE_REPOSITORY,
        "certificate_identity": CERTIFICATE_IDENTITY,
        "oidc_issuer": OIDC_ISSUER,
        "transparency_log_required": True,
        "image_digest": image_digest,
        "image_reference": None,
    }
    if image_digest is None:
        evidence["image_digest"] = PACKAGE_ACCESS_PENDING
        return _check(
            check_id,
            PENDING,
            "no published image digest; the protected release job must push to the canonical package first",
            **evidence,
        )
    if DIGEST.fullmatch(image_digest) is None:
        return _check(
            check_id, FAIL, "image digest is not an immutable sha256 digest", **evidence
        )
    evidence["image_reference"] = f"{IMAGE_REPOSITORY}@{image_digest}"
    return _check(
        check_id, PASS, "Cosign signs and verifies one immutable digest", **evidence
    )


def check_release_manifest(
    root: Path,
    manifest_path: Path | None,
    *,
    source_sha: str | None,
    image_digest: str | None,
    sbom_path: Path | None,
    vulnerability_report_path: Path | None,
) -> dict[str, Any]:
    check_id = "release_manifest"
    if manifest_path is None:
        return _check(check_id, PENDING, "canonical release manifest was not supplied")
    try:
        manifest = load_manifest(manifest_path)
        validate_manifest(
            manifest,
            expected_source_sha=source_sha,
            expected_image_digest=image_digest,
        )
        evidence_dir = manifest_path.resolve().parent
        for label, supplied, key in (
            ("SBOM", sbom_path, "sbom"),
            ("vulnerability report", vulnerability_report_path, "vulnerability_report"),
        ):
            if (
                supplied is not None
                and supplied.resolve()
                != evidence_dir / manifest["artifacts"][key]["path"]
            ):
                raise ReleaseManifestError(
                    f"supplied {label} is not the manifest's evidence file"
                )
        verify_workspace(manifest, root=root, evidence_dir=evidence_dir)
    except ReleaseManifestError as exc:
        return _check(check_id, FAIL, str(exc), path=manifest_path.name)
    return _check(
        check_id,
        PASS,
        "manifest is canonical and bound to source, digest, workspace and evidence",
        path=manifest_path.name,
        sha256=sha256_file(manifest_path),
        release_id=manifest["release_id"],
        schema_or_migration_head=manifest["runtime"]["schema_or_migration_head"],
    )


# --------------------------------------------------------------------------- gate


def evaluate(
    *,
    root: Path = ROOT,
    expected_source_sha: str | None = None,
    protected_main_sha: str | None = None,
    expected_schema_head: str = EXPECTED_SCHEMA_HEAD,
    image_digest: str | None = None,
    sbom_path: Path | None = None,
    vulnerability_report_path: Path | None = None,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    source = check_source_binding(
        root,
        expected_source_sha=expected_source_sha,
        protected_main_sha=protected_main_sha,
    )
    source_sha = source["evidence"].get("source_sha")
    alembic = check_alembic_single_head(root, expected_schema_head)
    manifest = check_release_manifest(
        root,
        manifest_path,
        source_sha=source_sha,
        image_digest=image_digest,
        sbom_path=sbom_path,
        vulnerability_report_path=vulnerability_report_path,
    )
    if (
        manifest["status"] == PASS
        and manifest["evidence"]["schema_or_migration_head"] != expected_schema_head
    ):
        manifest = _check(
            "release_manifest",
            FAIL,
            "manifest migration head is not the required schema head",
            **manifest["evidence"],
        )
    checks = [
        source,
        alembic,
        check_workflow_schema_binding(root, expected_schema_head),
        check_sbom(sbom_path),
        check_vulnerability_policy(vulnerability_report_path),
        check_provenance_predicate(source_sha),
        check_cosign_inputs(image_digest),
        manifest,
    ]
    assert tuple(item["id"] for item in checks) == CHECK_IDS
    failed = [item["id"] for item in checks if item["status"] == FAIL]
    pending = [item["id"] for item in checks if item["status"] == PENDING]
    decision = "FAIL" if failed else "BLOCKED" if pending else "READY_FOR_SIGNING"
    return {
        "schema_version": SCHEMA_VERSION,
        "repository": REPOSITORY,
        "decision": decision,
        "source": {
            "git_sha": source_sha,
            "git_tree_id": source["evidence"].get("git_tree_id"),
            "protected_main_sha": protected_main_sha,
        },
        "schema_head": {
            "expected": expected_schema_head,
            "observed": alembic["evidence"].get("heads", []),
        },
        "image": {
            "repository": IMAGE_REPOSITORY,
            "digest": image_digest or PACKAGE_ACCESS_PENDING,
        },
        "checks": checks,
        "failed_checks": failed,
        "pending_external": pending,
        "effects": {
            "signing_performed": False,
            "image_pushed": False,
            "release_published": False,
            "production_go": "NO",
            "signing_authority": f"{CERTIFICATE_IDENTITY} (GitHub Actions OIDC)",
        },
    }


EXIT_CODES = {"READY_FOR_SIGNING": 0, "FAIL": 1, "BLOCKED": 2}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--protected-main-sha")
    parser.add_argument("--expected-schema-head", default=EXPECTED_SCHEMA_HEAD)
    parser.add_argument("--image-digest")
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--vulnerability-report", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--output", type=Path, help="write the canonical gate report here"
    )
    parser.add_argument(
        "--provenance-predicate-output",
        type=Path,
        help="write the SLSA v1 predicate for the gated source here",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = evaluate(
        root=args.root.resolve(),
        expected_source_sha=args.expected_source_sha,
        protected_main_sha=args.protected_main_sha,
        expected_schema_head=args.expected_schema_head,
        image_digest=args.image_digest,
        sbom_path=args.sbom,
        vulnerability_report_path=args.vulnerability_report,
        manifest_path=args.manifest,
    )
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_json(report))
    source_sha = report["source"]["git_sha"]
    if (
        args.provenance_predicate_output is not None
        and source_sha
        and SHA40.fullmatch(source_sha)
    ):
        args.provenance_predicate_output.parent.mkdir(parents=True, exist_ok=True)
        args.provenance_predicate_output.write_bytes(
            canonical_json(provenance_predicate(source_sha))
        )
    for check in report["checks"]:
        print(f"RELEASE_GATE_CHECK {check['id']}={check['status']} {check['detail']}")
    print(
        f"RELEASE_GATE={report['decision']} SOURCE_SHA={source_sha} "
        f"SCHEMA_HEAD={','.join(report['schema_head']['observed']) or 'NONE'} "
        f"IMAGE_DIGEST={report['image']['digest']} SIGNING_PERFORMED=NO"
    )
    return EXIT_CODES[report["decision"]]


if __name__ == "__main__":
    raise SystemExit(main())
