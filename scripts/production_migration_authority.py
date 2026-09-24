"""Validate canonical production Alembic and SQL history without executing it.

The connector service's 20260828_* lineage is a separate database authority.
Changing an existing revision's parent or bytes requires an explicit change to
this protected release authority, even when the terminal revision ID is unchanged.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path

AUTHORITY_PATH = "config/middleware-forward-release-authority.v1.json"
HISTORY_KEY = "requiredMigrationHistorySha256"
SQL_BUNDLES = (("core", "migrations"), ("automation-v2", "migrations/automation"))
SQL_PATTERN = "[0-9][0-9][0-9][0-9]_*.sql"


class AuthorityError(ValueError):
    """The packaged migration source does not match the reviewed release."""


def migration_history(root: Path) -> tuple[dict[str, tuple[str, ...]], str]:
    paths = sorted((root / "migrations/versions").glob("*.py"))
    if not paths:
        raise AuthorityError("canonical production migration source is missing")
    graph: dict[str, tuple[str, ...]] = {}
    history: list[dict[str, object]] = []
    for path in paths:
        if path.name == "__init__.py":
            continue
        source = path.read_bytes()
        values: dict[str, object] = {}
        for node in ast.parse(source, filename=str(path)).body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id in {
                    "revision", "down_revision", "depends_on", "branch_labels"
                }:
                    if target.id in values or node.value is None:
                        raise AuthorityError(f"{path.name}: ambiguous {target.id}")
                    values[target.id] = ast.literal_eval(node.value)
        revision = values.get("revision")
        if not isinstance(revision, str) or not re.fullmatch(r"[A-Za-z0-9_]+", revision):
            raise AuthorityError(f"{path.name}: invalid revision")
        if revision in graph:
            raise AuthorityError(f"duplicate revision {revision!r}")
        if "down_revision" not in values:
            raise AuthorityError(f"{path.name}: missing down_revision")
        parent = values["down_revision"]
        parents: tuple[str, ...]
        if parent is None:
            parents = ()
        elif isinstance(parent, str) and parent:
            parents = (parent,)
        elif isinstance(parent, (list, tuple)) and parent and all(
            isinstance(item, str) and item for item in parent
        ):
            parents = tuple(parent)
        else:
            raise AuthorityError(f"{path.name}: invalid down_revision")
        if len(set(parents)) != len(parents):
            raise AuthorityError(f"{path.name}: duplicate parent")
        if values.get("depends_on") is not None or values.get("branch_labels") is not None:
            raise AuthorityError(f"{path.name}: dependency/branch authority requires explicit support")
        graph[revision] = parents
        history.append({
            "path": path.relative_to(root).as_posix(),
            "revision": revision,
            "down_revisions": list(parents),
            "source_sha256": hashlib.sha256(source).hexdigest(),
        })
    if not graph:
        raise AuthorityError("canonical production migration history is empty")
    missing = sorted({p for parents in graph.values() for p in parents} - graph.keys())
    if missing:
        raise AuthorityError("missing parent revisions: " + ", ".join(missing))
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(revision: str) -> None:
        if revision in visiting:
            raise AuthorityError("cycle in production migration history")
        if revision in visited:
            return
        visiting.add(revision)
        for parent in graph[revision]:
            visit(parent)
        visiting.remove(revision)
        visited.add(revision)

    for revision in graph:
        visit(revision)
    # Lock exactly the numbered SQL sources consumed by migrate_runtime.py.
    # Paths bind names and bundle membership; raw-byte hashes detect rewritten
    # DDL even when version receipts and the terminal Alembic head are unchanged.
    # Keep order deterministic. Do not execute SQL or update the pin at runtime.
    for bundle, relative in SQL_BUNDLES:
        directory = root / relative
        if directory.is_symlink():
            raise AuthorityError(f"{relative}: SQL bundle directory must not be a symlink")
        for path in sorted(directory.glob(SQL_PATTERN)):
            if path.is_symlink() or not path.is_file():
                raise AuthorityError(f"{path.name}: SQL migration must be a regular file")
            history.append({
                "authority": bundle,
                "path": path.relative_to(root).as_posix(),
                "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            })
    payload = json.dumps(history, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return graph, "sha256:" + hashlib.sha256(payload).hexdigest()


def validate_authority(root: Path) -> tuple[str, dict[str, tuple[str, ...]], str]:
    authority = json.loads((root / AUTHORITY_PATH).read_text(encoding="utf-8"))
    artifact = authority["artifactAuthority"]
    expected = artifact["requiredSchemaHead"]
    if not isinstance(expected, str) or not expected:
        raise AuthorityError("requiredSchemaHead must be a non-empty string")
    graph, digest = migration_history(root)
    parents = {parent for values in graph.values() for parent in values}
    heads = sorted(graph.keys() - parents)
    if heads != [expected]:
        raise AuthorityError(
            "production migration head drift: "
            f"authority requires {expected!r}, repository heads are {heads!r}; "
            "update the platform tuple through separate protected review before adding a head"
        )
    pinned = artifact.get(HISTORY_KEY)
    if not isinstance(pinned, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", pinned):
        raise AuthorityError("production migration history digest is missing or malformed")
    if pinned != digest:
        raise AuthorityError(
            "production migration history drift: revision parents or source bytes changed; "
            "existing database heads cannot prove newly inserted history was applied"
        )
    return expected, graph, digest
