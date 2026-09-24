#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import asyncio
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_RELATIVE_PATH = Path("config/migration-lineage.v1.json")
ALEMBIC_VERSION_TABLE = "public.alembic_version"
REVISION_GLOBS = ("services/**/migrations/versions/*.py",)


class LineageError(RuntimeError):
    """Raised when repository or database migration ancestry is not trustworthy."""


@dataclass(frozen=True)
class LineageReport:
    authority_revisions: tuple[str, ...]
    database_revisions: tuple[str, ...]
    alembic_table_present: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "status": "PASS",
            "authority_revisions": list(self.authority_revisions),
            "database_revisions": list(self.database_revisions),
            "alembic_table_present": self.alembic_table_present,
        }


def _literal_assignment(module: ast.Module, name: str, path: Path) -> Any:
    for node in module.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        value = node.value
        if value is None:
            return None
        try:
            return ast.literal_eval(value)
        except (ValueError, TypeError) as exc:
            raise LineageError(f"{path}: {name} must be a literal value") from exc
    raise LineageError(f"{path}: missing {name} assignment")


def _parents(value: Any, path: Path) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str) and value:
        return (value,)
    if isinstance(value, (tuple, list)) and all(isinstance(item, str) and item for item in value):
        return tuple(value)
    raise LineageError(f"{path}: down_revision must be null, a revision string, or revision sequence")


def _validate_graph(graph: dict[str, tuple[str, ...]], label: str) -> None:
    if not graph:
        raise LineageError(f"{label} contains no Alembic revisions")
    missing_parents = sorted(
        {parent for parents in graph.values() for parent in parents if parent not in graph}
    )
    if missing_parents:
        raise LineageError(
            f"{label} references missing parent revision(s): " + ", ".join(missing_parents)
        )
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(revision: str) -> None:
        if revision in visited:
            return
        if revision in visiting:
            raise LineageError(f"cycle detected in {label} at {revision}")
        visiting.add(revision)
        for parent in graph[revision]:
            visit(parent)
        visiting.remove(revision)
        visited.add(revision)

    for revision in graph:
        visit(revision)


def discover_repository_graph(root: Path = ROOT) -> dict[str, tuple[str, ...]]:
    graph: dict[str, tuple[str, ...]] = {}
    paths: list[Path] = []
    for pattern in REVISION_GLOBS:
        paths.extend(root.glob(pattern))
    for path in sorted(set(paths)):
        try:
            module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError) as exc:
            raise LineageError(f"cannot parse migration source {path}: {exc}") from exc
        revision = _literal_assignment(module, "revision", path)
        if not isinstance(revision, str) or not revision.strip():
            raise LineageError(f"{path}: revision must be a non-empty string")
        revision = revision.strip()
        if revision in graph:
            raise LineageError(f"duplicate Alembic revision in repository: {revision}")
        graph[revision] = _parents(_literal_assignment(module, "down_revision", path), path)
    _validate_graph(graph, "repository Alembic graph")
    return graph


def load_authority_manifest(root: Path = ROOT) -> dict[str, tuple[str, ...]]:
    path = root / MANIFEST_RELATIVE_PATH
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LineageError(f"cannot load migration lineage manifest {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise LineageError("migration lineage manifest root must be an object")
    if value.get("schema_version") != "1.0":
        raise LineageError("migration lineage manifest schema_version must be 1.0")
    if value.get("authority") != "reviewed-git-source":
        raise LineageError("migration lineage manifest authority is invalid")
    if value.get("alembic_version_table") != ALEMBIC_VERSION_TABLE:
        raise LineageError("migration lineage manifest version-table authority drifted")
    rows = value.get("revisions")
    if not isinstance(rows, list):
        raise LineageError("migration lineage manifest revisions must be an array")
    graph: dict[str, tuple[str, ...]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {"revision", "down_revisions"}:
            raise LineageError(f"manifest revisions[{index}] shape is invalid")
        revision = row["revision"]
        parents = row["down_revisions"]
        if not isinstance(revision, str) or not revision:
            raise LineageError(f"manifest revisions[{index}] revision is invalid")
        if revision in graph:
            raise LineageError(f"duplicate revision in migration lineage manifest: {revision}")
        if not isinstance(parents, list) or not all(isinstance(parent, str) and parent for parent in parents):
            raise LineageError(f"manifest revisions[{index}] down_revisions is invalid")
        graph[revision] = tuple(parents)
    _validate_graph(graph, "migration lineage manifest")
    return graph


def authority_graph(root: Path = ROOT) -> dict[str, tuple[str, ...]]:
    repository = discover_repository_graph(root)
    manifest = load_authority_manifest(root)
    if manifest != repository:
        raise LineageError(
            "migration lineage manifest does not exactly match reviewed Alembic source; regenerate/review the manifest before release"
        )
    return manifest


def validate_observed_revisions(
    observed: Iterable[str],
    *,
    root: Path = ROOT,
) -> LineageReport:
    graph = authority_graph(root)
    normalized = tuple(sorted({value.strip() for value in observed if value and value.strip()}))
    if not normalized:
        raise LineageError("Alembic version table exists but contains no revision")
    unknown = tuple(value for value in normalized if value not in graph)
    if unknown:
        raise LineageError(
            "database reports unknown Alembic revision(s): "
            + ", ".join(unknown)
            + "; restore the exact historical migration source before any stamp, upgrade, or runtime migration"
        )
    return LineageReport(
        authority_revisions=tuple(sorted(graph)),
        database_revisions=normalized,
        alembic_table_present=True,
    )


async def inspect_database_lineage(conn: Any, *, root: Path = ROOT) -> LineageReport:
    graph = authority_graph(root)
    table = await conn.fetchval("SELECT to_regclass('public.alembic_version')::text")
    if table is None:
        return LineageReport(
            authority_revisions=tuple(sorted(graph)),
            database_revisions=(),
            alembic_table_present=False,
        )
    rows = await conn.fetch(f"SELECT version_num FROM {ALEMBIC_VERSION_TABLE} ORDER BY version_num")
    return validate_observed_revisions((str(row["version_num"]) for row in rows), root=root)


async def _database_report(url: str, root: Path) -> LineageReport:
    try:
        import asyncpg
    except ImportError as exc:
        raise LineageError("asyncpg is required for database lineage inspection") from exc
    conn = await asyncpg.connect(url, command_timeout=30)
    try:
        return await inspect_database_lineage(conn, root=root)
    finally:
        await conn.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail closed when a database Alembic revision is absent from reviewed migration authority."
    )
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument(
        "--observed-revision",
        action="append",
        default=[],
        help="Validate one observed Alembic revision without connecting to a database. Repeatable.",
    )
    parser.add_argument(
        "--database-url-env",
        default="DATABASE_URL",
        help="Environment variable containing the database URL when no observed revision is supplied.",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.observed_revision:
            report = validate_observed_revisions(args.observed_revision, root=args.repo_root)
        else:
            url = os.environ.get(args.database_url_env)
            if not url:
                raise LineageError(f"{args.database_url_env} is required")
            report = asyncio.run(_database_report(url, args.repo_root))
    except LineageError as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(report.as_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
