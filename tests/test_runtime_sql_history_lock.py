"""SQL receipts must never substitute for immutable migration-source authority."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from scripts.production_migration_authority import (
    AUTHORITY_PATH,
    HISTORY_KEY,
    SQL_BUNDLES,
    SQL_PATTERN,
    AuthorityError,
    migration_history,
    validate_authority,
)

ROOT = Path(__file__).resolve().parents[1]
SQL_PATHS = tuple(
    path.relative_to(ROOT).as_posix()
    for _, relative in SQL_BUNDLES
    for path in sorted((ROOT / relative).glob(SQL_PATTERN))
)


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    """Use real migration bytes; the test-only pin is set before any mutation."""
    shutil.copytree(ROOT / "migrations", tmp_path / "migrations")
    (tmp_path / "config").mkdir()
    payload = json.loads((ROOT / AUTHORITY_PATH).read_text(encoding="utf-8"))
    payload["artifactAuthority"][HISTORY_KEY] = migration_history(tmp_path)[1]
    (tmp_path / AUTHORITY_PATH).write_text(json.dumps(payload), encoding="utf-8")
    return tmp_path


def test_current_protected_pin_covers_alembic_and_all_sql_bundles() -> None:
    assert len(SQL_PATHS) == 14
    expected, graph, digest = validate_authority(ROOT)
    assert expected == "0070_agent_provisioning_lifecycle"
    assert len(graph) == 84
    assert digest == migration_history(ROOT)[1]


@pytest.mark.parametrize("relative", SQL_PATHS)
def test_rewriting_numbered_sql_without_renaming_is_rejected(
    repository: Path,
    relative: str,
) -> None:
    path = repository / relative
    path.write_bytes(path.read_bytes() + b"\nSELECT 'rewritten migration';\n")
    before = (repository / AUTHORITY_PATH).read_bytes()
    with pytest.raises(AuthorityError, match="history drift"):
        validate_authority(repository)
    assert (repository / AUTHORITY_PATH).read_bytes() == before


@pytest.mark.parametrize("relative", ["migrations", "migrations/automation"])
def test_removing_a_sql_source_is_rejected(repository: Path, relative: str) -> None:
    next((repository / relative).glob(SQL_PATTERN)).unlink()
    with pytest.raises(AuthorityError, match="history drift"):
        validate_authority(repository)


@pytest.mark.parametrize("relative", ["migrations", "migrations/automation"])
def test_contiguous_new_sql_requires_new_reviewed_pin(
    repository: Path, relative: str
) -> None:
    directory = repository / relative
    version = max(int(path.name[:4]) for path in directory.glob(SQL_PATTERN)) + 1
    (directory / f"{version:04d}_unapproved.sql").write_text(
        "SELECT 1;\n", encoding="utf-8"
    )
    with pytest.raises(AuthorityError, match="history drift"):
        validate_authority(repository)


@pytest.mark.parametrize("relative", ["migrations", "migrations/automation"])
def test_same_number_and_bytes_with_different_name_are_rejected(
    repository: Path,
    relative: str,
) -> None:
    path = sorted((repository / relative).glob(SQL_PATTERN))[0]
    path.rename(path.with_name(path.name[:4] + "_renamed.sql"))
    with pytest.raises(AuthorityError, match="history drift"):
        validate_authority(repository)


def test_moving_identical_sql_between_bundles_is_rejected(repository: Path) -> None:
    source = repository / "migrations/automation/0001_automation_v2.sql"
    source.rename(repository / "migrations/0001_automation_v2.sql")
    with pytest.raises(AuthorityError, match="history drift"):
        validate_authority(repository)


@pytest.mark.parametrize("relative", ["migrations", "migrations/automation"])
def test_removing_a_whole_sql_bundle_is_rejected(
    repository: Path, relative: str
) -> None:
    for path in (repository / relative).glob(SQL_PATTERN):
        path.unlink()
    with pytest.raises(AuthorityError, match="history drift"):
        validate_authority(repository)


def test_sql_migration_symlink_is_rejected(repository: Path) -> None:
    path = repository / SQL_PATHS[0]
    target = repository / "unapproved-source.txt"
    target.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(target)
    with pytest.raises(AuthorityError, match="regular file"):
        validate_authority(repository)


def test_sql_bundle_symlink_is_rejected(repository: Path) -> None:
    directory = repository / "migrations/automation"
    target = repository / "other-automation"
    directory.rename(target)
    directory.symlink_to(target, target_is_directory=True)
    with pytest.raises(AuthorityError, match="symlink"):
        validate_authority(repository)


def test_history_is_independent_of_absolute_checkout_path(repository: Path) -> None:
    assert migration_history(repository) == migration_history(ROOT)


def test_unexecuted_notes_are_not_part_of_sql_migration_authority(
    repository: Path,
) -> None:
    before = migration_history(repository)
    (repository / "migrations/notes.sql").write_text(
        "-- not a numbered migration\n", encoding="utf-8"
    )
    assert migration_history(repository) == before
