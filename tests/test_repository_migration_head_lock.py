import json
from pathlib import Path

from scripts import validate_repository
from scripts.production_migration_authority import migration_history, HISTORY_KEY


def _write_migration(path: Path, revision: str, down_revision: str | None) -> None:
    path.write_text(
        f"revision = {revision!r}\ndown_revision = {down_revision!r}\n",
        encoding="utf-8",
    )


def _repository(tmp_path: Path, required_head: str = "0056_required") -> Path:
    (tmp_path / "config").mkdir()
    (tmp_path / "migrations/versions").mkdir(parents=True)
    (tmp_path / "config/middleware-forward-release-authority.v1.json").write_text(
        json.dumps({"artifactAuthority": {"requiredSchemaHead": required_head}}),
        encoding="utf-8",
    )
    _write_migration(tmp_path / "migrations/versions/0055.py", "0055_parent", None)
    _write_migration(
        tmp_path / "migrations/versions/0056.py", required_head, "0055_parent"
    )
    authority = tmp_path / "config/middleware-forward-release-authority.v1.json"
    payload = json.loads(authority.read_text())
    payload["artifactAuthority"][HISTORY_KEY] = migration_history(tmp_path)[1]
    authority.write_text(json.dumps(payload))
    return tmp_path


def test_current_repository_matches_production_migration_authority() -> None:
    errors: list[str] = []
    validate_repository.validate_production_migration_head(errors)
    assert errors == []


def test_rejects_a_new_head_without_platform_tuple_review(
    tmp_path: Path, monkeypatch
) -> None:
    root = _repository(tmp_path)
    _write_migration(
        root / "migrations/versions/0057.py", "0057_unapproved", "0056_required"
    )
    monkeypatch.setattr(validate_repository, "ROOT", root)

    errors: list[str] = []
    validate_repository.validate_production_migration_head(errors)

    assert errors == [
        "production migration head drift: authority requires '0056_required', "
        "repository heads are ['0057_unapproved']; update the platform tuple through "
        "separate protected review before adding a head"
    ]


def test_rejects_multiple_heads(tmp_path: Path, monkeypatch) -> None:
    root = _repository(tmp_path)
    _write_migration(root / "migrations/versions/branch.py", "branch_head", "0055_parent")
    monkeypatch.setattr(validate_repository, "ROOT", root)

    errors: list[str] = []
    validate_repository.validate_production_migration_head(errors)

    assert "repository heads are ['0056_required', 'branch_head']" in errors[0]


def test_inserting_history_before_unchanged_head_is_rejected(tmp_path, monkeypatch):
    root = _repository(tmp_path)
    _write_migration(root / "migrations/versions/inserted.py", "inserted", "0055_parent")
    _write_migration(root / "migrations/versions/0056.py", "0056_required", "inserted")
    monkeypatch.setattr(validate_repository, "ROOT", root)
    errors = []
    validate_repository.validate_production_migration_head(errors)
    assert "history drift" in errors[0]


def test_rewriting_existing_migration_body_is_rejected(tmp_path, monkeypatch):
    root = _repository(tmp_path)
    path = root / "migrations/versions/0055.py"
    path.write_text(path.read_text() + "\ndef upgrade():\n    raise RuntimeError('changed')\n")
    monkeypatch.setattr(validate_repository, "ROOT", root)
    errors = []
    validate_repository.validate_production_migration_head(errors)
    assert "history drift" in errors[0]


def test_missing_history_pin_is_rejected(tmp_path, monkeypatch):
    root = _repository(tmp_path)
    path = root / "config/middleware-forward-release-authority.v1.json"
    payload = json.loads(path.read_text())
    del payload["artifactAuthority"][HISTORY_KEY]
    path.write_text(json.dumps(payload))
    monkeypatch.setattr(validate_repository, "ROOT", root)
    errors = []
    validate_repository.validate_production_migration_head(errors)
    assert "digest is missing" in errors[0]


def test_cycle_is_rejected_even_with_an_unchanged_terminal_head(tmp_path, monkeypatch):
    root = _repository(tmp_path)
    _write_migration(root / "migrations/versions/a.py", "cycle_a", "cycle_b")
    _write_migration(root / "migrations/versions/b.py", "cycle_b", "cycle_a")
    monkeypatch.setattr(validate_repository, "ROOT", root)
    errors = []
    validate_repository.validate_production_migration_head(errors)
    assert "cycle" in errors[0]


def test_missing_source_is_not_silently_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(validate_repository, "ROOT", tmp_path)
    errors = []
    validate_repository.validate_production_migration_head(errors)
    assert errors
