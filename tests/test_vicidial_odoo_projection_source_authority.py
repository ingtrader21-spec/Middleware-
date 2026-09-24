from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from app.vicidial_odoo_projection_authority import (
    load_projection_source_locks,
    validate_projection_source_locks,
)
from app.vicidial_odoo_projection_errors import ProjectionConfigurationError

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = (
    ROOT
    / "config"
    / "vicidial-odoo-projection-source-authority.v1.json"
)

EXPECTED_LOCKS = {
    "KEYCLOAK_LIFECYCLE_SOURCE_SHA": (
        "922d039b5143f3ac738e88998036355562a8dd5d"
    ),
    "ODOO_CALL_EVENT_SOURCE_SHA": (
        "9f38f87138f2914622b8ac1243c7969691ac5317"
    ),
    "VICIDIAL_EVENT_SOURCE_SHA": (
        "8007f9550a933c1cb17f21da6028dcfc41b47b0a"
    ),
}


def _document() -> dict[str, Any]:
    value = json.loads(AUTHORITY.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _write_authority(
    document: dict[str, Any],
    path: Path,
) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _merged_authority(tmp_path: Path) -> Path:
    document = copy.deepcopy(_document())
    dependencies = document["dependencies"]
    for row in dependencies.values():
        row["state_at_lock"] = "merged"
        row["base_ref"] = "refs/heads/main"
        row["merge_sha"] = row["source_sha"]
        row.pop("base_sha", None)
    return _write_authority(document, tmp_path / "merged-authority.json")


def test_projection_authority_records_candidates_without_activating_them() -> None:
    dependencies = _document()["dependencies"]

    assert dependencies["keycloak"] == {
        "repository": "appolon1908-hue/Keycloak",
        "pull_request": 86,
        "state_at_lock": "merged",
        "base_ref": "refs/heads/main",
        "source_sha": EXPECTED_LOCKS["KEYCLOAK_LIFECYCLE_SOURCE_SHA"],
        "merge_sha": EXPECTED_LOCKS["KEYCLOAK_LIFECYCLE_SOURCE_SHA"],
        "runtime_env": "KEYCLOAK_LIFECYCLE_SOURCE_SHA",
        "merge_required_before_activation": True,
    }
    assert dependencies["odoo"]["state_at_lock"] == "open_candidate"
    assert dependencies["odoo"]["source_sha"] == EXPECTED_LOCKS[
        "ODOO_CALL_EVENT_SOURCE_SHA"
    ]
    assert dependencies["vicidial"]["state_at_lock"] == "open_candidate"
    assert dependencies["vicidial"]["source_sha"] == EXPECTED_LOCKS[
        "VICIDIAL_EVENT_SOURCE_SHA"
    ]

    with pytest.raises(
        ProjectionConfigurationError,
        match="odoo dependency must be a protected-main merge",
    ):
        load_projection_source_locks()


def test_exact_protected_merge_tuple_is_accepted(tmp_path: Path) -> None:
    path = _merged_authority(tmp_path)
    assert load_projection_source_locks(path) == EXPECTED_LOCKS
    assert (
        validate_projection_source_locks(EXPECTED_LOCKS, path=path)
        == EXPECTED_LOCKS
    )


@pytest.mark.parametrize("runtime_env", sorted(EXPECTED_LOCKS))
def test_missing_or_changed_projection_source_fails_closed(
    tmp_path: Path,
    runtime_env: str,
) -> None:
    path = _merged_authority(tmp_path)
    missing = dict(EXPECTED_LOCKS)
    missing.pop(runtime_env)
    with pytest.raises(
        ProjectionConfigurationError,
        match=runtime_env,
    ):
        validate_projection_source_locks(missing, path=path)

    changed = dict(EXPECTED_LOCKS)
    changed[runtime_env] = "0" * 40
    with pytest.raises(
        ProjectionConfigurationError,
        match=runtime_env,
    ):
        validate_projection_source_locks(changed, path=path)


def test_merged_dependency_must_identify_protected_main(tmp_path: Path) -> None:
    document = copy.deepcopy(_document())
    dependencies = document["dependencies"]
    for row in dependencies.values():
        row["state_at_lock"] = "merged"
        row["base_ref"] = "refs/heads/main"
        row["merge_sha"] = row["source_sha"]
        row.pop("base_sha", None)
    dependencies["odoo"]["base_ref"] = "refs/heads/release-candidate"
    path = _write_authority(document, tmp_path / "wrong-ref.json")

    with pytest.raises(
        ProjectionConfigurationError,
        match="protected refs/heads/main",
    ):
        load_projection_source_locks(path)


def test_merged_dependency_must_pin_its_merge_sha(tmp_path: Path) -> None:
    document = copy.deepcopy(_document())
    dependencies = document["dependencies"]
    for row in dependencies.values():
        row["state_at_lock"] = "merged"
        row["base_ref"] = "refs/heads/main"
        row["merge_sha"] = row["source_sha"]
        row.pop("base_sha", None)
    dependencies["vicidial"]["merge_sha"] = "0" * 40
    path = _write_authority(document, tmp_path / "wrong-merge.json")

    with pytest.raises(
        ProjectionConfigurationError,
        match="immutable merge SHA",
    ):
        load_projection_source_locks(path)


def test_authority_cannot_grant_runtime_or_external_effects(
    tmp_path: Path,
) -> None:
    document = copy.deepcopy(_document())
    boundary = document["activation_boundary"]
    assert boundary == {
        "source_merge_authorized_by_this_file": False,
        "runtime_activation_authorized_by_this_file": False,
        "production_dialing_authorized_by_this_file": False,
        "external_effects_authorized_by_this_file": False,
        "requires_exact_runtime_source_readback": True,
        "requires_protected_dependency_merges": True,
        "calls_placed_expected": 0,
    }

    boundary["runtime_activation_authorized_by_this_file"] = True
    unsafe = _write_authority(document, tmp_path / "unsafe-authority.json")
    with pytest.raises(
        ProjectionConfigurationError,
        match="grants an effect",
    ):
        load_projection_source_locks(unsafe)
