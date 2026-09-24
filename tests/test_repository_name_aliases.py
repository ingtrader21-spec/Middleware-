from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALIASES = ROOT / "config" / "repository-name-aliases.v1.json"
AUTHORITIES = ROOT / "config" / "repository-authorities.v1.json"
EXPECTED = {
    1221155447: (
        "appolon1908-hue/Frontend-Resturant-",
        "appolon1908-hue/restaurant-frontend",
    ),
    1343761049: (
        "appolon1908-hue/transportaion-Frontend",
        "appolon1908-hue/freight-platform-frontend",
    ),
    1343962199: (
        "appolon1908-hue/LARIM-A-Fornt-end",
        "appolon1908-hue/LARIM-A-Frontend",
    ),
    1351353723: (
        "appolon1908-hue/Codesrea-Social-",
        "appolon1908-hue/Codestra-Social-Control-Plane",
    ),
    1350724356: (
        "appolon1908-hue/documentaions",
        "appolon1908-hue/Codestra-Documentation",
    ),
    1350724865: (
        "appolon1908-hue/Infustruction-repo",
        "appolon1908-hue/Codestra-Infrastructure",
    ),
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_repository_name_aliases_are_exact_and_pre_cutover() -> None:
    aliases = load(ALIASES)
    assert aliases["schema_version"] == "1.0"
    assert aliases["status"] == "PREPARED_NOT_RENAMED"
    assert aliases["identity_key"] == "github_repository_id"
    assert aliases["historical_evidence_immutable"] is True

    mappings = aliases["mappings"]
    assert len(mappings) == len(EXPECTED)

    repository_ids = [item["github_repository_id"] for item in mappings]
    assert len(repository_ids) == len(set(repository_ids)) == len(EXPECTED)

    current_repositories = [item["current_repository"] for item in mappings]
    target_repositories = [item["target_repository_after_cutover"] for item in mappings]
    assert len(current_repositories) == len(set(current_repositories)) == len(EXPECTED)
    assert len(target_repositories) == len(set(target_repositories)) == len(EXPECTED)

    actual = {
        item["github_repository_id"]: (
            item["current_repository"],
            item["target_repository_after_cutover"],
        )
        for item in mappings
    }
    assert actual == EXPECTED
    assert all(item["status"] == "PREPARED_NOT_RENAMED" for item in mappings)


def test_authority_registry_uses_current_names_and_records_targets() -> None:
    aliases = load(ALIASES)
    authorities = load(AUTHORITIES)
    assert authorities["policy"]["repository_identity_key"] == "github_repository_id"
    assert authorities["policy"]["repository_name_migration_manifest"] == (
        "config/repository-name-aliases.v1.json"
    )

    by_component = {item["component"]: item for item in authorities["authorities"]}
    expected_components = {
        1221155447: "restaurant-frontend",
        1343761049: "freight-platform-frontend",
        1343962199: "larim-a-frontend",
        1351353723: "social-control-plane",
        1350724356: "platform-documentation",
        1350724865: "platform-infrastructure",
    }

    for mapping in aliases["mappings"]:
        repository_id = mapping["github_repository_id"]
        authority = by_component[expected_components[repository_id]]
        assert authority["github_repository_id"] == repository_id
        assert authority["principal_repository"] == mapping["current_repository"]
        assert authority["target_repository_after_cutover"] == mapping[
            "target_repository_after_cutover"
        ]
        assert authority["rename_status"] == "PREPARED_NOT_RENAMED"


def test_social_runtime_and_control_plane_remain_separate() -> None:
    authorities = load(AUTHORITIES)
    by_component = {item["component"]: item for item in authorities["authorities"]}
    assert by_component["social"]["principal_repository"] == (
        "appolon1908-hue/social.codestra.co"
    )
    assert by_component["social-control-plane"]["principal_repository"] == (
        "appolon1908-hue/Codesrea-Social-"
    )
    assert by_component["social"]["principal_repository"] != by_component[
        "social-control-plane"
    ]["principal_repository"]
