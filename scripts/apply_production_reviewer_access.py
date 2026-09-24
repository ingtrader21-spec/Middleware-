#!/usr/bin/env python3
"""Strict production reviewer-access authority.

The existing rollout engine is preserved in a base module. This wrapper adds
stable repository identity, exact write-level permission, and post-update
read-back without broad changes to the already reviewed invitation workflow.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Mapping, TYPE_CHECKING

ROOT = Path(__file__).resolve().parents[1]
BASE_SCRIPT = ROOT / "scripts" / "apply_production_reviewer_access_base.py"

if TYPE_CHECKING:
    from scripts import apply_production_reviewer_access_base as BASE
else:
    spec = importlib.util.spec_from_file_location(
        "production_reviewer_access_base",
        BASE_SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load production reviewer-access base")
    BASE = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(BASE)

EXPECTED_REPOSITORIES = {
    "appolon1908-hue/codestra-production-platform": 1314230781,
    "ingtrader21-spec/Middleware-": 1347559071,
    "appolon1908-hue/Websocket-": 1357322123,
    "appolon1908-hue/Odoo": 1347522940,
    "appolon1908-hue/Caddy": 1350228103,
    "appolon1908-hue/Kong": 1347790742,
    "appolon1908-hue/Keycloak": 1347523366,
    "appolon1908-hue/SDK-repository": 1349042079,
    "appolon1908-hue/Vicidialer-Codestra": 1347744324,
    "appolon1908-hue/N8N": 1347560645,
    "appolon1908-hue/klyrow.com": 1334863061,
    "appolon1908-hue/social.codestra.co": 1348783113,
    "appolon1908-hue/Codestra-AI": 1351354401,
    "appolon1908-hue/Codestra-Marketing-": 1351352422,
    "appolon1908-hue/codestra-provisioning-service": 1339900477,
    "appolon1908-hue/Codestra-Prometheus": 1350767800,
    "appolon1908-hue/telnexa": 1334764612,
    "appolon1908-hue/kyqra-crawler": 1334792686,
    "appolon1908-hue/beyvra-backend": 1319831182,
}
EXPECTED_TOP_LEVEL_FIELDS = {
    "schema_version",
    "authority_id",
    "owner",
    "reviewer",
    "repositories",
}


def _reject_duplicate_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def load_config(path: Path = BASE.CONFIG_PATH) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise BASE.AccessError(
            f"cannot load reviewer authority: {path}"
        ) from exc
    BASE.require(
        isinstance(value, dict),
        "reviewer authority must be an object",
    )
    return value


def validate_config(config: Mapping[str, Any]) -> list[str]:
    BASE.require(
        set(config) == EXPECTED_TOP_LEVEL_FIELDS,
        "reviewer authority field-set drift",
    )
    BASE.require(
        config.get("schema_version") == "1.0",
        "unsupported reviewer schema",
    )
    BASE.require(
        config.get("authority_id") == BASE.AUTHORITY_ID,
        "reviewer authority ID drift",
    )
    BASE.require(
        config.get("owner") == BASE.EXPECTED_OWNER,
        "reviewer owner drift",
    )
    BASE.require(
        config.get("reviewer") == BASE.EXPECTED_REVIEWER,
        "reviewer identity drift",
    )

    rows = config.get("repositories")
    if not isinstance(rows, list):
        raise BASE.AccessError("repositories must be a list")
    BASE.require(
        len(rows) == len(EXPECTED_REPOSITORIES),
        "fixed repository coverage drift",
    )
    observed_names: set[str] = set()
    observed_ids: set[int] = set()
    for row in rows:
        BASE.require(
            isinstance(row, Mapping),
            "repository authority row must be an object",
        )
        BASE.require(
            set(row) == {"repository", "repository_id"},
            "repository authority row field-set drift",
        )
        name = row.get("repository")
        repository_id = row.get("repository_id")
        BASE.require(
            isinstance(name, str) and name in EXPECTED_REPOSITORIES,
            "unknown repository",
        )
        BASE.require(name not in observed_names, f"duplicate repository: {name}")
        BASE.require(
            isinstance(repository_id, int)
            and not isinstance(repository_id, bool)
            and repository_id == EXPECTED_REPOSITORIES[name],
            f"{name}: stable repository ID drift",
        )
        BASE.require(
            repository_id not in observed_ids,
            f"duplicate repository ID: {repository_id}",
        )
        BASE.require(
            name.startswith(f"{BASE.expected_repository_owner(name)}/"),
            "foreign owner forbidden",
        )
        observed_names.add(name)
        observed_ids.add(repository_id)

    BASE.require(
        observed_names == set(EXPECTED_REPOSITORIES),
        "fixed repository coverage drift",
    )
    return sorted(observed_names, key=str.casefold)


def permission_is_write(value: Any) -> bool:
    """Accept only GitHub's exact read-back value for write access."""

    return isinstance(value, Mapping) and value.get("permission") == "write"


def _metadata_identity(path: str) -> tuple[str, int] | None:
    for repository, repository_id in EXPECTED_REPOSITORIES.items():
        encoded = urllib.parse.quote(repository, safe="/")
        if path == f"/repos/{encoded}":
            return repository, repository_id
    return None


def _collaborator_repository(path: str) -> str | None:
    suffix = f"/collaborators/{BASE.EXPECTED_REVIEWER['login']}"
    for repository in EXPECTED_REPOSITORIES:
        encoded = urllib.parse.quote(repository, safe="/")
        if path == f"/repos/{encoded}{suffix}":
            return repository
    return None


class GitHubApi(BASE.GitHubApi):
    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> tuple[int, Any]:
        status, value = super().request(method, path, payload)

        identity = _metadata_identity(path)
        if method == "GET" and identity is not None:
            repository, repository_id = identity
            BASE.require(
                status == 200 and isinstance(value, Mapping),
                f"{repository}: repository identity unavailable",
            )
            BASE.require(
                value.get("id") == repository_id,
                f"{repository}: stable repository ID drift",
            )
            BASE.require(
                value.get("full_name") == repository,
                f"{repository}: full-name readback drift",
            )

        collaborator_repository = _collaborator_repository(path)
        if method == "PUT" and collaborator_repository is not None and status == 204:
            permission_status, permission = super().request(
                "GET",
                f"{path}/permission",
            )
            BASE.require(
                permission_status == 200 and permission_is_write(permission),
                f"{collaborator_repository}: collaborator permission did not read back as exact write",
            )

        return status, value


BASE.load_config = load_config
BASE.validate_config = validate_config
BASE.permission_is_write = permission_is_write
if not TYPE_CHECKING:
    BASE.GitHubApi = GitHubApi
BASE.EXPECTED_REPOSITORIES = set(EXPECTED_REPOSITORIES)

execute = BASE.execute
write_evidence = BASE.write_evidence


def main(argv: list[str] | None = None) -> int:
    return BASE.main(list(sys.argv[1:] if argv is None else argv))


def __getattr__(name: str) -> Any:
    return getattr(BASE, name)


if __name__ == "__main__":
    raise SystemExit(main())
