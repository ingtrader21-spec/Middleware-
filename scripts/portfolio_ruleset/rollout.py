from __future__ import annotations

from typing import TYPE_CHECKING

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

if TYPE_CHECKING:
    from scripts.portfolio_ruleset.common import RolloutError, normalize_ruleset_payload, require
else:
    from portfolio_ruleset.common import RolloutError, normalize_ruleset_payload, require
if TYPE_CHECKING:
    from scripts.portfolio_ruleset.github_api import GitHubApi
else:
    from portfolio_ruleset.github_api import GitHubApi


def select_active_repositories(
    portfolio: Mapping[str, Any], observed: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for repository in observed:
        if portfolio.get("skip_archived", True) and repository.get("archived") is True:
            continue
        if portfolio.get("skip_disabled", True) and repository.get("disabled") is True:
            continue
        require(
            isinstance(repository.get("full_name"), str)
            and isinstance(repository.get("name"), str),
            "repository identity is invalid",
        )
        selected.append(repository)
    selected_names = {str(item["name"]) for item in selected}
    missing = sorted(
        set(portfolio["known_active_repositories"]) - selected_names,
        key=str.casefold,
    )
    require(
        not missing,
        "administrative token cannot see every known active repository: "
        + ", ".join(missing),
    )
    return sorted(selected, key=lambda item: str(item["full_name"]).casefold())


def find_named_ruleset(
    rulesets: list[dict[str, Any]], name: str, full_name: str
) -> dict[str, Any] | None:
    matches = [
        item
        for item in rulesets
        if item.get("name") == name
        and item.get("source_type", "Repository") == "Repository"
    ]
    require(len(matches) <= 1, f"{full_name}: duplicate named rulesets")
    return matches[0] if matches else None


def verify_repository(
    api: GitHubApi, full_name: str, desired: Mapping[str, Any]
) -> tuple[int, dict[str, Any]]:
    match = find_named_ruleset(api.list_rulesets(full_name), str(desired["name"]), full_name)
    if match is None:
        raise RolloutError(f"{full_name}: expected ruleset is missing")
    ruleset_id = match.get("id")
    if not isinstance(ruleset_id, int):
        raise RolloutError(f"{full_name}: ruleset ID is invalid")
    observed = normalize_ruleset_payload(api.get_ruleset(full_name, ruleset_id))
    expected = normalize_ruleset_payload(desired)
    require(observed == expected, f"{full_name}: live ruleset does not match policy")
    return ruleset_id, observed


def write_evidence(
    evidence_dir: Path, document: Mapping[str, Any]
) -> tuple[Path, Path]:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    json_path = evidence_dir / "portfolio-production-ruleset-result.json"
    markdown_path = evidence_dir / "portfolio-production-ruleset-result.md"
    json_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    lines = [
        "## Portfolio production-branch ruleset rollout",
        "",
        f"- Result: `{document.get('overall_result')}`",
        f"- Mode: `{document.get('mode')}`",
        f"- Owner: `{document.get('owner')}`",
        f"- Source SHA: `{document.get('source_sha')}`",
        f"- Ruleset: `{document.get('ruleset_name')}`",
        "- Target: `refs/heads/production`",
        f"- Repositories discovered: `{document.get('repositories_discovered')}`",
        f"- Repositories selected: `{document.get('repositories_selected')}`",
        f"- Repositories verified: `{document.get('repositories_verified')}`",
        f"- Failures: `{document.get('failure_count')}`",
        "",
        "| Repository | Action | Result | Ruleset ID |",
        "|---|---:|---:|---:|",
    ]
    for result in document.get("results", []):
        lines.append(
            f"| `{result.get('repository')}` | `{result.get('action', 'none')}` | "
            f"`{result.get('result')}` | `{result.get('ruleset_id', '')}` |"
        )
    if document.get("errors"):
        lines.extend(["", "### Errors", ""])
        lines.extend(f"- `{error}`" for error in document["errors"])
    markdown_path.write_text("\n".join(lines) + "\n")
    return json_path, markdown_path


def execute(
    *,
    mode: str,
    token: str,
    confirmation: str,
    evidence_dir: Path,
    portfolio: Mapping[str, Any],
    desired: Mapping[str, Any],
) -> dict[str, Any]:
    if mode == "apply":
        if TYPE_CHECKING:
            from scripts.portfolio_ruleset.common import CONFIRMATION
        else:
            from portfolio_ruleset.common import CONFIRMATION

        require(confirmation == CONFIRMATION, "exact apply confirmation is required")
    api = GitHubApi(token)
    owner = str(portfolio["owner"])
    observed = api.list_owned_repositories(owner)
    selected = select_active_repositories(portfolio, observed)
    document: dict[str, Any] = {
        "schema_version": "1.0",
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "mode": mode,
        "owner": owner,
        "source_sha": os.environ.get("GITHUB_SHA", "local"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "actor": os.environ.get("GITHUB_ACTOR", "local"),
        "ruleset_name": desired["name"],
        "ruleset_sha256": hashlib.sha256(
            json.dumps(desired, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "repositories_discovered": len(observed),
        "repositories_selected": len(selected),
        "repositories_verified": 0,
        "failure_count": 0,
        "overall_result": "IN_PROGRESS",
        "results": [],
        "errors": [],
    }

    # Every repository must pass administration-read preflight before any mutation.
    preflight: dict[str, dict[str, Any] | None] = {}
    for repository in selected:
        full_name = str(repository["full_name"])
        existing = find_named_ruleset(
            api.list_rulesets(full_name), str(desired["name"]), full_name
        )
        preflight[full_name] = existing
    document["preflight"] = [
        {
            "repository": full_name,
            "existing_ruleset_id": existing.get("id") if existing else None,
            "result": "PASS",
        }
        for full_name, existing in preflight.items()
    ]

    for repository in selected:
        full_name = str(repository["full_name"])
        result: dict[str, Any] = {
            "repository": full_name,
            "visibility": repository.get("visibility"),
            "default_branch": repository.get("default_branch"),
        }
        try:
            if mode == "apply":
                _, result["action"] = api.upsert_ruleset(
                    full_name, desired, preflight[full_name]
                )
            else:
                result["action"] = (
                    "already-present" if preflight[full_name] else "would-create"
                )
            if mode in {"apply", "verify"}:
                ruleset_id, _ = verify_repository(api, full_name, desired)
                result["ruleset_id"] = ruleset_id
                document["repositories_verified"] += 1
            else:
                result["ruleset_id"] = None
            result["result"] = "PASS"
        except RolloutError as exc:
            result.update(result="FAIL", error=str(exc))
            document["failure_count"] += 1
            document["errors"].append(str(exc))
        document["results"].append(result)
    document["overall_result"] = "PASS" if document["failure_count"] == 0 else "FAIL"
    write_evidence(evidence_dir, document)
    return document
