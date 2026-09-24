#!/usr/bin/env python3
"""Grant and verify one exact independent release reviewer on a fixed repository set."""

from __future__ import annotations

from typing import TYPE_CHECKING

import argparse
import datetime as dt
import json
import os
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Mapping

if TYPE_CHECKING:
    from scripts.portfolio_ruleset.common import RolloutError
else:
    from portfolio_ruleset.common import RolloutError
if TYPE_CHECKING:
    from scripts.portfolio_ruleset.github_api import GitHubApi
else:
    from portfolio_ruleset.github_api import GitHubApi

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "portfolio-main-release-authorities.v1.json"
EVIDENCE_DIR = ROOT / "artifacts" / "portfolio-release-reviewer-access"
TOKEN_ENV = "CODESTRA_REPOSITORY_ADMIN_TOKEN"
CONFIRMATION = "APPLY_MAIN_RELEASE_AUTHORITY_V1"
EXPECTED_REVIEWER = {
    "login": "kazan555",
    "user_id": 77101516,
    "permission": "push",
}
EXPECTED_REPOSITORIES = {
    "appolon1908-hue/codestra": 1319808791,
    "appolon1908-hue/backend2": 1319903950,
    "appolon1908-hue/Telnexa-web": 1346958528,
    "appolon1908-hue/scrapper": 1329513537,
    "appolon1908-hue/Breero.com": 1331354808,
    "appolon1908-hue/Moneybee-Backend": 1343760409,
}
ACCEPTED_PERMISSIONS = {"push", "maintain", "admin"}
ACCEPTED_ROLES = {"write", "maintain", "admin"}


class ReviewerAccessError(RuntimeError):
    """The reviewer authority or observed access is not acceptable."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReviewerAccessError(message)


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReviewerAccessError(f"cannot load reviewer authority: {path}") from exc
    require(isinstance(value, dict), "reviewer authority must be an object")
    return value


def validate_config(config: Mapping[str, Any]) -> list[dict[str, Any]]:
    require(
        config.get("authority_id") == "codestra.portfolio-main-release-authorities.v1",
        "authority ID drift",
    )
    reviewer = config.get("reviewer")
    if not isinstance(reviewer, Mapping):
        raise ReviewerAccessError("reviewer authority missing")
    require(dict(reviewer) == EXPECTED_REVIEWER, "reviewer authority drift")
    require(config.get("required_approvals") == 1, "exactly one approval is required")
    repositories = config.get("repositories")
    if not isinstance(repositories, list):
        raise ReviewerAccessError("repositories must be a list")
    require(len(repositories) == len(EXPECTED_REPOSITORIES), "repository count drift")
    normalized: list[dict[str, Any]] = []
    observed: set[str] = set()
    for raw in repositories:
        require(isinstance(raw, dict), "repository record must be an object")
        name = raw.get("repository")
        require(isinstance(name, str) and name in EXPECTED_REPOSITORIES, "unknown repository")
        require(name not in observed, f"duplicate repository: {name}")
        observed.add(name)
        require(raw.get("repository_id") == EXPECTED_REPOSITORIES[name], f"{name}: ID drift")
        require(raw.get("default_branch") == "main", f"{name}: default branch drift")
        normalized.append(dict(raw))
    require(observed == set(EXPECTED_REPOSITORIES), "repository coverage drift")
    return sorted(normalized, key=lambda item: str(item["repository"]).casefold())


def quote(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def repo_path(value: str) -> str:
    return urllib.parse.quote(value, safe="/")


def permission_state(payload: Any) -> tuple[str, str]:
    require(isinstance(payload, Mapping), "collaborator permission response is invalid")
    permission = payload.get("permission")
    role = payload.get("role_name")
    require(isinstance(permission, str), "collaborator permission is missing")
    require(isinstance(role, str), "collaborator role is missing")
    return permission, role


def write_evidence(document: Mapping[str, Any]) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / "result.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lines = [
        "## Portfolio release reviewer access",
        "",
        f"- Result: `{document.get('result')}`",
        f"- Mode: `{document.get('mode')}`",
        f"- Source SHA: `{document.get('source_sha')}`",
        f"- Reviewer: `{document.get('reviewer')}`",
        "- Requested permission: `push`",
        "- Repository set: `fixed by stable ID`",
        "- Runtime contacted: `false`",
        "- Production changed: `false`",
        "",
        "| Repository | Action | Observed permission | Result |",
        "|---|---|---|---|",
    ]
    for row in document.get("repositories", []):
        lines.append(
            f"| `{row.get('repository')}` | `{row.get('action')}` | "
            f"`{row.get('permission', '')}` | `{row.get('result')}` |"
        )
    (EVIDENCE_DIR / "result.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def execute(mode: str, confirmation: str) -> dict[str, Any]:
    config = load_config()
    repositories = validate_config(config)
    reviewer = dict(config["reviewer"])
    if mode == "validate":
        return {
            "schema_version": "1.0",
            "mode": mode,
            "source_sha": os.environ.get("GITHUB_SHA", "local"),
            "reviewer": reviewer["login"],
            "result": "PASS",
            "runtime_contacted": False,
            "production_changed": False,
            "repositories": [
                {
                    "repository": row["repository"],
                    "action": "policy-validated",
                    "permission": reviewer["permission"],
                    "result": "PASS",
                }
                for row in repositories
            ],
        }

    require(mode in {"apply", "verify"}, "unsupported mode")
    if mode == "apply":
        require(confirmation == CONFIRMATION, "exact apply confirmation required")
    token = os.environ.get(TOKEN_ENV, "")
    require(bool(token), f"{TOKEN_ENV} is required")
    api = GitHubApi(token)

    reviewer_payload = api.request("GET", f"/users/{quote(reviewer['login'])}").payload
    require(isinstance(reviewer_payload, Mapping), "reviewer identity response is invalid")
    require(reviewer_payload.get("login") == reviewer["login"], "reviewer login drift")
    require(reviewer_payload.get("id") == reviewer["user_id"], "reviewer stable ID drift")

    for repository in repositories:
        full_name = str(repository["repository"])
        metadata = api.request("GET", f"/repos/{repo_path(full_name)}").payload
        require(isinstance(metadata, Mapping), f"{full_name}: repository metadata invalid")
        require(metadata.get("id") == repository["repository_id"], f"{full_name}: ID drift")
        require(metadata.get("default_branch") == "main", f"{full_name}: default branch drift")
        require(metadata.get("archived") is False, f"{full_name}: repository is archived")
        require(metadata.get("disabled") is False, f"{full_name}: repository is disabled")
        permissions = metadata.get("permissions")
        require(
            isinstance(permissions, Mapping) and permissions.get("admin") is True,
            f"{full_name}: token lacks repository administration",
        )

    results: list[dict[str, Any]] = []
    pending_invitation = False
    for repository in repositories:
        full_name = str(repository["repository"])
        path = f"/repos/{repo_path(full_name)}/collaborators/{quote(reviewer['login'])}"
        action = "verify"
        if mode == "apply":
            response = api.request(
                "PUT",
                path,
                payload={"permission": reviewer["permission"]},
                expected=(201, 204),
            )
            if response.status == 201:
                action = "invitation-created"
                pending_invitation = True
                results.append(
                    {
                        "repository": full_name,
                        "action": action,
                        "permission": "pending-acceptance",
                        "result": "BLOCKED",
                    }
                )
                continue
            action = "configured"

        payload = api.request("GET", f"{path}/permission").payload
        permission, role = permission_state(payload)
        require(
            permission in ACCEPTED_PERMISSIONS or role in ACCEPTED_ROLES,
            f"{full_name}: reviewer lacks write-equivalent access",
        )
        results.append(
            {
                "repository": full_name,
                "action": action,
                "permission": permission,
                "role": role,
                "result": "PASS",
            }
        )

    result = "BLOCKED_REVIEWER_INVITATION_PENDING" if pending_invitation else "PASS"
    return {
        "schema_version": "1.0",
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "mode": mode,
        "source_sha": os.environ.get("GITHUB_SHA", "local"),
        "actor": os.environ.get("GITHUB_ACTOR", "local"),
        "reviewer": reviewer["login"],
        "reviewer_user_id": reviewer["user_id"],
        "result": result,
        "runtime_contacted": False,
        "production_changed": False,
        "repositories": results,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("validate", "apply", "verify"), default="validate")
    parser.add_argument("--confirm", default="")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        document = execute(args.mode, args.confirm)
        write_evidence(document)
        print(
            "PORTFOLIO_RELEASE_REVIEWER_ACCESS="
            f"{document['result']} mode={args.mode} reviewer={document['reviewer']}"
        )
        return 0 if document["result"] == "PASS" else 1
    except (ReviewerAccessError, RolloutError) as exc:
        document = {
            "schema_version": "1.0",
            "mode": args.mode,
            "source_sha": os.environ.get("GITHUB_SHA", "local"),
            "reviewer": EXPECTED_REVIEWER["login"],
            "result": "FAIL",
            "runtime_contacted": False,
            "production_changed": False,
            "error": str(exc),
            "repositories": [],
        }
        write_evidence(document)
        print(f"PORTFOLIO_RELEASE_REVIEWER_ACCESS=FAIL reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
