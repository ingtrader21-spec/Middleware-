#!/usr/bin/env python3
"""Apply and verify fixed least-privilege reviewer access for release repositories."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "production-reviewer-access.v1.json"
EVIDENCE_DIR = ROOT / "artifacts" / "production-reviewer-access"
TOKEN_ENV = "CODESTRA_REPOSITORY_ADMIN_TOKEN"
CONFIRMATION = "APPLY_PRODUCTION_REVIEWER_ACCESS_V1"
AUTHORITY_ID = "codestra.production-reviewer-access.v1"
EXPECTED_OWNER = "appolon1908-hue"
# Repositories transferred out of the authority owner's account keep their
# reviewer grant under the new owner, but only the exact names listed here;
# every other repository must still belong to EXPECTED_OWNER.
TRANSFERRED_REPOSITORY_OWNERS = {
    "ingtrader21-spec/Middleware-": "ingtrader21-spec",
}


def expected_repository_owner(repository: str) -> str:
    return TRANSFERRED_REPOSITORY_OWNERS.get(repository, EXPECTED_OWNER)
EXPECTED_REVIEWER = {
    "login": "kazan555",
    "user_id": 77101516,
    "permission": "push",
    "admin": False,
}
EXPECTED_REPOSITORIES = {
    "appolon1908-hue/codestra-production-platform",
    "ingtrader21-spec/Middleware-",
    "appolon1908-hue/Websocket-",
    "appolon1908-hue/Odoo",
    "appolon1908-hue/Caddy",
    "appolon1908-hue/Kong",
    "appolon1908-hue/Keycloak",
    "appolon1908-hue/SDK-repository",
    "appolon1908-hue/Vicidialer-Codestra",
    "appolon1908-hue/N8N",
    "appolon1908-hue/klyrow.com",
    "appolon1908-hue/social.codestra.co",
    "appolon1908-hue/Codestra-AI",
    "appolon1908-hue/Codestra-Marketing-",
    "appolon1908-hue/codestra-provisioning-service",
    "appolon1908-hue/Codestra-Prometheus",
    "appolon1908-hue/telnexa",
    "appolon1908-hue/kyqra-crawler",
    "appolon1908-hue/beyvra-backend",
}


class AccessError(RuntimeError):
    """Committed reviewer authority or observed GitHub state is invalid."""


class PendingInvitation(AccessError):
    """At least one exact reviewer invitation still needs acceptance."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AccessError(message)


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AccessError(f"cannot load reviewer authority: {path}") from exc
    require(isinstance(value, dict), "reviewer authority must be an object")
    return value


def validate_config(config: Mapping[str, Any]) -> list[str]:
    require(config.get("schema_version") == "1.0", "unsupported reviewer schema")
    require(config.get("authority_id") == AUTHORITY_ID, "reviewer authority ID drift")
    require(config.get("owner") == EXPECTED_OWNER, "reviewer owner drift")
    require(config.get("reviewer") == EXPECTED_REVIEWER, "reviewer identity drift")
    rows = config.get("repositories")
    if not isinstance(rows, list):
        raise AccessError("repositories must be a list")
    repositories: list[str] = []
    for row in rows:
        if not isinstance(row, str) or not row:
            raise AccessError("invalid repository name")
        repositories.append(row)
    require(len(repositories) == len(set(repositories)), "duplicate repository")
    require(set(repositories) == EXPECTED_REPOSITORIES, "fixed repository coverage drift")
    require(
        all(row.startswith(f"{expected_repository_owner(row)}/") for row in repositories),
        "foreign owner forbidden",
    )
    return sorted(repositories, key=str.casefold)


class FailClosedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never forward an administration bearer token through a redirect."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


NO_REDIRECT_OPENER = urllib.request.build_opener(FailClosedRedirectHandler())


class GitHubApi:
    def __init__(self, token: str) -> None:
        self.token = token
        self.base = "https://api.github.com"

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> tuple[int, Any]:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        request = urllib.request.Request(
            self.base + path,
            data=body,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "codestra-production-reviewer-access-v1",
            },
        )
        try:
            with NO_REDIRECT_OPENER.open(request, timeout=30) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            if exc.code == 404:
                return 404, None
            raise AccessError(
                f"GitHub API {method} {path} failed with HTTP {exc.code}: {raw[:500]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise AccessError(f"GitHub API {method} {path} unavailable") from exc


def repo_path(repository: str) -> str:
    return urllib.parse.quote(repository, safe="/")


def permission_is_write(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    permission = value.get("permission")
    return permission in {"admin", "maintain", "write", "push"}


def write_evidence(document: Mapping[str, Any]) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / "result.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "## Production reviewer access",
        "",
        f"- Result: `{document.get('result')}`",
        f"- Mode: `{document.get('mode')}`",
        f"- Source SHA: `{document.get('source_sha')}`",
        "- Reviewer: `kazan555` (`push`, non-admin)",
        "- Runtime contacted: `NO`",
        "- Production changed: `NO`",
        "",
        "| Repository | State | Result |",
        "|---|---|---|",
    ]
    for row in document.get("repositories", []):
        lines.append(
            f"| `{row.get('repository')}` | `{row.get('state')}` | `{row.get('result')}` |"
        )
    (EVIDENCE_DIR / "result.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def execute(mode: str, confirmation: str) -> dict[str, Any]:
    repositories = validate_config(load_config())
    base = {
        "schema_version": "1.0",
        "mode": mode,
        "source_sha": os.environ.get("GITHUB_SHA", "local"),
        "runtime_contacted": False,
        "production_changed": False,
        "external_effects_enabled": False,
    }
    if mode == "validate":
        return {
            **base,
            "result": "PASS",
            "repositories": [
                {"repository": repository, "state": "policy-validated", "result": "PASS"}
                for repository in repositories
            ],
        }

    require(mode in {"apply", "verify"}, "unsupported mode")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        require(
            os.environ.get("GITHUB_REPOSITORY") == "ingtrader21-spec/Middleware-",
            "workflow repository drift",
        )
        require(os.environ.get("GITHUB_REF") == "refs/heads/main", "protected main required")
        require(
            os.environ.get("GITHUB_ACTOR") == os.environ.get("GITHUB_REPOSITORY_OWNER"),
            "repository owner must dispatch or merge",
        )
    if mode == "apply":
        require(confirmation == CONFIRMATION, "exact apply confirmation required")
    token = os.environ.get(TOKEN_ENV, "")
    require(bool(token), f"{TOKEN_ENV} is required")
    api = GitHubApi(token)

    status, reviewer = api.request("GET", f"/users/{EXPECTED_REVIEWER['login']}")
    require(status == 200 and isinstance(reviewer, Mapping), "reviewer identity readback invalid")
    require(reviewer.get("id") == EXPECTED_REVIEWER["user_id"], "reviewer stable ID drift")

    pending = False
    results: list[dict[str, Any]] = []
    for repository in repositories:
        encoded = repo_path(repository)
        status, metadata = api.request("GET", f"/repos/{encoded}")
        require(status == 200 and isinstance(metadata, Mapping), f"{repository}: repository unavailable")
        require(metadata.get("full_name") == repository, f"{repository}: full-name readback drift")
        owner = metadata.get("owner")
        require(
            isinstance(owner, Mapping)
            and owner.get("login") == expected_repository_owner(repository),
            f"{repository}: owner drift",
        )
        require(metadata.get("archived") is False, f"{repository}: archived repository")
        require(metadata.get("disabled") is False, f"{repository}: disabled repository")
        permissions = metadata.get("permissions")
        require(
            isinstance(permissions, Mapping) and permissions.get("admin") is True,
            f"{repository}: token lacks administration",
        )

        permission_status, permission = api.request(
            "GET",
            f"/repos/{encoded}/collaborators/{EXPECTED_REVIEWER['login']}/permission",
        )
        if permission_status == 200 and permission_is_write(permission):
            state = "verified-write"
        elif mode == "verify":
            raise AccessError(f"{repository}: reviewer lacks accepted write access")
        else:
            invite_status, _ = api.request(
                "PUT",
                f"/repos/{encoded}/collaborators/{EXPECTED_REVIEWER['login']}",
                {"permission": "push"},
            )
            require(invite_status in {201, 204}, f"{repository}: unexpected invitation response")
            if invite_status == 201:
                state = "invitation-pending"
                pending = True
            else:
                state = "added-or-updated"

        results.append(
            {
                "repository": repository,
                "state": state,
                "result": "BLOCKED" if state == "invitation-pending" else "PASS",
            }
        )

    document = {
        **base,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "result": "BLOCKED" if pending else "PASS",
        "repositories": results,
    }
    if pending:
        write_evidence(document)
        raise PendingInvitation("one or more exact reviewer invitations require acceptance")
    return document


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
            "PRODUCTION_REVIEWER_ACCESS="
            f"PASS mode={args.mode} repositories={len(document['repositories'])}"
        )
        return 0
    except PendingInvitation as exc:
        print(f"PRODUCTION_REVIEWER_ACCESS=BLOCKED reason={exc}", file=sys.stderr)
        return 2
    except AccessError as exc:
        document = {
            "schema_version": "1.0",
            "mode": args.mode,
            "source_sha": os.environ.get("GITHUB_SHA", "local"),
            "result": "FAIL",
            "runtime_contacted": False,
            "production_changed": False,
            "external_effects_enabled": False,
            "error": str(exc),
            "repositories": [],
        }
        write_evidence(document)
        print(f"PRODUCTION_REVIEWER_ACCESS=FAIL reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
