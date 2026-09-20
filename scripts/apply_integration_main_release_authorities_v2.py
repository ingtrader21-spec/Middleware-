#!/usr/bin/env python3
"""Expanded fixed integration authority and exact owner issue-command gate."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
BASE_SCRIPT = (
    ROOT
    / "scripts"
    / "apply_integration_main_release_authorities_base.py"
)

spec = importlib.util.spec_from_file_location(
    "integration_authority_v1_base",
    BASE_SCRIPT,
)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load integration authority base")
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)

EXPECTED_OWNER = "appolon1908-hue"
EXPECTED_OWNER_ID = 275410064
EXPECTED_REPOSITORY = "ingtrader21-spec/Middleware-"
EXPECTED_REPOSITORY_ID = 1347559071
EXPECTED_ISSUE_NUMBER = 130
EXPECTED_ISSUE_COMMAND = "/apply-integration-main-release-authority v1"
EXPECTED_REPOSITORIES = {
    "appolon1908-hue/Codestra-AI": (
        1351354401,
        ("unit-and-contract", "postgres-certification", "container-build"),
    ),
    "appolon1908-hue/Codestra-Marketing-": (
        1351352422,
        ("unit-and-contract", "postgres-certification", "container-build"),
    ),
    "appolon1908-hue/Codestra-Prometheus": (
        1350767800,
        (
            "production-source-validation",
            "deploy-readiness / deploy-readiness / overlay-source-ci",
            "deploy-readiness / deploy-readiness / overlay-secret-scan",
        ),
    ),
    "appolon1908-hue/N8N": (
        1347560645,
        (
            "Validate exact repository SHA",
            "deploy-readiness / deploy-readiness / source-ci",
            "deploy-readiness / deploy-readiness / secret-scan",
        ),
    ),
    "appolon1908-hue/Vicidialer-Codestra": (
        1347744324,
        (
            "deploy-readiness / deploy-readiness / secret-scan",
            "deploy-readiness / deploy-readiness / source-ci",
        ),
    ),
    "appolon1908-hue/klyrow.com": (
        1334863061,
        ("frontend", "test", "secrets", "image"),
    ),
    "appolon1908-hue/social.codestra.co": (
        1348783113,
        (
            "Backend policy, migration, test, and build",
            "Backend container build and hardening",
            "certify",
        ),
    ),
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


def configure_base() -> None:
    """Make the preserved engine use the current seven-repository authority."""

    setattr(BASE, "EXPECTED_REPOSITORIES", EXPECTED_REPOSITORIES)


def require_mapping(value: object, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        BASE.require(False, message)
        raise AssertionError(message)
    return value


def validate_issue_comment_event(event: Mapping[str, Any]) -> None:
    BASE.require(event.get("action") == "created", "issue command action drift")
    repository = require_mapping(
        event.get("repository"),
        "issue command repository missing",
    )
    BASE.require(
        repository.get("id") == EXPECTED_REPOSITORY_ID,
        "issue command repository ID drift",
    )
    BASE.require(
        repository.get("full_name") == EXPECTED_REPOSITORY,
        "issue command repository drift",
    )
    BASE.require(
        repository.get("default_branch") == "main",
        "issue command default branch drift",
    )
    owner = require_mapping(
        repository.get("owner"),
        "issue command owner missing",
    )
    BASE.require(
        owner.get("login") == EXPECTED_OWNER,
        "issue command owner login drift",
    )
    BASE.require(
        owner.get("id") == EXPECTED_OWNER_ID,
        "issue command owner ID drift",
    )

    issue = require_mapping(
        event.get("issue"),
        "issue command issue missing",
    )
    BASE.require(
        issue.get("number") == EXPECTED_ISSUE_NUMBER,
        "issue command number drift",
    )
    BASE.require(
        "pull_request" not in issue,
        "issue command cannot originate from a pull request",
    )

    sender = require_mapping(
        event.get("sender"),
        "issue command sender missing",
    )
    comment = require_mapping(
        event.get("comment"),
        "issue command comment missing",
    )
    comment_user = require_mapping(
        comment.get("user"),
        "issue command comment user missing",
    )
    for actor, label in ((sender, "sender"), (comment_user, "comment user")):
        BASE.require(
            actor.get("login") == EXPECTED_OWNER,
            f"issue command {label} login drift",
        )
        BASE.require(
            actor.get("id") == EXPECTED_OWNER_ID,
            f"issue command {label} ID drift",
        )
    BASE.require(
        comment.get("body") == EXPECTED_ISSUE_COMMAND,
        "issue command body drift",
    )


def validate_runner_issue_comment_event() -> None:
    """Validate the runner-owned event file without an inline Python loader."""

    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    BASE.require(bool(event_path), "issue command event path missing")
    try:
        value = json.loads(
            Path(event_path).read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise BASE.PolicyError("cannot load issue command event") from exc
    validate_issue_comment_event(
        require_mapping(value, "issue command event must be an object")
    )


configure_base()


def main(argv: list[str] | None = None) -> int:
    configure_base()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--validate-issue-comment-event"]:
        validate_runner_issue_comment_event()
        return 0
    return BASE.main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
