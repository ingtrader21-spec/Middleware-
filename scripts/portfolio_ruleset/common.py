from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[2]
PORTFOLIO_PATH = ROOT / "config" / "portfolio-repositories.v1.json"
TOKEN_ENV = "CODESTRA_REPOSITORY_ADMIN_TOKEN"
API_VERSION = "2026-03-10"
CONFIRMATION = "APPLY_AI_PRODUCTION_RULESET_TO_ALL_OWNER_REPOSITORIES"
DEFAULT_EVIDENCE_DIR = ROOT / "artifacts" / "portfolio-production-ruleset"
RULESET_NAME = "AI automated production branch gates"


class RolloutError(RuntimeError):
    """The policy, API preflight, mutation, or verification failed."""


def require(condition: object, message: str) -> None:
    if not condition:
        raise RolloutError(message)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RolloutError(f"cannot load JSON: {path}") from exc


def normalize_ruleset_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    conditions = payload.get("conditions")
    if not isinstance(conditions, Mapping):
        raise RolloutError("ruleset conditions are missing")
    ref_name = conditions.get("ref_name")
    if not isinstance(ref_name, Mapping):
        raise RolloutError("ruleset ref_name conditions are missing")
    rules = payload.get("rules")
    if not isinstance(rules, list):
        raise RolloutError("ruleset rules are missing")

    normalized_rules: list[dict[str, Any]] = []
    for rule in rules:
        require(isinstance(rule, Mapping), "ruleset contains a non-object rule")
        rule_type = rule.get("type")
        require(isinstance(rule_type, str) and rule_type, "ruleset rule type is invalid")
        item: dict[str, Any] = {"type": rule_type}
        if rule_type == "pull_request":
            parameters = rule.get("parameters")
            require(isinstance(parameters, Mapping), "pull_request parameters are missing")
            item["parameters"] = {
                "allowed_merge_methods": list(parameters.get("allowed_merge_methods", [])),
                "dismiss_stale_reviews_on_push": parameters.get("dismiss_stale_reviews_on_push"),
                "require_code_owner_review": parameters.get("require_code_owner_review"),
                "require_last_push_approval": parameters.get("require_last_push_approval"),
                "required_approving_review_count": parameters.get("required_approving_review_count"),
                "required_review_thread_resolution": parameters.get("required_review_thread_resolution"),
            }
        normalized_rules.append(item)
    normalized_rules.sort(key=lambda item: item["type"])

    return {
        "name": payload.get("name"),
        "target": payload.get("target"),
        "enforcement": payload.get("enforcement"),
        "bypass_actors": payload.get("bypass_actors"),
        "conditions": {
            "ref_name": {
                "exclude": list(ref_name.get("exclude", [])),
                "include": list(ref_name.get("include", [])),
            }
        },
        "rules": normalized_rules,
    }


def validate_ruleset_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    normalized = normalize_ruleset_payload(payload)
    require(normalized["name"] == RULESET_NAME, "unexpected ruleset name")
    require(normalized["target"] == "branch", "ruleset must target branches")
    require(normalized["enforcement"] == "active", "ruleset must be active")
    require(normalized["bypass_actors"] == [], "ruleset must not define bypass actors")
    require(
        normalized["conditions"]
        == {"ref_name": {"exclude": [], "include": ["refs/heads/production"]}},
        "ruleset must target only refs/heads/production",
    )
    by_type = {rule["type"]: rule for rule in normalized["rules"]}
    require(
        set(by_type)
        == {"pull_request", "required_linear_history", "non_fast_forward", "deletion"},
        "ruleset rule types do not match the approved policy",
    )
    require(
        by_type["pull_request"].get("parameters")
        == {
            "allowed_merge_methods": ["squash"],
            "dismiss_stale_reviews_on_push": False,
            "require_code_owner_review": False,
            "require_last_push_approval": False,
            "required_approving_review_count": 0,
            "required_review_thread_resolution": True,
        },
        "pull-request rule parameters do not match the approved policy",
    )
    return normalized


def load_policy() -> tuple[dict[str, Any], dict[str, Any]]:
    portfolio = load_json(PORTFOLIO_PATH)
    require(isinstance(portfolio, dict), "portfolio policy must be an object")
    require(portfolio.get("schema_version") == "1.0", "unsupported portfolio schema")
    require(portfolio.get("owner") == "appolon1908-hue", "portfolio owner drift")
    known = portfolio.get("known_active_repositories")
    if not isinstance(known, list):
        raise RolloutError("known repository inventory is invalid")
    require(
        known and all(isinstance(item, str) and item for item in known),
        "known repository inventory is invalid",
    )
    require(len(known) == len(set(known)), "known repository inventory has duplicates")
    ruleset = load_json(ROOT / str(portfolio.get("ruleset_path", "")))
    require(isinstance(ruleset, dict), "ruleset policy must be an object")
    validate_ruleset_payload(ruleset)
    return portfolio, ruleset
