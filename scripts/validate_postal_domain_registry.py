#!/usr/bin/env python3
"""Validate the fail-closed Postal domain authority contract."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]

VERIFIED = {
    "beyvra.com",
    "breero.com",
    "breero.shop",
    "codestra.agency",
    "codestra.cloud",
    "codestra.co",
    "codestra.digital",
    "codestra.media",
    "klyrow.com",
    "kyqra.com",
    "moneybee.loan",
    "moneybeeloan.com",
    "nativoenglish.com",
    "telnexa.co",
}
UNVERIFIED = {"booked4seasons.com"}
EXPECTED = VERIFIED | UNVERIFIED

REGISTRY_FIELDS = {
    "version",
    "owner",
    "provider",
    "workstream",
    "evidence",
    "policies",
    "domains",
}
EVIDENCE_FIELDS = {
    "type",
    "private_key_material_recorded",
    "historical_private_key_exposure_reported",
}
REQUIRED_TRUE_POLICIES = {
    "middleware_is_domain_authority",
    "applications_must_not_submit_directly_to_postal",
    "private_keys_must_not_be_committed",
    "all_configured_domains_require_dkim_rotation",
    "post_rotation_postal_dns_recheck_required",
    "dns_pass_does_not_imply_send_authorization",
}
REQUIRED_FALSE_POLICIES = {
    "middleware_email_delivery_default",
    "external_delivery_default",
}
POLICY_FIELDS = (
    REQUIRED_TRUE_POLICIES | REQUIRED_FALSE_POLICIES | {"send_eligibility_requires"}
)
SEND_ELIGIBILITY_REQUIREMENTS = {
    "postal_dns_check_pass",
    "dkim_rotation_complete",
    "post_rotation_dns_recheck_pass",
    "middleware_policy_approval",
    "EMAIL_DELIVERY_ENABLED=true",
    "ENABLE_EXTERNAL_DELIVERY=true",
}
COMMON_DOMAIN_FIELDS = {
    "domain",
    "postal_configured",
    "latest_postal_dns_check",
    "spf",
    "dkim",
    "mx",
    "return_path",
    "dkim_rotation_required",
    "post_rotation_recheck_required",
    "middleware_send_eligible",
    "production_ready",
}
UNVERIFIED_DOMAIN_FIELDS = COMMON_DOMAIN_FIELDS | {
    "incoming_configured",
    "outgoing_configured",
}
REQUIRED_DISABLED_FLAGS = {
    "ALLOW_LIVE_EMAIL",
    "ENABLE_EXTERNAL_DELIVERY",
    "EXTERNAL_DELIVERY_ENABLED",
    "EMAIL_DELIVERY_ENABLED",
    "LIVE_EMAIL_DELIVERY",
}
FORBIDDEN_SECRET_MARKERS = (
    "begin private key",
    "begin encrypted private key",
    "begin rsa private key",
    "begin ec private key",
    "begin openssh private key",
    "private_key=",
    "dkim_private_key",
)
DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}\Z"
)
ENV_NAME_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*\Z")
SENSITIVE_ENV_NAME_PATTERN = re.compile(
    r"(?:^|_)(?:ACCESS_KEY|API_KEY|CREDENTIALS?|PASSWORD|PRIVATE_KEY|SECRETS?|TOKENS?)(?:_|$)"
)
DELIVERY_FLAG_PATTERN = re.compile(r"(?:EMAIL|DELIVERY)")
ENABLED_VALUES = {"1", "enabled", "on", "true", "yes"}


def fail(message: str) -> None:
    raise SystemExit(f"POSTAL_DOMAIN_REGISTRY_ERROR={message}")


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def reject_nonstandard_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_json_object,
            parse_constant=reject_nonstandard_json_constant,
        )
    except (OSError, UnicodeError, ValueError) as error:
        fail(f"invalid_json:{path.name}:{error}")
    if not isinstance(value, dict):
        fail(f"invalid_object:{path.name}")
    return cast(dict[str, Any], value)


def require_object(value: object, message: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        fail(message)
    return cast(dict[str, Any], value)


def require_list(value: object, message: str) -> list[Any]:
    if not isinstance(value, list):
        fail(message)
    return cast(list[Any], value)


def require_string(value: object, message: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        fail(message)
    return cast(str, value)


def require_string_list(value: object, message: str) -> list[str]:
    items = [require_string(item, message) for item in require_list(value, message)]
    if not items or len(items) != len(set(items)):
        fail(message)
    return items


def require_exact_fields(
    value: dict[str, Any], expected: set[str], message: str
) -> None:
    if set(value) != expected:
        fail(f"{message}:{sorted(set(value) ^ expected)}")


def reject_secret_material(registry: dict[str, Any]) -> None:
    serialized = json.dumps(registry, sort_keys=True).casefold()
    for marker in FORBIDDEN_SECRET_MARKERS:
        if marker in serialized:
            fail(f"forbidden_secret_marker:{marker}")


def load_safety_flags(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        fail(f"invalid_safety_file:{error}")

    flags: dict[str, str] = {}
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail(f"malformed_safety_line:{line_number}")
        name, value = line.split("=", 1)
        if (
            ENV_NAME_PATTERN.fullmatch(name) is None
            or not value
            or value != value.strip()
        ):
            fail(f"malformed_safety_line:{line_number}")
        if SENSITIVE_ENV_NAME_PATTERN.search(name) is not None:
            fail(f"forbidden_safety_secret_name:{name}")
        if any(
            ord(character) < 32 or 127 <= ord(character) <= 159 for character in value
        ):
            fail(f"invalid_safety_control_character:{name}")
        if name in flags:
            fail(f"duplicate_safety_flag:{name}")
        if DELIVERY_FLAG_PATTERN.search(name) and value.casefold() in ENABLED_VALUES:
            fail(f"enabled_delivery_alias:{name}")
        flags[name] = value
    return flags


def validate(root: Path = ROOT) -> tuple[int, int, int]:
    registry = load_object(root / "config/postal-domain-registry.json")
    reject_secret_material(registry)
    require_exact_fields(registry, REGISTRY_FIELDS, "registry_fields_changed")

    if registry.get("version") != 1 or isinstance(registry.get("version"), bool):
        fail("unsupported_registry_version")
    if registry.get("owner") != "middleware":
        fail("middleware_must_own_domain_eligibility")
    if registry.get("provider") != "postal":
        fail("provider_must_be_postal")
    if registry.get("workstream") != "integration/postal-email":
        fail("unexpected_workstream")

    evidence = require_object(registry.get("evidence"), "invalid_evidence")
    require_exact_fields(evidence, EVIDENCE_FIELDS, "evidence_fields_changed")
    if evidence.get("type") != "operator_reported_latest_postal_checks":
        fail("unexpected_evidence_type")
    if evidence.get("private_key_material_recorded") is not False:
        fail("private_key_material_must_never_be_recorded")
    if evidence.get("historical_private_key_exposure_reported") is not True:
        fail("historical_dkim_exposure_must_remain_acknowledged")

    policies = require_object(registry.get("policies"), "invalid_policies")
    require_exact_fields(policies, POLICY_FIELDS, "policy_fields_changed")
    for key in REQUIRED_TRUE_POLICIES:
        if policies.get(key) is not True:
            fail(f"policy_must_be_true:{key}")
    for key in REQUIRED_FALSE_POLICIES:
        if policies.get(key) is not False:
            fail(f"policy_must_be_false:{key}")
    requirements = require_string_list(
        policies.get("send_eligibility_requires"),
        "invalid_send_eligibility_requirements",
    )
    if set(requirements) != SEND_ELIGIBILITY_REQUIREMENTS:
        fail("send_eligibility_requirements_changed")

    raw_domains = require_list(registry.get("domains"), "domains_must_be_a_list")
    if not raw_domains:
        fail("domains_must_not_be_empty")
    by_name: dict[str, dict[str, Any]] = {}
    for index, raw_domain in enumerate(raw_domains):
        item = require_object(raw_domain, f"invalid_domain_entry:{index}")
        name = require_string(item.get("domain"), f"invalid_domain_name:{index}")
        if DOMAIN_PATTERN.fullmatch(name) is None:
            fail(f"invalid_domain_name:{name}")
        canonical_name = name.casefold()
        if canonical_name in by_name:
            fail(f"duplicate_domain:{name}")
        by_name[canonical_name] = item

    observed = set(by_name)
    if observed != EXPECTED:
        fail(f"unexpected_domain_set:{sorted(observed ^ EXPECTED)}")

    for name in VERIFIED:
        item = by_name[name]
        require_exact_fields(
            item, COMMON_DOMAIN_FIELDS, f"domain_fields_changed:{name}"
        )
        if item.get("postal_configured") is not True:
            fail(f"postal_configuration_required:{name}")
        if item.get("latest_postal_dns_check") != "pass":
            fail(f"postal_dns_pass_required:{name}")
        for check in ("spf", "dkim", "mx", "return_path"):
            if item.get(check) != "ok":
                fail(f"dns_check_must_be_ok:{name}:{check}")
        if item.get("dkim_rotation_required") is not True:
            fail(f"dkim_rotation_required:{name}")
        if item.get("post_rotation_recheck_required") is not True:
            fail(f"post_rotation_recheck_required:{name}")
        if item.get("middleware_send_eligible") is not False:
            fail(f"send_must_remain_ineligible:{name}")
        if item.get("production_ready") is not False:
            fail(f"production_must_remain_blocked:{name}")

    booked = by_name["booked4seasons.com"]
    require_exact_fields(
        booked,
        UNVERIFIED_DOMAIN_FIELDS,
        "domain_fields_changed:booked4seasons.com",
    )
    for key in (
        "postal_configured",
        "incoming_configured",
        "outgoing_configured",
        "dkim_rotation_required",
        "post_rotation_recheck_required",
    ):
        if booked.get(key) is not True:
            fail(f"booked4seasons_must_be_true:{key}")
    if booked.get("latest_postal_dns_check") != "never_completed":
        fail("booked4seasons_must_remain_unverified")
    for check in ("spf", "dkim", "mx", "return_path"):
        if booked.get(check) != "unknown":
            fail(f"booked4seasons_check_must_remain_unknown:{check}")
    for key in ("middleware_send_eligible", "production_ready"):
        if booked.get(key) is not False:
            fail(f"booked4seasons_must_fail_closed:{key}")

    safety_flags = load_safety_flags(root / "config/preproduction-safety.env.example")
    for name in REQUIRED_DISABLED_FLAGS:
        if safety_flags.get(name) != "false":
            fail(f"safety_flag_must_be_false:{name}")

    return len(EXPECTED), len(VERIFIED), len(UNVERIFIED)


def main() -> None:
    configured, verified, unverified = validate()
    print(f"POSTAL_DOMAINS_CONFIGURED={configured}")
    print(f"POSTAL_DNS_VERIFIED={verified}")
    print(f"POSTAL_DNS_UNVERIFIED={unverified}")
    print("DKIM_ROTATION_REQUIRED=ALL_CONFIGURED_DOMAINS")
    print("MIDDLEWARE_EMAIL_DELIVERY_DEFAULT=DISABLED")
    print("POSTAL_DOMAIN_REGISTRY=PASS")


if __name__ == "__main__":
    main()
