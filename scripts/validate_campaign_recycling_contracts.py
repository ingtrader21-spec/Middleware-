#!/usr/bin/env python3
"""Fail-closed validation for the MCR-A campaign recycling contracts.

The contracts are declarative only. This validator proves they parse, that
their enums agree with each other and with the existing sources they reuse
(app/communications.py, the Klyrow delivery event model, the dialing
eligibility contract, capability flags, HTTP conventions), that the API
endpoint set is exact, that suppression precedence is explicit, and that no
runtime route, migration, or production activation has been introduced.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = Path("contracts/campaign-recycling")
SCHEMA_FILES = {
    "lifecycle": CONTRACT_DIR / "lifecycle.v1.schema.json",
    "channel_health": CONTRACT_DIR / "channel-health.v1.schema.json",
    "exposure_ledger": CONTRACT_DIR / "exposure-ledger.v1.schema.json",
    "next_action": CONTRACT_DIR / "next-action.v1.schema.json",
    "delivery_event": CONTRACT_DIR / "delivery-event.v1.schema.json",
}
OPENAPI_FILE = CONTRACT_DIR / "campaign-engine.openapi.yaml"
AUTHORITY_FILE = CONTRACT_DIR / "authority.v1.json"
POLICY_FILE = Path("config/campaign-recycling-policy.v1.json")
DOC_FILE = Path("docs/architecture/MASTER_LEAD_LIFECYCLE_CAMPAIGN_RECYCLING_V1.md")
ID_BASE = "https://contracts.codestra.co/campaign-recycling/"

LIFECYCLE_STATES = [
    "NEW",
    "VALIDATED",
    "ELIGIBLE",
    "ACTIVE_CYCLE",
    "ENGAGED",
    "COOLING",
    "REACTIVATION",
    "CONVERTED",
    "SUPPRESSED",
]
CHANNEL_HEALTH_STATES = [
    "unknown",
    "valid",
    "possible",
    "soft_bounce",
    "hard_bounce",
    "complained",
    "unsubscribed",
    "suppressed",
    "invalid",
]
DESIRED_CHANNELS = ["email", "sms", "whatsapp", "voice"]
DELIVERY_EVENT_TYPES = [
    "accepted",
    "queued",
    "dispatched",
    "delivered",
    "deferred",
    "soft_bounce",
    "hard_bounce",
    "complaint",
    "unsubscribe",
    "open",
    "read",
    "click",
    "reply",
    "conversion",
]
EXPECTED_OPERATIONS = {
    ("post", "/platform/v1/campaign-engine/plan"),
    ("post", "/platform/v1/campaign-engine/execute"),
    ("get", "/platform/v1/leads/{lead_id}/journey"),
    ("get", "/platform/v1/leads/{lead_id}/next-action"),
    ("get", "/platform/v1/campaigns/{campaign_id}/eligible-leads"),
    ("post", "/platform/v1/delivery-events"),
    ("post", "/platform/v1/suppressions"),
    ("get", "/platform/v1/campaign-engine/status"),
}
EFFECTFUL_POSTS = {
    "/platform/v1/campaign-engine/execute",
    "/platform/v1/delivery-events",
    "/platform/v1/suppressions",
}
DRY_RUN_OPERATIONS = {
    "/platform/v1/campaign-engine/plan",
    "/platform/v1/leads/{lead_id}/next-action",
    "/platform/v1/campaigns/{campaign_id}/eligible-leads",
}
CANDIDATE_DISCLOSURE_OPERATIONS = {
    "/platform/v1/campaign-engine/plan",
    "/platform/v1/leads/{lead_id}/next-action",
}
REQUIRED_SYSTEMS = {
    "leads",
    "middleware",
    "klyrow",
    "odoo",
    "n8n",
    "thunderbird",
    "keycloak",
    "openbao",
    "kong",
    "caddy",
    "observability",
    "telnexa",
    "vicidial",
    "whatsapp",
    "evolution",
}
MISSION_FOUNDATIONS = {
    "docs/operations/campaign-registry/lead-eligibility.md",
    "app/core/campaign_identity.py",
    "app/core/lead_automation.py",
    "app/communications.py",
    "app/email_production_control.py",
    "migrations/versions/0056_klyrow_delivery_event_inbox.py",
    "migrations/versions/0066_reconcile_odoo_campaign_scope.py",
}
SUPPRESSION_REASON_CODES = {
    "global": "SUPPRESSED_GLOBAL",
    "channel": "SUPPRESSED_CHANNEL",
    "campaign": "SUPPRESSED_CAMPAIGN",
    "campaign_channel": "SUPPRESSED_CAMPAIGN_CHANNEL",
}
# Runtime surfaces that must not gain a handler, route, or table in MCR-A.
RUNTIME_MARKERS = (
    "campaign-engine",
    "/platform/v1/delivery-events",
    "/platform/v1/suppressions",
    "/next-action",
    "/journey",
    "eligible-leads",
    "campaign_recycling",
    "campaign-recycling",
    "exposure_ledger",
)
RUNTIME_SCAN_GLOBS = (
    "app/**/*.py",
    "migrations/**/*.py",
    "deploy/**/*",
    "config/caddy/**/*",
    "config/route-authority*.json",
    "contracts/platform/middleware-openapi.generated.json",
)

PURE_DOMAIN_MODULE = Path("app/core/campaign_recycling.py")
PURE_DOMAIN_FORBIDDEN_IMPORT_ROOTS = {
    "asyncpg",
    "sqlalchemy",
    "fastapi",
    "redis",
    "requests",
    "httpx",
    "alembic",
}
PURE_DOMAIN_FORBIDDEN_TEXT = (
    "APIRouter",
    "FastAPI",
    "Postgres",
    "CommandEnvelope",
    "CommandService",
    "CommandOperation",
    "provider_message_id",
    "klyrow_delivery_event",
    "/platform/",
    "migrations/",
)


def _pure_domain_module_is_safe(path: Path) -> bool:
    """Allow the C1 deterministic module without permitting runtime activation."""
    text = path.read_text(encoding="utf-8", errors="ignore")
    if any(marker in text for marker in PURE_DOMAIN_FORBIDDEN_TEXT):
        return False
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            return False
        if isinstance(node, ast.Import):
            if any(alias.name.split(".", 1)[0] in PURE_DOMAIN_FORBIDDEN_IMPORT_ROOTS for alias in node.names):
                return False
        if isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".", 1)[0]
            if root in PURE_DOMAIN_FORBIDDEN_IMPORT_ROOTS or (node.module or "").startswith("app.api"):
                return False
    return True


def load_artifacts(root: Path = ROOT) -> dict[str, Any]:
    artifacts: dict[str, Any] = {
        key: json.loads((root / path).read_text(encoding="utf-8"))
        for key, path in SCHEMA_FILES.items()
    }
    artifacts["openapi"] = yaml.safe_load(
        (root / OPENAPI_FILE).read_text(encoding="utf-8")
    )
    artifacts["authority"] = json.loads(
        (root / AUTHORITY_FILE).read_text(encoding="utf-8")
    )
    artifacts["policy"] = json.loads((root / POLICY_FILE).read_text(encoding="utf-8"))
    artifacts["doc"] = (root / DOC_FILE).read_text(encoding="utf-8")
    return artifacts


def registry_for(artifacts: dict[str, Any]) -> Registry:
    return Registry().with_resources(
        (artifacts[key]["$id"], Resource.from_contents(artifacts[key]))
        for key in SCHEMA_FILES
    )


def validator_for(
    artifacts: dict[str, Any], key: str, pointer: str = ""
) -> Draft202012Validator:
    schema: dict[str, Any] = artifacts[key]
    if pointer:
        schema = {"$ref": f"{schema['$id']}#{pointer}"}
    return Draft202012Validator(
        schema,
        registry=registry_for(artifacts),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


# --- existing-source readers -------------------------------------------------


def _module(root: Path, relative: str) -> ast.Module:
    return ast.parse((root / relative).read_text(encoding="utf-8"))


def _literal_alias(tree: ast.Module, name: str) -> list[str]:
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
            and isinstance(node.value, ast.Subscript)
        ):
            inner = node.value.slice
            elements = inner.elts if isinstance(inner, ast.Tuple) else [inner]
            return [ast.literal_eval(item) for item in elements]
    raise LookupError(name)


def _assigned_literal(tree: ast.Module, name: str) -> Any:
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            return ast.literal_eval(node.value)
    raise LookupError(name)


def communications_channels(root: Path = ROOT) -> list[str]:
    return _literal_alias(
        _module(root, "app/communications.py"), "CommunicationChannel"
    )


def communications_message_statuses(root: Path = ROOT) -> list[str]:
    return _literal_alias(_module(root, "app/communications.py"), "MessageStatus")


def communications_channel_commands(root: Path = ROOT) -> dict[str, tuple[str, ...]]:
    return _assigned_literal(_module(root, "app/communications.py"), "CHANNEL_COMMAND")


def klyrow_delivery_event_types(root: Path = ROOT) -> set[str]:
    tree = _module(root, "app/api/internal/klyrow_mail.py")
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "KlyrowDeliveryEvent":
            for item in node.body:
                if (
                    isinstance(item, ast.AnnAssign)
                    and isinstance(item.target, ast.Name)
                    and item.target.id == "event_type"
                    and isinstance(item.value, ast.Call)
                ):
                    pattern = next(
                        ast.literal_eval(k.value)
                        for k in item.value.keywords
                        if k.arg == "pattern"
                    )
                    match = re.fullmatch(
                        r"\^klyrow\\\.email\\\.\(([a-z_|]+)\)\$", pattern
                    )
                    if not match:
                        raise LookupError(
                            "unexpected KlyrowDeliveryEvent.event_type pattern"
                        )
                    return {
                        f"klyrow.email.{name}" for name in match.group(1).split("|")
                    }
    raise LookupError("KlyrowDeliveryEvent.event_type")


def dialing_contract_states(root: Path = ROOT) -> tuple[list[str], list[str]]:
    text = " ".join(
        (root / "docs/operations/campaign-registry/lead-eligibility.md")
        .read_text(encoding="utf-8")
        .split()
    )
    identity = re.search(r"Identity states are (.+?)\.", text)
    dialing = re.search(r"Dialing is separate: (.+?)\.", text)
    if not identity or not dialing:
        raise LookupError("lead-eligibility state sentences")
    tokens = re.compile(r"\b[A-Z][A-Z_]{2,}\b")
    return tokens.findall(identity.group(1)), tokens.findall(dialing.group(1))


def http_error_envelope_fields(root: Path = ROOT) -> set[str]:
    text = (root / "contracts/http-conventions.md").read_text(encoding="utf-8")
    block = re.search(r"## Canonical error envelope\s+```json\s+(.+?)```", text, re.S)
    if not block:
        raise LookupError("canonical error envelope block")
    return set(json.loads(block.group(1))["error"])


# --- helpers ----------------------------------------------------------------


def _enum(schema: dict[str, Any], name: str) -> list[Any]:
    return list(schema["$defs"][name]["enum"])


def _clause_map(
    schema: dict[str, Any], if_field: str, then_field: str
) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for clause in schema.get("allOf", []):
        condition = clause.get("if", {}).get("properties", {}).get(if_field, {})
        if "const" not in condition:
            continue
        then = clause.get("then")
        if then is False:
            mapping[condition["const"]] = []
            continue
        target = then["properties"][then_field]
        mapping[condition["const"]] = list(target.get("enum", [target.get("const")]))
    return mapping


def _walk_refs(value: Any) -> list[str]:
    if isinstance(value, dict):
        refs = [value["$ref"]] if isinstance(value.get("$ref"), str) else []
        return refs + [ref for item in value.values() for ref in _walk_refs(item)]
    if isinstance(value, list):
        return [ref for item in value for ref in _walk_refs(item)]
    return []


def _pointer(document: Any, pointer: str) -> Any:
    for part in [p for p in pointer.lstrip("/").split("/") if p]:
        part = part.replace("~1", "/").replace("~0", "~")
        document = document[int(part)] if isinstance(document, list) else document[part]
    return document


# --- checks -----------------------------------------------------------------


def check_schemas(artifacts: dict[str, Any], errors: list[str]) -> None:
    for key, path in SCHEMA_FILES.items():
        schema = artifacts[key]
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            errors.append(f"{path}: invalid JSON Schema: {exc.message}")
        if schema.get("$id") != ID_BASE + path.name:
            errors.append(f"{path}: $id must be {ID_BASE + path.name}")
        if (
            schema.get("x-codestra-contract", {}).get("runtime_status")
            != "contract_only"
        ):
            errors.append(f"{path}: runtime_status must be contract_only")
        for ref in _walk_refs(schema):
            target, _, pointer = ref.partition("#")
            document = (
                artifacts[key]
                if not target
                else next(
                    (artifacts[k] for k, p in SCHEMA_FILES.items() if p.name == target),
                    None,
                )
            )
            if document is None:
                errors.append(f"{path}: unresolved $ref {ref}")
                continue
            try:
                _pointer(document, pointer)
            except (KeyError, IndexError, ValueError):
                errors.append(f"{path}: unresolved $ref {ref}")


def check_lifecycle(artifacts: dict[str, Any], errors: list[str], root: Path) -> None:
    schema = artifacts["lifecycle"]
    meta = schema["x-lifecycle"]
    states = _enum(schema, "LifecycleState")
    if states != LIFECYCLE_STATES or meta["states"] != LIFECYCLE_STATES:
        errors.append("lifecycle: states must be exactly " + ",".join(LIFECYCLE_STATES))
    transitions: dict[str, list[str]] = meta["transitions"]
    if set(transitions) != set(LIFECYCLE_STATES):
        errors.append("lifecycle: every state needs a transition entry")
    for source, targets in transitions.items():
        unknown = set(targets) - set(LIFECYCLE_STATES)
        if unknown or source in targets:
            errors.append(
                f"lifecycle: invalid transitions from {source}: {sorted(unknown) or source}"
            )
    if meta["initial"] != "NEW":
        errors.append("lifecycle: initial state must be NEW")
    absorbing, terminal = set(meta["absorbing"]), set(meta["outreach_terminal"])
    if absorbing != {"SUPPRESSED"} or terminal != {"CONVERTED", "SUPPRESSED"}:
        errors.append("lifecycle: terminal semantics changed")
    if set(meta["terminal_semantics"]) != terminal:
        errors.append(
            "lifecycle: every outreach-terminal state needs terminal_semantics"
        )
    for state in absorbing:
        if transitions.get(state):
            errors.append(
                f"lifecycle: absorbing state {state} has outgoing transitions"
            )
    for state in set(LIFECYCLE_STATES) - absorbing:
        if "SUPPRESSED" not in transitions.get(state, []):
            errors.append(f"lifecycle: suppression must be reachable from {state}")
    for state in terminal - absorbing:
        if transitions.get(state) != ["SUPPRESSED"]:
            errors.append(
                f"lifecycle: outreach-terminal {state} may only move to SUPPRESSED"
            )
    if set(meta["engine_contactable"]) & terminal:
        errors.append("lifecycle: terminal states cannot be engine-contactable")
    reachable, frontier = {"NEW"}, ["NEW"]
    while frontier:
        for target in transitions.get(frontier.pop(), []):
            if target not in reachable:
                reachable.add(target)
                frontier.append(target)
    if reachable != set(LIFECYCLE_STATES):
        errors.append(
            f"lifecycle: unreachable states {sorted(set(LIFECYCLE_STATES) - reachable)}"
        )
    enforced = _clause_map(schema, "from_state", "to_state")
    if enforced != transitions:
        errors.append(
            "lifecycle: if/then transition rules differ from x-lifecycle.transitions"
        )
    reasons = _enum(schema, "TransitionReason")
    declared_reasons = meta["transition_reasons"]
    if set(declared_reasons) != set(LIFECYCLE_STATES) - {"NEW"}:
        errors.append(
            "lifecycle: transition_reasons must cover every non-initial state"
        )
    if any(set(codes) - set(reasons) for codes in declared_reasons.values()):
        errors.append("lifecycle: transition_reasons use undeclared reason codes")
    if _clause_map(schema, "to_state", "reason_code") != declared_reasons:
        errors.append(
            "lifecycle: if/then reason rules differ from x-lifecycle.transition_reasons"
        )
    separate = schema["x-codestra-contract"]["separate_from"]
    identity, dialing = dialing_contract_states(root)
    if separate["contract"] != "docs/operations/campaign-registry/lead-eligibility.md":
        errors.append("lifecycle: must reference the dialing eligibility contract")
    if separate["identity_states"] != identity or separate["dialing_states"] != dialing:
        errors.append(
            "lifecycle: referenced identity/dialing states drifted from lead-eligibility.md"
        )
    if "eligibility" in schema["properties"] or "dialing_state" in schema["properties"]:
        errors.append("lifecycle: lifecycle records must not carry dialing eligibility")


def check_channel_health(
    artifacts: dict[str, Any], errors: list[str], root: Path
) -> None:
    schema, policy = artifacts["channel_health"], artifacts["policy"]
    meta = schema["x-channel-health"]
    states = _enum(schema, "ChannelHealthState")
    if states != CHANNEL_HEALTH_STATES or meta["states"] != CHANNEL_HEALTH_STATES:
        errors.append(
            "channel-health: states must be exactly " + ",".join(CHANNEL_HEALTH_STATES)
        )
    if set(meta["contact_semantics"]) != set(CHANNEL_HEALTH_STATES):
        errors.append("channel-health: contact_semantics must cover every state")
    if meta["contact_semantics"].get("unknown") != "blocked_until_validated":
        errors.append("channel-health: unknown must fail closed")
    suppressed_states = sorted(
        s for s, v in meta["contact_semantics"].items() if v == "blocked_and_suppressed"
    )
    if sorted(meta["states_requiring_suppression"]) != suppressed_states:
        errors.append("channel-health: states_requiring_suppression mismatch")
    partition = [
        set(clause["if"]["properties"]["state"]["enum"])
        for clause in schema["allOf"]
        if "state" in clause.get("if", {}).get("properties", {})
    ]
    if (
        len(partition) != 2
        or partition[0] | partition[1] != set(CHANNEL_HEALTH_STATES)
        or partition[0] & partition[1]
    ):
        errors.append("channel-health: suppression if/then must partition every state")
    elif partition[0] != set(suppressed_states):
        errors.append(
            "channel-health: suppression-required rule differs from contact semantics"
        )
    channels = _enum(schema, "Channel")
    runtime_channels = communications_channels(root)
    if channels != meta["channels"] or channels != policy["channels"] or channels != DESIRED_CHANNELS:
        errors.append(
            "channel-health: channels must equal the frozen desired channel set"
        )
    if not set(runtime_channels) <= set(channels):
        errors.append(
            "channel-health: app/communications.py contains a runtime channel outside the desired contract"
        )
    scopes = _enum(schema, "SuppressionScope")
    if not (
        scopes
        == meta["suppression_scope_precedence"]
        == policy["suppression"]["scope_precedence"]
    ):
        errors.append(
            "channel-health: suppression scope precedence must be explicit and identical"
        )
    reasons = _enum(schema, "SuppressionReason")
    if not (
        reasons
        == meta["suppression_reason_precedence"]
        == policy["suppression"]["reason_precedence"]
    ):
        errors.append(
            "channel-health: suppression reason precedence must be explicit and identical"
        )
    if (
        meta["automatic_cross_channel_effect"] != "none"
        or schema["properties"]["cross_channel_effect"].get("const") != "none"
    ):
        errors.append("channel-health: automatic signals must stay channel-local")
    sources = set(_enum(schema, "HealthSource"))
    if not set(meta["global_scope_sources"]) <= sources:
        errors.append(
            "channel-health: global scope sources must be declared HealthSource values"
        )
    global_rule = schema["$defs"]["SuppressionRequest"]["allOf"][0]
    if set(global_rule["then"]["properties"]["source"]["enum"]) != set(
        meta["global_scope_sources"]
    ):
        errors.append("channel-health: global suppression request sources drifted")
    if (
        policy["suppression"]["overrides_eligibility"] is not True
        or policy["suppression"]["positive_signal_can_lift"] is not False
    ):
        errors.append("channel-health: suppression must always override eligibility")


def check_exposure(artifacts: dict[str, Any], errors: list[str], root: Path) -> None:
    schema = artifacts["exposure_ledger"]
    meta = schema["x-exposure-ledger"]
    natural = meta["natural_key"]
    if natural != [
        "tenant_id",
        "lead_id",
        "campaign_id",
        "campaign_version",
        "channel",
        "touch_index",
    ]:
        errors.append(
            "exposure-ledger: natural key must be lead x campaign x version x channel x touch"
        )
    if (
        meta["unique_constraints"][0] != natural
        or ["tenant_id", "idempotency_key"] not in meta["unique_constraints"]
    ):
        errors.append(
            "exposure-ledger: natural key and idempotency key must both be unique"
        )
    for field in (
        "correlation_id",
        "command_id",
        "provider_message_id",
        "idempotency_key",
        *natural,
    ):
        if field not in schema["required"]:
            errors.append(f"exposure-ledger: {field} must be required")
    if set(meta["idempotency_key_recipe"]["example_input"]) != set(natural):
        errors.append(
            "exposure-ledger: idempotency recipe must hash exactly the natural key"
        )
    if not set(meta["immutable_after_reserve"]) <= set(schema["properties"]):
        errors.append("exposure-ledger: immutable fields must be declared properties")
    statuses = _enum(schema, "ExposureStatus")
    if statuses != ["reserved", *communications_message_statuses(root)]:
        errors.append(
            "exposure-ledger: statuses must be reserved + communications MessageStatus"
        )
    terminal = meta["transport_terminal_statuses"]
    source = (root / "app/communications.py").read_text(encoding="utf-8")
    if "{" + ", ".join(f'"{s}"' for s in terminal) + "}" not in source:
        errors.append(
            "exposure-ledger: transport-terminal statuses drifted from app/communications.py"
        )
    if meta["engagement_outcome_rank"] != _enum(schema, "EngagementOutcome"):
        errors.append("exposure-ledger: engagement outcome rank mismatch")
    if meta["negative_outcome_rank"] != _enum(schema, "NegativeOutcome"):
        errors.append("exposure-ledger: negative outcome rank mismatch")


def check_next_action(artifacts: dict[str, Any], errors: list[str]) -> None:
    schema, policy, lifecycle = (
        artifacts["next_action"],
        artifacts["policy"],
        artifacts["lifecycle"],
    )
    codes = _enum(schema, "ReasonCode")
    if codes != policy["decision"]["reason_code_precedence"]:
        errors.append(
            "next-action: reason codes must equal policy reason_code_precedence (ordered)"
        )
    if len(set(codes)) != len(codes) or codes[-1] != "ELIGIBLE":
        errors.append("next-action: reason codes must be unique with ELIGIBLE last")
    if set(schema["x-reason-codes"]["classes"]) != set(codes):
        errors.append("next-action: every reason code needs a class")
    scope_codes = [
        SUPPRESSION_REASON_CODES[s]
        for s in artifacts["channel_health"]["x-channel-health"][
            "suppression_scope_precedence"
        ]
    ]
    positions = [codes.index(c) if c in codes else -1 for c in scope_codes]
    if -1 in positions or positions != sorted(positions):
        errors.append(
            "next-action: suppression reason codes must follow scope precedence"
        )
    if positions and -1 not in positions:
        suppression_start = positions[0]
        policy_codes = {
            c
            for c, k in schema["x-reason-codes"]["classes"].items()
            if k in {"blocking", "temporal"}
        }
        if any(codes.index(c) < suppression_start for c in policy_codes):
            errors.append(
                "next-action: suppression must be evaluated before every eligibility rule"
            )
    if policy["fail_closed"]["null_parameter_result"] not in codes:
        errors.append("next-action: fail-closed result must be a declared reason code")
    if schema["properties"]["provider_effects"].get("const") != "none":
        errors.append("next-action: decisions must declare zero provider effects")
    if not re.fullmatch(
        schema["$defs"]["PolicyVersion"]["pattern"], policy["policy_version"]
    ):
        errors.append(
            "next-action: policy_version does not match PolicyVersion pattern"
        )
    for field in (
        "eligible",
        "selected",
        "next_eligible_at",
        "policy_version",
        "reason_codes",
        "candidates",
    ):
        if field not in schema["required"]:
            errors.append(f"next-action: {field} must be required")
    contactable = set(lifecycle["x-lifecycle"]["engine_contactable"])
    blocked = next(
        set(c["if"]["properties"]["lifecycle_state"]["enum"])
        for c in schema["allOf"]
        if "lifecycle_state" in c.get("if", {}).get("properties", {})
    )
    if blocked != set(LIFECYCLE_STATES) - contactable:
        errors.append(
            "next-action: non-contactable lifecycle states must force eligible=false"
        )


def check_delivery_event(
    artifacts: dict[str, Any], errors: list[str], root: Path
) -> None:
    schema = artifacts["delivery_event"]
    meta = schema["x-delivery-taxonomy"]
    types = schema["properties"]["event_type"]["enum"]
    if types != DELIVERY_EVENT_TYPES or meta["event_types"] != DELIVERY_EVENT_TYPES:
        errors.append(
            "delivery-event: event types must be exactly "
            + ",".join(DELIVERY_EVENT_TYPES)
        )
    if set(meta["signal_class"]) != set(types) or set(meta["effects"]) != set(types):
        errors.append(
            "delivery-event: signal_class and effects must cover every event type"
        )
    signal = meta["signal_class"]
    if (
        signal.get("open") != "weak_engagement"
        or signal.get("read") != "weak_engagement"
        or {signal.get("click"), signal.get("reply")} != {"strong_engagement"}
        or signal.get("conversion") != "conversion"
    ):
        errors.append(
            "delivery-event: opens/reads must be weak; clicks/replies strong; conversions strongest"
        )
    if meta["signal_strength_order"] != ["open", "read", "click", "reply", "conversion"]:
        errors.append("delivery-event: signal strength order changed")
    if (
        meta["effects"]["open"]["lifecycle"] is not None
        or meta["effects"]["read"]["lifecycle"] is not None
    ):
        errors.append("delivery-event: open/read must never change lifecycle state")
    reasons = set(_enum(artifacts["lifecycle"], "TransitionReason"))
    health = set(_enum(artifacts["channel_health"], "ChannelHealthState"))
    for event_type, effect in meta["effects"].items():
        if effect["lifecycle"] is not None and effect["lifecycle"] not in reasons:
            errors.append(
                f"delivery-event: {event_type} lifecycle effect is not a transition reason"
            )
        if (
            effect["channel_health"] is not None
            and effect["channel_health"] not in health
        ):
            errors.append(
                f"delivery-event: {event_type} health effect is not a channel-health state"
            )
        if "suppression" in effect and effect["suppression"]["scope"] != "channel":
            errors.append(
                f"delivery-event: {event_type} must only suppress its own channel"
            )
    if meta["effects_are_channel_local"] is not True:
        errors.append("delivery-event: effects must be channel-local")
    if meta["dedupe"]["identity"] != ["source", "event_id"]:
        errors.append("delivery-event: dedupe identity must be (source, event_id)")
    for field in (
        "source",
        "provider",
        "event_id",
        "schema_version",
        "occurred_at",
        "received_at",
        "payload_hash",
    ):
        if field not in schema["required"]:
            errors.append(f"delivery-event: {field} must be required")
    klyrow = schema["x-source-mappings"]["klyrow"]["event_types"]
    if set(klyrow) != klyrow_delivery_event_types(root):
        errors.append(
            "delivery-event: Klyrow mapping must cover exactly KlyrowDeliveryEvent event types"
        )
    for raw, mapped in klyrow.items():
        if isinstance(mapped, dict):
            classes = mapped["by_bounce_class"]
            if classes.get("unknown") != "hard_bounce" or not set(
                classes.values()
            ) <= set(types):
                errors.append(f"delivery-event: {raw} must fail closed to hard_bounce")
        elif mapped is not None and mapped not in types:
            errors.append(f"delivery-event: {raw} maps to unknown type {mapped}")
    telnexa_schema = json.loads(
        (root / "contracts/telnexa-delivery-event.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    telnexa = schema["x-source-mappings"]["telnexa"]["event_types"]
    if not set(telnexa_schema["properties"]["event_type"]["enum"]) <= set(telnexa):
        errors.append(
            "delivery-event: Telnexa mapping must cover every Telnexa event type"
        )


def check_openapi(artifacts: dict[str, Any], errors: list[str], root: Path) -> None:
    api = artifacts["openapi"]
    if not str(api.get("openapi", "")).startswith("3.1"):
        errors.append("openapi: must be OpenAPI 3.1")
    info = api.get("info", {})
    if (
        info.get("x-codestra-runtime-status") != "contract_only"
        or info.get("x-codestra-implemented") is not False
    ):
        errors.append("openapi: must be declared contract_only and not implemented")
    if "servers" in api:
        errors.append("openapi: contract must not bind a live server")
    operations = {
        (method, path)
        for path, item in api.get("paths", {}).items()
        for method in item
        if method
        in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
    }
    if operations != EXPECTED_OPERATIONS:
        errors.append(
            "openapi: endpoint set must be exact; "
            f"missing={sorted(EXPECTED_OPERATIONS - operations)} extra={sorted(operations - EXPECTED_OPERATIONS)}"
        )
    scopes = set(
        api["components"]["securitySchemes"]["codestraOAuth"]["flows"][
            "clientCredentials"
        ]["scopes"]
    )
    params = api["components"]["parameters"]
    for method, path in sorted(operations & EXPECTED_OPERATIONS):
        operation = api["paths"][path][method]
        names = {
            params[p["$ref"].rsplit("/", 1)[1]]["name"]
            for p in operation.get("parameters", [])
        }
        required = {"X-Tenant-ID", "X-Correlation-ID"}
        if path in EFFECTFUL_POSTS:
            required.add("Idempotency-Key")
        if path == "/platform/v1/delivery-events":
            required |= {
                "X-Codestra-Event-ID",
                "X-Codestra-Timestamp",
                "X-Codestra-Signature",
            }
        if not required <= names:
            errors.append(
                f"openapi: {method.upper()} {path} missing headers {sorted(required - names)}"
            )
        security = operation.get("security", [])
        granted = [
            scope for entry in security for scope in entry.get("codestraOAuth", [])
        ]
        if len(granted) != 1 or granted[0] not in scopes:
            errors.append(
                f"openapi: {method.upper()} {path} needs exactly one declared scope"
            )
        if path in DRY_RUN_OPERATIONS and (
            operation.get("x-codestra-effects") != "none"
            or operation.get("x-codestra-dry-run") != "always"
        ):
            errors.append(f"openapi: {path} must be a dry run with no effects")
        if path in CANDIDATE_DISCLOSURE_OPERATIONS:
            disclosure_scope = operation.get(
                "x-codestra-candidate-disclosure-scope"
            )
            if (
                disclosure_scope != "campaign.engine.candidates.read"
                or disclosure_scope not in scopes
            ):
                errors.append(
                    f"openapi: {method.upper()} {path} must gate candidate "
                    "disclosure with campaign.engine.candidates.read"
                )
        for status, response in operation["responses"].items():
            if status.startswith(("4", "5")) and not response.get(
                "$ref", ""
            ).startswith("#/components/responses/"):
                errors.append(
                    f"openapi: {method.upper()} {path} {status} must use the shared error envelope"
                )
    for ref in _walk_refs(api):
        target, _, pointer = ref.partition("#")
        try:
            document = (
                api
                if not target
                else json.loads(
                    (root / CONTRACT_DIR / target).read_text(encoding="utf-8")
                )
            )
            _pointer(document, pointer)
        except (OSError, KeyError, IndexError, ValueError):
            errors.append(f"openapi: unresolved $ref {ref}")
    for ref in _walk_refs(api):
        target = ref.partition("#")[0]
        if target and not any(
            target == "./" + path.name for path in SCHEMA_FILES.values()
        ):
            errors.append(
                f"openapi: external $ref must target a campaign-recycling schema: {ref}"
            )
    envelope = api["components"]["schemas"]["ErrorEnvelope"]["properties"]["error"]
    if set(envelope["required"]) != http_error_envelope_fields(root):
        errors.append(
            "openapi: error envelope must match contracts/http-conventions.md"
        )
    status = api["components"]["schemas"]["EngineStatus"]["properties"]
    for flag in ("engine_enabled", "execute_enabled", "production_authorized"):
        if status[flag].get("const") is not False:
            errors.append(f"openapi: EngineStatus.{flag} must be pinned false in MCR-A")
    if any(
        value.get("const") is not False
        for value in status["capabilities"]["properties"].values()
    ):
        errors.append(
            "openapi: EngineStatus capabilities must be pinned false in MCR-A"
        )


def check_policy(artifacts: dict[str, Any], errors: list[str], root: Path) -> None:
    policy = artifacts["policy"]
    if (
        policy["runtime_status"] != "contract_only"
        or any(
            policy["production"][flag] is not False
            for flag in (
                "authorized",
                "live_effects_enabled",
                "provider_calls_enabled",
                "execute_enabled",
            )
        )
        or policy["production"]["lock_decision"] != "NO_GO"
    ):
        errors.append("policy: production must remain unauthorized (NO_GO)")
    if policy["fail_closed"]["code_defaults_allowed"] is not False:
        errors.append("policy: code defaults must be forbidden")
    definitions = policy["parameters"]["definitions"]
    profiles = policy["parameters"]["profiles"]
    if set(profiles) != {"test", "staging", "production"}:
        errors.append("policy: profiles must be test, staging, production")

    def expected_leaves() -> set[str]:
        leaves = set()
        for group, spec in definitions.items():
            prefixes = (
                [f"{group}.{c}" for c in policy["channels"]]
                if spec.get("per_channel")
                else [group]
            )
            leaves |= {
                f"{prefix}.{field}" for prefix in prefixes for field in spec["fields"]
            }
        return leaves

    def leaves(values: dict[str, Any], prefix: str = "") -> dict[str, Any]:
        found: dict[str, Any] = {}
        for key, value in values.items():
            path = f"{prefix}{key}"
            found.update(
                leaves(value, path + ".") if isinstance(value, dict) else {path: value}
            )
        return found

    expected = expected_leaves()
    for name, profile in profiles.items():
        values = leaves(profile["values"])
        if set(values) != expected:
            errors.append(f"policy: profile {name} parameters differ from definitions")
            continue
        if name in {"staging", "production"}:
            if any(value is not None for value in values.values()):
                errors.append(
                    f"policy: profile {name} must stay unconfigured (null) in MCR-A"
                )
            continue
        for leaf, value in values.items():
            parts = leaf.split(".")
            spec = definitions[parts[0]]["fields"][parts[-1]]
            if spec["type"] == "boolean":
                valid = isinstance(value, bool) and (
                    "const" not in spec or value == spec["const"]
                )
            else:
                valid = (
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= spec["minimum"]
                )
            if not valid:
                errors.append(
                    f"policy: test value {leaf}={value!r} violates its definition"
                )
    test = profiles["test"]["values"]
    exposure = test["exposure"]
    if not (
        exposure["max_recent_all_campaigns"] <= exposure["max_lifetime_all_campaigns"]
        and exposure["max_lifetime_per_campaign"]
        <= exposure["max_lifetime_all_campaigns"]
        and test["campaign"]["max_touches_per_version"]
        <= exposure["max_lifetime_per_campaign"]
    ):
        errors.append("policy: test exposure caps are internally inconsistent")
    if profiles["test"]["tenant_binding"] != [
        "TEST_SYN_TENANT",
        "TEST_SYN",
        "TEST_SYN",
    ]:
        errors.append("policy: test profile must stay bound to TEST_SYN")
    commands = communications_channel_commands(root)
    capabilities = json.loads(
        (root / "config/capabilities.v2.json").read_text(encoding="utf-8")
    )
    for channel, execution in policy["channel_execution"].items():
        capability = execution["capability"]
        capability_value = capabilities["capabilities"].get(capability)
        pending = execution["execution"] == "blocked_pending_dependency"
        if pending:
            if capability_value not in (None, False):
                errors.append(
                    f"policy: pending {channel} capability {capability} must be absent or disabled"
                )
            dependency = execution.get("dependency", {})
            if dependency.get("kind") != "github_pr" or not dependency.get("url"):
                errors.append(
                    f"policy: pending {channel} needs an explicit GitHub PR dependency"
                )
        elif capability_value is not False:
            errors.append(
                f"policy: {channel} capability {capability} must exist and be disabled"
            )
        if channel in commands:
            command_type, adapter, cap, provider = commands[channel]
            if (
                execution["command_type"],
                execution["adapter"],
                capability,
                execution["provider_key"],
            ) != (command_type, adapter, cap, provider):
                errors.append(
                    f"policy: {channel} execution drifted from CHANNEL_COMMAND"
                )
        elif pending:
            if not all(
                isinstance(execution.get(field), str) and execution[field]
                for field in ("command_type", "adapter", "capability", "provider_key")
            ):
                errors.append(
                    f"policy: pending {channel} execution contract is incomplete"
                )
        elif (
            execution["execution"] != "not_supported_in_v1"
            or execution["command_type"] is not None
        ):
            errors.append(
                f"policy: {channel} has no communications command and must be unsupported or dependency-blocked"
            )
    if set(policy["channel_execution"]) != set(policy["channels"]):
        errors.append("policy: channel_execution must cover every channel")
    sender = policy["sender_identity"]
    if (
        sender["selection"] != "policy_governed"
        or any(
            sender[flag] is not False
            for flag in (
                "rotation_for_deliverability_evasion",
                "per_touch_rotation",
                "lookalike_or_throwaway_domains",
            )
        )
        or not (
            sender["require_brand_or_campaign_owned"]
            and sender["require_channel_verified_identity"]
        )
    ):
        errors.append(
            "policy: sender identity must be legitimate, authenticated, and never rotated for evasion"
        )


def check_authority(artifacts: dict[str, Any], errors: list[str], root: Path) -> None:
    authority = artifacts["authority"]
    if authority["runtime_status"] != "contract_only" or any(
        v is not False
        for k, v in authority["production"].items()
        if k != "lock_decision"
    ):
        errors.append("authority: every production/runtime flag must be false")
    for path in authority["artifacts"].values():
        if not (root / path).is_file():
            errors.append(f"authority: missing artifact {path}")
    foundations = {item["path"] for item in authority["reused_foundations"]}
    if not MISSION_FOUNDATIONS <= foundations:
        errors.append(
            f"authority: must reference foundations {sorted(MISSION_FOUNDATIONS - foundations)}"
        )
    for path in foundations:
        if not (root / path).exists():
            errors.append(f"authority: referenced foundation does not exist: {path}")
    systems = authority["systems"]
    if set(systems) != REQUIRED_SYSTEMS:
        errors.append(f"authority: systems must be exactly {sorted(REQUIRED_SYSTEMS)}")
    ownership = json.loads(
        (root / "config/system-ownership.v2.json").read_text(encoding="utf-8")
    )["systems"]
    for name, system in systems.items():
        if set(system["owns"]) & set(system["forbidden"]):
            errors.append(f"authority: {name} both owns and is forbidden the same item")
        platform = ownership.get(name)
        if platform and set(system["owns"]) & set(platform["forbidden"]):
            errors.append(
                f"authority: {name} claims items forbidden by system-ownership.v2.json"
            )
    required_forbidden = {
        "n8n": {"policy_decisioning", "direct_provider_write", "suppression_override"},
        "thunderbird": {"automated_sending", "campaign_touches"},
        "observability": {"policy_decisioning"},
    }
    for name, items in required_forbidden.items():
        if not items <= set(systems.get(name, {}).get("forbidden", [])):
            errors.append(f"authority: {name} must forbid {sorted(items)}")
    if (
        "policy_decisioning" not in systems["middleware"]["owns"]
        or "lifecycle_state" not in systems["leads"]["owns"]
    ):
        errors.append(
            "authority: middleware must own decisioning and leads must own lifecycle"
        )
    for key, entry in authority["artifact_authority"].items():
        if entry["system_of_record"] not in systems or not set(entry["writers"]) <= set(
            systems
        ):
            errors.append(f"authority: {key} references an unknown system")
    for key in SCHEMA_FILES:
        declared = artifacts[key]["x-codestra-contract"]["system_of_record"]
        if authority["artifact_authority"][key]["system_of_record"] != declared:
            errors.append(
                f"authority: {key} system_of_record disagrees with its schema"
            )
    rule = authority["sender_identity_rule"]
    if (
        rule["rotation_for_deliverability_evasion"] is not False
        or rule["selection"] != "policy_governed"
        or rule["auditable"] is not True
    ):
        errors.append(
            "authority: sender identity rule must forbid evasion and stay auditable"
        )


def check_documentation(artifacts: dict[str, Any], errors: list[str]) -> None:
    doc = artifacts["doc"]
    required = [
        *LIFECYCLE_STATES,
        *(f"`{s}`" for s in CHANNEL_HEALTH_STATES),
        *(f"`{c}`" for c in DESIRED_CHANNELS),
        *(f"`{t}`" for t in DELIVERY_EVENT_TYPES),
        *(f"{m.upper()} {p}" for m, p in EXPECTED_OPERATIONS),
        *(f"`{c}`" for c in _enum(artifacts["next_action"], "ReasonCode")),
        *MISSION_FOUNDATIONS,
    ]
    missing = [item for item in required if item not in doc]
    if missing:
        errors.append(f"doc: missing required references {missing}")


def check_no_runtime_activation(
    artifacts: dict[str, Any], errors: list[str], root: Path
) -> None:
    for pattern in RUNTIME_SCAN_GLOBS:
        for path in sorted(root.glob(pattern)):
            if not path.is_file():
                continue
            relative = path.relative_to(root)
            if relative == PURE_DOMAIN_MODULE:
                if not _pure_domain_module_is_safe(path):
                    errors.append(
                        "runtime: app/core/campaign_recycling.py violates the pure-domain boundary"
                    )
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            hits = [marker for marker in RUNTIME_MARKERS if marker in text]
            if hits:
                errors.append(
                    f"runtime: {relative} references MCR-A surface {hits}"
                )
    serialized = (
        json.dumps({k: v for k, v in artifacts.items() if k != "doc"})
        + artifacts["doc"]
    )
    for marker in ("secret://", "-----BEGIN", "Bearer ey"):
        if marker in serialized:
            errors.append(
                f"secrets: artifacts must not contain secret material ({marker})"
            )


def validate(artifacts: dict[str, Any] | None = None, root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    try:
        artifacts = artifacts if artifacts is not None else load_artifacts(root)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [f"load: {exc}"]
    checks = (
        lambda: check_schemas(artifacts, errors),
        lambda: check_lifecycle(artifacts, errors, root),
        lambda: check_channel_health(artifacts, errors, root),
        lambda: check_exposure(artifacts, errors, root),
        lambda: check_next_action(artifacts, errors),
        lambda: check_delivery_event(artifacts, errors, root),
        lambda: check_openapi(artifacts, errors, root),
        lambda: check_policy(artifacts, errors, root),
        lambda: check_authority(artifacts, errors, root),
        lambda: check_documentation(artifacts, errors),
        lambda: check_no_runtime_activation(artifacts, errors, root),
    )
    for check in checks:
        try:
            check()
        except (KeyError, TypeError, IndexError, LookupError, StopIteration) as exc:
            errors.append(f"structure: {type(exc).__name__}: {exc}")
    return errors


def main() -> int:
    errors = validate()
    for error in errors:
        print(f"CAMPAIGN_RECYCLING_CONTRACT_ERROR={error}", file=sys.stderr)
    if errors:
        print("CAMPAIGN_RECYCLING_CONTRACTS=FAIL")
        return 1
    print("CAMPAIGN_RECYCLING_CONTRACTS=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
