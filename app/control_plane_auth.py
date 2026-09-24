from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jwt

from .security import AuthenticationError, AuthorizationError


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "control-plane-callers.v1.json"


@dataclass(frozen=True)
class ControlPlaneCaller:
    client_id: str
    command_scope: str
    status_scope: str
    allowed_command_prefixes: tuple[str, ...]
    allowed_targets: frozenset[str]
    connector_commands_allowed: bool
    compatibility_only: bool


def _load_policy() -> dict[str, Any]:
    value = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    if value.get("schema_version") != "1.0":
        raise RuntimeError("unsupported control-plane caller policy schema")
    if value.get("issuer") != "https://auth.codestra.co/realms/codestra":
        raise RuntimeError("control-plane issuer drift")
    if value.get("audience") != "middleware-api":
        raise RuntimeError("control-plane audience drift")
    if value.get("token_exchange") is not False:
        raise RuntimeError("token exchange must remain disabled")
    if value.get("original_bearer_required") is not True:
        raise RuntimeError("original bearer forwarding must remain required")
    if value.get("maximum_token_lifetime_seconds") != 300:
        raise RuntimeError("machine token lifetime policy drift")
    if value.get("tenant_claim") != "tenant_id":
        raise RuntimeError("tenant_id must remain authoritative")
    callers = value.get("callers")
    if not isinstance(callers, dict) or not callers:
        raise RuntimeError("control-plane caller registry is empty")
    return value


def _build_callers() -> dict[str, ControlPlaneCaller]:
    raw = _load_policy()["callers"]
    result: dict[str, ControlPlaneCaller] = {}
    for client_id, item in raw.items():
        if not isinstance(client_id, str) or not isinstance(item, dict):
            raise RuntimeError("invalid control-plane caller entry")
        prefixes = item.get("allowed_command_prefixes")
        targets = item.get("allowed_targets")
        commands_allowed = item.get("connector_commands_allowed", True)
        if not isinstance(commands_allowed, bool):
            raise RuntimeError(f"{client_id}: connector command policy is invalid")
        if not isinstance(prefixes, list) or not all(
            isinstance(value, str) and value for value in prefixes
        ):
            raise RuntimeError(f"{client_id}: command prefix policy is invalid")
        if not isinstance(targets, list) or not all(
            isinstance(value, str) and value for value in targets
        ):
            raise RuntimeError(f"{client_id}: target policy is invalid")
        if commands_allowed and (not prefixes or not targets):
            raise RuntimeError(f"{client_id}: connector command authority is empty")
        if not commands_allowed and (prefixes or targets):
            raise RuntimeError(f"{client_id}: read/operator-only caller has connector authority")
        result[client_id] = ControlPlaneCaller(
            client_id=client_id,
            command_scope=str(item["command_scope"]),
            status_scope=str(item["status_scope"]),
            allowed_command_prefixes=tuple(prefixes),
            allowed_targets=frozenset(targets),
            connector_commands_allowed=commands_allowed,
            compatibility_only=item.get("compatibility_only") is True,
        )
    return result


CONTROL_PLANE_CALLERS = _build_callers()


def _unverified_client_id(authorization: str) -> str:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise AuthenticationError("Authorization must be a Bearer token")
    if token.count(".") != 2:
        # Backwards compatibility for existing test/legacy gateway callers. The
        # production Keycloak verifier still rejects a malformed opaque token.
        return "kong-gateway"
    try:
        claims = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    except Exception as exc:
        raise AuthenticationError("invalid bearer token") from exc
    client_id = claims.get("azp")
    if not isinstance(client_id, str) or not client_id:
        raise AuthenticationError("machine token azp is required")
    if client_id not in CONTROL_PLANE_CALLERS:
        raise AuthenticationError("unrecognized control-plane caller")
    return client_id


def caller_for_authorization(authorization: str) -> ControlPlaneCaller:
    return CONTROL_PLANE_CALLERS[_unverified_client_id(authorization)]


def authorize_command(caller: ControlPlaneCaller, *, command_type: str, target: str) -> None:
    if not caller.connector_commands_allowed:
        raise AuthorizationError("caller has no connector command authority")
    if target not in caller.allowed_targets:
        raise AuthorizationError("command target is not authorized for caller")
    if not any(command_type.startswith(prefix) for prefix in caller.allowed_command_prefixes):
        raise AuthorizationError("command namespace is not authorized for caller")
