from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

DEFAULT_POLICY_PATH = (
    Path(__file__).resolve().parents[1]
    / "contracts"
    / "automation"
    / "operation-policy.v2.json"
)

FORBIDDEN_GENERIC_SCOPES = frozenset(
    {
        "*",
        "execute",
        "command",
        "automation.execute",
        "automation.command",
        "middleware.execute",
        "middleware.command",
    }
)
EXPECTED_INVARIANTS: dict[str, bool] = {
    "generic_execute_scope_allowed": False,
    "generic_command_scope_allowed": False,
    "client_can_claim_other_family": False,
    "caller_tenant_authoritative": False,
    "caller_actor_authoritative": False,
    "active_lease_required_for_steps_and_commands": True,
    "public_provider_callbacks_to_n8n": False,
    "workflow_activation_enables_capability": False,
    "live_apply_authorized": False,
}
EXPECTED_CONTEXT: dict[str, Any] = {
    "tenant": "automation_job.tenant_id",
    "actor": "automation_job.actor_context",
    "workflow_family": "automation_job.workflow_family",
    "workflow_version": "automation_job.workflow_version",
    "caller_tenant_assertion_authoritative": False,
    "caller_actor_assertion_authoritative": False,
}
EXPECTED_CLIENT_IDS = frozenset(
    {
        "n8n-platform-runtime",
        "n8n-identity-automation",
        "n8n-crm-automation",
        "n8n-telephony-automation",
        "n8n-messaging-automation",
        "n8n-social-automation",
        "n8n-crawler-automation",
        "n8n-product-automation",
        "n8n-privacy-automation",
        "n8n-operations-automation",
    }
)
EXPECTED_OPERATION_IDS = frozenset(
    {
        "POST /v2/automation/jobs/claim",
        "GET /v2/automation/jobs/{job_id}",
        "POST /v2/automation/jobs/{job_id}/heartbeat",
        "POST /v2/automation/jobs/{job_id}/steps",
        "POST /v2/automation/jobs/{job_id}/complete",
        "POST /v2/automation/jobs/{job_id}/fail",
        "POST /v2/automation/commands",
        "GET /v2/automation/commands/{command_id}",
        "POST /v2/automation/approvals",
        "GET /v2/automation/approvals/{approval_id}",
        "POST /v2/automation/dead-letters/{dead_letter_id}/replay",
        "POST /v2/automation/jobs/reconcile",
        "GET /v2/automation/capabilities/{capability}",
    }
)


class AutomationPolicyError(RuntimeError):
    """The source policy is malformed or internally contradictory."""


class AutomationAuthorizationError(RuntimeError):
    """A verified machine identity is not authorized by the source policy."""


@dataclass(frozen=True)
class AutomationClientPolicy:
    client_id: str
    workflow_families: frozenset[str]
    command_prefixes: tuple[str, ...]
    scopes: frozenset[str]


@dataclass(frozen=True)
class CommandFamilyPolicy:
    prefix: str
    scope: str
    client_id: str
    workflow_families: frozenset[str]


@dataclass(frozen=True)
class OperationPolicy:
    method: str
    path: str
    scope: str
    allowed_clients: str | tuple[str, ...]
    required_fields: tuple[str, ...]
    constraints: tuple[str, ...]

    @property
    def operation_id(self) -> str:
        return f"{self.method} {self.path}"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AutomationPolicyError(message)


def _strings(value: Any, *, label: str, allow_empty: bool = False) -> tuple[str, ...]:
    _require(isinstance(value, list), f"{label} must be a list")
    _require(
        all(isinstance(item, str) and item and item.strip() == item for item in value),
        f"{label} must contain normalized strings",
    )
    result = tuple(value)
    _require(len(result) == len(set(result)), f"{label} contains duplicates")
    _require(allow_empty or bool(result), f"{label} must not be empty")
    return result


def _is_generic(scope: str) -> bool:
    return scope in FORBIDDEN_GENERIC_SCOPES or "*" in scope


def _token_scopes(value: Any) -> frozenset[str]:
    if isinstance(value, str):
        raw = value.split()
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        raw = value
    else:
        raise AutomationAuthorizationError("token scope claim is missing or malformed")
    if not raw or len(raw) != len(set(raw)):
        raise AutomationAuthorizationError("token scopes must be non-empty and unique")
    if any(not item or item.strip() != item for item in raw):
        raise AutomationAuthorizationError("token scopes must be normalized")
    generic = sorted(item for item in raw if _is_generic(item))
    if generic:
        raise AutomationAuthorizationError(
            "generic or wildcard machine scopes are prohibited: " + ", ".join(generic)
        )
    return frozenset(raw)


class AutomationPolicy:
    def __init__(
        self,
        *,
        source: Mapping[str, Any],
        clients: Mapping[str, AutomationClientPolicy],
        operations: tuple[OperationPolicy, ...],
        command_families: tuple[CommandFamilyPolicy, ...],
    ) -> None:
        self.source = dict(source)
        self.schema_version = str(source.get("schema_version", ""))
        self.status = str(source.get("status", ""))
        self.issuer = str(source.get("issuer", ""))
        self.audience = str(source.get("audience", ""))
        self.maximum_access_token_lifetime_seconds = source.get(
            "maximum_access_token_lifetime_seconds"
        )
        self.scope_resolution = str(source.get("scope_resolution", ""))
        self.authoritative_context = dict(source.get("authoritative_context", {}))
        self.product_boundaries = dict(source.get("product_boundaries", {}))
        self.invariants = dict(source.get("invariants", {}))
        self.clients = dict(clients)
        self.operations = operations
        self.command_families = command_families
        self._families = tuple(
            sorted(command_families, key=lambda family: len(family.prefix), reverse=True)
        )

    @classmethod
    def from_path(cls, path: Path = DEFAULT_POLICY_PATH) -> "AutomationPolicy":
        try:
            return cls.from_mapping(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            raise AutomationPolicyError(f"cannot load automation policy: {path}") from exc

    @classmethod
    def from_mapping(cls, raw: Any) -> "AutomationPolicy":
        _require(isinstance(raw, dict), "automation policy must be an object")
        clients_raw = raw.get("clients")
        _require(isinstance(clients_raw, dict), "clients must be an object")
        clients: dict[str, AutomationClientPolicy] = {}
        for client_id, value in clients_raw.items():
            _require(
                isinstance(client_id, str) and bool(client_id) and "*" not in client_id,
                "invalid automation client ID",
            )
            _require(isinstance(value, dict), f"{client_id}: policy must be an object")
            scopes = _strings(value.get("scopes"), label=f"{client_id}.scopes")
            _require(
                not any(_is_generic(scope) for scope in scopes),
                f"{client_id}: generic scopes are prohibited",
            )
            clients[client_id] = AutomationClientPolicy(
                client_id=client_id,
                workflow_families=frozenset(
                    _strings(
                        value.get("workflow_families"),
                        label=f"{client_id}.workflow_families",
                    )
                ),
                command_prefixes=_strings(
                    value.get("command_prefixes"),
                    label=f"{client_id}.command_prefixes",
                    allow_empty=True,
                ),
                scopes=frozenset(scopes),
            )

        operations_raw = raw.get("operations")
        _require(isinstance(operations_raw, list), "operations must be a list")
        operations: list[OperationPolicy] = []
        for index, value in enumerate(operations_raw):
            _require(isinstance(value, dict), f"operations[{index}] must be an object")
            allowed = value.get("allowed_clients")
            allowed_clients: str | tuple[str, ...]
            if isinstance(allowed, str):
                allowed_clients = allowed
            else:
                allowed_clients = _strings(
                    allowed,
                    label=f"operations[{index}].allowed_clients",
                )
            operations.append(
                OperationPolicy(
                    method=str(value.get("method", "")),
                    path=str(value.get("path", "")),
                    scope=str(value.get("scope", "")),
                    allowed_clients=allowed_clients,
                    required_fields=_strings(
                        value.get("required_fields", []),
                        label=f"operations[{index}].required_fields",
                        allow_empty=True,
                    ),
                    constraints=_strings(
                        value.get("constraints"),
                        label=f"operations[{index}].constraints",
                    ),
                )
            )

        families_raw = raw.get("command_families")
        _require(isinstance(families_raw, list), "command_families must be a list")
        families: list[CommandFamilyPolicy] = []
        for index, value in enumerate(families_raw):
            _require(isinstance(value, dict), f"command_families[{index}] must be an object")
            families.append(
                CommandFamilyPolicy(
                    prefix=str(value.get("prefix", "")),
                    scope=str(value.get("scope", "")),
                    client_id=str(value.get("client", "")),
                    workflow_families=frozenset(
                        _strings(
                            value.get("workflow_families"),
                            label=f"command_families[{index}].workflow_families",
                        )
                    ),
                )
            )

        policy = cls(
            source=raw,
            clients=clients,
            operations=tuple(operations),
            command_families=tuple(families),
        )
        policy.assert_contract_invariants()
        return policy

    def assert_contract_invariants(self) -> None:
        _require(self.schema_version == "2.2", "automation schema must remain 2.2")
        _require(self.status == "SOURCE_ONLY", "automation policy must remain SOURCE_ONLY")
        _require(
            self.issuer == "https://auth.codestra.co/realms/codestra",
            "automation issuer drift",
        )
        _require(self.audience == "middleware-api", "automation audience drift")
        _require(
            self.maximum_access_token_lifetime_seconds == 300,
            "machine token lifetime must remain 300 seconds",
        )
        _require(
            self.scope_resolution == "client_scopes_are_exact_no_implicit_union",
            "scope resolution must remain exact",
        )
        _require(self.authoritative_context == EXPECTED_CONTEXT, "authoritative context drift")
        _require(self.invariants == EXPECTED_INVARIANTS, "automation invariant set drift")
        _require(set(self.clients) == EXPECTED_CLIENT_IDS, "automation client set drift")

        operation_ids = [operation.operation_id for operation in self.operations]
        _require(set(operation_ids) == EXPECTED_OPERATION_IDS, "automation operation set drift")
        _require(len(operation_ids) == len(set(operation_ids)), "duplicate operation IDs")
        for operation in self.operations:
            _require(
                operation.method == operation.method.upper()
                and operation.path.startswith("/v2/automation/")
                and bool(operation.scope),
                f"invalid operation: {operation.operation_id}",
            )
            if isinstance(operation.allowed_clients, tuple):
                _require(
                    not (set(operation.allowed_clients) - set(self.clients)),
                    f"{operation.operation_id}: unknown client",
                )

        prefixes = [family.prefix for family in self.command_families]
        _require(len(prefixes) == 18, "exactly eighteen command families are required")
        _require(len(prefixes) == len(set(prefixes)), "duplicate command prefix")
        for left in prefixes:
            _require(left.endswith(".") and "*" not in left, f"invalid prefix: {left}")
            _require(
                all(left == right or not right.startswith(left) for right in prefixes),
                f"ambiguous command prefix: {left}",
            )

        observed_prefixes: dict[str, set[str]] = {client_id: set() for client_id in self.clients}
        declared_scopes = set().union(*(client.scopes for client in self.clients.values()))
        for family in self.command_families:
            client = self.clients.get(family.client_id)
            if client is None:
                raise AutomationPolicyError(f"unknown command client: {family.client_id}")
            _require(
                family.scope.startswith("automation.command.")
                and not _is_generic(family.scope)
                and family.scope in client.scopes,
                f"{family.prefix}: command scope drift",
            )
            _require(
                family.workflow_families <= client.workflow_families,
                f"{family.prefix}: workflow family escapes client",
            )
            observed_prefixes[family.client_id].add(family.prefix)
        for client_id, client in self.clients.items():
            _require(
                set(client.command_prefixes) == observed_prefixes[client_id],
                f"{client_id}: command prefix registry drift",
            )
        for operation in self.operations:
            _require(
                operation.scope == "resolved_from_command_prefix"
                or operation.scope in declared_scopes,
                f"{operation.operation_id}: unassigned scope",
            )

        for client_id in ("n8n-platform-runtime", "n8n-operations-automation"):
            _require(
                not self.clients[client_id].command_prefixes,
                f"{client_id} cannot issue commands",
            )
        for client_id, client in self.clients.items():
            privileged = {
                scope
                for scope in client.scopes
                if scope.startswith("automation.operations.")
                or scope.startswith("automation.dead-letter.")
            }
            _require(
                bool(privileged) == (client_id == "n8n-operations-automation"),
                f"{client_id}: operations scope isolation drift",
            )

        command = self.operation("POST", "/v2/automation/commands")
        _require(
            {
                "active_lease_required",
                "command_prefix_scope_match",
                "tenant_and_actor_derived_server_side",
                "capability_rechecked_before_effect",
                "exact_replay_returns_original",
                "semantic_conflict_rejected",
            }
            <= set(command.constraints),
            "automation command constraints drift",
        )
        for name, boundary in self.product_boundaries.items():
            _require(isinstance(boundary, dict), f"{name}: boundary must be an object")
            for flag in ("financial_effects_allowed", "demo_order_effects_allowed"):
                _require(boundary.get(flag) is not True, f"{name}: {flag} must remain false")

    def operation(self, method: str, path: str) -> OperationPolicy:
        operation_id = f"{method.upper()} {path}"
        for operation in self.operations:
            if operation.operation_id == operation_id:
                return operation
        raise AutomationPolicyError(f"unknown automation operation: {operation_id}")

    def client(self, client_id: str) -> AutomationClientPolicy:
        client = self.clients.get(client_id)
        if client is None:
            raise AutomationAuthorizationError("automation client is not declared")
        return client

    def authorize_token(
        self,
        claims: Mapping[str, Any],
        *,
        required_scope: str,
    ) -> AutomationClientPolicy:
        if claims.get("iss") != self.issuer:
            raise AutomationAuthorizationError("token issuer does not match automation policy")
        audience = claims.get("aud")
        if audience != self.audience and audience != [self.audience]:
            raise AutomationAuthorizationError("token audience does not match automation policy")
        client_id = claims.get("azp")
        if not isinstance(client_id, str):
            raise AutomationAuthorizationError("token azp is missing")
        client = self.client(client_id)
        scopes = _token_scopes(claims.get("scope"))
        undeclared = scopes - client.scopes
        if undeclared:
            raise AutomationAuthorizationError(
                "token contains scopes not declared for its client: "
                + ", ".join(sorted(undeclared))
            )
        if required_scope not in scopes:
            raise AutomationAuthorizationError("required exact automation scope is missing")
        return client

    def authorize_job_family(
        self,
        claims: Mapping[str, Any],
        *,
        required_scope: str,
        workflow_family: str,
    ) -> AutomationClientPolicy:
        client = self.authorize_token(claims, required_scope=required_scope)
        if workflow_family not in client.workflow_families:
            raise AutomationAuthorizationError(
                "automation client cannot act on another workflow family"
            )
        return client

    def resolve_command_family(self, command_type: str) -> CommandFamilyPolicy:
        if not isinstance(command_type, str) or not command_type:
            raise AutomationAuthorizationError("command_type is required")
        for family in self._families:
            if command_type.startswith(family.prefix):
                return family
        raise AutomationAuthorizationError("command type has no declared command family")

    def authorize_command(
        self,
        claims: Mapping[str, Any],
        *,
        command_type: str,
        workflow_family: str,
    ) -> CommandFamilyPolicy:
        family = self.resolve_command_family(command_type)
        client = self.authorize_token(claims, required_scope=family.scope)
        if client.client_id != family.client_id:
            raise AutomationAuthorizationError(
                "automation client cannot issue another command family's command"
            )
        if workflow_family not in family.workflow_families:
            raise AutomationAuthorizationError(
                "command type is not valid for the job workflow family"
            )
        return family
