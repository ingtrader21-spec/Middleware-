"""The verified principal of a kernel request.

Nothing here is taken from the request body: the client is the token's
``azp`` (which must be a registered control-plane caller), the subject is
``sub``, the tenants are the token's ``tenant_id``/``tenant_ids`` claims, the
roles come from Keycloak's ``realm_access``/``resource_access`` (or a flat
``roles`` claim) and the scopes from ``scope``. The JWT itself is verified by
the RuntimeContainer's :class:`~app.security.KeycloakJwtVerifier` (RS256
only, exact issuer, exact audience, bounded lifetime).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Mapping

from fastapi import Request

from app.api_inputs import authorization_header
from app.control_plane_auth import ControlPlaneCaller, caller_for_authorization
from app.security import AuthorizationError

MAX_TENANTS = 64
MAX_ROLES = 64
MAX_SCOPES = 128
# The synthetic TEST_SYN family is a kernel construct (policy registered at
# runtime outside production, no connector manifest). Its caller authority is
# granted here to the platform's own workload identity, never through the
# static caller registry and never in production.
SYNTHETIC_CALLERS = frozenset({"middleware-api"})
SYNTHETIC_ENVIRONMENTS = frozenset({"development", "test", "staging", "preproduction"})
SYNTHETIC_PREFIX = "test.syn."
SYNTHETIC_TARGET = "test-syn"


def with_synthetic_authority(caller: ControlPlaneCaller, environment: str) -> ControlPlaneCaller:
    if environment not in SYNTHETIC_ENVIRONMENTS or caller.client_id not in SYNTHETIC_CALLERS:
        return caller
    return replace(
        caller,
        allowed_command_prefixes=tuple(dict.fromkeys((*caller.allowed_command_prefixes, SYNTHETIC_PREFIX))),
        allowed_targets=frozenset(caller.allowed_targets | {SYNTHETIC_TARGET}),
        connector_commands_allowed=True,
    )


class PrincipalType(StrEnum):
    HUMAN = "HUMAN"
    SERVICE = "SERVICE"
    WORKLOAD = "WORKLOAD"
    SYSTEM = "SYSTEM"


@dataclass(frozen=True)
class KernelPrincipal:
    subject: str
    client_id: str
    tenants: tuple[str, ...]
    roles: tuple[str, ...]
    scopes: tuple[str, ...]
    caller: ControlPlaneCaller
    principal_type: PrincipalType = PrincipalType.HUMAN
    actor_id: str | None = None
    service_id: str | None = None
    campaigns: tuple[str, ...] = ()

    def authorized_for(self, tenant_id: str) -> bool:
        return "*" not in self.tenants and tenant_id in self.tenants

    @property
    def principal_id(self) -> str:
        return self.actor_id or self.service_id or self.subject


def _string_items(value: Any, *, limit: int) -> tuple[str, ...]:
    if isinstance(value, str):
        items = value.split()
    elif isinstance(value, list):
        items = [item for item in value if isinstance(item, str)]
    else:
        return ()
    cleaned = tuple(dict.fromkeys(item.strip() for item in items if item.strip()))
    if len(cleaned) > limit:
        raise AuthorizationError("token claim exceeds the allowed cardinality")
    return cleaned


def roles_from_claims(claims: Mapping[str, Any], client_id: str) -> tuple[str, ...]:
    roles: list[str] = []
    realm = claims.get("realm_access")
    if isinstance(realm, Mapping):
        roles.extend(_string_items(realm.get("roles"), limit=MAX_ROLES))
    resource = claims.get("resource_access")
    if isinstance(resource, Mapping):
        own = resource.get(client_id)
        if isinstance(own, Mapping):
            roles.extend(_string_items(own.get("roles"), limit=MAX_ROLES))
        api = resource.get("middleware-api")
        if isinstance(api, Mapping):
            roles.extend(_string_items(api.get("roles"), limit=MAX_ROLES))
    roles.extend(_string_items(claims.get("roles"), limit=MAX_ROLES))
    unique = tuple(dict.fromkeys(roles))
    if len(unique) > MAX_ROLES:
        raise AuthorizationError("token carries too many roles")
    return unique


def tenants_from_claims(claims: Mapping[str, Any]) -> tuple[str, ...]:
    tenants: list[str] = []
    single = claims.get("tenant_id")
    if isinstance(single, str) and single.strip():
        tenants.append(single.strip())
    tenants.extend(_string_items(claims.get("tenant_ids"), limit=MAX_TENANTS))
    unique = tuple(dict.fromkeys(tenants))
    if "*" in unique:
        raise AuthorizationError("wildcard tenant authorization is prohibited")
    return unique


def principal_from_claims(claims: Mapping[str, Any], caller: ControlPlaneCaller, *, environment: str | None = None) -> KernelPrincipal:
    if environment is not None:
        caller = with_synthetic_authority(caller, environment)
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise AuthorizationError("token subject is required")
    if len(subject) > 300:
        raise AuthorizationError("token subject is malformed")
    client_id = claims.get("azp")
    if client_id != caller.client_id:
        raise AuthorizationError("token azp does not match the authenticated caller")
    username = claims.get("preferred_username")
    explicit_type = str(claims.get("principal_type", "")).upper()
    if explicit_type in PrincipalType.__members__:
        principal_type = PrincipalType[explicit_type]
    elif isinstance(username, str) and username.startswith("service-account-"):
        principal_type = PrincipalType.SERVICE
    elif caller.client_id in {"middleware-worker", "provisioning-service", "automation-service"}:
        principal_type = PrincipalType.WORKLOAD
    else:
        principal_type = PrincipalType.HUMAN
    campaigns = _string_items(claims.get("campaign_ids") or claims.get("campaigns"), limit=MAX_TENANTS)
    return KernelPrincipal(
        subject=subject.strip(),
        client_id=caller.client_id,
        tenants=tenants_from_claims(claims),
        roles=roles_from_claims(claims, caller.client_id),
        scopes=_string_items(claims.get("scope"), limit=MAX_SCOPES),
        caller=caller,
        principal_type=principal_type,
        actor_id=subject.strip() if principal_type is PrincipalType.HUMAN else None,
        service_id=caller.client_id if principal_type is not PrincipalType.HUMAN else None,
        campaigns=campaigns,
    )


async def authenticate(request: Request, *, required_scope: str) -> KernelPrincipal:
    """Steps 3–6 of the canonical sequence: JWT, issuer, audience, client."""
    authorization = authorization_header(request)
    caller = caller_for_authorization(authorization)
    claims = await request.app.state.runtime.tokens.verify(
        authorization,
        expected_client_id=caller.client_id,
        required_scope=required_scope,
    )
    return principal_from_claims(claims, caller, environment=request.app.state.runtime.settings.app_env)

@dataclass(frozen=True)
class RequestSecurityContext:
    principal: KernelPrincipal
    tenant_id: str
    request_id: str
    correlation_id: str
    causation_id: str | None
    environment: str
    source: str = "http"

@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    decision_code: str
    principal_id: str
    tenant_id: str
    resource: str
    action: str
    required_scopes: tuple[str, ...]
    matched_policy: str | None = None
    effect_class: str = "read"

ROLE_PERMISSIONS = {
    "platform_admin": frozenset({"*"}),
    "integration_administrator": frozenset({"connector.*", "command.*", "reconcile.*"}),
    "tenant_admin": frozenset({"command.*", "automation.*", "provisioning.*", "connector.read"}),
    "campaign_supervisor": frozenset({"command.create", "command.read", "automation.execute"}),
    "agent": frozenset({"command.create", "command.read"}),
    "service_client": frozenset({"command.create", "command.read"}),
    "read_only_auditor": frozenset({"command.read", "connector.read", "service.read"}),
    "automation_service": frozenset({"automation.*", "command.create", "command.read"}),
    "provisioning_service": frozenset({"provisioning.*", "command.create", "command.read"}),
}

def authorize(principal: KernelPrincipal, *, action: str, resource: str, tenant_id: str,
              required_scopes: tuple[str, ...] = (), campaign_id: str | None = None,
              effect_class: str = "read", environment: str = "production") -> AuthorizationDecision:
    """Canonical default-deny resource/effect authorization decision."""
    args=(principal.principal_id, tenant_id, resource, action, required_scopes)
    if not principal.authorized_for(tenant_id):
        return AuthorizationDecision(False, "TENANT_MISMATCH", *args, effect_class=effect_class)
    if required_scopes and not set(required_scopes).issubset(principal.scopes):
        return AuthorizationDecision(False, "SCOPE_REQUIRED", *args, effect_class=effect_class)
    if campaign_id and principal.campaigns and campaign_id not in principal.campaigns:
        return AuthorizationDecision(False, "CAMPAIGN_FORBIDDEN", *args, effect_class=effect_class)
    permissions=set().union(*(ROLE_PERMISSIONS.get(role, frozenset()) for role in principal.roles))
    allowed="*" in permissions or action in permissions or any(p.endswith(".*") and action.startswith(p[:-1]) for p in permissions)
    # Exact verified scope is itself an explicit policy grant for the matching
    # API action; roles can grant additional resource permissions but never
    # replace signature/issuer/audience/scope verification.
    if required_scopes and set(required_scopes).issubset(principal.scopes):
        allowed=True
    if effect_class != "read" and environment == "production" and "platform.production.effects" not in principal.scopes:
        return AuthorizationDecision(False, "ENVIRONMENT_NOT_AUTHORIZED", *args, effect_class=effect_class)
    return AuthorizationDecision(allowed, "ALLOW" if allowed else "AUTHORIZATION_DENIED", *args, "role_scope_policy" if allowed else None, effect_class)
