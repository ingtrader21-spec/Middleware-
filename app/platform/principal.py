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


@dataclass(frozen=True)
class KernelPrincipal:
    subject: str
    client_id: str
    tenants: tuple[str, ...]
    roles: tuple[str, ...]
    scopes: tuple[str, ...]
    caller: ControlPlaneCaller

    def authorized_for(self, tenant_id: str) -> bool:
        return "*" not in self.tenants and tenant_id in self.tenants


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
    return KernelPrincipal(
        subject=subject.strip(),
        client_id=caller.client_id,
        tenants=tenants_from_claims(claims),
        roles=roles_from_claims(claims, caller.client_id),
        scopes=_string_items(claims.get("scope"), limit=MAX_SCOPES),
        caller=caller,
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
