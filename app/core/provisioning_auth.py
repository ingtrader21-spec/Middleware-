"""Machine-to-machine authority for the agent provisioning API.

Odoo (via the ``provisioning-service`` Keycloak client - see
``appolon1908-hue/Keycloak``'s ``config/contracts/service-access-matrix.json``)
calls this API with a client-credentials token carrying ``aud=middleware-api``
and a ``scope`` claim of ``identity.request integration.configure
tenant.provision``. That client intentionally holds no realm role - the
matrix authorizes it purely on scope + audience + authorized-party, not on
the human ``platform_admin``/``platform_reviewer``/``platform_operator``
roles ``app.core.platform_auth`` checks for. This module mirrors
``platform_auth.require_platform_scope`` but for that machine-credential
shape, reusing the same ``KeycloakValidator`` (JWKS caching, issuer/audience
checks) rather than re-implementing token verification.

The Keycloak contract also explicitly prohibits this caller from ever
receiving Keycloak admin API access
(``administrativeBoundaries.provisioning-service.keycloakAdminApiAccess:
false``) - this dependency validates only that Odoo is allowed to ask
Middleware to provision an agent; it grants no Keycloak access whatsoever.
Only ``app.adapters.keycloak.lifecycle_client`` ever talks to Keycloak, using
a wholly separate, narrowly-scoped service account.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.core.jwt_auth import JWTAuthError, KeycloakValidator, identity_validator_kwargs
from app.control_plane_auth import ControlPlaneCaller
from app.platform.principal import KernelPrincipal, PrincipalType, authorize as authorize_resource

BEARER = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class ProvisioningPrincipal:
    subject: str
    authorized_party: str
    tenant_ids: frozenset[str]
    scopes: frozenset[str] = frozenset()

    def kernel_principal(self) -> KernelPrincipal:
        caller = ControlPlaneCaller(self.authorized_party, "identity.request", "identity.request", (), frozenset(), False, False)
        return KernelPrincipal(self.subject, self.authorized_party, tuple(sorted(self.tenant_ids)), (), tuple(sorted(self.scopes)), caller, PrincipalType.SERVICE, None, self.authorized_party)


def require_provisioning_scope(
    scope: str,
) -> Callable[..., ProvisioningPrincipal]:
    def authorize(
        credential: HTTPAuthorizationCredentials | None = Depends(BEARER),
    ) -> ProvisioningPrincipal:
        if credential is None or credential.scheme.lower() != "bearer":
            raise HTTPException(
                401, "verified provisioning bearer required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        parties = frozenset(
            item.strip()
            for item in settings.agent_provisioning_authorized_parties.split(",")
            if item.strip()
        )
        identity = settings.identity
        if not identity.explicit or not parties:
            raise HTTPException(503, "provisioning identity authority is not configured")
        validator = KeycloakValidator(
            **identity_validator_kwargs(
                identity,
                authorized_parties=parties,
                required_scopes=frozenset({scope}),
            )
        )
        try:
            claims = validator.validate(credential.credentials)
            subject = claims.get("sub")
            azp = claims.get("azp")
            if not isinstance(subject, str) or not subject.strip():
                raise JWTAuthError("stable subject required")
            tenant_claim = claims.get("tenant_ids", claims.get("tenant_id", []))
            if isinstance(tenant_claim, str):
                tenant_claim = [tenant_claim]
            if not isinstance(tenant_claim, list) or not all(
                isinstance(item, str) for item in tenant_claim
            ):
                raise JWTAuthError("tenant claim malformed")
        except (JWTAuthError, AttributeError, TypeError, ValueError):
            raise HTTPException(403, "provisioning authority denied") from None
        return ProvisioningPrincipal(
            subject=subject, authorized_party=str(azp),
            tenant_ids=frozenset(tenant_claim),
            scopes=frozenset(str(claims.get("scope", "")).split()),
        )

    return authorize


def authorize_provisioning(principal: ProvisioningPrincipal, *, tenant_id: str, action: str, effect_class: str = "PROVISIONING") -> None:
    decision = authorize_resource(principal.kernel_principal(), action=action, resource="agent-provisioning", tenant_id=tenant_id, required_scopes=("identity.request",), effect_class=effect_class, environment=settings.app_env)
    if not decision.allowed:
        raise HTTPException(403, decision.decision_code)


def require_tenant_match(principal: ProvisioningPrincipal, tenant_id: str) -> None:
    """Every request body's tenant_id must be one the caller's token covers.

    An empty tenant_ids claim is a configuration gap, not an all-tenant
    grant - it denies rather than defaulting open.
    """
    if not principal.tenant_ids or tenant_id not in principal.tenant_ids:
        raise HTTPException(403, "tenant claim does not cover the requested tenant")


def require_current_policy_revision(policy_revision: str) -> None:
    if policy_revision != settings.agent_provisioning_policy_revision:
        raise HTTPException(409, "stale policy revision")
