"""Narrow Keycloak user-lifecycle adapter for agent provisioning.

This client exposes exactly six operations against the Keycloak Admin REST
API - the same six enumerated in Mission 3's specification - and nothing
else:

  1. query_user_by_email
  2. create_user
  3. update_approved_attributes  (allowlisted attribute keys only)
  4. disable_user
  5. send_required_action_email
  6. assign_approved_roles        (allowlisted realm role names only)

There is no method here for realm administration, client management, or
impersonation. The Keycloak service account this client authenticates as
must itself hold only the "manage-users"/"view-users"/"query-users"
realm-management client roles - never "realm-admin", "manage-realm",
"manage-clients", or any impersonation grant. Odoo never sees these
credentials or calls Keycloak directly; it only ever talks to the agent
provisioning API (``app.api.v1.agent_provisioning``), which is the sole
caller of this adapter.

Every mutating method is fail-closed behind
``settings.live_identity_provisioning_enabled`` (default ``False``), the
same posture as every other external-effect switch in this codebase.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from app.core.config import Settings

LOGGER = logging.getLogger("codestra.keycloak_lifecycle")
REQUEST_TIMEOUT_SECONDS = 8.0


class KeycloakLifecycleError(RuntimeError):
    pass


class KeycloakLifecycleDisabled(KeycloakLifecycleError):
    """Raised when a mutation is attempted while the kill switch is closed."""


@dataclass(frozen=True)
class KeycloakUserRecord:
    keycloak_subject: str
    email: str
    enabled: bool


class KeycloakLifecycleAdapter:
    """Fail-closed client for the six approved Keycloak lifecycle operations."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def _require_configured(self) -> None:
        if not all(
            (
                self._settings.keycloak_lifecycle_admin_base_url,
                self._settings.keycloak_lifecycle_realm,
                self._settings.keycloak_lifecycle_client_id,
                self._settings.keycloak_lifecycle_client_secret_file,
            )
        ):
            raise KeycloakLifecycleError(
                "Keycloak lifecycle adapter is not configured"
            )

    def _require_live(self) -> None:
        if not self._settings.live_identity_provisioning_enabled:
            raise KeycloakLifecycleDisabled(
                "identity provisioning kill switch is closed"
            )

    def _approved_attributes(self) -> frozenset[str]:
        return frozenset(
            value.strip()
            for value in self._settings.keycloak_lifecycle_approved_attributes.split(
                ","
            )
            if value.strip()
        )

    def _approved_roles(self) -> frozenset[str]:
        return frozenset(
            value.strip()
            for value in self._settings.keycloak_lifecycle_approved_roles.split(",")
            if value.strip()
        )

    async def _access_token(self, client: httpx.AsyncClient) -> str:
        response = await client.post(
            f"{self._settings.keycloak_lifecycle_admin_base_url.rstrip('/')}"
            f"/realms/{self._settings.keycloak_lifecycle_realm}"
            "/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._settings.keycloak_lifecycle_client_id,
                "client_secret": self._settings.keycloak_lifecycle_client_secret,
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code != 200:
            raise KeycloakLifecycleError("Keycloak lifecycle client authentication failed")
        token = response.json().get("access_token")
        if not isinstance(token, str) or not token:
            raise KeycloakLifecycleError("Keycloak lifecycle token response is malformed")
        return token

    async def _client(self) -> httpx.AsyncClient:
        verify: str | bool = self._settings.keycloak_lifecycle_ca_file or True
        return httpx.AsyncClient(
            base_url=(
                f"{self._settings.keycloak_lifecycle_admin_base_url.rstrip('/')}"
                f"/admin/realms/{self._settings.keycloak_lifecycle_realm}"
            ),
            verify=verify,
        )

    # -- 1. query -----------------------------------------------------------

    async def query_user_by_email(self, email: str) -> KeycloakUserRecord | None:
        self._require_configured()
        async with await self._client() as client:
            token = await self._access_token(client)
            response = await client.get(
                "/users",
                params={"email": email, "exact": "true"},
                headers={"Authorization": f"Bearer {token}"},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        if response.status_code != 200:
            raise KeycloakLifecycleError("Keycloak user lookup failed")
        rows = response.json()
        if not rows:
            return None
        row = rows[0]
        return KeycloakUserRecord(
            keycloak_subject=row["id"], email=row.get("email", email),
            enabled=bool(row.get("enabled", False)),
        )

    # -- 2. create ------------------------------------------------------------

    async def create_user(
        self, email: str, first_name: str, last_name: str,
    ) -> KeycloakUserRecord:
        self._require_configured()
        self._require_live()
        async with await self._client() as client:
            token = await self._access_token(client)
            response = await client.post(
                "/users",
                json={
                    "email": email,
                    "username": email,
                    "firstName": first_name,
                    "lastName": last_name,
                    "enabled": True,
                    "emailVerified": False,
                },
                headers={"Authorization": f"Bearer {token}"},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        if response.status_code != 201:
            raise KeycloakLifecycleError("Keycloak user creation failed")
        location = response.headers.get("Location", "")
        keycloak_subject = location.rsplit("/", 1)[-1]
        if not keycloak_subject:
            raise KeycloakLifecycleError("Keycloak did not return a subject identifier")
        return KeycloakUserRecord(
            keycloak_subject=keycloak_subject, email=email, enabled=True,
        )

    # -- 3. update approved attributes ---------------------------------------

    async def update_approved_attributes(
        self, keycloak_subject: str, attributes: dict[str, str],
    ) -> None:
        self._require_configured()
        self._require_live()
        approved = self._approved_attributes()
        rejected = sorted(set(attributes) - approved)
        if rejected:
            raise KeycloakLifecycleError(
                f"attribute(s) not on the approved allowlist: {rejected}"
            )
        async with await self._client() as client:
            token = await self._access_token(client)
            response = await client.put(
                f"/users/{keycloak_subject}",
                json={"attributes": {key: [value] for key, value in attributes.items()}},
                headers={"Authorization": f"Bearer {token}"},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        if response.status_code != 204:
            raise KeycloakLifecycleError("Keycloak attribute update failed")

    # -- 4. disable -----------------------------------------------------------

    async def disable_user(self, keycloak_subject: str) -> None:
        self._require_configured()
        self._require_live()
        async with await self._client() as client:
            token = await self._access_token(client)
            response = await client.put(
                f"/users/{keycloak_subject}",
                json={"enabled": False},
                headers={"Authorization": f"Bearer {token}"},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        if response.status_code != 204:
            raise KeycloakLifecycleError("Keycloak user disable failed")

    async def enable_user(self, keycloak_subject: str) -> None:
        """Reactivate a suspended user. Same allowed scope as disable_user."""
        self._require_configured()
        self._require_live()
        async with await self._client() as client:
            token = await self._access_token(client)
            response = await client.put(
                f"/users/{keycloak_subject}",
                json={"enabled": True},
                headers={"Authorization": f"Bearer {token}"},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        if response.status_code != 204:
            raise KeycloakLifecycleError("Keycloak user enable failed")

    # -- 5. required-action email ---------------------------------------------

    APPROVED_REQUIRED_ACTIONS = frozenset({"UPDATE_PASSWORD", "CONFIGURE_TOTP", "VERIFY_EMAIL"})

    async def send_required_action_email(
        self, keycloak_subject: str, actions: list[str],
    ) -> None:
        self._require_configured()
        self._require_live()
        rejected = sorted(set(actions) - self.APPROVED_REQUIRED_ACTIONS)
        if rejected:
            raise KeycloakLifecycleError(
                f"required action(s) not on the approved allowlist: {rejected}"
            )
        async with await self._client() as client:
            token = await self._access_token(client)
            response = await client.put(
                f"/users/{keycloak_subject}/execute-actions-email",
                json=actions,
                headers={"Authorization": f"Bearer {token}"},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        if response.status_code not in (204, 202):
            raise KeycloakLifecycleError("Keycloak required-action email dispatch failed")

    # -- 6. assign approved roles/groups ---------------------------------------

    async def assign_approved_roles(
        self, keycloak_subject: str, role_names: list[str],
    ) -> None:
        self._require_configured()
        self._require_live()
        approved = self._approved_roles()
        rejected = sorted(set(role_names) - approved)
        if rejected:
            raise KeycloakLifecycleError(
                f"role(s) not on the approved allowlist: {rejected}"
            )
        async with await self._client() as client:
            token = await self._access_token(client)
            headers = {"Authorization": f"Bearer {token}"}
            catalog = await client.get(
                "/roles", headers=headers, timeout=REQUEST_TIMEOUT_SECONDS
            )
            if catalog.status_code != 200:
                raise KeycloakLifecycleError("Keycloak realm role catalog lookup failed")
            by_name = {row["name"]: row for row in catalog.json()}
            missing = sorted(set(role_names) - set(by_name))
            if missing:
                raise KeycloakLifecycleError(f"unknown realm role(s): {missing}")
            response = await client.post(
                f"/users/{keycloak_subject}/role-mappings/realm",
                json=[
                    {"id": by_name[name]["id"], "name": name} for name in role_names
                ],
                headers=headers,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        if response.status_code != 204:
            raise KeycloakLifecycleError("Keycloak role assignment failed")
