"""Permanent denial authority for legacy effect paths (PAS-59).

The registry ``config/legacy-effect-registry.v1.json`` names every obsolete
command, provider and business-mutation path. These tests prove that no
registered DENIED path can execute its former effect on any application
profile, that the justified read-only compatibility paths still read, that an
application mounting a DENIED path without its denial refuses to build, and
that the readback API reports the enforced state.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient

from app import legacy_effects
from app.application import AppProfile, create_app
from app.commands import (
    CommandEnvelope,
    CommandPolicy,
    CommandPolicyRegistry,
    CommandService,
    MemoryCommandStore,
)
from app.core.runtime import RuntimeContainer as Runtime
from app.legacy_effects import (
    DENIAL_CODE,
    DENIAL_STATUS,
    LegacyEffectRegistryError,
    denial_dependency,
    enforce_legacy_effect_registry,
    load_registry,
    registry,
)
from app.replay import MemoryReplayGuard
from app.security import AuthenticationError
from app.storage import MemoryInboxStore

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_FILE = ROOT / "config" / "legacy-effect-registry.v1.json"
BEARER = "legacy-effect-denial-test-secret-with-32-plus-chars"
AUTH = {"Authorization": f"Bearer {BEARER}"}
TENANT = "tenant-1"
SUBJECT = "n8n-service-subject"


class SpyTokenVerifier:
    """Records every verification; a denied path must never reach it."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.tenant_id = TENANT

    async def verify(self, authorization: str, *, expected_client_id: str, required_scope: str) -> dict[str, Any]:
        self.calls.append((authorization, expected_client_id, required_scope))
        if authorization != f"Bearer {required_scope}":
            raise AuthenticationError("invalid test token")
        return {
            "azp": expected_client_id,
            "scope": required_scope,
            "aud": "middleware-api",
            "tenant_id": self.tenant_id,
            "sub": SUBJECT,
            "client_id": expected_client_id,
        }

    async def ready(self) -> bool:
        return True


class SpyCommandStore(MemoryCommandStore):
    """Records every ledger mutation; a denied path must never reach it."""

    def __init__(self) -> None:
        super().__init__()
        self.mutations: list[str] = []

    async def submit(self, command, **kwargs):  # type: ignore[override]
        self.mutations.append(f"submit:{command.command_id}")
        return await super().submit(command, **kwargs)

    async def mutate_operation(self, tenant_id, command_id, **kwargs):  # type: ignore[override]
        self.mutations.append(f"{kwargs.get('action')}:{command_id}")
        return await super().mutate_operation(tenant_id, command_id, **kwargs)


def _policy() -> CommandPolicyRegistry:
    return CommandPolicyRegistry(
        (CommandPolicy(prefix="crm.", target="odoo-19", capability="ODOO_WRITE", readback_required=True),),
        {"ODOO_WRITE": True},
    )


def _payload(command_id: str) -> dict[str, Any]:
    return {
        "lead_source": "synthetic-form",
        "source_record_id": f"source-{command_id}",
        "initial_stage": "review_pending",
        "review_required": True,
        "allow_external_contact": False,
        "provenance": {
            "method": "submitted_by_person",
            "captured_by": "legacy-effect-test",
            "source_reference": "synthetic://legacy-effect-test",
            "legal_basis": "unknown_review_required",
            "content_digest": "a" * 64,
        },
        "consent": {
            "status": "unknown",
            "captured_at": "2026-09-25T00:00:00+00:00",
            "policy_version": "test-v1",
            "channels": {"email": False, "sms": False, "phone": False},
        },
        "lead": {
            "name": "CODESTRA-INTEGRATION-TEST-Lead",
            "description": "Synthetic test only.",
            "contact": {
                "name": "Synthetic Contact",
                "email": "synthetic@example.invalid",
                "phone": "+18095550199",
                "preferred_language": "en",
            },
            "company": {"name": "Synthetic Company", "domain": "example.invalid", "industry": "Testing"},
            "campaign_code": None,
            "tags": [],
        },
    }


def _command() -> CommandEnvelope:
    command_id = str(uuid4())
    return CommandEnvelope.model_validate(
        {
            "command_id": command_id,
            "command_type": "crm.lead.upsert",
            "command_version": "1.0",
            "target": "odoo-19",
            "tenant_id": TENANT,
            "requested_by": SUBJECT,
            "correlation_id": "corr-legacy-effect-denial",
            "idempotency_key": f"idem-legacy-effect-{command_id}",
            "capability": "ODOO_WRITE",
            "payload": _payload(command_id),
        }
    )


def _command_body() -> dict[str, Any]:
    return _command().model_dump(mode="json")


@pytest.fixture
def settings(test_settings):
    # Provider writes are switched ON deliberately: the denial must not depend
    # on any capability flag being off.
    return test_settings.replace(middleware_secret=BEARER, umbrella_n8n_external_provider_writes=True)


@pytest.fixture
def harness(settings):
    verifier = SpyTokenVerifier()
    store = SpyCommandStore()
    runtime = Runtime(
        settings=settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=verifier,
        commands=CommandService(store, _policy()),
    )
    app = create_app(settings=settings, runtime=runtime, profile=AppProfile.MONOLITH)
    with TestClient(app) as client:
        yield client, verifier, store, app


def _concrete(path: str) -> str:
    return path.replace("{command_id}", str(uuid4())).replace("{operation_id}", str(uuid4()))


DENIED_ROUTES = [entry for entry in registry().entries if entry.denied and entry.route_scoped]
READ_ONLY = [entry for entry in registry().entries if not entry.denied]


# --- registry ------------------------------------------------------------------------


def test_registry_is_valid_and_its_digest_is_the_committed_file() -> None:
    active = load_registry()
    assert active.sha256 == hashlib.sha256(REGISTRY_FILE.read_bytes()).hexdigest()
    assert active.policy["reactivation_allowed"] is False
    assert active.policy["runtime_override_allowed"] is False
    assert active.policy["provider_effects_enabled"] is False
    assert len(DENIED_ROUTES) >= 10
    for entry in active.entries:
        if entry.denied:
            assert entry.method in {"POST", "PUT", "PATCH", "DELETE"}, entry
            assert entry.effect_class != "read", entry
        else:
            assert entry.method in {"GET", "HEAD", "OPTIONS"}, entry
            assert entry.effect_class == "read", entry


def test_every_obsolete_mutation_path_is_registered_as_denied() -> None:
    denied = {(entry.method, entry.path) for entry in registry().entries if entry.denied}
    assert {
        ("POST", "/v1/integrations/n8n/commands"),
        ("POST", "/v1/integrations/n8n/operations/{operation_id}/cancel"),
        ("POST", "/v1/integrations/n8n/operations/{operation_id}/reconcile"),
        ("POST", "/api/v1/events/odoo"),
        ("POST", "/api/v1/integrations/odoo/commands"),
        ("POST", "/api/v1/integrations/n8n/dispatch"),
        ("POST", "/api/v1/integrations/n8n/progress"),
        ("POST", "/api/v1/integrations/n8n/dead-letter"),
        ("POST", "/api/v1/integrations/n8n/errors"),
        ("POST", "/api/v1/integrations/n8n/reconciliation"),
        ("POST", "/api/v1/integrations/n8n/results"),
    } <= denied


def _mutated(tmp_path: Path, mutate) -> Path:
    document = json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
    mutate(document)
    target = tmp_path / "registry.json"
    target.write_text(json.dumps(document), encoding="utf-8")
    return target


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        ("read-only POST", lambda d: d["entries"][1].update(method="POST")),
        ("denied read", lambda d: d["entries"][0].update(method="GET")),
        ("reactivation", lambda d: d["policy"].update(reactivation_allowed=True)),
        ("runtime override", lambda d: d["policy"].update(runtime_override_allowed=True)),
        ("provider effects", lambda d: d["policy"].update(provider_effects_enabled=True)),
        ("unknown disposition", lambda d: d["entries"][0].update(disposition="ALLOWED")),
        ("unknown effect class", lambda d: d["entries"][0].update(effect_class="anything")),
        ("duplicate id", lambda d: d["entries"].append(dict(d["entries"][0], path="/v1/other"))),
        ("duplicate operation", lambda d: d["entries"].append(dict(d["entries"][0], id="LE-DUPLICATE"))),
        ("extra field", lambda d: d["entries"][0].update(enabled=True)),
        ("wrong schema", lambda d: d.update(schema="other")),
        ("empty", lambda d: d.update(entries=[])),
    ],
)
def test_malformed_registry_fails_closed(tmp_path: Path, label: str, mutate) -> None:
    with pytest.raises(LegacyEffectRegistryError):
        load_registry(_mutated(tmp_path, mutate))


def test_denial_dependency_refuses_unknown_and_read_only_ids() -> None:
    with pytest.raises(LegacyEffectRegistryError):
        denial_dependency("LE-DOES-NOT-EXIST")
    with pytest.raises(LegacyEffectRegistryError):
        denial_dependency(READ_ONLY[0].id)
    with pytest.raises(LegacyEffectRegistryError):
        denial_dependency("LE-INTEGRATIONS-N8N-UNAUTHENTICATED-CALLBACK")  # payload-shape entry


# --- enforcement at application build ------------------------------------------------


@pytest.mark.parametrize("profile", list(AppProfile))
def test_every_profile_enforces_every_mounted_denied_path(settings, profile: AppProfile) -> None:
    app = create_app(settings=settings, profile=profile)
    state = app.state.legacy_effects
    for entry in registry().entries:
        item = state[entry.id]
        if item["mounted"]:
            assert item["enforced"], entry.id
    if profile is AppProfile.MONOLITH:
        assert all(state[entry.id]["mounted"] for entry in DENIED_ROUTES)


def test_integration_profile_mounts_no_legacy_n8n_alias(settings) -> None:
    state = create_app(settings=settings, profile=AppProfile.INTEGRATION).state.legacy_effects
    for effect_id in ("LE-N8N-V1-COMMAND-SUBMIT", "LE-N8N-V1-OPERATION-CANCEL", "LE-N8N-V1-OPERATION-RECONCILE"):
        assert state[effect_id]["mounted"] is False


def test_an_application_mounting_a_denied_path_without_denial_refuses_to_build() -> None:
    router = APIRouter()

    @router.post("/v1/integrations/n8n/commands")
    async def resurrected() -> dict[str, str]:  # pragma: no cover - never served
        return {"status": "accepted"}

    app = FastAPI()
    app.include_router(router)
    with pytest.raises(LegacyEffectRegistryError, match="LE-N8N-V1-COMMAND-SUBMIT"):
        enforce_legacy_effect_registry(app)


def test_a_denial_dependency_mounted_on_the_wrong_operation_refuses_to_build() -> None:
    router = APIRouter()

    @router.post("/v1/some/other/path", dependencies=[Depends(denial_dependency("LE-N8N-V1-COMMAND-SUBMIT"))])
    async def misplaced() -> None:  # pragma: no cover - never served
        return None

    app = FastAPI()
    app.include_router(router)
    with pytest.raises(LegacyEffectRegistryError, match="mounted on POST /v1/some/other/path"):
        enforce_legacy_effect_registry(app)


def test_a_payload_shape_denial_removed_from_its_handler_refuses_to_build() -> None:
    router = APIRouter()

    @router.post("/api/v1/integrations/n8n/results")
    async def accepts_everything() -> dict[str, str]:  # pragma: no cover - never served
        return {"accepted": "true"}

    app = FastAPI()
    app.include_router(router)
    with pytest.raises(LegacyEffectRegistryError, match="LE-INTEGRATIONS-N8N-UNAUTHENTICATED-CALLBACK"):
        enforce_legacy_effect_registry(app)


# --- runtime denial --------------------------------------------------------------------


@pytest.mark.parametrize("entry", DENIED_ROUTES, ids=lambda entry: entry.id)
def test_denied_path_answers_410_before_any_auth_ledger_or_provider_effect(harness, entry) -> None:
    client, verifier, store, _ = harness
    body = _command_body()
    headers = {
        **AUTH,
        "X-Tenant-ID": TENANT,
        "X-Correlation-ID": "corr-legacy-effect-denial",
        "Idempotency-Key": body["idempotency_key"],
        # Every legacy header the old handlers read, made valid on purpose.
        "X-Timestamp": "0",
        "X-Nonce": "nonce",
        "X-Signature": "signature",
    }
    if entry.path.startswith("/v1/integrations/n8n/"):
        headers["Authorization"] = "Bearer middleware.request.forward"
    response = client.request(entry.method, _concrete(entry.path), json=body, headers=headers)

    assert response.status_code == DENIAL_STATUS, response.text
    error = response.json()["error"]
    assert error["code"] == DENIAL_CODE
    assert error["retryable"] is False
    assert error["details"]["legacy_effect_id"] == entry.id
    assert error["details"]["successor"] == entry.successor
    assert response.headers["deprecation"] == "true"
    if entry.successor_path:
        assert entry.successor_path in response.headers["link"]
    assert verifier.calls == []
    assert store.mutations == []


def test_denial_precedes_request_validation(harness) -> None:
    client, verifier, store, _ = harness
    response = client.post(
        "/v1/integrations/n8n/commands",
        content=b"{}",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == DENIAL_STATUS
    assert verifier.calls == [] and store.mutations == []


def test_legacy_n8n_submission_cannot_reach_the_ledger_even_with_valid_authority(harness) -> None:
    client, verifier, store, app = harness
    body = _command_body()
    response = client.post(
        "/v1/integrations/n8n/commands",
        json=body,
        headers={
            "Authorization": "Bearer middleware.request.forward",
            "X-Tenant-ID": TENANT,
            "X-Correlation-ID": body["correlation_id"],
            "Idempotency-Key": body["idempotency_key"],
        },
    )
    assert response.status_code == DENIAL_STATUS
    assert "location" not in response.headers
    assert store.mutations == []
    assert verifier.calls == []


def test_legacy_cancel_and_reconcile_cannot_mutate_an_existing_operation(harness) -> None:
    client, verifier, store, app = harness
    command = _command()
    import asyncio

    service = app.state.runtime.commands
    asyncio.run(
        service.submit(command, authenticated_subject=SUBJECT, authenticated_client_id="n8n-automation")
    )
    store.mutations.clear()
    before = asyncio.run(service.get(TENANT, UUID(str(command.command_id))))
    for action in ("cancel", "reconcile"):
        response = client.post(
            f"/v1/integrations/n8n/operations/{command.command_id}/{action}",
            json={"expected_version": 1, "reason": "legacy caller"},
            headers={"Authorization": "Bearer middleware.command.write", "X-Tenant-ID": TENANT, "Idempotency-Key": "idem-legacy-mutation"},
        )
        assert response.status_code == DENIAL_STATUS, response.text
    after = asyncio.run(service.get(TENANT, UUID(str(command.command_id))))
    assert after.model_dump() == before.model_dump()
    assert store.mutations == [] and verifier.calls == []


def test_legacy_callback_payload_shape_is_denied_on_the_live_results_path(harness) -> None:
    client, _, _, _ = harness
    response = client.post(
        "/api/v1/integrations/n8n/results",
        json={
            "command_id": "cmd-1",
            "status": "completed",
            "payload": {},
            "correlation_id": "corr-1",
            "trace_id": "trace-1",
        },
        headers={**AUTH, "Idempotency-Key": "idem-legacy-callback"},
    )
    assert response.status_code == DENIAL_STATUS, response.text
    assert response.json()["error"]["details"]["legacy_effect_id"] == "LE-INTEGRATIONS-N8N-UNAUTHENTICATED-CALLBACK"


# --- justified read-only compatibility ------------------------------------------------


def test_read_only_compatibility_status_still_reads_tenant_scoped(harness) -> None:
    client, verifier, _, app = harness
    command = _command()
    import asyncio

    asyncio.run(
        app.state.runtime.commands.submit(
            command, authenticated_subject=SUBJECT, authenticated_client_id="n8n-automation"
        )
    )
    status = client.get(
        f"/v1/integrations/n8n/operations/{command.command_id}",
        headers={"Authorization": "Bearer middleware.status.read", "X-Tenant-ID": TENANT},
    )
    assert status.status_code == 200, status.text
    assert status.json()["command_id"] == str(command.command_id)
    assert status.headers["deprecation"] == "true"
    assert f"/v2/automation/commands/{command.command_id}" in status.headers["link"]

    verifier.tenant_id = "tenant-2"
    denied = client.get(
        f"/v1/integrations/n8n/operations/{command.command_id}",
        headers={"Authorization": "Bearer middleware.status.read", "X-Tenant-ID": TENANT},
    )
    assert denied.status_code == 403, denied.text


def test_read_only_compatibility_entries_are_mounted_as_reads_only(settings) -> None:
    app = create_app(settings=settings, profile=AppProfile.MONOLITH)
    from app.router_registry import route_operations

    operations = set(route_operations(app))
    for entry in READ_ONLY:
        assert (entry.method, entry.path) in operations, entry.id


# --- readback API -----------------------------------------------------------------------


def test_readback_reports_registry_policy_and_enforced_state(harness) -> None:
    client, _, _, _ = harness
    unauthenticated = client.get("/api/v1/legacy-effects")
    assert unauthenticated.status_code == 401

    response = client.get("/api/v1/legacy-effects", headers=AUTH)
    assert response.status_code == 200, response.text
    document = response.json()
    assert document["schema"] == "codestra.middleware.legacy-effect-readback.v1"
    assert document["registry"]["sha256"] == hashlib.sha256(REGISTRY_FILE.read_bytes()).hexdigest()
    assert document["registry"]["entries"] == len(registry().entries)
    assert document["profile"] == "monolith"
    assert document["enforcement_verified"] is True
    assert document["provider_effects_enabled"] is False
    assert document["policy"]["reactivation_allowed"] is False
    by_id = {entry["id"]: entry for entry in document["entries"]}
    for entry in DENIED_ROUTES:
        assert by_id[entry.id]["mounted"] is True and by_id[entry.id]["enforced"] is True


def test_readback_counts_observed_denials(harness) -> None:
    client, _, _, _ = harness
    before = client.get("/api/v1/legacy-effects/LE-INTEGRATIONS-N8N-DISPATCH", headers=AUTH).json()
    client.post("/api/v1/integrations/n8n/dispatch", json={}, headers=AUTH)
    after = client.get("/api/v1/legacy-effects/LE-INTEGRATIONS-N8N-DISPATCH", headers=AUTH)
    assert after.status_code == 200
    assert after.json()["entry"]["denials_observed"] == before["entry"]["denials_observed"] + 1
    assert after.json()["entry"]["disposition"] == "DENIED"


def test_readback_single_entry_unknown_and_malformed_ids(harness) -> None:
    client, _, _, _ = harness
    assert client.get("/api/v1/legacy-effects/LE-NOT-REGISTERED", headers=AUTH).status_code == 404
    assert client.get("/api/v1/legacy-effects/not-an-id", headers=AUTH).status_code == 422


def test_readback_is_served_on_the_deployed_integration_profile(settings) -> None:
    app = create_app(settings=settings, profile=AppProfile.INTEGRATION)
    with TestClient(app) as client:
        response = client.get("/api/v1/legacy-effects", headers=AUTH)
    assert response.status_code == 200, response.text
    document = response.json()
    assert document["profile"] == "integration"
    assert document["enforcement_verified"] is True


def test_denial_counter_is_process_local_and_monotonic() -> None:
    before = legacy_effects.denials_observed().get("LE-INTEGRATIONS-N8N-ERRORS", 0)
    with pytest.raises(legacy_effects.LegacyEffectDenied):
        legacy_effects.deny("LE-INTEGRATIONS-N8N-ERRORS")
    assert legacy_effects.denials_observed()["LE-INTEGRATIONS-N8N-ERRORS"] == before + 1
    with pytest.raises(LegacyEffectRegistryError):
        legacy_effects.deny(READ_ONLY[0].id)
