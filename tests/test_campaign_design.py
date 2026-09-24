"""Campaign design contracts and real PostgreSQL transaction invariants."""

import asyncio
import copy
import importlib.util
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from alembic.migration import MigrationContext
from alembic.operations import Operations

from app.core.campaign_design_contract import (
    CampaignDesignInput,
    build_manifest,
    manifest_hash,
)
from app.core.campaign_design import (
    CampaignDesignService,
    PostgresDesignStore,
    DesignConflict,
)
from app import campaign_design_api as api

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "contracts/campaign-design-request.v1.fixture.json"


def request(**changes):
    body = json.loads(FIXTURE.read_text())
    body.update(
        event_id=str(uuid4()),
        integration_uuid=str(uuid4()),
        correlation_id=str(uuid4()),
    )
    body.update(changes)
    return CampaignDesignInput.model_validate(body)


@pytest.mark.parametrize(
    "direction,suffix", [("outbound", "OUT"), ("inbound", "IN"), ("blended", "BLENDED")]
)
@pytest.mark.parametrize(
    "environment,prefix",
    [("test", "TEST"), ("staging", "STAGING"), ("production", "PROD")],
)
def test_canonical_odoo_preview(direction, suffix, environment, prefix):
    item = request(
        direction=direction,
        campaign_code=f"TEST-E2E-{suffix}",
        expected_campaign_code=f"TEST-E2E-{suffix}",
        environment=environment,
    )
    manifest = build_manifest(item, 1, 91000)
    assert manifest["odoo"]["campaign_code"] == item.campaign_code
    assert manifest["vicidial"]["campaign_id"] == item.campaign_code
    assert manifest["n8n"]["scope"] == f"{prefix}-TEST-E2E-V1"
    assert manifest["n8n"]["workflows_active"] is False
    assert manifest["vicidial"]["active"] is False
    assert set(manifest["feature_flags"].values()) == {False}
    assert manifest["validation_errors"] == []
    assert manifest_hash(manifest) == manifest_hash(json.loads(json.dumps(manifest)))


@pytest.mark.parametrize(
    "change",
    [
        {"design_request_revision": True},
        {"design_request_revision": 0},
        {"campaign_code": "COD-E2E-OUT"},
        {"environment": "unknown"},
        {"business_unit": "UNKNOWN"},
        {"integration_uuid": "not-a-uuid"},
        {"owner_user_id": True},
        {
            "feature_flags": {
                "lead_publication": False,
                "agent_sync": False,
                "live_call_control": False,
                "production_dialing": True,
            }
        },
        {
            "feature_flags": {
                "lead_publication": False,
                "agent_sync": False,
                "live_call_control": False,
                "production_dialing": "false",
            }
        },
    ],
)
def test_invalid_request_rejected(change):
    with pytest.raises(ValidationError):
        request(**change)


def test_missing_inputs_are_visible_and_cannot_be_approved():
    config = copy.deepcopy(json.loads(FIXTURE.read_text())["design_configuration"])
    config["inputs"].pop("recording_policy")
    manifest = build_manifest(request(design_configuration=config), 1, 91000)
    assert "DESIGN_INPUT_REQUIRED:recording_policy" in manifest["validation_errors"]


def test_secret_shaped_inputs_are_rejected():
    config = copy.deepcopy(json.loads(FIXTURE.read_text())["design_configuration"])
    config["inputs"]["provider_secret"] = "synthetic-not-a-runtime-secret"
    with pytest.raises(ValidationError):
        request(design_configuration=config)


@pytest.mark.parametrize(
    "field,value",
    [
        ("calling_hour_start", float("nan")),
        ("time_zone", "not/a/timezone"),
        ("supervisor_ids", [True]),
        ("team_ids", [1, 1]),
    ],
)
def test_invalid_configuration_rejected(field, value):
    config = copy.deepcopy(json.loads(FIXTURE.read_text())["design_configuration"])
    config[field] = value
    with pytest.raises(ValidationError):
        request(design_configuration=config)


def test_api_disabled_without_database_access(monkeypatch):
    monkeypatch.setattr(api.settings, "campaign_design_enabled", False)
    app = FastAPI()
    app.include_router(api.router)

    async def run():
        item = request()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.post(
                "/api/v1/campaign-designs/preview",
                json=item.model_dump(mode="json"),
                headers={
                    "Authorization": "Bearer synthetic",
                    "X-Business-Unit": "TEST",
                    "X-Tenant-ID": "campaign-design-test",
                    "Idempotency-Key": item.event_id,
                    "X-Correlation-ID": item.correlation_id,
                },
            )
        assert r.status_code == 503

    asyncio.run(run())


def _explicit_identity(monkeypatch) -> None:
    """The route only binds a validator to an explicitly configured identity."""
    monkeypatch.setattr(api.settings, "keycloak_issuer", "https://auth-staging.codestra.co/realms/codestra")
    monkeypatch.setattr(api.settings, "keycloak_audience", "middleware-api")
    monkeypatch.setattr(
        api.settings,
        "keycloak_jwks_url",
        "https://auth-staging.codestra.co/realms/codestra/protocol/openid-connect/certs",
    )


def test_scope_auth_refuses_an_implicit_identity(monkeypatch):
    monkeypatch.setattr(api.settings, "campaign_design_enabled", True)
    monkeypatch.setattr(api.settings, "campaign_design_environments", "staging")
    monkeypatch.setattr(api.settings, "keycloak_issuer", "")
    monkeypatch.setattr(api.settings, "keycloak_jwks_url", "")

    class NeverCalled:
        def __init__(self, **kwargs):
            raise AssertionError("validator must not be built for an implicit identity")

    monkeypatch.setattr(api, "KeycloakValidator", NeverCalled)
    with pytest.raises(api.HTTPException) as exc:
        api.authorize(
            "Bearer synthetic",
            unit="TEST",
            environment="staging",
            scope="campaign.design.preview",
            tenant_id="campaign-design-test",
        )
    assert exc.value.status_code == 403


def test_scope_auth_requires_verified_unit_and_subject(monkeypatch):
    monkeypatch.setattr(api.settings, "campaign_design_enabled", True)
    monkeypatch.setattr(api.settings, "campaign_design_environments", "staging")
    _explicit_identity(monkeypatch)

    class Validator:
        def __init__(self, **kwargs):
            assert kwargs["required_scopes"] == frozenset({"campaign.design.preview"})
            assert kwargs["required_business_unit"] == "TEST"
            assert kwargs["required_environment"] == "staging"

        def validate(self, token):
            return {"business_units": ["OTHER"], "sub": "synthetic-service"}

    monkeypatch.setattr(api, "KeycloakValidator", Validator)
    with pytest.raises(api.HTTPException) as exc:
        api.authorize(
            "Bearer synthetic",
            unit="TEST",
            environment="staging",
            scope="campaign.design.preview",
            tenant_id="campaign-design-test",
        )
    assert exc.value.status_code == 403


def test_production_preview_requires_explicit_environment(monkeypatch):
    monkeypatch.setattr(api.settings, "campaign_design_enabled", True)
    monkeypatch.setattr(api.settings, "campaign_design_environments", "test,staging")
    with pytest.raises(api.HTTPException) as exc:
        api.authorize(
            "Bearer synthetic",
            unit="TEST",
            environment="production",
            scope="campaign.design.preview",
            tenant_id="campaign-design-test",
        )
    assert exc.value.status_code == 403


@pytest.fixture
def database():
    dedicated_url = os.environ.get("CAMPAIGN_DESIGN_TEST_DATABASE_URL", "")
    url = dedicated_url or os.environ.get("TEST_DATABASE_URL", "")
    if not url:
        pytest.skip("isolated campaign design PostgreSQL is required")
    parsed = make_url(url)
    database_name = parsed.database or ""
    if parsed.host not in {"127.0.0.1", "localhost"}:
        pytest.fail("refusing a non-local campaign design database")
    if dedicated_url:
        if database_name != "campaign_design_test":
            pytest.fail("refusing a dedicated database not named campaign_design_test")
    elif not (
        database_name.startswith("middleware_")
        and any(marker in database_name for marker in ("test", "rehearsal", "diag"))
    ):
        pytest.fail("refusing a shared database without an isolated test name")

    def run(scenario):
        async def execute():
            schema = "campaign_test_" + uuid4().hex
            engine = create_async_engine(
                url, connect_args={"server_settings": {"search_path": schema}}
            )
            try:
                async with engine.begin() as conn:
                    await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
                    await conn.execute(
                        text("""CREATE TABLE audit_event(
                        id uuid PRIMARY KEY,action text,subject text,correlation_id text,
                        decision text,redacted_payload jsonb)""")
                    )
                    spec = importlib.util.spec_from_file_location(
                        "campaign_migration",
                        ROOT / "migrations/versions/0058_campaign_design.py",
                    )
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    def migrate(sync_conn):
                        with Operations.context(MigrationContext.configure(sync_conn)):
                            module.upgrade()

                    await conn.run_sync(migrate)
                await scenario(async_sessionmaker(engine, expire_on_commit=False))
            finally:
                async with engine.begin() as conn:
                    await conn.execute(
                        text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
                    )
                await engine.dispose()

        return asyncio.run(execute())

    return run


async def consume(factory, item, **kwargs):
    async with factory() as db:
        return await CampaignDesignService(PostgresDesignStore(db, **kwargs)).consume(
            item
        )


async def approve(factory, item, result, **changes):
    values = dict(
        integration_uuid=item.integration_uuid,
        revision=result["design_revision"],
        expected_manifest_hash=result["manifest_hash"],
        actor="verified-odoo-service",
        reason="Synthetic design review, no activation",
        idempotency_key=str(uuid4()),
        correlation_id=item.correlation_id,
        business_unit=item.business_unit,
        environment=item.environment,
        tenant_id=item.tenant_id,
    )
    values.update(changes)
    async with factory() as db:
        return await CampaignDesignService(PostgresDesignStore(db)).approve(**values)


def test_postgres_concurrent_duplicate_one_allocation(database):
    async def scenario(factory):
        item = request()
        first, second = await asyncio.gather(
            consume(factory, item), consume(factory, item)
        )
        assert {first["idempotent_replay"], second["idempotent_replay"]} == {
            False,
            True,
        }
        assert first["manifest_hash"] == second["manifest_hash"]
        async with factory() as db:
            for table in (
                "campaign_event_inbox",
                "campaign_design_revision",
                "campaign_resource_allocation",
            ):
                assert await db.scalar(text(f"SELECT count(*) FROM {table}")) == 1

    database(scenario)


def test_postgres_shared_test_range_is_serialized(database):
    async def scenario(factory):
        a = request()
        b = request(
            business_unit="STAGING",
            campaign_code="STAGING-E2E-OUT",
            expected_campaign_code="STAGING-E2E-OUT",
        )
        results = await asyncio.gather(consume(factory, a), consume(factory, b))
        assert {r["manifest"]["vicidial"]["default_list_id"] for r in results} == {
            91000,
            91001,
        }

    database(scenario)


def test_postgres_revision_change_and_delayed_replay(database):
    async def scenario(factory):
        a = request()
        first = await consume(factory, a)
        b = request(
            integration_uuid=a.integration_uuid,
            odoo_campaign_id=a.odoo_campaign_id,
            design_request_revision=2,
        )
        second = await consume(factory, b)
        assert second["design_revision"] == 2
        replay = await consume(factory, a)
        assert replay["manifest_hash"] == first["manifest_hash"]
        with pytest.raises(DesignConflict):
            await consume(
                factory,
                request(integration_uuid=a.integration_uuid, design_request_revision=4),
            )
        with pytest.raises(DesignConflict):
            await approve(factory, a, first)

    database(scenario)


def test_postgres_event_conflict_does_not_overwrite(database):
    async def scenario(factory):
        a = request()
        first = await consume(factory, a)
        with pytest.raises(DesignConflict):
            await consume(
                factory,
                request(
                    event_id=a.event_id,
                    integration_uuid=a.integration_uuid,
                    campaign_code="TEST-OTHER-OUT",
                    expected_campaign_code="TEST-OTHER-OUT",
                    purpose="OTHER",
                ),
            )
        assert (await consume(factory, a))["manifest_hash"] == first["manifest_hash"]

    database(scenario)


def test_postgres_approval_scope_and_replay(database):
    async def scenario(factory):
        a = request()
        result = await consume(factory, a)
        key = str(uuid4())
        with pytest.raises(DesignConflict):
            await approve(factory, a, result, business_unit="COD")
        first = await approve(factory, a, result, idempotency_key=key)
        second = await approve(factory, a, result, idempotency_key=key)
        assert first["approval"] == second["approval"]
        assert first["approval"]["provisioning_authorized"] is False
        assert first["n8n"]["workflows_active"] is False
        assert set(first["feature_flags"].values()) == {False}

    database(scenario)


def test_postgres_invalid_design_cannot_be_approved(database):
    async def scenario(factory):
        config = copy.deepcopy(json.loads(FIXTURE.read_text())["design_configuration"])
        config["inputs"].pop("recording_policy")
        a = request(design_configuration=config)
        result = await consume(factory, a)
        with pytest.raises(DesignConflict):
            await approve(factory, a, result)

    database(scenario)


def test_postgres_failure_rolls_back_and_records_retry(database):
    async def scenario(factory):
        a = request()

        def fail(point):
            if point == "after_allocation":
                raise RuntimeError("synthetic transaction failure")

        with pytest.raises(RuntimeError):
            await consume(factory, a, fault_hook=fail)
        async with factory() as db:
            assert (
                await db.scalar(
                    text("SELECT count(*) FROM campaign_resource_allocation")
                )
                == 0
            )
            assert (
                await db.scalar(text("SELECT count(*) FROM campaign_event_inbox")) == 0
            )
            assert (
                await db.scalar(text("SELECT attempts FROM campaign_design_failure"))
                == 1
            )
            await db.execute(
                text(
                    "UPDATE campaign_design_failure SET next_attempt_at=now()-interval '1 second'"
                )
            )
            await db.commit()
        assert (await consume(factory, a))["idempotent_replay"] is False

    database(scenario)


@pytest.mark.parametrize("roles", ["SDR", 1, True, [""], ["SDR", 42], ["../AGENT"]])
def test_invalid_roles_block_approval(roles):
    config = copy.deepcopy(json.loads(FIXTURE.read_text())["design_configuration"])
    config["inputs"]["agent_roles"] = roles
    value = build_manifest(request(design_configuration=config), 1, 91000)
    assert "AGENT_ROLES_INVALID" in value["validation_errors"]


def test_postgres_approval_replay_survives_new_incomplete_revision(database):
    async def scenario(factory):
        item = request()
        result = await consume(factory, item)
        key = str(uuid4())
        approved = await approve(factory, item, result, idempotency_key=key)
        config = copy.deepcopy(json.loads(FIXTURE.read_text())["design_configuration"])
        config["inputs"].pop("recording_policy")
        newer = request(
            integration_uuid=item.integration_uuid,
            odoo_campaign_id=item.odoo_campaign_id,
            design_request_revision=2,
            design_configuration=config,
        )
        await consume(factory, newer)
        replay = await approve(factory, item, result, idempotency_key=key)
        assert replay["approval"] == approved["approval"]

    database(scenario)


@pytest.mark.parametrize("entrypoint", ["canonical", "integration", "compatibility"])
@pytest.mark.parametrize("enabled,status", [(False, 503), (True, 403)])
def test_real_application_route_requires_own_authorization(
    monkeypatch, entrypoint, enabled, status
):
    from app.main import app as canonical, create_app
    from app.entrypoints.integration_api import app as integration
    from app.core.config import Settings
    from app.core.jwt_auth import JWTAuthError

    compatibility = create_app(
        settings=Settings.from_env(
            {"APP_ENV": "test", "ALLOW_IN_MEMORY_STORAGE": "true"}
        )
    )
    app = {
        "canonical": canonical,
        "integration": integration,
        "compatibility": compatibility,
    }[entrypoint]
    monkeypatch.setattr(api.settings, "campaign_design_enabled", enabled)
    monkeypatch.setattr(api.settings, "campaign_design_environments", "test,staging")
    _explicit_identity(monkeypatch)

    class DeniedValidator:
        def __init__(self, **kwargs):
            pass

        def validate(self, token):
            raise JWTAuthError("synthetic invalid token")

    monkeypatch.setattr(api, "KeycloakValidator", DeniedValidator)

    async def run():
        item = request()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/campaign-designs/preview",
                json=item.model_dump(mode="json"),
                headers={
                    "Authorization": "Bearer synthetic-invalid",
                    "X-Business-Unit": item.business_unit,
                    "X-Tenant-ID": "campaign-design-test",
                    "Idempotency-Key": item.event_id,
                    "X-Correlation-ID": item.correlation_id,
                },
            )
        assert response.status_code == status, response.text

    asyncio.run(run())


def test_postgres_tenant_binding_is_immutable(database):
    async def scenario(factory):
        item = request()
        result = await consume(factory, item)
        with pytest.raises(DesignConflict):
            await consume(
                factory,
                request(
                    integration_uuid=item.integration_uuid,
                    odoo_campaign_id=item.odoo_campaign_id,
                    design_request_revision=2,
                    tenant_id="other-tenant",
                ),
            )
        with pytest.raises(DesignConflict):
            await approve(factory, item, result, tenant_id="other-tenant")

    database(scenario)


def test_verified_business_unit_does_not_replace_tenant_authority(monkeypatch):
    monkeypatch.setattr(api.settings, "campaign_design_enabled", True)
    monkeypatch.setattr(api.settings, "campaign_design_environments", "staging")
    _explicit_identity(monkeypatch)

    class Validator:
        def __init__(self, **kwargs):
            pass

        def validate(self, token):
            return {
                "business_units": ["TEST"],
                "sub": "service",
                "tenant_ids": ["other-tenant"],
            }

    monkeypatch.setattr(api, "KeycloakValidator", Validator)
    with pytest.raises(api.HTTPException) as exc:
        api.authorize(
            "Bearer synthetic",
            unit="TEST",
            environment="staging",
            scope="campaign.design.preview",
            tenant_id="campaign-design-test",
        )
    assert exc.value.status_code == 403


def test_preview_and_approval_api_persist_verified_tenant(database, monkeypatch):
    monkeypatch.setattr(api.settings, "campaign_design_enabled", True)
    monkeypatch.setattr(api.settings, "campaign_design_environments", "staging,test")
    _explicit_identity(monkeypatch)

    class Validator:
        def __init__(self, **kwargs):
            assert kwargs["issuer"] == "https://auth-staging.codestra.co/realms/codestra"
            assert kwargs["required_scopes"] in (
                frozenset({"campaign.design.preview"}),
                frozenset({"campaign.design.approve"}),
            )

        def validate(self, token):
            return {
                "business_units": ["TEST"],
                "sub": "verified-test-service",
                "tenant_id": "campaign-design-test",
            }

    monkeypatch.setattr(api, "KeycloakValidator", Validator)

    async def scenario(factory):
        app = FastAPI()
        app.include_router(api.router)

        async def session():
            async with factory() as db:
                yield db

        app.dependency_overrides[api.get_session] = session
        item = request()
        payload = item.model_dump(mode="json", exclude={"tenant_id"})
        headers = {
            "Authorization": "Bearer synthetic",
            "X-Business-Unit": "TEST",
            "X-Tenant-ID": "campaign-design-test",
            "Idempotency-Key": item.event_id,
            "X-Correlation-ID": item.correlation_id,
        }
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            first = await client.post(
                "/api/v1/campaign-designs/preview", json=payload, headers=headers
            )
            assert first.status_code == 200, first.text
            receipt = first.json()
            assert receipt["manifest"]["tenant_id"] == "campaign-design-test"
            replay = await client.post(
                "/api/v1/campaign-designs/preview", json=payload, headers=headers
            )
            assert replay.status_code == 200 and replay.json()["idempotent_replay"]
            assert replay.json()["manifest_hash"] == receipt["manifest_hash"]
            approval = {
                "integration_uuid": item.integration_uuid,
                "business_unit": "TEST",
                "environment": item.environment,
                "design_revision": 1,
                "manifest_hash": receipt["manifest_hash"],
                "reason": "Synthetic scoped approval",
            }
            approved = await client.post(
                "/api/v1/campaign-designs/approvals",
                json=approval,
                headers={**headers, "Idempotency-Key": str(uuid4())},
            )
            assert approved.status_code == 200, approved.text
            assert approved.json()["approval"]["provisioning_authorized"] is False
            assert approved.json()["n8n"]["workflows_active"] is False

    database(scenario)
