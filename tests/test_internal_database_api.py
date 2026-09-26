from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.internal import database as database_api


class _Acquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeConn:
    async def fetchrow(self, query, *args):
        if "current_database()" in query and "pg_is_in_recovery" in query:
            return {
                "database_name": "middleware_staging",
                "role_name": "middleware_staging",
                "server_version": "17.6",
                "in_recovery": False,
            }
        if "pg_stat_ssl" in query:
            return {
                "ssl": True,
                "version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "bits": 256,
            }
        if "relrowsecurity" in query:
            return {"rls_tables": 4, "total_tables": 170}
        if "pg_stat_database" in query:
            return {
                "numbackends": 3,
                "xact_commit": 100,
                "xact_rollback": 1,
                "blks_read": 10,
                "blks_hit": 1000,
                "tup_returned": 500,
                "tup_fetched": 200,
                "tup_inserted": 20,
                "tup_updated": 10,
                "tup_deleted": 2,
                "deadlocks": 0,
                "temp_files": 0,
            }
        if "FROM pg_locks" in query:
            return {"granted": 5, "waiting": 0}
        if "pg_database_size" in query:
            return {
                "database_bytes": 123456,
                "max_connections": 100,
                "connections": 3,
            }
        raise AssertionError(query)

    async def fetchval(self, query, *args):
        if "to_regclass" in query:
            return True
        if "pg_policies" in query:
            return 4
        raise AssertionError(query)

    async def fetch(self, query, *args):
        if "alembic_version" in query:
            return [{"version_num": "0070_agent_provisioning_lifecycle"}]
        if "pg_catalog.pg_tables" in query:
            return [
                {"tablename": name}
                for name in database_api._REQUIRED_TABLES
            ]
        raise AssertionError(query)


class FakePool:
    def __init__(self):
        self.conn = FakeConn()

    def acquire(self):
        return _Acquire(self.conn)

    def get_size(self):
        return 4

    def get_idle_size(self):
        return 3

    def get_min_size(self):
        return 1

    def get_max_size(self):
        return 8


class FakeTokens:
    def __init__(self):
        self.scopes = []

    async def verify(
        self, authorization, *, expected_client_id, required_scope
    ):
        assert authorization == "Bearer test"
        assert expected_client_id == "observability-operator"
        self.scopes.append(required_scope)
        return {
            "azp": expected_client_id,
            "scope": required_scope,
            "sub": "test",
        }


def _client(monkeypatch):
    tokens = FakeTokens()
    settings = SimpleNamespace(
        database_url=(
            "postgresql+asyncpg://middleware_staging@middleware-db/"
            "middleware_staging?sslmode=verify-full"
            "&sslrootcert=/run/secrets/ca.pem"
        ),
        schema_head="0070_agent_provisioning_lifecycle",
        database_certification_evidence_dir="",
    )
    runtime = SimpleNamespace(
        pool=FakePool(), tokens=tokens, settings=settings
    )
    app = FastAPI()
    app.state.runtime = runtime
    app.include_router(database_api.router)
    monkeypatch.setattr(
        database_api,
        "caller_for_authorization",
        lambda _authorization: SimpleNamespace(
            client_id="observability-operator"
        ),
    )
    return TestClient(app), tokens


def test_readiness_schema_and_verify_are_read_only(monkeypatch):
    client, tokens = _client(monkeypatch)
    headers = {"Authorization": "Bearer test"}

    ready = client.get(
        "/internal/v1/database/readiness", headers=headers
    )
    assert ready.status_code == 200
    assert ready.json()["ready"] is True
    assert (
        ready.json()["alembic_head"]
        == "0070_agent_provisioning_lifecycle"
    )
    assert ready.json()["tls_active"] is True

    schema = client.get("/internal/v1/database/schema", headers=headers)
    assert schema.status_code == 200
    assert schema.json()["runtime_schema_verified"] is True
    assert schema.json()["drift_detected"] is False

    verify = client.post(
        "/internal/v1/database/migrations/verify", headers=headers
    )
    assert verify.status_code == 200
    assert verify.json()["verified"] is True
    assert verify.json()["read_only"] is True
    assert database_api.READ_SCOPE in tokens.scopes
    assert database_api.VERIFY_SCOPE in tokens.scopes


def test_forbidden_mutation_surfaces_do_not_exist(monkeypatch):
    client, _tokens = _client(monkeypatch)
    headers = {"Authorization": "Bearer test"}
    for path in (
        "/internal/v1/database/migrations/apply",
        "/internal/v1/database/sql",
        "/internal/v1/database/query",
        "/internal/v1/database/execute",
        "/internal/v1/database/raw",
    ):
        assert client.post(path, headers=headers).status_code == 404


def test_tls_pool_rls_and_capacity_are_safe(monkeypatch):
    client, _tokens = _client(monkeypatch)
    headers = {"Authorization": "Bearer test"}
    assert client.get(
        "/internal/v1/database/security/tls", headers=headers
    ).json() == {
        "required": True,
        "active": True,
        "verification_mode": "verify-full",
        "ca_verification": True,
        "hostname_verification": True,
        "protocol": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "bits": 256,
    }
    cert = client.get(
        "/internal/v1/database/security/certificates", headers=headers
    ).json()
    assert cert["private_key_exposed"] is False
    assert cert["dsn_exposed"] is False
    assert "password" not in str(cert).lower()
    assert client.get(
        "/internal/v1/database/pool", headers=headers
    ).json()["max_size"] == 8
    assert client.get(
        "/internal/v1/database/security/rls", headers=headers
    ).json()["policy_count"] == 4
    assert client.get(
        "/internal/v1/database/capacity", headers=headers
    ).json()["max_connections"] == 100


def test_canonical_registry_owns_private_database_router():
    from app.router_registry import CANONICAL_ROUTERS

    assert database_api.router in CANONICAL_ROUTERS
