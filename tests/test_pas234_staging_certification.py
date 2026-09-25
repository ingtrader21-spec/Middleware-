"""PAS-234 staging certification ratchet.

Binds the committed staging certification packet to repository truth so the
packet cannot silently drift from the source it certifies, and freezes the
effects-off shape of the canonical runtime compose file.  Every assertion is
static except the boot-defect ratchet, which imports the configuration in a
subprocess; nothing here opens a network connection.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PACKET_PATH = (
    ROOT
    / "docs"
    / "evidence"
    / "pas234-staging-certification-20260924"
    / "staging-certification-packet.v1.json"
)
PACKET = json.loads(PACKET_PATH.read_text(encoding="utf-8"))
COMPOSE = yaml.safe_load(
    (ROOT / "deploy" / "compose.runtime.yaml").read_text(encoding="utf-8")
)
PROFILES = {
    profile["profile_id"]: profile
    for profile in json.loads(
        (ROOT / "config" / "runtime-profiles.v1.json").read_text(encoding="utf-8")
    )["profiles"]
}
TRUTHY = {"true", "1", "yes", "on", "enabled", "production"}


def _environment(service: str) -> dict[str, str]:
    environment = COMPOSE["services"][service].get("environment") or {}
    assert isinstance(environment, dict), f"{service} environment must be a mapping"
    return {str(key): str(value) for key, value in environment.items()}


def _truthy_values() -> set[tuple[str, str, str]]:
    safety_positive = set(PACKET["effects_off"]["safety_positive_true_flags"])
    return {
        (service, key, value)
        for service in COMPOSE["services"]
        for key, value in _environment(service).items()
        if value.lower() in TRUTHY and key not in safety_positive
    }


def test_packet_is_not_certified_while_blockers_are_open() -> None:
    status = PACKET["status"]
    assert status["RUNTIME_MUTATION"] == 0
    assert status["PROVIDER_EFFECTS"] == 0
    assert status["PRODUCTION_GO"] == "NO"
    if any(blocker["status"] != "CLOSED" for blocker in PACKET["blockers"]):
        assert status["GATE_B"] == "NO_GO"
        assert status["STAGING_CERTIFIED"] == "NO"
        assert status["ROLLBACK_PROVEN"] == "NO"
    if status["TARGET_IMAGE_DIGEST"].startswith("PENDING"):
        assert status["STAGING_CERTIFIED"] == "NO"


def test_packet_source_identity_matches_repository() -> None:
    from app.core.config import CANONICAL_SCHEMA_HEAD

    source = PACKET["source"]
    assert source["alembic_head"] == CANONICAL_SCHEMA_HEAD
    assert source["core_sql_receipts"] == len(
        list((ROOT / "migrations").glob("[0-9]*.sql"))
    )

    release = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    )
    build_steps = [
        step
        for job in release["jobs"].values()
        for step in job.get("steps", [])
        if step.get("with", {}).get("file") == "Dockerfile.runtime"
    ]
    assert [step["with"]["target"] for step in build_steps] == [
        source["image_build_target"]
    ]
    assert any(
        job.get("env", {}).get("IMAGE_REPOSITORY") == source["image_repository"]
        for job in release["jobs"].values()
    )

    dockerfile = (ROOT / "Dockerfile.runtime").read_text(encoding="utf-8")
    runtime_common = dockerfile.split("AS runtime-common", 1)[1].split("\nFROM ", 1)[0]
    assert f"USER {source['image_user']}" in runtime_common
    assert COMPOSE["x-runtime"]["user"] == source["compose_runtime_user"]


def test_staging_profile_is_locked_and_never_production() -> None:
    profile = PROFILES[PACKET["source"]["runtime_profile_id"]]
    assert profile["environment"] == "staging"
    assert profile["production_activation_allowed"] is False
    assert profile["database"]["sslmode"] == "verify-full"
    assert profile["redis"]["scheme"] == "rediss"
    assert profile["secret_path_prefix"] == "/run/secrets/middleware-staging-"


def test_staging_units_match_the_canonical_compose_services() -> None:
    for unit in PACKET["staging_units"]:
        service = COMPOSE["services"][unit["service"]]
        assert service["command"] == unit["command"]
        assert (
            f"{unit['database_url_secret']}:/run/secrets/database_url:ro"
            in service["volumes"]
        )
        assert (
            service["image"]
            == "${MIDDLEWARE_IMAGE:?set immutable middleware image digest}"
        )


def test_compose_effect_exceptions_are_frozen() -> None:
    recorded = {
        tuple(item) for item in PACKET["effects_off"]["recorded_compose_exceptions"]
    }
    assert _truthy_values() == recorded


def test_staging_units_carry_no_unrecorded_effect_enablement() -> None:
    allowed = {
        tuple(item) for item in PACKET["effects_off"]["staging_unit_allowed_exceptions"]
    }
    units = {unit["service"] for unit in PACKET["staging_units"]}
    assert {item for item in _truthy_values() if item[0] in units} == allowed
    for service in units:
        environment = _environment(service)
        assert "ENVIRONMENT" not in environment
        for key, value in environment.items():
            if key.endswith("_ENABLED") and (service, key, value) not in allowed:
                assert value == "false", f"{service}:{key}={value}"


def test_staging_env_template_keeps_every_dispatch_path_off() -> None:
    values = dict(
        line.split("=", 1)
        for line in (ROOT / "config" / "environments" / "staging.runtime.env.example")
        .read_text(encoding="utf-8")
        .splitlines()
        if line and not line.startswith("#")
    )
    assert values["APP_ENV"] == "staging"
    assert values["RUNTIME_PROFILE_ID"] == PACKET["source"]["runtime_profile_id"]
    assert values["NATS_DISPATCH_MODE"] == "disabled"
    assert values["TEMPORAL_WORKER_MODE"] == "disabled"
    assert values["PRODUCTION_DIALING"] == "DISABLED"
    for key, value in values.items():
        if key.endswith(("_ENABLED", "_WRITES", "_WRITE", "_DISPATCH")) or key in {
            "SEND_EVENTS",
            "LIVE_WRITE",
            "LIVE_WRITES",
            "ENABLE_EXTERNAL_DELIVERY",
        }:
            assert value == "false", f"{key}={value}"


def test_certification_routes_and_forbidden_routes_match_contracts() -> None:
    contracts = PACKET["contracts"]
    digest = (
        (ROOT / "deploy" / "public-api-route-contract.sha256")
        .read_text(encoding="utf-8")
        .split()[0]
    )
    assert digest == contracts["public_route_contract_sha256"]

    paths = json.loads(
        (
            ROOT / "contracts" / "platform" / "middleware-openapi.generated.json"
        ).read_text(encoding="utf-8")
    )["paths"]
    for method, path in contracts["required_openapi_operations"]:
        assert method in paths.get(path, {}), f"{method.upper()} {path}"
    for path in contracts["forbidden_openapi_paths"]:
        assert path not in paths

    environment = json.loads(
        (ROOT / contracts["postman_db_staging_environment"]).read_text(encoding="utf-8")
    )
    values = {item["key"]: item for item in environment["values"]}
    assert values["environment"]["value"] == "staging"
    assert values["allow_database_mutations"]["value"] == "false"
    assert values["expected_alembic_head"]["value"] == PACKET["source"]["alembic_head"]
    for item in environment["values"]:
        if item.get("type") == "secret":
            assert item["value"] == ""


_BOOT_PROBE = """
import json, sys
from pathlib import Path
from app.core.config import settings
profile = next(
    p for p in json.loads(Path("config/runtime-profiles.v1.json").read_text())["profiles"]
    if p["profile_id"] == sys.argv[1]
)
settings._validate_database_profile(profile["database"])
"""


@pytest.mark.xfail(
    strict=True,
    raises=pytest.fail.Exception,
    reason=(
        "PAS-234 B-03: app.core.config rewrites DATABASE_URL to postgresql+asyncpg:// at "
        "import, so validate_runtime rejects every locked-profile DSN. Remove this marker "
        "with the fix."
    ),
)
def test_module_settings_accept_a_profile_exact_staging_dsn() -> None:
    database = PROFILES[PACKET["source"]["runtime_profile_id"]]["database"]
    dsn = (
        f"{database['scheme']}://{database['username']}:probe@{database['host']}:"
        f"{database['port']}/{database['name']}?sslmode={database['sslmode']}"
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "HOME", "LANG", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP"}
    }
    environment.update(
        {"APP_ENV": "development", "DATABASE_URL": dsn, "PYTHONPATH": str(ROOT)}
    )
    result = subprocess.run(
        [sys.executable, "-c", _BOOT_PROBE, PACKET["source"]["runtime_profile_id"]],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        assert (
            "DATABASE_URL does not match the locked runtime profile" in result.stderr
        ), result.stderr[-400:]
        pytest.fail("locked-profile DSN rejected by module-level settings (B-03)")
