"""MCR-C route-registration phase of the campaign recycling runtime marker.

MCR-A contracts stay contract_only. The milestone marker may register exactly
the reviewed MCR-C routes from exactly the reviewed files; anything else, and
any production or provider activation, fails validation.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from app.api.v1 import campaign_recycling as api
from scripts import validate_campaign_recycling_contracts as mcr

ROOT = Path(__file__).resolve().parents[1]
MARKER = "config/campaign-recycling-runtime.v1.json"


@pytest.fixture(scope="module")
def artifacts() -> dict[str, Any]:
    return mcr.load_artifacts()


@pytest.fixture
def marker() -> dict[str, Any]:
    return json.loads((ROOT / MARKER).read_text(encoding="utf-8"))


def _errors(
    artifacts: dict[str, Any],
    root: Path,
    marker: dict[str, Any] | None,
    files: dict[str, str] | None = None,
    generated_paths: dict[str, Any] | None = None,
) -> list[str]:
    if marker is not None:
        (root / "config").mkdir(parents=True, exist_ok=True)
        (root / MARKER).write_text(json.dumps(marker), encoding="utf-8")
    for relative, text in (files or {}).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    if generated_paths is not None:
        path = root / mcr.GENERATED_OPENAPI
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"paths": generated_paths}), encoding="utf-8")
    errors: list[str] = []
    mcr.check_no_runtime_activation(artifacts, errors, root)
    return errors


def _reviewed_paths() -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for method, path in mcr.REVIEWED_ROUTE_DISPOSITIONS:
        paths.setdefault(path, {})[method] = {}
    return paths


def test_repository_marker_is_the_reviewed_mcr_c_phase(marker) -> None:
    assert marker["phase"] == "MCR-C" and marker["routes_registered"] is True
    assert marker["production_authorized"] is False
    assert marker["provider_effects_enabled"] is False
    errors: list[str] = []
    mcr.check_no_runtime_activation(mcr.load_artifacts(), errors, ROOT)
    assert errors == []


def test_marker_routes_equal_the_registered_router_and_frozen_contract(marker) -> None:
    registered = {
        (method.lower(), route.path)
        for route in api.router.routes
        for method in route.methods
    }
    declared = {
        (route["method"], route["path"]) for route in marker["reviewed_runtime"]["routes"]
    }
    assert registered == declared == mcr.EXPECTED_OPERATIONS


def test_reviewed_files_may_reference_mcr_surfaces(artifacts, marker, tmp_path) -> None:
    files = {name: "'/platform/v1/suppressions'\n" for name in mcr.REVIEWED_RUNTIME_FILES
             if name.endswith(".py")}
    assert _errors(artifacts, tmp_path, marker, files, _reviewed_paths()) == []


def test_unwhitelisted_mcr_runtime_file_fails(artifacts, marker, tmp_path) -> None:
    errors = _errors(artifacts, tmp_path, marker, {
        "app/api/v1/rogue_campaign_engine.py": "PATH = '/platform/v1/campaign-engine/rollout'\n",
        "migrations/versions/0070_rogue.py": "op.execute('CREATE TABLE exposure_ledger ()')\n",
    }, _reviewed_paths())
    assert any("rogue_campaign_engine.py references MCR-A surface" in e for e in errors)
    assert any("0070_rogue.py references MCR-A surface" in e for e in errors)


def test_marker_cannot_self_whitelist_unreviewed_files(artifacts, marker, tmp_path) -> None:
    marker["reviewed_runtime"]["files"].append("app/api/v1/rogue.py")
    errors = _errors(artifacts, tmp_path, marker, generated_paths=_reviewed_paths())
    assert any("outside the reviewed MCR-C set" in e for e in errors)


@pytest.mark.parametrize("flag", ["production_authorized", "provider_effects_enabled"])
@pytest.mark.parametrize("value", [True, "false", None])
def test_any_production_or_provider_activation_fails(
    artifacts, marker, tmp_path, flag, value
) -> None:
    marker[flag] = value
    errors = _errors(artifacts, tmp_path, marker, generated_paths=_reviewed_paths())
    assert f"runtime: {flag} must remain false" in errors


@pytest.mark.parametrize("flag", ["production_authorized", "provider_effects_enabled"])
def test_removing_an_activation_flag_fails(artifacts, marker, tmp_path, flag) -> None:
    del marker[flag]
    errors = _errors(artifacts, tmp_path, marker, generated_paths=_reviewed_paths())
    assert f"runtime: {flag} must remain false" in errors


@pytest.mark.parametrize("phase", [None, "MCR-D", "production"])
def test_route_registration_requires_the_reviewed_phase(
    artifacts, marker, tmp_path, phase
) -> None:
    if phase is None:
        del marker["phase"]
    else:
        marker["phase"] = phase
    errors = _errors(artifacts, tmp_path, marker, generated_paths=_reviewed_paths())
    assert any("routes may only be registered in phase MCR-C" in e for e in errors)


def test_extra_or_missing_reviewed_route_fails(artifacts, marker, tmp_path) -> None:
    extra = copy.deepcopy(marker)
    extra["reviewed_runtime"]["routes"].append(
        {"method": "post", "path": "/platform/v1/campaign-engine/rollout",
         "disposition": "durable_record_only"}
    )
    assert any("extra=[('post', '/platform/v1/campaign-engine/rollout')]" in e
               for e in _errors(artifacts, tmp_path, extra))
    missing = copy.deepcopy(marker)
    missing["reviewed_runtime"]["routes"] = [
        route for route in missing["reviewed_runtime"]["routes"]
        if route["path"] != "/platform/v1/suppressions"
    ]
    assert any("missing=[('post', '/platform/v1/suppressions')]" in e
               for e in _errors(artifacts, tmp_path, missing))


@pytest.mark.parametrize(
    ("path", "disposition"),
    [
        ("/platform/v1/campaign-engine/execute", "durable_record_only"),
        ("/platform/v1/campaign-engine/plan", "read_only_tenant_bound"),
        ("/platform/v1/campaign-engine/status", "enabled"),
    ],
)
def test_route_dispositions_are_pinned(artifacts, marker, tmp_path, path, disposition) -> None:
    for route in marker["reviewed_runtime"]["routes"]:
        if route["path"] == path:
            route["disposition"] = disposition
    errors = _errors(artifacts, tmp_path, marker, generated_paths=_reviewed_paths())
    assert any(path in e and "disposition must be" in e for e in errors)


def test_durable_dispositions_must_match_frozen_effects(artifacts, marker, tmp_path) -> None:
    changed = copy.deepcopy(artifacts)
    changed["openapi"]["paths"]["/platform/v1/suppressions"]["post"][
        "x-codestra-effects"] = "provider_effects"
    errors = _errors(changed, tmp_path, marker, generated_paths=_reviewed_paths())
    assert any("must match frozen x-codestra-effects" in e for e in errors)


def test_unreviewed_generated_route_fails(artifacts, marker, tmp_path) -> None:
    paths = _reviewed_paths()
    paths["/platform/v1/campaign-engine/rollout"] = {"post": {}}
    errors = _errors(artifacts, tmp_path, marker, generated_paths=paths)
    assert any("unreviewed=[('post', '/platform/v1/campaign-engine/rollout')]" in e
               for e in errors)
    del paths["/platform/v1/campaign-engine/rollout"]
    del paths["/platform/v1/suppressions"]
    errors = _errors(artifacts, tmp_path, marker, generated_paths=paths)
    assert any("unregistered=[('post', '/platform/v1/suppressions')]" in e for e in errors)


def test_pre_route_marker_keeps_the_no_route_guard(artifacts, marker, tmp_path) -> None:
    for key in ("phase", "reviewed_runtime"):
        del marker[key]
    marker["routes_registered"] = False
    errors = _errors(artifacts, tmp_path, marker, {
        "app/api/v1/campaign_recycling.py": "PATH = '/platform/v1/suppressions'\n",
    })
    assert any("campaign_recycling.py references MCR-A surface" in e for e in errors)


def test_pre_route_marker_cannot_carry_a_reviewed_phase(artifacts, marker, tmp_path) -> None:
    marker["routes_registered"] = False
    errors = _errors(artifacts, tmp_path, marker)
    assert "runtime: a pre-route marker must not declare a reviewed runtime phase" in errors


@pytest.mark.parametrize("value", [None, "true", 1])
def test_routes_registered_must_be_boolean(artifacts, marker, tmp_path, value) -> None:
    marker["routes_registered"] = value
    errors = _errors(artifacts, tmp_path, marker)
    assert "runtime: routes_registered must be a boolean" in errors


def test_contracts_stay_contract_only_while_routes_are_registered(artifacts) -> None:
    assert artifacts["openapi"]["info"]["x-codestra-runtime-status"] == "contract_only"
    assert artifacts["openapi"]["info"]["x-codestra-implemented"] is False
    assert artifacts["policy"]["production"]["authorized"] is False
    assert artifacts["authority"]["runtime_status"] == "contract_only"
    status = artifacts["openapi"]["components"]["schemas"]["EngineStatus"]["properties"]
    assert status["production_authorized"]["const"] is False
