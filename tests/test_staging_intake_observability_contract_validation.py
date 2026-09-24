from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/validate_staging_intake_observability_contract.py"
BOUND_FILES = (
    "contracts/staging-intake-observability-runtime.v1.json",
    "config/runtime-profiles.v1.json",
    "config/api-webhook-contracts.json",
    "config/provider-operation-policy.json",
    "config/environments/staging.intake-observability.runtime.env.example",
    ".github/workflows/staging-intake-observability-contract.yml",
)
FACTORY = "app/application.py"
ROUTES = "app/appolon_routes.py"
GUARD = "app/core/request_guard.py"

METRICS_AUTHENTICATION = """    await request.app.state.runtime.tokens.verify(
        request.headers.get("Authorization", ""),
        expected_client_id="monitoring-readonly",
        required_scope="metrics.read",
    )"""
FASTAPI_IMPORT_MARKER = (
    "from fastapi.responses import JSONResponse, Response, StreamingResponse\n"
)


def _replace_once(path: Path, marker: str, replacement: str) -> None:
    source = path.read_text(encoding="utf-8")
    changed = source.replace(marker, replacement, 1)
    assert changed != source, f"marker not found in {path.name}: {marker!r}"
    path.write_text(changed, encoding="utf-8")


@pytest.mark.parametrize("optimized", [False, True])
@pytest.mark.parametrize(
    "mutation",
    [
        "production_authorized",
        "effect_enabled",
        "public_metrics",
        "wrong_source",
        "commented_metrics_route",
        "dead_metrics_authentication",
        "unrelated_metrics_verifier",
        "unawaited_metrics_verifier",
        "decorated_metrics_handler",
        "shadow_metrics_registration",
        "parameterized_metrics_shadow",
        "keyword_metrics_shadow",
        "mounted_metrics_shadow",
        "app_alias_metrics_shadow",
        "unapproved_included_router",
        "factory_direct_route",
        "included_router_shadow",
        "provider_side_effect_shadow",
        "route_helper_shadow",
        "health_route_shadow",
        "webhook_shadow",
        "request_dependency_proxy",
        "rebound_request_type",
        "class_request_rebind",
        "aliased_request_rebind",
        "missing_workflow_bound_source",
        "middleware_short_circuit",
        "middleware_public_json_short_circuit",
        "custom_middleware",
        "constructor_middleware",
        "middleware_status_rewrite",
        "middleware_path_rewrite",
        "second_middleware",
        "registry_extra_router",
    ],
)
def test_staging_contract_fails_closed(
    tmp_path: Path,
    optimized: bool,
    mutation: str,
) -> None:
    # The validator reads every router module the registry mounts, so the
    # whole application package is bound.
    shutil.copytree(ROOT / "app", tmp_path / "app")
    for relative in BOUND_FILES:
        source = ROOT / relative
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())

    contract_path = tmp_path / "contracts/staging-intake-observability-runtime.v1.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    if mutation == "production_authorized":
        contract["production_authorized"] = True
    elif mutation == "effect_enabled":
        contract["runtime_recognized_external_effects"]["LIVE_WRITE"] = True
    elif mutation == "public_metrics":
        contract["authenticated_read_endpoints"][0]["public_exposure"] = True
    elif mutation == "wrong_source":
        contract["immutable_release"]["source_sha"] = "0" * 40
    contract_path.write_text(json.dumps(contract), encoding="utf-8")

    routes_path = tmp_path / ROUTES
    factory_path = tmp_path / FACTORY
    guard_path = tmp_path / GUARD
    metrics_marker = '@router.get("/metrics")\n'
    if mutation == "commented_metrics_route":
        _replace_once(routes_path, metrics_marker, '# @router.get("/metrics")\n')
        routes_path.write_text(
            routes_path.read_text(encoding="utf-8")
            + '\n# @router.get("/metrics") required_scope="metrics.read"\n',
            encoding="utf-8",
        )
    elif mutation == "dead_metrics_authentication":
        _replace_once(
            routes_path,
            METRICS_AUTHENTICATION,
            "    if False:\n"
            + "\n".join("    " + line for line in METRICS_AUTHENTICATION.splitlines()),
        )
    elif mutation == "unrelated_metrics_verifier":
        _replace_once(
            routes_path,
            METRICS_AUTHENTICATION,
            METRICS_AUTHENTICATION.replace(
                "request.app.state.runtime.tokens.verify", "unrelated.verify"
            ),
        )
    elif mutation == "unawaited_metrics_verifier":
        _replace_once(
            routes_path,
            METRICS_AUTHENTICATION,
            METRICS_AUTHENTICATION.replace("    await ", "    ", 1),
        )
    elif mutation == "decorated_metrics_handler":
        _replace_once(routes_path, metrics_marker, metrics_marker + "@replace_handler\n")
    elif mutation == "shadow_metrics_registration":
        _replace_once(
            routes_path,
            metrics_marker,
            'router.add_api_route("/" + "metrics", public_metrics, methods=["GET"])\n\n'
            + metrics_marker,
        )
    elif mutation == "parameterized_metrics_shadow":
        _replace_once(
            routes_path,
            metrics_marker,
            '@router.get("/{shadow:path}")\n'
            "async def parameterized_shadow():\n"
            "    return None\n\n" + metrics_marker,
        )
    elif mutation == "keyword_metrics_shadow":
        _replace_once(
            routes_path,
            metrics_marker,
            'router.add_api_route(path="/metrics", endpoint=public_metrics, methods=["GET"])\n\n'
            + metrics_marker,
        )
    elif mutation == "mounted_metrics_shadow":
        _replace_once(
            factory_path,
            "    register_health_routes(app, service=service_name, state=state)\n",
            '    app.mount("/", public_app)\n'
            "    register_health_routes(app, service=service_name, state=state)\n",
        )
    elif mutation == "app_alias_metrics_shadow":
        _replace_once(
            factory_path,
            "    register_health_routes(app, service=service_name, state=state)\n",
            "    shadow = app\n"
            '    @shadow.get("/metrics")\n'
            "    async def aliased_shadow():\n"
            "        return None\n\n"
            "    register_health_routes(app, service=service_name, state=state)\n",
        )
    elif mutation == "unapproved_included_router":
        _replace_once(
            factory_path,
            "    mount_canonical_routers(app)\n",
            "    app.include_router(public_metrics_router)\n    mount_canonical_routers(app)\n",
        )
    elif mutation == "factory_direct_route":
        _replace_once(
            factory_path,
            "    mount_canonical_routers(app)\n",
            '    app.add_api_route("/metrics", public_metrics, methods=["GET"])\n'
            "    mount_canonical_routers(app)\n",
        )
    elif mutation == "included_router_shadow":
        router_path = tmp_path / "app/control_api.py"
        router_path.write_text(
            router_path.read_text(encoding="utf-8")
            + '\nshadow_path = "/metrics"\n'
            'router.add_api_route(shadow_path, public_metrics, methods=["GET"])\n',
            encoding="utf-8",
        )
    elif mutation == "provider_side_effect_shadow":
        router_path = tmp_path / "app/provider_control_api.py"
        router_path.write_text(
            router_path.read_text(encoding="utf-8")
            + '\n@router.get("/metrics")\n'
            "async def public_metrics_shadow():\n"
            "    return None\n",
            encoding="utf-8",
        )
    elif mutation == "route_helper_shadow":
        _replace_once(
            tmp_path / "app/survey_routes.py",
            '    @app.post("/v1/intake/surveys/responses")\n',
            '    @app.get("/{shadow:path}")\n'
            "    async def public_metrics_shadow():\n"
            "        return None\n\n"
            '    @app.post("/v1/intake/surveys/responses")\n',
        )
    elif mutation == "health_route_shadow":
        _replace_once(
            tmp_path / "app/core/health.py",
            '    app.add_api_route("/version", version, methods=["GET"], tags=["health"], name="version")\n',
            '    app.add_api_route("/metrics", version, methods=["GET"], tags=["health"], name="version")\n'
            '    app.add_api_route("/version", version, methods=["GET"], tags=["health"], name="version")\n',
        )
    elif mutation == "webhook_shadow":
        webhook_path = tmp_path / "config/api-webhook-contracts.json"
        webhook_contract = json.loads(webhook_path.read_text(encoding="utf-8"))
        webhook_contract["webhooks"][0]["path"] = "/metrics"
        webhook_path.write_text(json.dumps(webhook_contract), encoding="utf-8")
    elif mutation == "request_dependency_proxy":
        _replace_once(
            routes_path,
            "async def metrics(request: Request) -> Response:\n",
            "async def metrics(\n    request: object = Depends(public_request),\n) -> Response:\n",
        )
    elif mutation == "rebound_request_type":
        _replace_once(routes_path, FASTAPI_IMPORT_MARKER, FASTAPI_IMPORT_MARKER + "Request = object\n")
    elif mutation == "class_request_rebind":
        _replace_once(
            routes_path,
            FASTAPI_IMPORT_MARKER,
            FASTAPI_IMPORT_MARKER + "class Request:\n    pass\n",
        )
    elif mutation == "aliased_request_rebind":
        _replace_once(
            routes_path,
            FASTAPI_IMPORT_MARKER,
            FASTAPI_IMPORT_MARKER + "from proxy_module import Proxy as Request\n",
        )
    elif mutation == "missing_workflow_bound_source":
        workflow_path = tmp_path / ".github/workflows/staging-intake-observability-contract.yml"
        _replace_once(workflow_path, '      - "app/**/*.py"\n', "")
    elif mutation == "middleware_short_circuit":
        _replace_once(
            guard_path,
            "        correlation_id = safe_correlation_id(",
            '        if request.url.path == "/metrics":\n'
            '            return Response(content="public")\n'
            "        correlation_id = safe_correlation_id(",
        )
    elif mutation == "middleware_public_json_short_circuit":
        _replace_once(
            guard_path,
            "        correlation_id = safe_correlation_id(",
            '        if request.url.path == "/metrics":\n'
            '            return JSONResponse({"public": True}, status_code=200)\n'
            "        correlation_id = safe_correlation_id(",
        )
    elif mutation == "custom_middleware":
        _replace_once(
            factory_path,
            "    install_request_guard(\n",
            "    app.add_middleware(PublicMetricsMiddleware)\n    install_request_guard(\n",
        )
    elif mutation == "constructor_middleware":
        _replace_once(
            factory_path,
            "        title=APPLICATION_TITLE,\n",
            "        title=APPLICATION_TITLE,\n        middleware=[PublicMetricsMiddleware],\n",
        )
    elif mutation == "middleware_status_rewrite":
        _replace_once(
            guard_path,
            "        return response\n",
            "        response.status_code = 200\n        return response\n",
        )
    elif mutation == "middleware_path_rewrite":
        _replace_once(
            guard_path,
            "        started = self.telemetry.start_request()",
            '        request.scope["path"] = "/health"\n'
            "        started = self.telemetry.start_request()",
        )
    elif mutation == "second_middleware":
        _replace_once(
            guard_path,
            '    app.middleware("http")(guard)\n',
            '    app.middleware("http")(guard)\n    app.middleware("http")(public_metrics)\n',
        )
    elif mutation == "registry_extra_router":
        _replace_once(
            tmp_path / "app/router_registry.py",
            "APPOLON_ROUTERS: tuple[APIRouter, ...] = (\n",
            "APPOLON_ROUTERS: tuple[APIRouter, ...] = (\n    public_metrics_router,\n",
        )

    program = (
        "import importlib.util,pathlib;"
        f'spec=importlib.util.spec_from_file_location("staging_contract",{str(SCRIPT)!r});'
        "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);"
        f"m.ROOT=pathlib.Path({str(tmp_path)!r});m.main()"
    )
    result = subprocess.run(
        [sys.executable, *(("-O",) if optimized else ()), "-c", program],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "ContractError" in result.stderr


def test_committed_staging_contract_is_valid() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "MIDDLEWARE_STAGING_INTAKE_OBSERVABILITY_CONTRACT=PASS" in result.stdout
