"""Route ownership of the n8n control plane after ad8b2f9.

The v2 automation router is canonical (mounted by the registry in every
factory, exactly once); the deprecated ``/v1/integrations/n8n/*`` aliases are
the monolith-only registry group, never nested around v2, never mounted by the
deployed integration API, and denied at the edge. The first half proves this
on the composed applications; the second half proves that
``scripts/validate_platform_control_plane.py`` fails closed when any of it
drifts.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from app.automation_v2 import v2_router
from app.entrypoints.integration_api import app as integration_app
from app.main import app as monolith_app
from app.domain_api import legacy_n8n_router as domain_alias_router
from app.n8n_control_plane import router as n8n_alias_router
from app.router_registry import (
    CANONICAL_ROUTERS,
    LEGACY_MONOLITH_ONLY_ROUTERS,
)

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_platform_control_plane.py"
EDGE_CONTRACT = json.loads(
    (ROOT / "deploy" / "public-api-route-contract.json").read_text(encoding="utf-8")
)

V2_COMMAND_ROUTES = {
    ("POST", "/v2/automation/commands"),
    ("GET", "/v2/automation/commands/{command_id}"),
}
DEPRECATED_ALIASES = {
    ("POST", "/v1/integrations/n8n/commands"),
    ("GET", "/v1/integrations/n8n/operations/{command_id}"),
}
# The canonical core moved the remaining ``/v1/integrations/n8n/*`` reads out
# of the domain API into the same deprecated group; the edge denies all of it.
DOMAIN_DEPRECATED_ALIASES = {
    ("GET", "/v1/integrations/n8n/operations"),
    ("POST", "/v1/integrations/n8n/operations/{operation_id}/cancel"),
    ("POST", "/v1/integrations/n8n/operations/{operation_id}/reconcile"),
}


def template_shape(path: str) -> str:
    """Edge matching ignores the template parameter *name*, only its position."""
    return re.sub(r"\{[^}]+\}", "{}", path)


def iter_routes(routes, prefix=""):
    for route in routes:
        original = getattr(route, "original_router", None)
        if original is not None:
            context = getattr(route, "include_context", None)
            yield from iter_routes(
                original.routes, prefix + (getattr(context, "prefix", "") or "")
            )
            continue
        path = getattr(route, "path", None)
        if path is not None:
            for method in getattr(route, "methods", None) or ():
                yield method, prefix + path, getattr(route, "endpoint", None)


def route_table(application) -> list[tuple[str, str, object]]:
    table = list(iter_routes(application.routes))
    assert table, "route walk found nothing"
    return table


# --- composed applications -------------------------------------------------


def test_v2_automation_router_is_canonical_and_the_aliases_are_monolith_only():
    assert v2_router in CANONICAL_ROUTERS
    assert CANONICAL_ROUTERS.count(v2_router) == 1
    assert LEGACY_MONOLITH_ONLY_ROUTERS == (n8n_alias_router, domain_alias_router)
    assert n8n_alias_router not in CANONICAL_ROUTERS
    assert domain_alias_router not in CANONICAL_ROUTERS
    # Whatever the group holds, the edge denies every route it serves: the
    # group cannot grow a publicly reachable path.
    denied = {
        (row["method"], template_shape(row["path"]))
        for row in EDGE_CONTRACT["routes"]
        if row["classification"] == "denied"
    }
    group_routes = {
        (method, path)
        for router in LEGACY_MONOLITH_ONLY_ROUTERS
        for method, path, _endpoint in iter_routes(router.routes)
    }
    assert group_routes == DEPRECATED_ALIASES | DOMAIN_DEPRECATED_ALIASES
    assert {(m, template_shape(p)) for m, p in group_routes} <= denied


def test_v2_routes_are_not_nested_under_the_deprecated_alias_router():
    nested = {
        (method, path)
        for method, path, _endpoint in iter_routes(n8n_alias_router.routes)
        if path.startswith("/v2/")
    }
    assert nested == set()
    assert {
        (method, path) for method, path, _endpoint in iter_routes(n8n_alias_router.routes)
    } == DEPRECATED_ALIASES


@pytest.mark.parametrize(
    "application", [monolith_app, integration_app], ids=["main", "integration_api"]
)
def test_every_v2_automation_route_is_mounted_exactly_once(application):
    counts = Counter(
        (method, path)
        for method, path, _endpoint in route_table(application)
        if path.startswith("/v2/automation/")
    )
    assert V2_COMMAND_ROUTES <= set(counts)
    assert {key: count for key, count in counts.items() if count != 1} == {}
    owners = {
        endpoint.__module__
        for method, path, endpoint in route_table(application)
        if (method, path) in V2_COMMAND_ROUTES
    }
    assert owners == {"app.automation_v2"}


def test_monolith_serves_the_deprecated_aliases_once_from_the_alias_module():
    counts = Counter(
        (method, path)
        for method, path, _endpoint in route_table(monolith_app)
        if (method, path) in DEPRECATED_ALIASES
    )
    assert counts == {key: 1 for key in DEPRECATED_ALIASES}
    owners = {
        endpoint.__module__
        for method, path, endpoint in route_table(monolith_app)
        if (method, path) in DEPRECATED_ALIASES
    }
    assert owners == {"app.n8n_control_plane"}


def test_deployed_integration_api_never_mounts_a_retired_or_denied_route():
    mounted = {(method, path) for method, path, _endpoint in route_table(integration_app)}
    assert mounted & DEPRECATED_ALIASES == set()
    denied = {
        (row["method"], row["path"])
        for row in EDGE_CONTRACT["routes"]
        if row["classification"] == "denied"
    }
    assert DEPRECATED_ALIASES <= denied
    assert mounted & denied == set()
    assert V2_COMMAND_ROUTES <= {
        (row["method"], row["path"])
        for row in EDGE_CONTRACT["routes"]
        if row["classification"] == "shared_edge"
    }


# --- the source validator fails closed --------------------------------------

VALIDATOR_INPUTS = (
    "scripts/validate_platform_control_plane.py",
    "contracts/platform-control-plane.v1.json",
    "contracts/odoo-hmac-test-vector.v1.json",
    "config/capabilities.v2.json",
    "config/route-authority.v1.json",
    "workers/run_temporal.py",
    "deploy/public-api-route-contract.json",
)


def build_tree(target: Path) -> Path:
    for relative in VALIDATOR_INPUTS:
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    shutil.copytree(
        ROOT / "app",
        target / "app",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    return target


def run_validator(tree: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(tree / "scripts" / "validate_platform_control_plane.py")],
        capture_output=True,
        text=True,
        cwd=tree,
    )


def append(tree: Path, relative: str, text: str) -> None:
    path = tree / relative
    path.write_text(path.read_text(encoding="utf-8") + text, encoding="utf-8")


def replace_once(tree: Path, relative: str, old: str, new: str) -> None:
    path = tree / relative
    source = path.read_text(encoding="utf-8")
    assert source.count(old) == 1, (relative, old)
    path.write_text(source.replace(old, new), encoding="utf-8")


def nest_v2_in_aliases(tree: Path) -> None:
    append(
        tree,
        "app/n8n_control_plane.py",
        "\nfrom .automation_v2 import v2_router\nrouter.include_router(v2_router)\n",
    )


def mount_aliases_on_the_deployed_api(tree: Path) -> None:
    append(
        tree,
        "app/entrypoints/integration_api.py",
        "\nfrom app.router_registry import mount_legacy_monolith_routers\n"
        "mount_legacy_monolith_routers(app)\n",
    )


def make_aliases_canonical(tree: Path) -> None:
    replace_once(
        tree,
        "app/router_registry.py",
        "    automation_v2_router,\n",
        "    automation_v2_router,\n    n8n_control_plane_router,\n",
    )


def drop_v2_from_canonical(tree: Path) -> None:
    replace_once(tree, "app/router_registry.py", "    automation_v2_router,\n", "")


def bind_v2_twice(tree: Path) -> None:
    replace_once(
        tree,
        "app/router_registry.py",
        "    automation_v2_router,\n",
        "    automation_v2_router,\n    automation_v2_router,\n",
    )


def mount_aliases_directly_in_main(tree: Path) -> None:
    append(
        tree,
        "app/main.py",
        "\nfrom app.n8n_control_plane import router as n8n_control_plane_router\n"
        "app.include_router(n8n_control_plane_router)\n",
    )


def second_owner_of_v2(tree: Path) -> None:
    (tree / "app" / "second_mount.py").write_text(
        "from app.automation_v2 import v2_router\n", encoding="utf-8"
    )


# The exact factory block the mutations rewrite: aliases mounted only under
# the monolith profile.
MONOLITH_ONLY_MOUNT = (
    "    if profile is AppProfile.MONOLITH:\n"
    "        mount_monolith_routers(app)\n"
    "        mount_legacy_monolith_routers(app)\n"
)


def mount_aliases_unconditionally(tree: Path) -> None:
    """The factory mounts the edge-denied aliases for every profile."""
    replace_once(
        tree,
        "app/application.py",
        MONOLITH_ONLY_MOUNT,
        "    if profile is AppProfile.MONOLITH:\n        mount_monolith_routers(app)\n    mount_legacy_monolith_routers(app)\n",
    )


def mount_aliases_on_the_control_plane_profile(tree: Path) -> None:
    """The deployed control-plane canary would serve the retired aliases."""
    replace_once(
        tree,
        "app/application.py",
        MONOLITH_ONLY_MOUNT,
        "    if profile is AppProfile.MONOLITH:\n        mount_monolith_routers(app)\n    if profile in {AppProfile.CONTROL_PLANE, AppProfile.MONOLITH}:\n        mount_legacy_monolith_routers(app)\n",
    )


def expose_an_alias_at_the_edge(tree: Path) -> None:
    contract_path = tree / "deploy" / "public-api-route-contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    for row in contract["routes"]:
        if (row["method"], row["path"]) == ("POST", "/v1/integrations/n8n/commands"):
            row["classification"] = "shared_edge"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")


def demote_v2_at_the_edge(tree: Path) -> None:
    contract_path = tree / "deploy" / "public-api-route-contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    for row in contract["routes"]:
        if (row["method"], row["path"]) == ("POST", "/v2/automation/commands"):
            row["classification"] = "denied"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")


def test_committed_source_passes_the_validator(tmp_path):
    result = run_validator(build_tree(tmp_path / "tree"))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PLATFORM_CONTROL_PLANE=PASS" in result.stdout


@pytest.mark.parametrize(
    "mutate,expected",
    [
        (nest_v2_in_aliases, "nested in the legacy n8n aliases"),
        (mount_aliases_on_the_deployed_api, "deployed entrypoint mounts edge-denied"),
        (make_aliases_canonical, "must not be canonical"),
        (drop_v2_from_canonical, "exactly once in CANONICAL_ROUTERS"),
        (bind_v2_twice, "exactly once in CANONICAL_ROUTERS"),
        (mount_aliases_directly_in_main, "owned outside the registry"),
        (second_owner_of_v2, "owned outside the registry"),
        (mount_aliases_unconditionally, "outside the monolith profile"),
        (mount_aliases_on_the_control_plane_profile, "outside the monolith profile"),
        (expose_an_alias_at_the_edge, "not denied at the edge"),
        (demote_v2_at_the_edge, "not a shared edge route"),
    ],
    ids=lambda value: getattr(value, "__name__", value),
)
def test_validator_fails_closed_on_route_ownership_drift(tmp_path, mutate, expected):
    tree = build_tree(tmp_path / "tree")
    mutate(tree)
    result = run_validator(tree)
    assert result.returncode != 0
    assert "PLATFORM_CONTROL_PLANE=FAIL" in result.stderr
    assert expected in result.stderr, result.stderr
