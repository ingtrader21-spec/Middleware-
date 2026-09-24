"""Parity between contracts/odoo/campaign-control.v1.json and the code that
embeds it: the Odoo client's operation table, migration 0066's static ROUTES
snapshot and pinned hash, and the campaign-control adapter vocabulary.
"""

import hashlib
import importlib.util
import inspect
import json
import re
import typing
from pathlib import Path

import pytest

from app.adapters.odoo import campaign_control
from app.adapters.odoo.client import ODOO_ENDPOINTS


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "contracts" / "odoo" / "campaign-control.v1.json"
MIGRATION_PATH = (
    ROOT / "migrations" / "versions" / "0066_reconcile_odoo_campaign_scope.py"
)
APP_DIR = ROOT / "app"
FORBIDDEN_SCOPE = "odoo.campaign.control.write"


def _load_catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def _load_migration():
    # The module imports alembic.op at import time, which is fine; upgrade()
    # and downgrade() are never called here.
    spec = importlib.util.spec_from_file_location("migration_0066", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def catalog() -> dict:
    return _load_catalog()


@pytest.fixture(scope="module")
def migration():
    return _load_migration()


@pytest.fixture(scope="module")
def migration_source() -> str:
    return MIGRATION_PATH.read_text(encoding="utf-8")


# --- hash and operation table ------------------------------------------------


def test_migration_pins_the_canonical_catalog_hash(catalog, migration):
    canonical = json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(canonical).hexdigest() == migration.CATALOG_SHA256
    assert migration.CATALOG_PATH == "contracts/odoo/campaign-control.v1.json"


def test_client_operation_table_equals_catalog_operations(catalog):
    expected = {
        operation: spec["endpoint_key"]
        for operation, spec in catalog["operations"].items()
    }
    assert ODOO_ENDPOINTS == expected
    assert set(ODOO_ENDPOINTS) == set(expected)


def test_retired_operations_are_absent_from_the_client(catalog):
    retired = catalog["retired_operations"]
    assert retired, "catalog lists no retired operations"
    for operation, spec in retired.items():
        assert operation not in ODOO_ENDPOINTS
        assert spec["endpoint_key"] not in ODOO_ENDPOINTS.values()


# --- migration snapshot parity -----------------------------------------------


def test_migration_routes_snapshot_matches_catalog(catalog, migration):
    operations = catalog["operations"]
    seen = set()
    for (
        endpoint_id,
        operation,
        endpoint_key,
        method,
        path,
        scope,
        kind,
        request_schema,
    ) in migration.ROUTES:
        assert endpoint_id.startswith("66000000-")
        spec = operations[operation]
        assert spec["registered_by"] == "0066", operation
        assert spec["endpoint_key"] == endpoint_key, operation
        assert spec["method"] == method, operation
        assert spec["path"] == path, operation
        assert spec["scope"] == scope, operation
        assert spec["kind"] == kind, operation
        assert spec["request_schema"] == request_schema, operation
        seen.add(operation)
    registered_by_0066 = {
        operation
        for operation, spec in operations.items()
        if spec["registered_by"] == "0066"
    }
    assert seen == registered_by_0066
    assert len(migration.ROUTES) == len(seen)


def test_retired_operation_is_the_0054_route_kill_switched_by_0066(catalog, migration):
    retired = catalog["retired_operations"]["campaign_actions.apply"]
    assert retired["registered_by"] == "0054"
    assert retired["retired_by"] == "0066"
    assert migration.LEGACY_0054_ENDPOINT_VERSION_ID.startswith("54000000-")


# --- scope policy ------------------------------------------------------------


def test_catalog_never_grants_the_odoo_campaign_control_write_scope(catalog):
    scopes = {spec["scope"] for spec in catalog["operations"].values()}
    assert FORBIDDEN_SCOPE not in scopes
    assert FORBIDDEN_SCOPE not in json.dumps(catalog)


def test_forbidden_scope_literal_never_appears_in_migration_or_app(migration_source):
    assert FORBIDDEN_SCOPE not in migration_source
    offenders = [
        str(path.relative_to(ROOT))
        for path in sorted(APP_DIR.rglob("*.py"))
        if FORBIDDEN_SCOPE in path.read_text(encoding="utf-8", errors="replace")
    ]
    assert offenders == []


def test_middleware_scopes_in_catalog_are_the_reviewed_set(catalog):
    operations = catalog["operations"]
    assert (
        operations["campaign.actual_state.write"]["scope"]
        == "odoo.campaign.actual_state.write"
    )
    assert (
        operations["automation_results.apply"]["scope"]
        == "odoo.integration.automation_results.write"
    )
    assert (
        operations["provider_activities.create"]["scope"]
        == "odoo.integration.provider_activities.write"
    )
    assert operations["campaigns.read"]["scope"] == "odoo.campaign.control.read"
    assert operations["desired_state.read"]["scope"] == "odoo.campaign.control.read"


# --- migration is static ------------------------------------------------------


@pytest.mark.parametrize("needle", ["json.load", "read_text(", "open("])
def test_migration_never_reads_the_catalog_at_upgrade_time(migration_source, needle):
    assert needle not in migration_source


# --- binding policy -----------------------------------------------------------


def test_environment_policy_matches_catalog_registry_policy(catalog, migration):
    by_name = {row[0]: row for row in migration.ENVIRONMENTS}
    assert set(by_name) == {"staging", "production"}
    assert set(catalog["registry_policy_0066"]) == {"staging", "production"}
    # (environment, base_url, credential, audience, tls_profile, version_prefix,
    #  configuration_version, write_kill_switch, write_binding)
    assert by_name["production"][7] is True
    assert by_name["staging"][7] is False
    assert by_name["staging"][8] == ("TEST_SYN_TENANT", "TEST_SYN", "TEST_SYN")
    assert migration.TEST_SYN_BINDING == ("TEST_SYN_TENANT", "TEST_SYN", "TEST_SYN")
    assert by_name["production"][8] == ("", "", "")


def test_downgrade_never_reactivates_the_0054_route(migration):
    source = inspect.getsource(migration.downgrade)
    assert not re.search(r"kill_switch\s*=\s*false", source, re.IGNORECASE)
    assert "54000000" not in source
    assert migration.LEGACY_0054_ENDPOINT_VERSION_ID not in source
    patterns = re.findall(r"LIKE '([^']*)'", source)
    assert patterns, "downgrade deletes nothing by id prefix"
    assert all(pattern == "66000000-%" for pattern in patterns), patterns


def test_upgrade_kill_switches_only_the_legacy_0054_version(migration):
    source = inspect.getsource(migration.upgrade)
    assert "SET kill_switch = true" in source
    assert "LEGACY_0054_ENDPOINT_VERSION_ID" in source
    assert not re.search(r"kill_switch\s*=\s*false", source, re.IGNORECASE)


# --- vocabulary parity --------------------------------------------------------


def test_effective_states_match_the_adapter_literal(catalog):
    assert catalog["effective_states"] == list(
        typing.get_args(campaign_control.EffectiveState)
    )


def test_synthetic_adapter_result_states_use_catalog_vocabulary(catalog):
    operations = set(typing.get_args(campaign_control.CampaignOperation))
    result_state = catalog["synthetic_adapter_result_state"]
    assert set(result_state) == operations
    assert (
        set(catalog["outbox_events"]["operation_by_event_type"].values()) == operations
    )
    for operation, state in result_state.items():
        assert state is None or state in catalog["effective_states"], operation


def test_outbox_allowlist_matches_saga_allowed_event_types(catalog):
    from app import odoo_campaign_saga

    allowed = odoo_campaign_saga.ALLOWED_EVENT_TYPES
    allowlist = catalog["outbox_events"]["allowlist"]
    assert set(allowed) == set(allowlist)
    assert len(allowlist) == len(set(allowlist))
    assert set(catalog["outbox_events"]["operation_by_event_type"]) == set(allowlist)


def test_actual_state_readback_fields_match_the_catalog(catalog):
    fields = campaign_control.ActualStateReadback.model_fields
    required = catalog["actual_state_readback"]["required_fields"]
    assert set(fields) == set(required)
    assert len(required) == len(set(required))
    assert all(field.is_required() for field in fields.values())
    assert campaign_control.ActualStateReadback.model_config.get("extra") == "forbid"


def test_desired_state_response_fields_match_the_catalog(catalog):
    fields = campaign_control.DesiredState.model_fields
    expected = catalog["operations"]["desired_state.read"]["response_fields"]
    assert set(fields) == set(expected)
    assert all(field.is_required() for field in fields.values())


def test_staging_write_binding_snapshot_matches_the_catalog():
    """0066 snapshots the TEST_SYN triple; the catalog is the reviewed source."""
    import importlib.util
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    catalog = json.loads(
        (root / "contracts/odoo/campaign-control.v1.json").read_text(encoding="utf-8")
    )
    binding = catalog["registry_policy_0066"]["staging"]["write_binding"]
    spec = importlib.util.spec_from_file_location(
        "migration_0066_binding",
        root / "migrations/versions/0066_reconcile_odoo_campaign_scope.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    assert module.TEST_SYN_BINDING == (
        binding["organization_public_id"],
        binding["business_unit_public_id"],
        binding["campaign_public_id"],
    )
    assert catalog["registry_policy_0066"]["production"]["write_binding"] is None
    assert "downgrade" in module.downgrade.__code__.co_name
    assert "refusing downgrade" in __import__("inspect").getsource(module.downgrade)
