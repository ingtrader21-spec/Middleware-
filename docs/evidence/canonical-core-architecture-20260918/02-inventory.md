# 02 — Inventory and explicit migrations

The consumer inventory (38 `app.config` importers with the attributes each uses, 141 `app.core.config`
importers, 7 `app.runtime` importers, 20 `app.entrypoints.runtime` importers, resource owners) is recorded
in `docs/architecture/canonical-core-migration.md` § Consumer inventory. No blind global replacement was
performed; each migration below was a named, per-file edit.

## Import migrations (per file)

| Group | Files | Change |
| --- | --- | --- |
| `app.config` → `app.core.config` (20 production modules) | `app/appolon_factory.py`, `app/email_production_control.py`, `app/entrypoints/integration_api.py`, `app/klyrow_alert_adapter.py`, `app/klyrow_email_adapter.py`, `app/nats_transport.py`, `app/observability.py`, `app/observability_alert_contract.py`, `app/observability_alerts.py`, `app/odoo_provider_adapter.py`, `app/postly_social_adapter.py`, `app/runtime.py`, `app/runtime_safety.py`, `app/security.py`, `app/telnexa_provider_adapter.py`, `app/temporal_runtime.py`, `app/vicidial_internal_call_adapter.py`, `workers/run_outbox.py`, `workers/run_temporal.py`, `scripts/generate_api_contracts.py` | import path only, plus attribute renames below |
| `app.config` → `app.core.config` (18 test modules) | `tests/conftest.py`, `tests/integration/test_nats_jetstream.py`, `tests/integration/test_synthetic_acceptance.py`, `tests/test_calling_api.py`, `tests/test_campaign_design.py`, `tests/test_control_api_validation.py`, `tests/test_email_production_control.py`, `tests/test_klyrow_alert_adapter.py`, `tests/test_klyrow_email_adapter.py`, `tests/test_observability_alerts.py`, `tests/test_odoo_transport.py`, `tests/test_operation_domain_api_validation.py`, `tests/test_platform_control_plane.py`, `tests/test_postly_social_adapter.py`, `tests/test_public_api_route_contract.py`, `tests/test_security.py`, `tests/test_telnexa_provider_adapter.py`, `tests/test_temporal_worker_wiring.py` | import path only |
| Attribute renames (name collisions between lineages) | `workers/run_outbox.py` (`odoo_delivery_enabled`→`odoo_19_delivery_enabled`, `odoo_base_url`→`odoo_19_base_url`), `tests/test_odoo_transport.py` | explicit |
| `dataclasses.replace(settings, …)` → `settings.replace(…)` | `tests/test_runtime.py`, `tests/test_full_api_routes.py`, `tests/test_n8n_security_invariants.py`, `tests/test_platform_control_plane.py`, `tests/test_staging_acceptance.py` (`umbrella_controls={…}` → the underlying `umbrella_*` field) | explicit |
| `app.runtime` → `app.core.runtime` (7 production, 23 test modules) | `app/survey_intake.py`, `app/service.py`, `app/sdk_events.py`, `app/observability_alerts.py`, `app/lead_intake.py`, `app/appolon_factory.py`, `app/entrypoints/integration_api.py` + tests | `RuntimeContainer as Runtime`, `build_runtime_container` |
| `KeycloakValidator(issuer=settings.keycloak_issuer, …)` → `KeycloakValidator(**identity_validator_kwargs(settings.identity, …))` (8 sites) | `app/api/v1/ai_console.py`, `app/api/v1/campaign_search.py`, `app/api/v1/webphone.py`, `app/api/v1/integrations.py`, `app/campaign_design_api.py`, `app/monitoring/auth.py`, `app/core/provisioning_auth.py`, `app/core/platform_auth.py` | explicit |
| Store constructors | `PostgresInboxStore`, `PostgresCommandStore`, `PostgresCommunicationsStore`, `PostgresRealtimeStore` gain `owns_pool` (default `True`), `RedisReplayGuard` gains `owns_client` | `connect()` classmethods unchanged |

Verification: `tests/test_architecture_governance.py::test_no_consumer_imports_a_legacy_shim` (no importer of
`app.config`, `app.runtime`, `app.appolon_factory` remains) and
`test_canonical_identity_is_consumed_through_identity_settings` (no raw `issuer=settings.keycloak_issuer`).
