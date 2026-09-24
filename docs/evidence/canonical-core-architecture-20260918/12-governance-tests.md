# 12 — Governance tests: `tests/test_architecture_governance.py`

Source-level tests (AST/regex over the repository) that fail before a second authority can land.

| Test | Forbids |
| --- | --- |
| `test_settings_class_is_defined_once` | any `class Settings` outside `app/core/config.py` |
| `test_legacy_modules_are_pure_shims` | `app/config.py`, `app/runtime.py`, `app/appolon_factory.py` defining anything or dropping the deprecation warning |
| `test_no_consumer_imports_a_legacy_shim` | importing the shims from `app/`, `workers/`, `scripts/`, `tests/` |
| `test_environment_is_read_only_by_configuration_authority` | new `os.getenv`/`os.environ` readers in `app/` (ratchet allowlist of 20 files, may only shrink) |
| `test_fastapi_is_constructed_only_by_approved_modules` | `FastAPI(` outside the factory, `worker_app`, the seven narrow entrypoints, three isolated services and the monitoring OpenAPI script |
| `test_create_app_is_defined_once` | a second `create_app` for Middleware processes (isolated services excepted by name) |
| `test_routers_are_mounted_only_through_the_registry` | `app.include_router(` outside `app/router_registry.py` and the narrow/isolated processes |
| `test_every_profile_is_unique_and_nested_in_the_monolith` | duplicate operations in any profile; a deployed profile mounting an edge-denied alias; profiles that are not subsets of the monolith |
| `test_health_routes_are_registered_only_by_the_health_authority` | `@app.get("/health…")`-style registrations outside `app/core/health.py` and the approved processes |
| `test_single_request_guard` | `app.middleware("http")` outside `app/core/request_guard.py` and the approved processes |
| `test_asyncpg_pools_are_opened_only_by_owners` | `asyncpg.create_pool(` outside the container, the store `connect()` classmethods, `workers/run_outbox.py`, `scripts/verify_event_ledger.py` |
| `test_sqlalchemy_engine_is_created_only_by_the_session_module` | `create_async_engine(` outside `app/db/session.py` (+ migration runner, benchmark) |
| `test_jwks_clients_are_created_only_by_the_identity_verifiers` | `PyJWKClient(` outside the two verifiers (+ email service, certification probe) |
| `test_canonical_identity_is_consumed_through_identity_settings` | `issuer=settings.keycloak_issuer` raw construction |
| `test_security_module_keeps_machine_token_policy` | removal of the 300-second lifetime or the azp check |
| `test_synthetic_ci_identity_is_never_valid_in_staging_or_production` | the synthetic identity becoming valid outside development/test |
| `test_bootstrap_rejects_implicit_https_downgrade` | an `http://` authority passing startup validation |

Related structural tests kept or added elsewhere: `tests/test_route_table_uniqueness.py` (duplicate detection
incl. `test_registry_refuses_duplicate_registrations`), `tests/test_n8n_jwt_guard_routing.py`,
`tests/test_public_api_route_contract.py`, `tests/test_staging_intake_observability_contract_validation.py`.
