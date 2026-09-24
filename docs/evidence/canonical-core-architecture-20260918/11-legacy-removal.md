# 11 — Legacy removal

| Item | State after Mission 2 |
| --- | --- |
| `app/config.py` | deprecated shim: re-exports `Settings`, `ConfigurationError`, `EXTERNAL_DELIVERY_EFFECTS`, `RUNTIME_PROFILES_PATH`, `SUPPORTED_EXTERNAL_EFFECTS`, `UMBRELLA_CONTROL_NAMES`, `WEBHOOK_PRODUCERS`; `DeprecationWarning`; one documented importer left (`app/vicidial_internal_call_adapter.py`, blocked by the lead-automation workflow gate on vicidial-named files; governance allowlist `LEGACY_SHIM_IMPORTERS_PENDING`) |
| `app/runtime.py` | deprecated shim (`Runtime`, `build_runtime`, `ReadinessReport`, `_asyncpg_dsn`); zero importers |
| `app/appolon_factory.py` | deprecated shim (`create_app`); inline routes moved to `app/appolon_routes.py`; zero importers |
| `app/main.py` | 40 lines: `app = create_app(profile=AppProfile.MONOLITH)`, re-exports; the 320-line inline guard/health/version/capabilities module is gone |
| `app/entrypoints/integration_api.py` | 20 lines: `app = create_app(profile=AppProfile.INTEGRATION, service=SERVICE)`; the 21-router route list and the private lifespan are gone |
| `app/entrypoints/runtime.py` | `validate_runtime` → `bootstrap.validate_startup`; `add_api_runtime` → `RequestGuard` + `register_service_health_routes`; the 230-line guard/readiness/version/capabilities/dependencies copy is gone; `worker_app` unchanged by design |
| `control.event` `POST /events/vicidial` alias | removed (always shadowed by the HMAC ingress) |
| `lead_automation.receive_odoo_event` route | registration removed (always shadowed); function kept importable |
| `api.v1.telephony.originate_call` route | registration removed (operation owned by the Odoo calling contract); function kept for its lifecycle tests |
| Deprecated n8n aliases on the canary | no longer mounted (`LEGACY_MONOLITH_ONLY_ROUTERS` are monolith-only) |
| `os.getenv("SOURCE_SHA")` in `/version` | removed (settings-based) |

## Source-contract validators re-targeted (they are part of the required `validate` check)

| Validator | Change |
| --- | --- |
| `scripts/validate_staging_intake_observability_contract.py` (Historical Stage 6) | analyses `app/application.py` (single factory, single FastAPI, approved helpers only, nothing registered on `app` directly), `app/core/request_guard.py` (exactly one `app.middleware("http")`, exact `__call__` signature, one `call_next`, only header mutations, only `request.state` writes, refusals only as `JSONResponse` with a fail-closed constant status), `app/appolon_routes.py` (governed reads authenticate first with static bindings; dynamic webhook registration counted), `app/core/health.py` (literal paths only), `app/router_registry.py` (exact import set, exact six tuples, `_mount` is the only `include_router`); shadow scan over every mounted router module. 34 mutations × (plain, `-O`) = 68 fail-closed cases + the committed-state pass |
| `scripts/validate_platform_control_plane.py` | markers for the n8n compatibility router moved to the registry (`LEGACY_MONOLITH_ONLY_ROUTERS`, `mount_legacy_monolith_routers`), v2 router must be canonical, factory must mount the legacy group, `app.main` must build the monolith profile — this validator had been failing since `ad8b2f9` on the base |
| `scripts/validate_intake_observability.py` | metrics route and lead-intake request context read from `app/appolon_routes.py` |
| `scripts/certify_edge_integration.py` | `both_entrypoints_share_route_matcher` proves the single guard imports `route_policy` and neither entry module carries a matcher or `verify_bearer` |
| `scripts/generate_api_contracts.py` | unchanged; artifacts regenerated from the control-plane profile |
