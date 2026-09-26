# 14 — Route inventory

Integration profile (8095): 304 operations — {"DENIED_LEGACY": 10, "DIRECT_INTERNAL_SERVICE": 3, "DURABLE_OUTBOX_INTENT": 5, "INTERNAL_EVENT_INGRESS": 123, "KERNEL_WRAPPER": 15, "READ_ONLY": 148}; DIRECT_EFFECT_BYPASSES=0; KERNEL_CONVERGENCE_PENDING=0; APPROVED_DURABLE_OUTBOX_EXCEPTIONS=5 (POST /api/v1/n8n/acknowledgements, POST /v1/observability/incidents, POST /v1/observability/kpis, POST /webhooks/sms/inbound/, POST /webhooks/vicidial/call-result/); DIRECT_INTERNAL_SERVICE_CALLS=3 (POST /webphone-api/v1/renew, POST /webphone-api/v1/revoke, POST /webphone-api/v1/session). Report: config/route-authority-report.v1.json (generator scripts/generate_route_authority_report.py, test tests/test_route_authority_report.py).

Six kernel operations on every profile (INTEGRATION, CONTROL_PLANE, MONOLITH) through app/router_registry.CANONICAL_ROUTERS; DUPLICATE_ROUTES=0 (assert_unique_routes at build), UNREGISTERED_ROUTES=0 (only app.core.health routes outside the registry, as on main), SHADOW_ROUTES=0 (tests/test_route_shadowing.py on every profile).

Quarantine shadow: QUARANTINE_SHADOW_BEFORE=1 (GET /api/v1/quarantine/events answered by app.api.v1.quarantine.detail on the monolith), QUARANTINE_SHADOW_AFTER=0 (record routes constrained to `{record_id:uuid}`; regression test proves compatibility_api.quarantine_list owns the path).
