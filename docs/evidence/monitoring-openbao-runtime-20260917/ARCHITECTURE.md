# Architecture — runtime integration stage (2026-09-17)

Three authority planes, unchanged from the source stage and now wired for runtime:

| Plane | Authority | What it owns | What it never owns |
| --- | --- | --- | --- |
| Operational control plane | Middleware (`middleware-integration-api:8095`, PR #279 @ `30498a30381a`) | service catalog with monitoring desired/observed/certification state, incidents (Alertmanager ingestion with fingerprint + idempotency), delivery intent/read-back, correlation, audit, reconciliation (`pending/applying/synced/drifted/failed/unknown`), drift, authorization | secret values, raw telemetry storage, unsealing OpenBao |
| Secrets / credentials / PKI plane | OpenBao (`bao.codestra.media`, PR #78 @ `b8e2144f9257`) with Keycloak as issuer (PR #119 @ `886ce5e64e12`) | KV v2 `codestra/<environment>/<service>/...`, per-identity policies, `jwt-codestra` CEL roles (300 s), audit device | monitoring decisions, business data |
| Telemetry data plane | Prometheus (#70), Alertmanager (#29), Alloy (#39) / OTel (#57), Loki (#40), Tempo (#33), Grafana (#32), exporters (#38/#41/#40/#20/#36), Superset (#51, analytics only) | metrics, logs, traces, alert routing, dashboards | secrets, control decisions |

Telemetry is **not** centralised through Middleware: Alloy/OTel ship to Loki/Tempo/Prometheus directly; Middleware only ingests Alertmanager webhooks and collector observations (config digests, health, deployment identity), and exposes read-only observability views to Grafana.

## Runtime wiring added in this stage

```text
                    +----------------------- read-only GET, verified TLS, no redirects -----------------------+
                    |                                                                                        |
  Prometheus  /-/ready /api/v1/status/config /api/v1/targets /api/v1/rules  --+                              |
  Alertmanager /-/ready /api/v2/status(config.original) /api/v2/alerts        |                              |
  Grafana /api/health /api/datasources(+health) /api/search?type=dash-db      |   app/monitoring/collector   |
  Loki /ready /config /loki/api/v1/labels (X-Scope-OrgID)                     +-> digest + freshness ------>-+-> POST /platform/v1/runtime/observations (kind=config)
  Tempo /ready /status/config      Alloy /-/ready /api/v0/web/components      |   (tokens from 0600 files)   |   POST /platform/v1/services/{id}/monitoring-state/observations
  OTel gateway :13133   OpenBao /v1/sys/health   exporters /metrics sentinel  +                              |   (Idempotency-Key, X-Correlation-ID, monotonic sequence)
                                                                                                             |
  Middleware reconcile_one: fresh (<=90 s) config observations -> component_state -> service_state (failed > applying > unknown > drifted > synced)
```

- Prometheus side: `codestra/scripts/target_inventory.py` derives the desired per-target inventory (`codestra/target-inventory.v1.json`, 44 targets: 23 active, 21 pending) and merges the live `/api/v1/targets` view (actual endpoint, scrape status, last-scrape age, freshness, redacted last error, unexplained active targets).
- OpenBao side: `scripts/certify_staging_identity.py` proves one identity end-to-end against the staging authority (17 checks; see OPENBAO-IDENTITY.md) and `config/rotation-certification.v1.json` binds the eight rotation steps to `rotate-test.sh` / `revoke-test.sh`.
- Middleware side: `scripts/certify_test_syn.py` executes the eight TEST_SYN steps across edge, Tempo, Loki, Prometheus, Alertmanager, Grafana and the runtime-safety read-back (TEST-SYN.md).

## Decisions carried forward (not reopened)

R7–R12 from the source stage stand: monitoring identities admitted to OpenBao; per-environment Keycloak issuer; OTel agent (not Alloy) for local OTLP; correlation kept on spans/logs; identity name `alertmanager`; catalog routes private. `monitoring-readonly` keeps exactly `health.read` + `metrics.read` with `audience = middleware-api`. Canonical edge contract digest `7580123dead97ea342c704a57a3c8eed9f5dce69aab247d4b693db96bc7334d5` is unchanged. Middleware remains on the 8095 authority; no canonical monitoring route depends on legacy port 8080 (enforced by the Prometheus inventory invariant and the TEST_SYN metrics step).
