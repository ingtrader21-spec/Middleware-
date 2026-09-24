# Architecture — three authority planes (2026-09-16)

```text
                        KEYCLOAK  (workload identities; openbao.workload optional scope -> aud openbao + codestra_environment)
                           |
                           v
                      OPENBAO  (secrets / PKI / leases; jwt-codestra mount, CEL roles per identity x environment)
                  /        |        \
          Middleware    exporters     apps          <- agent-rendered /run/secrets files, 0400, no env, no Git
              |
   Operational control plane: service catalog + monitoring state, incidents, Alertmanager ingestion,
   delivery intent/read-back, correlation, audit, reconciliation (never a metrics/log/trace store)

Applications / Hosts --metrics--> Prometheus (authenticated dedicated jobs for Middleware and OpenBao)
                    --logs-----> Alloy (redaction, structured metadata) --> Loki
                    --OTLP-----> local OTel agent (127.0.0.1, redaction) --> central OTel gateway (mTLS) --> Tempo / Loki
                    --health---> Blackbox (GET/HEAD/DNS/TCP/TLS only) --> Prometheus
Prometheus --alerts--> Alertmanager --webhook (OpenBao-referenced bearer)--> Middleware durable incidents
Prometheus + Loki + Tempo + Middleware Observability API --> Grafana (Infinity datasource, read-only)
Curated Middleware/Odoo projections --> Superset (read-only analytics identity)
```

## Authority rules as implemented

| Plane | Owner | Proven by |
| --- | --- | --- |
| Operational control | Middleware | `app/api/v1/platform.py` catalog + `monitoring-state` endpoints, `app/monitoring/routes.py` per-component reconciliation, `app/observability_alerts.py` Alertmanager ingestion and incidents (Alembic 0067) |
| Secrets / credentials / PKI | OpenBao | `config/workload-secret-authority.v1.json` (78 roles, 26 identities), `contracts/secret-reference.v1.schema.json`, `config/secret-references.v1.json` (50 references) |
| Metrics | Prometheus | `codestra/prometheus/prometheus.yml` jobs `codestra-middleware-metrics` (oauth2 monitoring-readonly) and `codestra-openbao` (`/v1/sys/metrics?format=prometheus`, bearer + mTLS from files) |
| Logs | Alloy -> Loki | Alloy redaction (Bearer, OpenBao tokens, JWTs, keys, personal data), OpenBao audit tail; Loki redaction contract and bounded labels |
| Traces | OTel agent -> gateway -> Tempo | agent loopback receivers, gateway mTLS, Tempo receiver TLS, `correlation.id` preserved on spans/logs, trace-propagation contract |
| Alert routing | Prometheus rules -> Alertmanager grouping/inhibition -> Middleware incidents | Alertmanager receivers file-backed, Stage 6 routing matrix (11 cases), Middleware fingerprint dedup |
| Presentation | Grafana | four datasources (Prometheus, Loki, Tempo, Alertmanager read-only) + Middleware Observability (Infinity, pinned, file-expanded bearer) |
| Analytics | Superset | boundary declaration forbids observability backends and OpenBao administration; read-only identity |

Middleware stores only secret references (`app/secret_reference.py`: provider, environment, service_id, secret_ref, secret_class, version, identity, rotation, hashed lease metadata). No Middleware API resolves a reference. Telemetry never flows through Middleware; only operational authority does.

## Decisions recorded

| ID | Decision |
| --- | --- |
| R7-2026-09-16-monitoring-identities-admitted | Grafana, Alertmanager, Alloy, OTel gateway, Loki, Tempo, Redis/Postgres exporters and Superset are admitted OpenBao identities (supersedes the earlier "no role admitted" note); Node Exporter, cAdvisor, Blackbox stay credential-free. |
| R8-2026-09-16-per-environment-issuer | Each OpenBao environment binds the Keycloak issuer of that environment; only the production mount trusts `auth.codestra.co`. Development/test bind the staging issuer and remain unsatisfiable until a non-production issuer exists. |
| R9-2026-09-16-local-otlp-receiver | The per-host OTLP receiver is the OpenTelemetry Collector *agent* profile (Codestra-Telemetry), not Alloy: the reviewed `opentelemetryOwnsApplicationOtlp` boundary is kept; Alloy stays the log/journal agent. |
| R10-2026-09-16-correlation-on-spans-and-logs | `correlation.id` (bounded, opaque) is preserved on spans and logs at the gateway and as Loki structured metadata; it is still stripped from metrics and resource attributes. |
| R11-2026-09-16-alertmanager-identity | The OpenBao identity for Alertmanager is `alertmanager`, the existing Keycloak client id, because OpenBao roles bind `azp`. |
| R12-2026-09-16-private-catalog-routes | The new Middleware catalog monitoring routes are private-network operations like the existing catalog CRUD; the canonical edge contract (digest `7580123d…`) is unchanged. |
