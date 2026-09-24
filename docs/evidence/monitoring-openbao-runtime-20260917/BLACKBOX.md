# Blackbox safety (2026-09-17) — Codestra-Blackbox-Exporter @ `61450f8030cb`

Modules (`config/blackbox.yml`): `tcp_connect`, `dns_codestra_a`, `icmp_private`, `https_openbao_health`, `dns_a_record`, `tls_expiry` (+ `https_2xx`, `http_2xx_internal` in the Prometheus `blackbox.yml`). Every HTTP module is `method: GET` (or HEAD); **no module issues POST, PUT, PATCH or DELETE**, and `validate_probe_policy` / Prometheus `validate_blackbox_modules` fail closed on any other method.

Targets (`targets-production.json`): public API health, OIDC discovery, public web, OpenBao health (`probe_enabled: false`, pending), Middleware readiness (`http_2xx_internal`), Grafana login page, Superset health — all idempotent read paths. No probe can send e-mail/SMS, dial PSTN, create Odoo records, trigger provider delivery or activate workflows: probes hit only health/readiness/discovery/login-page URLs, never a business API.

`https_openbao_health`: GET `/v1/sys/health`, valid status 200/429, body regex requires `initialized` and unsealed; a sealed state is a probe failure and an alert, never an unseal.

Probe state is reconciled through Prometheus `probe_success`/`probe_duration_seconds` (collector `read_prometheus` target records; inventory `probe_module` column). Runtime probe results on staging: **not observed**.
