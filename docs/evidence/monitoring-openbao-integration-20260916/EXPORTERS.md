# Exporters and Blackbox (2026-09-16)

| Repository | Head | PR | Credential policy | Prometheus target |
| --- | --- | --- | --- | --- |
| Codestra-Node-Exporter | `d054cafe` | #38 | credential-free, no OpenBao identity | `node-exporter` (10.40.0.1/2/4:9100, active) |
| Codestra-cAdvisor | `f19d0c4e` | #41 | credential-free, no OpenBao identity | `cadvisor` (active) |
| Codestra-Redis-Exporter | `fc8ed43d` | #40 | `redis-exporter` -> `observability/exporters/redis/monitoring-user` rendered to `/run/secrets/redis_password_map.json` (`--redis.password-file`) | `redis-exporter:9121` (active) |
| Codestra-Postgres-Exporter | `992c1826` | #20 | `postgres-exporter` -> `observability/exporters/postgres/monitoring-role` rendered to the URI/user/password files (`DATA_SOURCE_*_FILE`); runtime.v1.json aligned to the admitted prefix | `postgres-exporter:9187` (active) |
| Codestra-Blackbox-Exporter | `61450f80` | #36 | credential-free; probe policy GET/HEAD/DNS/TCP/ICMP only, no bodies, no business API targets; modules `https_openbao_health`, `dns_a_record`, `tls_expiry` added to the authoritative `config/blackbox.yml`; bundle manifest re-pinned | `blackbox-exporter:9115` |

Each repository declares `codestra/monitoring-platform.v1.json` and runs `scripts/validate_monitoring_platform.py` (PASS everywhere; unittest suites OK), which fails closed on a non-loopback host port, an inline credential, a credential file without an OpenBao reference, a business effect and any non-read-only probe module. One exporter per host/deployment stays the placement model (`INTEGRATED-MONITORING-DESIGN.md`).
