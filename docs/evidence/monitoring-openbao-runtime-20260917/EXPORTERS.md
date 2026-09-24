# Exporters (2026-09-17)

| Exporter | Repo @ SHA | Private endpoint | Credentials | Collector sentinel | Validation |
| --- | --- | --- | --- | --- | --- |
| node_exporter | Codestra-Node-Exporter @ `d054cafe67be` | `10.40.0.{1,2,4}:9100` (private network) | none | `node_exporter_build_info` | `validate_monitoring_platform.py` PASS, unittest OK, CI step |
| cAdvisor | Codestra-cAdvisor @ `f19d0c4e6575` | `10.40.0.{1,2,4}:8080` (cAdvisor's own port; not a Middleware route) | none | `cadvisor_version_info` | same |
| redis_exporter | Codestra-Redis-Exporter @ `fc8ed43d3e14` | `redis-exporter:9121` | Redis password from OpenBao (`codestra/<env>/observability/exporters/redis/*`, identity `redis-exporter`); secret references vendored | `redis_up` | same + secret references |
| postgres_exporter | Codestra-Postgres-Exporter @ `992c18266167` | `postgres-exporter:9187` | DSN from OpenBao (`codestra/<env>/observability/exporters/postgres/*`, identity `postgres-exporter`) | `pg_up` | same + secret references |
| blackbox_exporter | Codestra-Blackbox-Exporter @ `61450f8030cb` | `blackbox-exporter:9115` | none | `blackbox_exporter_build_info` | `validate_probe_policy` PASS, manifest re-pinned (LF) |

All exporters are reachable only on the private observability network (Prometheus `codestra-targets`, `activation: active`); none is edge-routed. Inline-credential heuristic (`inline_credential()`) rejects literal secrets while allowing Docker secret names and `_FILE` paths. Runtime `/metrics` sentinel reads on staging: **not performed**.
