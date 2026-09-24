# Rollback (2026-09-16)

Every change in this mission is source-only; rollback is a Git revert of the pull request, plus the following runtime-specific steps if any part had been applied:

| Component | Rollback |
| --- | --- |
| Keycloak staging scope/clients | `reconcile_openbao_workload_identity_staging.py --mode disable` (disables the nine clients, unlinks `openbao.workload` from every bound client); deletion is a separately approved step |
| OpenBao policies/roles | the saved-plan apply is zero-destroy; a rollback plan removes only the roles/policies this branch added; secrets under the new prefixes are left in place and revoked through `revoke-test.sh` procedures |
| Middleware | Alembic downgrade of `0067` removes the catalog columns only while `platform_service_monitoring_audit` is empty; certification evidence is never destroyed by an application rollback; schema head returns to `0066` with the previous history pin |
| Prometheus | previous `prometheus.yml`/rules (Middleware and OpenBao return to their prior jobs); `promtool` gates the reload |
| Alertmanager | previous config bundle (manifest-pinned); inhibitions removed |
| Telemetry / Alloy / Loki / Tempo | previous collector/agent/config files; Tempo receivers fall back to plaintext OTLP only if the gateway exporter is reverted in the same window |
| Grafana | previous image without the Infinity plugin; the Middleware datasource is pruned by provisioning (`prune: true`) |
| Exporters / Superset | declarations and validators only; no runtime effect |

Backup, restore and rollback rehearsal evidence for databases remains under the existing gates (`docs/recovery`, `RESTORE_REHEARSAL_GATE`).
