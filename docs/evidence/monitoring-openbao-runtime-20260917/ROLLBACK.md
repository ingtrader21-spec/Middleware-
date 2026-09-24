# Rollback (2026-09-17)

Nothing was deployed, activated, merged or rotated in this stage; rollback of source changes is `git revert` of the listed SHAs per repository (REPOSITORY-SHAS.md), or closing the PRs. Specific reversibility notes:

- Middleware `0067` migration: downgrade refuses while monitoring rows exist (data-preserving); the collector and runners are additive scripts; `service_state` folding changes only the derived `state` value (tests updated). Reverting `30498a30381a602952eefff269e826265e27c810`'s parents restores the source-stage behaviour.
- Prometheus: `target-inventory.v1.json` is derived; deleting it and the validator hook restores the previous validation set; no scrape configuration changed in this stage.
- OpenBao: certifier, rotation matrix and tests are additive; no policy, role, mount or secret changed.
- Keycloak: rebase only; desired state unchanged.
- Staging/production runtime: unchanged (`deployment_performed=false`, `prometheus_target_activated=false`, `tokens_provisioned=false`, `production_changed=false`).

Runtime rollback for a future staging activation: disable the activated Prometheus target (`activation: pending`), unlink the `openbao.workload` scope via `reconcile_openbao_workload_identity_staging.py --mode disable`, revoke workload tokens (`revoke-test.sh` driver), and re-run the collector to confirm `unknown`/`pending` states.
