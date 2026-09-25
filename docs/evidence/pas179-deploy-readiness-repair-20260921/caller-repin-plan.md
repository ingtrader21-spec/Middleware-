# Caller repin plan — reusable deploy-readiness workflows → `5b8cdbb8`

`CALLER_REPIN_SHA = 5b8cdbb8819863c9230d9bc3a39f2aa9b57e2636` (squash merge of Infustruction PR #126; tree
`e0699d97bef0118118dc0c95d0b921cee5652cb7`). main moved to `c288723b` right after (docs-only ADR #124); the reusable
workflow bytes are identical at both, and the mission records the merge SHA.

## Current pins (read from each caller's `origin/main` on 2026-09-21)

| Caller | Visibility | main | File:line | Current `uses:` |
|---|---|---|---|---|
| ingtrader21-spec/Caddy | public | `22c6d51e` | `.github/workflows/codestra-deploy-readiness.yml:32` | `ingtrader21-spec/Infustruction-repo/.github/workflows/reusable-codestra-deploy-readiness.yml@9d32d421c8272ef33b7a442ac81617bea6d16897` |
| ingtrader21-spec/N8N | private | `dd100d8e` | `…/codestra-deploy-readiness.yml:32` | `appolon1908-hue/Infustruction-repo/.github/workflows/reusable-codestra-deploy-readiness.yml@1b4a90810eb03db3eae2b676b2d418daa434ec16` |
| ingtrader21-spec/Odoo | public | `1bad5819` | `…/codestra-deploy-readiness.yml:32` | same as N8N (`@1b4a9081`) |
| ingtrader21-spec/Codestra-Alertmanager | private | `abfd0f55` | `…/codestra-deploy-readiness.yml:31` | `appolon1908-hue/Infustruction-repo/.github/workflows/reusable-codestra-upstream-deploy-readiness.yml@92f731039333846ef067f1ddbcb276463a92d9ba` |
| ingtrader21-spec/Codestra-Alloy | private | `7ec73806` | `:31` | same (`@92f73103`) |
| ingtrader21-spec/Codestra-Loki | private | `6b3ded98` | `:31` | same (`@92f73103`) |
| ingtrader21-spec/Codestra-Prometheus | private | `d6473a6c` | `:31` | same (`@92f73103`) |
| ingtrader21-spec/Codestra-Telemetry | private | `ced55617` | `:31` | same (`@92f73103`) |
| ingtrader21-spec/Codestra-Tempo | private | `9e6e60fa` | `:31` | same (`@92f73103`) |
| ingtrader21-spec/Codestra-Node-Exporter | private (per lane report; API read timed out) | `fb05e07f` | `…/codestra-deploy-readiness.yml:30` | `appolon1908-hue/Infustruction-repo/.github/workflows/reusable-codestra-upstream-deploy-readiness.yml@f509d61a6207c7cd9e5f2562de0c2b32a85b6cca` |

Every pinned SHA above carries the pre-transfer literal `appolon1908-hue/Infustruction-repo` inside the reusable
workflow, so each caller's `immutable-candidate` / source-signing step signs and then rejects its own certificate the
first time it runs on a main push (observed: Caddy run 35560075759).

## Target lines

Deploy-readiness callers (Caddy, N8N, Odoo):

```yaml
    uses: ingtrader21-spec/Infustruction-repo/.github/workflows/reusable-codestra-deploy-readiness.yml@5b8cdbb8819863c9230d9bc3a39f2aa9b57e2636
```

Upstream-overlay callers (Alertmanager, Alloy, Loki, Prometheus, Telemetry, Tempo, Node-Exporter):

```yaml
    uses: ingtrader21-spec/Infustruction-repo/.github/workflows/reusable-codestra-upstream-deploy-readiness.yml@5b8cdbb8819863c9230d9bc3a39f2aa9b57e2636
```

## Call-contract compatibility (checked from the reusable workflows' `workflow_call` blocks)

- `reusable-codestra-deploy-readiness.yml` `1b4a9081` → `5b8cdbb8`: two **optional** inputs added
  (`dockerfile_path`, `docker_build_context`, default `""`); nothing removed or retyped; no secrets. N8N/Odoo repins
  are one-line changes.
- `reusable-codestra-upstream-deploy-readiness.yml` `92f73103` / `f509d61a` → `5b8cdbb8`: identical inputs
  (`canary_percent`, `confirmation`, `health_paths`, `operation`, `repository_class`, `runtime_deployable`), no
  secrets. Monitoring and Node-Exporter repins are one-line changes.
- Caddy `9d32d421` → `5b8cdbb8`: identical inputs.

## Preconditions (all owner-level, none satisfied at time of writing)

1. `Infustruction-repo` must be **callable** by each caller. GitHub does not let a public repository call a private
   repository's reusable workflow: Caddy and Odoo fail at workflow startup (`workflow file issue`) regardless of the
   SHA until `Infustruction-repo` is public (or those callers stop using the shared workflow). Private callers (N8N,
   all `Codestra-*`) are unaffected by this rule.
2. Hosted Actions must execute for private repositories (billing gate) — otherwise N8N/`Codestra-*` repin PRs cannot
   show a green `deploy-readiness` check.
3. The user's ruling on the `2862af0a → bd406a65` accepted-authority change escalated by middleware-69: hold all
   repins until then (peer coordination 2026-09-21).
4. Optional but recommended before repinning: land the Infustruction repair candidate so callers pin a main whose
   own `Production orchestrator contract` is green (F1 in README). Pinning `5b8cdbb8` is still correct — the
   reusable workflow bytes do not change with that repair.

## Sequence and ownership (agreed with middleware-8f, 2026-09-21)

1. Caddy — middleware-8f (closes PAS-162 / PAS-146 dependency); blocked by ruleset 22657889 until main is removed
   from it, and by precondition 1.
2. N8N, Odoo — middleware-06: one PR each, `uses:` line only, commit message
   `ci(deploy-readiness): repin the reusable deploy-readiness workflow to ingtrader21-spec/Infustruction-repo@5b8cdbb8`.
3. Codestra-Alertmanager, -Alloy, -Loki, -Prometheus, -Telemetry, -Tempo, -Node-Exporter — middleware-06: one PR
   each, same shape. Monitoring repos follow the monitoring ownership rule (one writer per repo, no force push, no
   admin merge).
4. Each repin PR is merged only after its `deploy-readiness` check executed on the exact head and the
   `immutable-candidate` job's cosign verification is observed green on the first main push.

No repin has been pushed by this lane.
