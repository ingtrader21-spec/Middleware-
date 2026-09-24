# 15 — Commit, PR and exact-SHA CI

| Item | Value |
| --- | --- |
| Branch | `mission/middleware-canonical-core-20260918` |
| Base (PR #278 head) | `899585932c51fdb02827c8e28777d388fbb43c44` |
| Mission-2 commits | `cbfeb369034f0d5314371faf25b69824e49a145e` (the implementation, parent = base), then one CI-loop fix per round: `af7f23f` (round 1), `c09fd64` (round 2), `759f814` (round 3) |
| PR | #280 (draft), base branch `codex/cross-repo-authority-20260916` — stacked on #278 |
| Push | `origin` (`appolon1908-hue/Middleware-`, GitHub now redirects to `ingtrader21-spec/Middleware-`) |

Merge rules in force: not before #278; not while any required check is pending or red; no force-merge, no
bypass. The PR is a draft until the exact-SHA CI of its head is green and #278 is merged.

## Required checks (branch protection on `main`)

`validate` · `docker-test-build` · `docker-runtime-build` · `container-security` ·
`Disposable PostgreSQL Redis integration` · `Disposable NATS JetStream integration` ·
`Temporal critical workflow integration` · `Synthetic no-effect acceptance E2E`, plus the
`Required exact-SHA CI` / `codestra/required-ci` status.

## State inherited from #278 (base) at the time of writing

`Required exact-SHA CI`: success. `Middleware CI` `validate`: **failure** — `Validate middleware source head`
and `Validate middleware merge result` (source validators; `validate_platform_control_plane.py` is fixed by
this PR), `connector-runtime-build` and `container-security` (connector runtime image and its security scan —
root cause found in round 3: the `httpx2` pin from `e541d91`; fixed on this branch by restoring the lock's
`httpx==0.28.1`, see round 3). Also red on #278: `Production orchestrator contract`, `Trusted production
orchestrator evidence`, `beyvra-email-authority`. These are not caused by Mission 2 and cannot be fixed inside
its scope; they block #278 first.

## Exact-SHA CI loop

Per the mission: run CI on the exact SHA, read every failing job's log, fix root causes in follow-up commits
on this branch (each recorded here with its SHA), never re-run to get lucky, never skip a required test.

| Round | SHA | Result | Root cause | Fix |
| --- | --- | --- | --- | --- |
| 1 | `cbfeb36` | red: `Required exact-SHA CI` (mypy: `pydantic_settings.sources` has no `parse_env_vars`), every `Middleware CI` job, `Integrated monitoring API`, `lead-automation-v1`, `Release component matrix (middleware)` — all with `ImportError: cannot import name 'parse_env_vars' from 'pydantic_settings.sources'` | the locked CI environment pins `pydantic-settings==2.10.1`, which no longer exports the private `parse_env_vars` helper the mapping source imported (the development host has 2.7.1) | `_MappingEnvSource._load_env_vars` normalizes the mapping itself (case folding, empty-value skipping, none-string parsing) and delegates to the parent for `os.environ`; verified in a venv with `pydantic==2.10.4`/`pydantic-settings==2.10.1`. Passing in round 1 despite the import error: `Historical Stage 6 … validate`, `Production route contract`, `Observability alert contract`, `Production integration lock`, `Connector SDK`, `Python quality baseline`; `PLATFORM_CONTROL_PLANE=PASS` was reached in `run_ci.sh` before the import failure. |
| 2 | `af7f23f` | `Required exact-SHA CI`: 3348 passed, **1 failed** (`test_campaign_design.py::test_preview_and_approval_api_persist_verified_tenant`, PostgreSQL-backed); `Middleware CI`: `Disposable NATS JetStream integration` refused the isolated JetStream configuration ("broad-event activation requires every canonical gate"), `connector-runtime-build` (pre-existing, inherited from #278), `validate` (pytest inside `project_ci.sh` — same campaign-design failure); `Integrated monitoring API`: import-time `StartupError: KEYCLOAK_ISSUER must match the development identity authority`; `lead-automation-v1`: prohibited-file grep (`app/api/v1/recordings.py`, `app/vicidial_internal_call_adapter.py`) + trailing whitespace. `Release component matrix CI` green (was red on #278 for the connector image). | (a) `SEND_EVENTS` overloaded for two pipelines; (b) development/test issuer rule too strict for disposable identities; (c) fake validators built on an implicit identity; (d) lead-automation gate scope | (a) split into `SEND_EVENTS` + `BROAD_EVENT_SEND_ENABLED`; (b) dev/test accept explicit https authorities; (c) explicit identity in the campaign-design tests; (d) restore the two gated files, `app/api/v1/service_identity.py`, whitespace |
| 3 | `c09fd64` | green: `Required exact-SHA CI` / `codestra/required-ci`, `Integrated monitoring API`, `lead-automation-v1`, `Release component matrix CI`, `Historical Stage 6 … validate`, `Production route contract`, `Observability alert contract`, `Production integration lock`, `Connector SDK`, `Python quality baseline`; `Middleware CI`: every Mission-2 job green (`Validate middleware source head`, `Validate middleware merge result`, `docker-runtime-build`, `docker-test-build`, `Disposable PostgreSQL Redis integration`, `Disposable NATS JetStream integration`, `Temporal critical workflow integration`, `Synthetic no-effect acceptance E2E`); **red**: `connector-runtime-build`, `container-security` (both: `codestra-connector-runtime 1.0.0 requires httpx2, which is not installed` from `pip check` at `Dockerfile.runtime:71`) and therefore the `validate` aggregator, which requires both | inherited from the base lineage: commit `e541d91` ("commit pre-existing uncommitted work … not reviewed") rewrote `httpx==0.28.1` as `httpx2==2.13.0` in `requirements-connector-runtime.in` and `services/connector-runtime/pyproject.toml` without recompiling the hash-locked `requirements-connector-runtime.txt`, which still binds `httpx==0.28.1` (as does `main`). `scripts/validate_release_supply_chain.py` reports exactly this (`connector lock does not bind httpx2==2.13.0`). `httpx2` is not a package the lock (or PyPI) provides. | both declarations restored to `httpx==0.28.1` — byte-identical to `main`, matching the lock; no new pin, no lock recompile. Verified: `validate_release_supply_chain.py` → `RELEASE_SUPPLY_CHAIN=PASS`; `docker build --target connector-dependencies -f Dockerfile.runtime` locally → `pip check`: "No broken requirements found". The same one-line fix is needed on #278 itself (its `connector-runtime-build`/`container-security` reds have this cause). |
| 4 | `759f814` | **all green.** `Middleware CI` run `35328499666`: `validate` (aggregator) success with `Validate middleware source head`, `Validate middleware merge result`, `docker-runtime-build`, `docker-test-build`, `connector-runtime-build`, `container-security`, `Disposable PostgreSQL Redis integration`, `Disposable NATS JetStream integration`, `Temporal critical workflow integration`, `Synthetic no-effect acceptance E2E` all success (`Validate middleware main push` skipped, as required for `pull_request`). `Required exact-SHA CI` / `codestra/required-ci` success. Also success: `Integrated monitoring API`, `lead-automation-v1`, `Release component matrix CI` (agent-desktop, middleware, websocket-gateway), `Historical Stage 6 …`, `Production route contract`, `Observability alert contract`, `Production integration lock`, `Connector SDK v1 validation`, `Connector Runtime API validation`, `Connector storage v1`, `Marketing Stage 5 Certification`, `Python quality baseline`, `GitHub Advanced Security`. PR #280 status rollup: every required context (`validate`, `docker-test-build`, `docker-runtime-build`, `container-security`, the four integration jobs, `codestra/required-ci`) `SUCCESS`; no pending, no failure. | — | — |
| 5 | (evidence-only commit recording round 4) | see below | — | — |

This file is updated in the same branch after each CI round.

## Merge state at the end of Mission 2

- PR #280 head is green on every required context; it stays a **draft** and is **not merged**: the base
  PR #278 is still open and red (`connector-runtime-build`/`container-security` from the same `httpx2` pin —
  fixed here in `759f814`, cherry-pickable to #278 — plus `Production orchestrator contract`, `Trusted
  production orchestrator evidence`, `beyvra-email-authority`, which are outside this change set).
- Merge order remains #278 first, then #280 (after a re-run of its required checks on the post-merge
  base); no force-merge, no bypass, no re-run to get lucky was used at any round.
