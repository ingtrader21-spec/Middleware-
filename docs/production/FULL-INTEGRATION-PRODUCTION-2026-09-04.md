# Full integration production program

Date: 2026-09-04  
Authority: `appolon1908-hue/Middleware-`  
Base Middleware source: `4092b3b1e57819da75eb45631176b022f70a0c55`  
Decision: **NO-GO until every runtime gate passes**

## Purpose

This program turns the current source-complete Middleware core into a truthful
multi-repository production release. It does not collapse component ownership
into Middleware. Each repository remains authoritative for its own code,
configuration, immutable artifact, tests, rollback, and runtime evidence.

The machine-readable authority is
`config/production-integration-lock.v1.json`. Its validator rejects false
production claims, stale or malformed source identities, duplicate repository
authorities, enabled external effects, unprotected source-ready claims, and
runtime certification without immutable digest, staging, backup/restore,
rollback, and readback evidence.

## What this change completes

- fixes the missing required Social `certify` check on PR 45;
- creates a fixed-ID protected-main reviewer/ruleset program for Social, AI,
  Marketing, and VICIdial;
- locks Middleware and every primary application/provider authority to exact
  repository IDs, branches, current SHAs, candidate PR heads, dependencies,
  source state, governance state, runtime state, and explicit blockers;
- references the exact production platform, infrastructure, SDK, OpenBao,
  Prometheus, Grafana, alerting, logs, traces, collectors, and exporter
  authorities;
- requires one immutable artifact tuple across staging and production;
- preserves a maximum one-percent `GET`/`HEAD`-only canary;
- keeps every business and provider effect disabled and `CALLS_PLACED=0`.

## Current production-critical sequence

1. Merge this authority through protected Middleware `main`.
2. From that exact protected commit, dispatch
   `APPLY_INTEGRATION_MAIN_RELEASE_AUTHORITY_V1` in the protected
   `repository-administration` environment.
3. `kazan555` accepts any resulting repository invitations. Rerun `verify`
   until reviewer permission and every named ruleset read back exactly.
4. Obtain fresh independent approval on the unchanged exact heads and merge:
   Social 45, AI 10, Marketing 11, Provisioning 26, and VICIdial 10.
5. Refresh Odoo 67 and 69 from current protected Odoo `main`; rerun source,
   merge-result, Odoo/PostgreSQL, security, and container checks.
6. Merge Keycloak 83 to `development` using a merge commit so the reconciled
   ancestry remains. Replace or refresh stale promotion PR 75 from that exact
   reconciled development head.
7. Merge Kong 55 to protected `main`, refresh Kong 48 to the resulting SHA, and
   promote only into protected staging. Complete declarative-route, identity,
   backup/restore, rollback, and runtime readback there.
8. Refresh Caddy 103 to the final Middleware and Kong SHAs, merge it to
   development, then promote `development -> test -> staging -> production ->
   main` without rebuilding the artifact.
9. Install active required status checks for N8N, Klyrow, Prometheus, and every
   observability authority currently recorded as missing or unverified.
10. Replace connector template endpoints only with evidence-backed private
    endpoints. Render secrets through OpenBao into mounted files. Never commit
    credentials, certificates, private keys, access tokens, or runtime payloads.
11. Build and sign each exact protected-source artifact once. Record source SHA,
    image digest, SBOM/provenance, configuration checksum, schema head, and
    rollback image.
12. Deploy those exact digests to `staging-readonly`. Do not rebuild or retag.
13. Execute:
    - source/digest/configuration readback;
    - Keycloak issuer, audience, `azp`, scope, tenant, expiry, and negative
      identity cases;
    - Caddy-to-Kong-to-Middleware route alignment;
    - health, readiness, version, dependencies, capabilities, and protected
      metrics;
    - PostgreSQL/Redis/NATS/Temporal durability and restart behavior;
    - Odoo/n8n/VICIdial/Kyqra/provider fail-closed behavior;
    - controlled Klyrow, Telnexa, VICIdial, and Social provider readback;
    - Prometheus, Grafana, Alertmanager, Loki, Tempo, Alloy, and exporter
      continuity;
    - zero unauthorized writes and zero movement in live-effect counters.
14. Produce paired database, Odoo filestore, configuration, secret-policy, and
    off-host backups. Restore them in isolation.
15. Rehearse rollback to the previous exact tuple and record RTO, RPO, data
    integrity, health, readiness, version, source, and digest readback.
16. Promote the same immutable tuple through a production canary of no more than
    one percent and only `GET`/`HEAD` traffic.
17. Stop and roll back on any source/digest mismatch, readiness loss, monitoring
    loss, database drift, latency/error regression, write, provider effect, or
    live-counter movement.
18. Update the protected production-platform source lock only after every
    component evidence record passes. Live email, SMS, calls, advertising,
    social publishing, external AI, Odoo/n8n/VICIdial writes, provisioning,
    payments, and trading each require a separate explicit activation release.

## Current repository gates

| Authority | State |
|---|---|
| Middleware | protected source ready; runtime not certified |
| Odoo | protected source; PRs 67/69 require current-main refresh |
| N8N | branch marked protected but active required checks are absent |
| Keycloak | development reconciliation PR 83 first; main promotion 75 stale |
| Kong | PR 55 first; refresh main-to-staging PR 48 afterward |
| Caddy | PR 103 pending and must pin final Middleware/Kong |
| Telnexa | protected source ready; private binding and DLR readback missing |
| Klyrow | immutable readiness source merged; active required checks and provider readback missing |
| Social | PR 45 has repaired `certify`; reviewer access and final CI pending |
| AI | PR 10 CI green; reviewer access pending |
| Marketing | PR 11 CI green; reviewer access pending |
| Provisioning | PR 26 CI green; independent approval pending |
| VICIdial | PR 10 CI green; main protection and reviewer access pending |
| Kyqra/Beyvra | configured source only; active runtime authority unconfirmed |
| Observability train | exact infrastructure release train exists; several component repos remain initialization or documentation-level |

## Safety invariants

```text
PRODUCTION_ACTIVATED=NO
EMAIL_DELIVERY=false
SMS_DELIVERY=false
SOCIAL_PUBLISH=false
PRODUCTION_DIALING=false
ODOO_WRITE=false
N8N_EXTERNAL_PROVIDER_WRITES=false
VICIDIAL_WRITE=false
PROVISIONING_WRITE=false
LIVE_ADVERTISING=false
EXTERNAL_MODEL_CALLS=false
PAYMENTS=false
TRADING=false
CALLS_PLACED=0
SSH_CHANGED=NO
```
