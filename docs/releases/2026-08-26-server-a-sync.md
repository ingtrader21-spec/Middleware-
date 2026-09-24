# Server A middleware Git sync release evidence

Date: 2026-08-26

Purpose: record the reviewed Git-only synchronization package for Application Server A (`65.109.65.169`).

## Included state

- middleware service identity/API/webhook contracts are already merged into `main` through PR #7;
- `auth.codestra.co` is recorded active after end-to-end OIDC/TLS verification;
- host Caddy remains `auth.codestra.co -> 127.0.0.1:18103`;
- upstream gateway remains `codestra-caddy-upstream-gateway -> codestra-identity-keycloak-1:8080`;
- the staging Keycloak container is not the public target;
- `www.booked4seasons.com` remains out of scope and its recorded TLS degradation is unchanged;
- contract-only middleware ingress paths are not represented as runnable endpoints.

## Review feedback addressed

Codex review findings were addressed before release:

- exact caller/target/scope equality is now enforced for the complete least-privilege service-grant matrix;
- auth discovery uses fresh temporary response bodies and cannot report a stale issuer after a failed curl request.

These fixes must be included in the exact-head CI result used for merge.

## Deployment boundary

This release synchronizes Git content only. It does not authorize Caddy reload, Keycloak restart, Odoo/n8n changes, external delivery, or creation of middleware API listeners that do not yet have authoritative runtime source.

The server must pull the exact merged `main` SHA with `--ff-only`, rerun `scripts/run_ci.sh`, and run `scripts/discover_auth_codestra_edge.sh` read-only after synchronization.
