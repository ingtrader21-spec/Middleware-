# Middleware production runtime certification

> **Status (2026-09-20):** the canonical Alembic head is now
> `0067_service_catalog_monitoring_state` (`config/middleware-forward-release-authority.v1.json`,
> `.github/workflows/release.yml`). References to `0057_platform_service_catalog` below
> describe the signed evidence generation of 2026-09-08 and are retained as history; they
> are not the current forward release or runtime requirement.

This runbook defines the only repository-authorized path for certifying the
Codestra Middleware runtime on Server 65 (`65.109.65.169`). It deploys an
immutable, internal-only, read-only canary. It does not route public traffic or
enable a business/provider effect.

## Authority

- Repository: `ingtrader21-spec/Middleware-`
- Source ref: protected `main`
- Change authority: issue `#118`
- Owner command: `/deploy-middleware-production-readonly v1`
- Server role: `CODESTRA_APPLICATION_SERVER_A`
- Restricted server identity: `middleware-deploy`
- Root controller: `/usr/local/sbin/codestra-middleware-deploy`
- Compose project: `codestra-middleware-production-canary`
- Runtime service: `middleware-api-canary`
- Migration head: `0057_platform_service_catalog`

The workflow rejects a non-owner actor, another issue, a stale default-branch
SHA, an unsigned image, a mutable image reference, a failed release or
production-admission run, an unexpected server, an untrusted SSH host key, or a
controller checksum mismatch.

## Repository release gates

Before server access, the workflow requires:

1. a signed GitHub `main` commit;
2. a successful `Middleware CI` run for that exact commit;
3. a successful `Signed Middleware Release` run for the exact commit;
4. a successful automated production-admission run for the exact commit;
5. the signed release manifest and image to bind the same source SHA, tree,
   digest, release ID, migration head, SBOM, vulnerability report, and signer;
6. Cosign verification of the image, SPDX attestation, and signed manifest;
7. an exact digest reference under
   `ghcr.io/appolon1908-hue/codestra-middleware`.

## Required GitHub production secrets

The `production` environment or repository must contain:

- `MIDDLEWARE_DEPLOY_SSH_KEY`: private key for only the restricted
  `middleware-deploy` server account;
- `MIDDLEWARE_DEPLOY_HOST_KEY`: pinned known-hosts record for
  `65.109.65.169:22`.

The workflow may use the compatible legacy aliases encoded in the workflow, but
the names above are canonical. It never uses `ssh-keyscan`, disables host-key
checking, prints a private key, or writes an SSH setting on the server. The
short-lived job `GITHUB_TOKEN` is transmitted only through standard input to
perform the exact GHCR digest pull and is never stored in the deployment
bundle.

## One-time root installation

A root administrator must install the controller from an exact clean repository
checkout. The installer changes only the controller, backup command, root-owned
configuration, required directories, and one command-restricted sudoers file.
It does not create or modify an SSH key, `authorized_keys`, `sshd_config`,
firewall rule, proxy route, DNS record, or application credential.

```bash
sudo deploy/production/server/install-restricted-command.sh \
  /srv/codestra-middleware/repository \
  <exact-protected-main-sha>
```

Then replace only verified host-specific values in
`/etc/codestra-middleware/deploy.conf` and keep it `root:root` mode `0600`.
The production runtime environment must exist at
`/etc/codestra-middleware/runtime.env`, be root-owned mode `0600`, match the
locked `codestra-middleware-production-compose-v1` profile, contain the required
webhook secrets, and keep every effect control disabled.

## Runtime certification sequence

The root controller performs these operations under an exclusive lock:

1. validates every argument, caller, controller checksum, bundle checksum,
   bundle path, file ownership, and root configuration;
2. safely extracts only regular files and directories;
3. validates the signed release manifest and release artifact checksums;
4. confirms the runtime environment is production-locked and all effect gates
   are disabled;
5. resolves exactly one private Docker network shared by PostgreSQL and Redis,
   or uses the explicitly configured network;
6. authenticates to GHCR through a temporary Docker configuration and pulls the
   exact digest;
7. verifies image architecture, non-root user, OCI source revision, and version
   labels;
8. creates a PostgreSQL custom-format backup and validates its catalog;
9. restores the backup into a temporary isolated database, verifies the schema,
   and deletes the temporary database;
10. applies the reviewed idempotent migrations through the exact candidate
    image and verifies versions `1` through `9`;
11. snapshots exact Middleware/observability table counts;
12. starts only `middleware-api-canary`, with no published port or gateway
    discovery label;
13. verifies container hardening plus `/health`, `/readiness`, `/version`, and
    `/capabilities` from inside the container;
14. observes the canary for the configured minimum window and repeats all
    runtime checks;
15. removes only the canary service, records rollback RTO, verifies removal,
    and redeploys the same immutable candidate;
16. repeats health/readiness/version/capability checks and proves application
    row counts did not move;
17. retains root-owned JSON/Markdown evidence and emits a sanitized evidence
    bundle for the GitHub workflow.

No outbox worker is started. No port is published. No Caddy, Kong, Traefik,
Keycloak, DNS, TLS, firewall, or shared-service setting is changed. Broad
`docker compose down`, Docker prune operations, and mutable image tags are
forbidden.

## GO rule

Issue `#118` is closed only when the server response and downloaded evidence
both independently prove:

- exact source SHA, image digest, release run, and release ID;
- backup and isolated restore `PASS`;
- migration head `0057_platform_service_catalog`;
- container `running` and `healthy`;
- health, readiness, version, and capabilities `PASS`;
- every external-effect capability false;
- business writes `NO`;
- gateway exposure `NONE`;
- calls placed `0`;
- observation window completed;
- rollback rehearsal `PASS` with recorded RTO;
- data integrity `PASS`;
- evidence checksum verified.

The resulting decision is **GO for the immutable read-only production canary**.
It is not authorization for full public traffic or live email, SMS, PSTN,
Odoo, n8n, social, advertising, crawler, or external-model effects.
