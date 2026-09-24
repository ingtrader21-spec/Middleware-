# Server A scraper certification checkpoint

Generated: 2026-08-13T00:44Z

This is an interim, redacted checkpoint. It does not authorize production
deployment or external scraper delivery.

## Release candidate

- Pull request: `Codestra-SRL/codestra-middleware#202` (draft)
- Exact head: `e13ac18487fa6aa04984c178ff04b45c38f0711d`
- Local runtime digest:
  `sha256:6cf4c4c070342ade4124ea56b603422974f040f87860e8c758dbb7a5f1e9e57c`
- Protected-main merge: pending
- Independent approval: pending
- Required CI: pending at checkpoint time

## Verified locally

- Full middleware tests: 1131 passed, 28 skipped
- Ruff: pass
- Prometheus rule validation: pass, 35 rules
- Migration `0043_scraper_durable_inbox`: isolated upgrade, downgrade and forward
  upgrade pass; no published ports
- Redis work signals: namespaced, deduplicated and recoverable from PostgreSQL
- Permanent Odoo failures dead-letter without unbounded retry
- Ingress contract checksum:
  `0f34fcd0cd131408d63110c87a441ee82f001a1905b02af7b3d4d0e3f4fe7fa3`

## Dedicated n8n canary lane

Exactly two workflows were imported into staging and read back inactive:

- `CdstScraperIngestionCanaryV1`, checksum
  `cf03a903cb720e182b1f9b2891c2395048dda4e6e5ab6d10fb93d3575e80f578`
- `CdstScraperDeadLetterCanaryV1`, checksum
  `d009561783d0a1db9e88c031375a7a063e2cbe159bba25897b707cee17cac186`

The node allowlist contains only webhook, code validation and webhook response.
There are no HTTP-request, email, SMS, Redis, PostgreSQL, VICIdial, telephony or
social-publishing nodes. Redrive defaults false.

## Backup and restore

- Staging n8n backup:
  `/opt/codestra/n8n-staging/backups/20260813T004241Z`
- Database and workflow export checksums: pass
- Isolated internal-only PostgreSQL restore: pass
- Restored workflows: 251
- Restored scraper workflows: exactly 2, both inactive
- The staging backup script was corrected to export into the persistent n8n
  data mount before Docker copy.

## Safety readback

Production deployment did not occur. Production scraper intake, Odoo writes,
n8n delivery, VICIdial writes, callbacks, outreach, SMS, email and publishing
remain outside this checkpoint and are not authorized.

## Remaining gates

- protected CI and independent PR approval
- merge through protected main and build from the merge commit
- complete production-data backup/off-server/restore gate
- deploy exact merged digest with rollback package
- authenticate and reconcile a local synthetic event through receiver, inbox,
  Redis, Odoo and the inactive/no-message n8n canary
- test alert notification fire/recovery and full failure matrix
- enroll the external scraper identity and run the external synthetic canary

`SERVER_A_READY_FOR_SCRAPER_CANARY=NO`
