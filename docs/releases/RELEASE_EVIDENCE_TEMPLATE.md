# Cross-Repository Release Evidence — TEMPLATE

## Change

- Change ID: `CHG-...`
- Capability/scope:
- Environment:
- Production activation included: `NO`

## Accepted source identities

| Repository | Accepted commit SHA | PR | CI run(s) | Result |
|---|---|---|---|---|
| `appolon1908-hue/...` | `<40-char SHA>` | `#...` | `...` | `PASS` |

## Immutable artifacts

| Repository/component | Image/artifact | Digest | Signature/provenance |
|---|---|---|---|
| | | `sha256:...` | |

## Contract versions

- Command/API contract:
- Event/webhook contract:
- Database migration head(s):
- Keycloak issuer/client contract:
- Kong/Caddy edge contract:

## Safety flags

```text
ODOO_WRITE=false
VICIDIAL_WRITES_ENABLED=false
LIVE_SMS_DELIVERY=false
LIVE_EMAIL_DELIVERY=false
UNRESTRICTED_CRAWLING=false
PROVISIONING_WRITE=false
DEAD_LETTER_REPLAY=false
```

Record only approved changes from these defaults. Never infer activation from a merged PR.

## Staging evidence

- Deployment digest set:
- Authentication/tenant-isolation:
- Idempotency/replay:
- Provider/read-back:
- Odoo state read-back:
- n8n workflow status:
- DLQ/unexpected errors:

## Backup / restore / rollback

- Backup identity:
- Restore/rehearsal run:
- Previous digest/config:
- Rollback result:

## Production approval

- Required: `YES/NO`
- Approval/change reference:
- Exact flags activated:
- Bake/read-back evidence:

## Final verdict

```text
SOURCE_SET_ACCEPTED=NO
STAGING_ACCEPTED=NO
ROLLBACK_PROVEN=NO
PRODUCTION_APPROVED=NO
RELEASED=NO
```
