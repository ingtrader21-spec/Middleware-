# Lead Automation HMAC Caller Matrix

| Capability | Route / component | Authentication | Audit status |
| --- | --- | --- | --- |
| Result submission | `POST /api/v1/lead-automation/results` | HMAC-V2, `lead-automation.results.write` | BOUND_AND_TESTED |
| Registration acknowledgement | n8n execution registration transport | JWT transport contract | NOT_APPLICABLE |
| Terminal acknowledgement | n8n acknowledgement transport | JWT transport contract | NOT_APPLICABLE |
| Middleware-to-Odoo apply delivery | `POST /codestra/api/v1/leads/automation/apply` | HMAC-V2, `lead-automation.odoo-apply.write` | BOUND_AND_TESTED |
| Odoo callback delivery | result callback above | HMAC-V2 verifier | BOUND_AND_TESTED |
| Generic integration result routes | non-lead route owners | route-specific authentication | NOT_APPLICABLE |

For both HMAC callers, version, method, path, body digest, timestamp, nonce,
service identity, environment, and scope are `BOUND_AND_TESTED`. Audience and
idempotency identity remain additionally bound. No `BOUND_BUT_UNTESTED`,
`MISSING`, `AMBIGUOUS`, or `LEGACY_ONLY` lead-automation HMAC caller remains.
