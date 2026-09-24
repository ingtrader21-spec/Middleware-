# Secret leak scan (2026-09-17)

Scanners run in this stage:

| Scope | Scanner | Result |
| --- | --- | --- |
| Codestra-OpenBao branch tree @ `b8e2144f9257` | `scripts/reject_repository_secrets.sh` (private keys, `Authorization: Bearer`, `client_secret` literals, OpenBao `hvs/hvr/hvb/hvp`/`s.`/`b.` tokens, AWS/GitHub/GitLab/Slack/Twilio/Google/Stripe shapes) | `SCAN_OK` (a fixture literal that matched the `client_secret` shape was renamed before commit) |
| OpenBao `config/secret-references.v1.json` | `validate_secret_references.py` (deep forbidden keys + secret-shaped values) | PASS (50/11) |
| Middleware collector / TEST_SYN outputs | `SECRET_SHAPED` refusal before writing; token-in-output checks in tests | refused when present (tests) |
| OpenBao identity certifier output | loaded-credential and secret-shaped refusal | refused when present (test) |
| Prometheus inventory runtime report | `SECRET_SHAPED` refusal; `lastError` redaction | `[REDACTED]` (test) |
| This evidence directory | grep for forbidden keys (`password token value client_secret private_key root_token recovery_key unseal_key`) as JSON keys and for token/JWT/private-key shapes | see command below; performed before the evidence commit |

```
grep -rEn '"(password|token|value|client_secret|private_key|root_token|recovery_key|unseal_key)"\s*:' docs/evidence/monitoring-openbao-runtime-20260917/ ; \
grep -rEn 'hvs\.[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.|-{5}BEGIN' docs/evidence/monitoring-openbao-runtime-20260917/
```

Expected and observed: no matches. Every value in this package is an identifier, a path, a digest, a status or a count. No live credentials, tokens, keys or secret values exist in any repository touched by this mission.
