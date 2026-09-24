# Rotation (2026-09-17) — staging only; production rotation not authorised

Matrix: `Codestra-OpenBao/config/rotation-certification.v1.json` (guarded by `tests/security/test_rotation_certification_contract.py`, 4 OK).

| Step | Name | Executor / hook | Proof |
| --- | --- | --- | --- |
| 1 | workload-obtains-credential | `certify_staging_identity.py` (keycloak-token, login-own-role, own-path-read) | 300 s token, exact workload policy, own prefix authorised |
| 2 | workload-functions-on-version-n | `rotate-test.sh` (`OPENBAO_ROTATION_EXPECTED_CURRENT_VERSION`, `…_HEALTH_VERIFIER`) | rendered file 0400 / service uid:gid / expected sha256; health passes |
| 3 | rotate-n-to-n-plus-1 | `rotate-test.sh` (`bao kv put -cas=<N>` after prefix check against the authority; confirmation `ROTATE_<IDENTITY>_<ENV>_N_TO_N_PLUS_1`) | version N+1 written under own prefix only |
| 4 | agent-renders-n-plus-1 | `rotate-test.sh` (≤ 120 s poll) | rendered sha256 = expected, mode/ownership unchanged |
| 5 | new-credential-verified | `…_NEW_VERIFIER` (read-only; `OPENBAO_PROVIDER_EFFECTS_DISABLED_ACKNOWLEDGED=true` required) | verifier passes |
| 6 | old-credential-revoked-and-denied | `…_OLD_REVOKE`, `…_OLD_VERIFIER` | old verifier must fail; still-working old credential → exit 2 |
| 7 | workload-re-authenticates-and-stays-healthy | `…_HEALTH_VERIFIER`; certifier `token-revocation` | health passes; revoked OpenBao token denied |
| 8 | sanitized-evidence-recorded | `OPENBAO_ROTATION_EVIDENCE` (0400) | `secretValuesIncluded=false`, `providerBusinessEffectsEnabled=false`, versions/sha256/PASS flags only |

Revocation matrix (`revoke-test.sh`): target denied, unrelated workload unaffected, cross-environment still denied, sanitised audit alert observed.

Guards: `rotate-test.sh` accepts only `development|test|staging`; `runtimeApplyAuthorized` must be true for the environment (staging currently `false`); no destructive production rotation exists in any script. Staging rotation run: **not performed** (no `bao` access / staging runtime).
