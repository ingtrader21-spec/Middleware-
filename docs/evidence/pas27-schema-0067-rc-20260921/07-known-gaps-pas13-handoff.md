# 07 — Known gaps recorded for the PAS-13 handoff (not changed here)

These were observed during the PAS-27 lane and are outside its acceptance list. They are recorded so the staging lane does not rediscover them; each needs its own governed change.

## F-07 — deploy script pins SQL receipts `1..10`, main ships `0011`

`deploy/production/server/codestra-middleware-deploy`, line 510 on `8ecf6e9`:

```bash
[[ "$migration_versions" == "1,2,3,4,5,6,7,8,9,10" ]] || fail "middleware_migration_head_mismatch"
```

`migrations/` on the same main ends with `0009_observability_incidents.sql`, `0010_realtime_gateway.sql`, `0011_audit_timeline_indexes.sql`. The first controller deploy from this main will apply receipt 11 and then fail the assertion. Reported by the PAS-180 preflight (`middleware-96`); verified here against `origin/main`. The file is release/trust-owned — its bytes are covered by the source closure — so the fix must ride a governed change with closure re-derivation, not a hotfix.

## PR #304 collides with the closure entry

`mission/db-connection-tls-authority-20260921-v2` (PR #304, head `61c30e1c`, base `bd406a65`) also rewrites the `ingtrader21-spec/Middleware-` entry of `EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256`. Now that #301 has merged, #304 must:

1. rebase onto `8ecf6e9b…`;
2. run `scripts/derive_trust_pins.py --apply-candidate` and commit the re-derived closure;
3. update `EXPECTED_PROFILE` in `scripts/validate_staging_intake_observability_contract.py` (its "staging runtime profile drift" test is red per the PAS-180 preflight).

This is the PAS-79/PAS-80 lane's work; recorded here only because the collision was created by the #301 merge order.

## The source closure covers the complete tracked tree

`source_closure_fingerprint` in `.codestra/validate-release-intent.py` hashes every blob and commit of the exact source tree except the release validator itself and the controller's reviewed candidate JSON ("an omitted direct or transitive check executable cannot leave the closure unchanged"). Consequently **every** change to protected main — documentation, CODEOWNERS, tests, deploy scripts — moves `EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256` for `ingtrader21-spec/Middleware-`, and `tests/test_release_authority.py::test_trust_derivation_check_passes` fails closed until the PR carries the re-derived entry. This is why #302 (CODEOWNERS), #304 (DB/TLS) and this evidence PR each touch that one table entry. Lanes should run `scripts/derive_trust_pins.py --apply-candidate` as the last step before pushing any PR, and expect a rebase + re-derive whenever main moves underneath them.

## Windows host limitation in the trust gate test

`tests/test_trusted_production_orchestrator_gate.py::test_safe_file_rejects_a_symlinked_parent_that_escapes_candidate` needs `os.symlink`, which fails with `WinError 1314` on an unprivileged Windows session. It passes on the Linux runners. Local certification on Windows should treat this one failure as host-only, as in 02.
