# PAS-27 — V3-M0 signed schema-0067 RC: evidence index (2026-09-21)

Linear: https://linear.app/passion-fruit/issue/PAS-27/v3-m0-certify-protected-main-and-publish-signed-schema-0067-rc
Program: PAS-43 (V3 certification to production). Blocks PAS-13 (staging deploy).

## State at 2026-09-21 13:20Z

| Item | Value |
| --- | --- |
| Protected main | `8ecf6e9b75a7adf4c82c4c7094ba71d64d73e692` (PR #301 squash-merged) |
| Successor generation PR | #301 `security/ghcr-package-authority-generation-20260920-v2`, exact head `0d61de48870fd990e8992c9547e08196a3bb09d8` |
| Candidate tree | `e56bba865b87062edb874198e76c843e3dbcc2cc` |
| Validator (`FINAL_VALIDATOR_SHA256`) | `15c35ad11c65b7605d44812e08d45493e31afdea678876b3a44a16d27c1c1a21` |
| Release-security fingerprint | `63192fd83f7fc19fa624e2bf26d3b2ccc3941042e4e3c941ba378ff50581e565` |
| Source closure (`ingtrader21-spec/Middleware-`) | `96701332522babe435f3f145294e657ca188bf4f034487cae6ec17cca06ff9c8` |
| Canonical package | `ghcr.io/ingtrader21-spec/codestra-middleware` |
| Required schema head | `0067_service_catalog_monitoring_state` |
| Signed release run on main | 35602170321 — **FAILED at push** (`permission_denied: read_package`) |
| `TARGET_IMAGE_DIGEST` | `PENDING_OWNER_PACKAGE_ACCESS` |
| `RELEASE_SEAL` | OPEN |
| Provider / production effects | 0 / 0, `PRODUCTION_GO=NO` |

## Documents

1. [01-red-head-0185fc84-diagnosis.md](01-red-head-0185fc84-diagnosis.md) — why the refreshed PR #301 head was red on three required gates (one stale closure pin).
2. [02-closure-repair-0d61de4.md](02-closure-repair-0d61de4.md) — the repository-owned re-derivation, fixed-point proof and local tests.
3. [03-exact-head-ci-0d61de4.md](03-exact-head-ci-0d61de4.md) — hosted check results on the repaired exact head.
4. [04-merge-and-main-8ecf6e9.md](04-merge-and-main-8ecf6e9.md) — governed merge, reviews, and main-push CI.
5. [05-release-run-35602170321.md](05-release-run-35602170321.md) — the signed release attempt from exact main and where it stopped.
6. [06-ghcr-package-access-diagnosis.md](06-ghcr-package-access-diagnosis.md) — read-only evidence behind the owner decision.
7. [07-known-gaps-pas13-handoff.md](07-known-gaps-pas13-handoff.md) — pre-existing gaps recorded for the staging lane, not changed here.
8. [trust-derivation-report-0185fc84-to-e56bba86.json](trust-derivation-report-0185fc84-to-e56bba86.json) — `scripts/derive_trust_pins.py --json-output` for the repair.

## What remains to exit V3-M0

1. Owner grants `ingtrader21-spec/Middleware-` write access on the GHCR package (or GitHub Support if the package does not exist) — see 06.
2. Re-run the failed release job (`gh run rerun 35602170321 --failed`, `SOURCE_SHA` stays `8ecf6e9…`) or `workflow_dispatch` `release.yml` on `main`.
3. Independently verify: one immutable digest; OCI `revision`/`source` labels equal the exact source; single Alembic head `0067_service_catalog_monitoring_state`; SBOM bound to the digest; Grype and Trivy policy; SLSA provenance subject equals digest/source; Cosign identity/issuer.
4. Record the digest for PAS-13.

No workflow, validator or launcher bytes change is required for steps 1–4; the trust generation merged in #299/#301 stays authoritative.

Note on this evidence change itself: `EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256` fingerprints the complete tracked tree (see 07), so adding these documents moves the `ingtrader21-spec/Middleware-` closure entry. The PR that carries this directory therefore also carries the mechanically re-derived entry in `.codestra/validate-release-intent.py`, produced by `scripts/derive_trust_pins.py --apply-candidate`; validator digest, fingerprint and launcher parity are unaffected.

Safety held throughout: no PAT, no personal registry credential, no local `docker push`, no unreviewed namespace, no force push, no self-approval.
