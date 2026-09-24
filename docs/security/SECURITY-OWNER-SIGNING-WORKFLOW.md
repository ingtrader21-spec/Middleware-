# Security Owner decision signing workflow

The protected-main `security-owner-decision-sign.yml` workflow consumes only
repository-relative paths and SHA-256 values. It fetches the exact PR files as
inert data and validates them with the validator checked out from protected
`main`; it never executes PR-controlled code.

The workflow requires the `security-owner-signing` environment. It rediscovers
the open PR and exact head, checks `codestra/required-ci`, confirms evidence
hashes and isolation gates, creates a canonical decision, signs it through
GitHub Actions OIDC with pinned Cosign, verifies the exact certificate identity
and issuer, and uploads a finite-retention evidence bundle.

The decision authorizes staging preparation only. It does not deploy, activate,
publish images, access Server B, or authorize production.

Run the validator locally with:

```bash
python scripts/security/validate-security-owner-decision.py request \
  --request security-owner-decision-request.json \
  --image-manifest image-manifest.json \
  --expected-repository Codestra-SRL/codestra-middleware \
  --expected-pr-number 68 \
  --expected-pr-head <40-character-sha>
```
