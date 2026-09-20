#!/usr/bin/env bash
set -euo pipefail

decision="${1:?decision path required}"
bundle="${2:?Sigstore bundle path required}"
identity='https://github.com/ingtrader21-spec/Middleware-/.github/workflows/security-owner-decision-sign.yml@refs/heads/main'
issuer='https://token.actions.githubusercontent.com'

cosign verify-blob \
  --bundle "${bundle}" \
  --certificate-identity "${identity}" \
  --certificate-oidc-issuer "${issuer}" \
  "${decision}"
echo SECURITY_DECISION_SIGNATURE_GATE=PASS
