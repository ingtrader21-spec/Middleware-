#!/usr/bin/env bash
set -euo pipefail

directory="${1:?artifact directory required}"
source_sha="${2:?source SHA required}"
image_digest="${3:?image digest required}"
cosign_bin="${COSIGN_BIN:-cosign}"
identity="https://github.com/ingtrader21-spec/Middleware-/.github/workflows/security-owner-decision-sign.yml@refs/heads/main"
issuer="https://token.actions.githubusercontent.com"

if command -v python >/dev/null 2>&1; then
  python_bin="python"
elif command -v python3 >/dev/null 2>&1; then
  python_bin="python3"
else
  printf 'python or python3 is required to validate the production OpenVEX payload\n' >&2
  exit 127
fi

test -f "${directory}/openvex.json"
test -f "${directory}/openvex.sigstore.json"
test -f "${directory}/SHA256SUMS"
(cd "${directory}" && sha256sum -c SHA256SUMS)
"${python_bin}" scripts/security/validate-production-openvex.py \
  --openvex "${directory}/openvex.json" --source-sha "${source_sha}" \
  --image-digest "${image_digest}"
"${cosign_bin}" verify-blob \
  --bundle "${directory}/openvex.sigstore.json" \
  --certificate-identity "${identity}" \
  --certificate-oidc-issuer "${issuer}" \
  "${directory}/openvex.json"
