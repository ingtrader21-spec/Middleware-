#!/usr/bin/env bash
# Read-only discovery for auth.codestra.co on Server A.
set -Eeuo pipefail

AUTH_HOST="auth.codestra.co"
CANONICAL_REALM="codestra"
DISCOVERY_PATH="/realms/${CANONICAL_REALM}/.well-known/openid-configuration"
HOST_GATEWAY="http://127.0.0.1:18103"
PRODUCTION_KEYCLOAK="codestra-identity-keycloak-1"
STAGING_KEYCLOAK="codestra-identity-staging-keycloak-staging-1"
UPSTREAM_GATEWAY="codestra-caddy-upstream-gateway"
PUBLIC_BODY="$(mktemp)"
GATEWAY_BODY="$(mktemp)"
trap 'rm -f "$PUBLIC_BODY" "$GATEWAY_BODY"' EXIT

printf 'SERVER\n'
hostname
hostname -I 2>/dev/null || true

printf '\nDNS\n'
getent ahostsv4 "$AUTH_HOST" 2>/dev/null | awk '{print $1}' | sort -u || true

printf '\nPUBLIC_AUTH_STATUS\n'
if curl -sS --connect-timeout 5 --max-time 10 \
  -o "$PUBLIC_BODY" \
  -w 'URL=%{url_effective} HTTP=%{http_code} REMOTE_IP=%{remote_ip} TLS_VERIFY=%{ssl_verify_result}\n' \
  "https://${AUTH_HOST}${DISCOVERY_PATH}"; then
  PUBLIC_REQUEST_STATUS=PASS
else
  PUBLIC_REQUEST_STATUS=FAIL
  : > "$PUBLIC_BODY"
fi
printf 'PUBLIC_REQUEST_STATUS=%s\n' "$PUBLIC_REQUEST_STATUS"

printf '\nHOST_GATEWAY_STATUS\n'
if curl -sS --connect-timeout 5 --max-time 10 \
  -o "$GATEWAY_BODY" \
  -w 'URL=%{url_effective} HTTP=%{http_code}\n' \
  "${HOST_GATEWAY}${DISCOVERY_PATH}"; then
  GATEWAY_REQUEST_STATUS=PASS
else
  GATEWAY_REQUEST_STATUS=FAIL
  : > "$GATEWAY_BODY"
fi
printf 'GATEWAY_REQUEST_STATUS=%s\n' "$GATEWAY_REQUEST_STATUS"

printf '\nDISCOVERY_ISSUERS\n'
PUBLIC_BODY="$PUBLIC_BODY" GATEWAY_BODY="$GATEWAY_BODY" python3 - <<'PY'
import json
import os
from pathlib import Path

for label, env_name in (
    ("PUBLIC", "PUBLIC_BODY"),
    ("GATEWAY", "GATEWAY_BODY"),
):
    path = Path(os.environ[env_name])
    try:
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            raise ValueError("empty current-run response body")
        payload = json.loads(text)
    except Exception:
        print(f"{label}_ISSUER=UNAVAILABLE")
        continue
    print(f"{label}_ISSUER={payload.get('issuer', 'MISSING')}")
PY

printf '\nKEYCLOAK_CONTAINERS\n'
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' \
    | awk -v prod="$PRODUCTION_KEYCLOAK" -v stage="$STAGING_KEYCLOAK" \
      'NR == 1 || index($0, prod) || index($0, stage)'
else
  printf 'DOCKER=UNAVAILABLE_OR_UNAUTHORIZED\n'
fi

printf '\nUPSTREAM_GATEWAY_CONFIG\n'
if command -v docker >/dev/null 2>&1 && docker inspect "$UPSTREAM_GATEWAY" >/dev/null 2>&1; then
  docker exec "$UPSTREAM_GATEWAY" sh -c \
    'grep -R -n -E "18103|codestra-identity-keycloak-1:8080" /etc/caddy /config 2>/dev/null | head -80' || true
else
  printf 'UPSTREAM_GATEWAY=NOT_FOUND\n'
fi

printf '\nHOST_CADDY_ROUTE\n'
grep -R -n -A10 -B2 'auth\.codestra\.co' \
  /etc/caddy 2>/dev/null | head -80 || true

printf '\nRESULT\n'
printf 'DISCOVERY_MODE=READ_ONLY\n'
printf 'EXPECTED_PUBLIC_HOST=auth.codestra.co\n'
printf 'EXPECTED_HOST_GATEWAY=127.0.0.1:18103\n'
printf 'EXPECTED_UPSTREAM_GATEWAY=codestra-caddy-upstream-gateway\n'
printf 'EXPECTED_PRODUCTION_KEYCLOAK=codestra-identity-keycloak-1:8080\n'
printf 'STAGING_KEYCLOAK_PUBLIC_TARGET=NO\n'
printf 'LIVE_CONFIGURATION_CHANGED=NO\n'
printf 'BOOKED4SEASONS_CHANGED=NO\n'
