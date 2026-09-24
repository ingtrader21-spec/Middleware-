# auth.codestra.co edge status

## Ownership

This branch owns the public `auth.codestra.co` site behavior and acceptance criteria. Identity semantics remain owned by `integration/keycloak`; reverse-proxy implementation remains owned by `platform/caddy`; host execution and rollback remain owned by `operations/application-host`.

Booked4Seasons is explicitly out of scope.

## Verified route — 2026-08-26

```text
Internet
  -> auth.codestra.co:443
  -> host Caddy on 65.109.65.169
  -> 127.0.0.1:18103
  -> codestra-caddy-upstream-gateway
  -> codestra-identity-keycloak-1:8080
  -> realm: codestra
```

The staging Keycloak container exists separately and is not the public target.

## Current acceptance evidence

```text
AUTH_PUBLIC_TLS=PASS
AUTH_OPENID_DISCOVERY=HTTP_200
AUTH_ISSUER=https://auth.codestra.co/realms/codestra
AUTH_HTTP_502=ABSENT
INTERNAL_GATEWAY_DISCOVERY=HTTP_200
PUBLIC_TLS_VERIFY_RESULT=0
PRODUCTION_KEYCLOAK_HEALTH=healthy
CADDY_RELOAD_REQUIRED=NO
LIVE_CONFIGURATION_CHANGED=NO
```

The OpenID Connect discovery body advertises the canonical issuer exactly:

```text
https://auth.codestra.co/realms/codestra
```

## Interpretation

The previously recorded `502` is no longer reproducible. The existing route is healthy, so no Caddy edit or reload is justified by the current evidence. Treat an unnecessary reload or topology change as risk rather than remediation.

## Regression gate

If `auth.codestra.co` fails again, first verify these layers independently:

1. `codestra-identity-keycloak-1` remains healthy.
2. `codestra-caddy-upstream-gateway` listener `:18103` still targets `codestra-identity-keycloak-1:8080`.
3. `http://127.0.0.1:18103/realms/codestra/.well-known/openid-configuration` returns 200.
4. `https://auth.codestra.co/realms/codestra/.well-known/openid-configuration` returns 200 with TLS verification result 0.
5. The discovery issuer remains `https://auth.codestra.co/realms/codestra`.

Do not substitute the staging Keycloak service or an obsolete remote-host route as a recovery shortcut.
