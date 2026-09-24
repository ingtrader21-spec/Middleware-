# auth.codestra.co Keycloak contract

## Scope

This workstream owns the identity-side contract for `auth.codestra.co` without changing Keycloak realm data, users, credentials, TOTP, clients, Odoo, n8n, telephony, or Booked4Seasons.

Canonical identity contract:

```text
issuer=https://auth.codestra.co/realms/codestra
realm=codestra
openid_configuration=/realms/codestra/.well-known/openid-configuration
```

## Verified Server A runtime — 2026-08-26

Current server evidence establishes the production identity runtime on Server A (`65.109.65.169`):

```text
production_container=codestra-identity-keycloak-1
production_container_health=healthy
production_port=8080/tcp
staging_container=codestra-identity-staging-keycloak-staging-1
public_staging_selection=NO
```

The public route does not proxy to a remote Keycloak host. The verified routing chain is:

```text
Internet
 -> auth.codestra.co:443
 -> host Caddy
 -> 127.0.0.1:18103
 -> codestra-caddy-upstream-gateway
 -> codestra-identity-keycloak-1:8080
 -> realm codestra
```

The earlier `49.12.145.107` runtime hypothesis is superseded for this site and must not be used for `auth.codestra.co` routing.

## Verification result

The observed end-to-end checks returned:

```text
UPSTREAM_GATEWAY_HTTP=200
PUBLIC_OPENID_DISCOVERY_HTTP=200
PUBLIC_TLS_VERIFY=0
DISCOVERY_ISSUER=https://auth.codestra.co/realms/codestra
AUTH_HTTP_502=ABSENT
```

No Caddy reload or Keycloak mutation was required to achieve this result; the existing production path was already healthy when tested.

## Acceptance

The route remains accepted only while all of the following hold:

```text
GET https://auth.codestra.co/realms/codestra/.well-known/openid-configuration = 200
issuer field = https://auth.codestra.co/realms/codestra
certificate chain validates
production Keycloak container is healthy
public route selects production, not staging
HTTP 502 absent
```

## Forbidden actions

- Do not create, delete, or modify users, realms, clients, roles, credentials, or TOTP as part of edge maintenance.
- Do not expose Keycloak admin endpoints or credentials.
- Do not proxy the public hostname back through public DNS.
- Do not replace the verified local production route with the superseded remote-host hypothesis.
- Do not disable TLS validation to conceal a routing failure.
- Do not change Booked4Seasons as part of this workstream.
