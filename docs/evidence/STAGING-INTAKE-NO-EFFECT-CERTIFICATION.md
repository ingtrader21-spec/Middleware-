# Staging intake no-effect certification

## Authority

The manual workflow `.github/workflows/staging-intake-e2e-no-effect.yml` is the
only repository workflow for issue #65. It runs only from protected `main` and
uses the protected `intake-staging-certification` environment.

## Required protected secrets

- `STAGING_SDK_INTAKE_TOKEN`: confidential `sdk-intake` identity, restricted to
  the intake scopes used by the synthetic lead and survey requests.
- `STAGING_RUNTIME_SAFETY_TOKEN`: confidential `monitoring-readonly` identity
  with `health.read` only, used solely for authenticated `/v1/runtime/safety`
  read-back.

Neither token belongs in workflow inputs, issue comments, commits, logs, or
artifacts.

## Required protected variable

- `STAGING_INTAKE_APPROVED_HOST`: the exact reviewed DNS hostname of the
  isolated staging Caddy endpoint. It must not be an IPv4/IPv6 literal or the
  production gateway. The workflow refuses to send either bearer token when
  the requested base URL does not match this protected authority exactly.

## Fail-closed sequence

1. Check out and prove the exact protected-main workflow SHA.
2. Require the exact protected staging hostname and standard HTTPS port; reject
   arbitrary hosts, credentials, IPv4/IPv6 literals, the committed production
   gateway, and malformed base URLs before loading a bearer token into a
   request.
3. Read `/version` and require consistent source/git SHA, immutable image,
   schema, build, release, and configuration identities plus the staging
   environment and locked runtime profile.
4. Read authenticated `/v1/runtime/safety` and require durable persistence,
   disabled outbox/NATS/Temporal dispatch, every external effect and umbrella
   control false, production dialing disabled, no production activation, and
   `staging_safe=true`.
5. Exercise unauthenticated denial, authenticated synthetic lead acceptance,
   exact duplicate replay, changed-content conflict, and anonymous survey
   acceptance.
6. Repeat the exact version/safety read-back and reject any source, digest,
   schema, release, configuration, profile, or control movement during the run.

## Non-authorization boundary

A passing run certifies only the isolated staging intake path for the exact
protected-main source and immutable runtime read back by that run. It does not
authorize production deployment, public production routing, Odoo/n8n delivery,
provider activation, email, SMS, social publishing, crawler effects, PSTN, or
any other external effect.
