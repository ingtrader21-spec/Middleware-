# Protected staging machine-identity matrix

## Purpose

`scripts/staging_product_auth_read_matrix.py` verifies the reviewed Keycloak → Kong → Middleware machine-identity path without creating a command, changing business data, or invoking any provider.

The harness performs only two network operation classes:

1. OAuth 2.0 Client Credentials token issuance at the explicitly supplied staging token endpoint.
2. One read-only `GET` using a freshly generated random UUID: regular callers use `/v1/operations/{command_id}`, while provider-control callers use `/api/v1/control/identity-probes/{probe_id}` so they never receive tenant-wide operation-read authority.

A valid bearer must receive tenant-scoped `404` for the deliberately nonexistent identifier. For regular callers, that result proves authentication and tenant authorization before the durable ledger lookup. For provider-control callers, it proves the same identity controls through the isolated probe route without reading the command ledger or any tenant resource.

The harness never sends `POST /v1/commands`, never calls a provider adapter, and never enables a capability.

Provider-control route registration belongs to the FastAPI application module, not package initialization. This keeps dependency-light governance checks and Temporal workflow sandbox imports isolated from web-runtime side effects while ensuring the packaged API deterministically mounts every policy-derived provider route.

## Source authority

The client inventory is derived from:

- `config/control-plane-callers.v1.json`
- `config/provider-operation-policy.json`

Entries participate only when `staging_auth_matrix=true`. Compatibility-only callers are excluded. Provider-control callers are denied access to the generic operation-read and generic mutation planes:

- their generic mutation scope ends in `.denied` and is not granted;
- their generic operation-read scope ends in `.denied` and is not granted;
- `connector_commands_allowed=false`;
- `allowed_command_prefixes=[]`;
- `allowed_targets=[]`;
- their isolated identity probe uses one exact provider-operation scope already present in the canonical identity grant.

The matrix must include all marked product and control-plane identities. This includes the six product clients and the provider-control identities for AI, communications, marketing, and social.

Every repository change after generated-contract refresh requires a new exact-head source and synthetic merge-result validation. Evidence from an earlier commit cannot certify a later head.

## Per-client probes

For each selected client, the harness requests a short-lived staging token and verifies:

- issuer is exactly `https://auth.codestra.co/realms/codestra`;
- audience is exactly `middleware-api`;
- `azp` equals the selected client ID;
- subject is present;
- token lifetime is no more than 300 seconds;
- the configured read-probe scope is present;
- `tenant_id` is present, bounded, and not a wildcard.

It then executes:

- valid original bearer → expected `404`;
- tampered JWT signature → expected `401`;
- mismatched `X-Tenant-ID` → expected `403`.

Shared probes verify:

- missing Authorization → `401`;
- malformed bearer → `401`;
- `X-Forwarded-Authorization` without the real Authorization header → `401`.

## Extended negative fixtures

A certification-eligible run also needs validly signed, staging-only negative tokens covering:

- wrong issuer;
- wrong audience;
- wrong `azp`;
- expired token;
- not-yet-valid token;
- missing scope;
- cross-client scope confusion.

Supply these through a private JSON file referenced by `AUTH_MATRIX_NEGATIVE_TOKEN_FILE`. The repository must never contain the file or its tokens.

Example shape:

```json
{
  "wrong_issuer": {
    "token": "<staging-only negative bearer>",
    "tenant_id": "<staging tenant>"
  }
}
```

All seven cases are required when `AUTH_MATRIX_REQUIRE_EXTENDED_NEGATIVES=true`, which is the default. A partial client selection or incomplete extended-negative set may be useful for diagnosis, but it is not certification eligible.

## Required environment

```bash
export AUTH_MATRIX_ENVIRONMENT=staging
export AUTH_MATRIX_GATEWAY_BASE_URL='https://<reviewed-staging-gateway>'
export AUTH_MATRIX_TOKEN_ENDPOINT='https://<reviewed-keycloak>/realms/codestra/protocol/openid-connect/token'
export AUTH_MATRIX_SOURCE_SHA='<exact 40-character protected source SHA>'
export AUTH_MATRIX_IMAGE_DIGEST='sha256:<exact 64-hex image digest>'
export AUTH_MATRIX_NEGATIVE_TOKEN_FILE='/run/private/staging-negative-tokens.json'
```

Client secrets are supplied only through process environment variables:

```text
AUTH_MATRIX_SECRET_<UPPERCASE_CLIENT_ID_WITH_UNDERSCORES>
```

For example:

```text
AUTH_MATRIX_SECRET_MONEYBEE_BACKEND
AUTH_MATRIX_SECRET_CODESTRA_AI
AUTH_MATRIX_SECRET_CODESTRA_COMMUNICATION
```

No token or secret value is printed or written to evidence.

## Running

Run the complete policy-derived matrix:

```bash
python3 scripts/staging_product_auth_read_matrix.py
```

A diagnostic subset may be selected explicitly:

```bash
AUTH_MATRIX_CLIENTS='moneybee-backend,codestra-ai' \
AUTH_MATRIX_REQUIRE_EXTENDED_NEGATIVES=false \
python3 scripts/staging_product_auth_read_matrix.py
```

A subset cannot produce `AUTH_MATRIX_CERTIFICATION_ELIGIBLE=YES`.

## Evidence

Evidence is written outside the repository, by default under a new private directory in `/tmp`. The JSON record contains:

- exact source SHA and image digest;
- SHA-256 of the combined caller/provider policy;
- client ID and required scope;
- issuer, audience, `azp`, and token lifetime facts;
- SHA-256 of each tenant ID, never the raw tenant;
- expected and actual HTTP status for every probe;
- sanitized error codes;
- complete-client and extended-negative coverage flags;
- `command_posts=0`;
- `provider_calls=0`;
- `business_mutations=0`;
- `tokens_recorded=false`;
- `secrets_recorded=false`;
- `external_effects_enabled=NONE`.

A result is certification eligible only when every probe passes, all policy-marked clients are included, and all extended negative fixtures are present.

## Safety interpretation

This matrix proves staging authentication and tenant isolation only. It does not authorize:

- provider dispatch;
- email, SMS, voice, social, advertising, or AI effects;
- Odoo, n8n, or VICIdial writes;
- crawling or provisioning;
- production activation;
- DNS, proxy, firewall, credential, database, or SSH changes.

The final certification record must remain fail-closed until the evidence source SHA and image digest exactly match the immutable image deployed to protected staging.
