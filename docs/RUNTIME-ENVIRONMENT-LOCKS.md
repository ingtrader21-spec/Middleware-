# Locked runtime environments

Staging and production run the same immutable application image, but they must
never share service identities or backing resources. The checked-in
`config/runtime-profiles.v1.json` registry assigns each environment its own:

- profile ID and application environment;
- PostgreSQL hostname, database, role, TLS requirement, and port;
- Redis hostname, ACL user, logical database, TLS requirement, and port;
- NATS hostname, stream, subject namespace, and credential-name prefix;
- Temporal hostname, namespace, task queue, TLS name, and credential-name prefix.

Startup fails unless `RUNTIME_PROFILE_ID` selects the profile matching
`APP_ENV` and every configured endpoint matches that profile exactly. Staging
also rejects any `PRODUCTION_ACTIVATION_ID`. Test and development runtimes reject
production/staging profile IDs entirely.

The profile hostnames are deployment contracts. Provision those DNS identities
in the corresponding private namespace. Changing a hostname, database, role,
queue, or secret prefix requires a reviewed profile change in the immutable
image; it is not an ad hoc deployment override.

Use the credential-free templates:

- `config/environments/staging.runtime.env.example`
- `config/environments/production.runtime.env.example`

They are safe baselines, not secret files. The database/Redis passwords,
webhook secrets, NATS credential, and Temporal certificates must be injected by
the environment's secret manager. Both templates keep all effects disabled;
production activation is a separate reviewed release action.

`GET /version` exposes the selected runtime profile ID so deployment evidence
can prove which environment lock the process enforced.
