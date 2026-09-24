# Write-boundary hardening controls

These controls close ambiguity left by marker-only workflow inspection, size-limited configuration scans, and annotation-only date-time validation.

## n8n destinations

Tracked JSON that contains n8n nodes is inspected regardless of its repository directory. Node types are fail-closed against the reviewed orchestration-only allowlist in `config/write-boundary-hardening.json`.

A generic HTTP Request node is accepted only when its URL uses the exact `{{$env.MIDDLEWARE_BASE_URL}}` expression and a static route below `/v1/commands`, `/v1/queries`, or `/v1/triggers`.

The path must already be canonical. Literal or encoded traversal, percent escapes, repeated slashes, backslashes, dynamic path expressions, fragments, and paths outside the approved Middleware route trees fail CI. Dynamic values belong in a validated request body or query field, not in the route path.

Inbound n8n webhook nodes must declare an authentication mode and use the reserved `middleware/` path namespace. Provider callbacks still enter Middleware's signed durable inbox; n8n receives only normalized trigger contracts.

## Repository-wide credential scan

All tracked non-binary source and configuration files are scanned as byte streams. There is no size exemption. Large Compose, Kubernetes, deployment, workflow, generated-manifest, and root configuration files therefore cannot bypass the Odoo database-credential guard by adding padding.

Known binary artifact formats, generated dependency/cache directories, the validators themselves, and explicit negative-test fixtures are excluded. Production credentials remain outside Git.

## Calendar-valid timestamps

`requested_at` retains the original RFC-3339-shaped assertion for compatibility and adds a second assertive schema pattern through `allOf`. The strict assertion validates month length, Gregorian leap-year rules, time ranges, offset ranges, and disallows year zero.

CI proves valid leap dates are accepted while February 31, April 31, non-leap February 29, 1900-02-29, and year zero are rejected even when a downstream JSON Schema implementation treats `format` as annotation-only.

## Change control

Changing the node allowlist, route prefixes, webhook namespace, scan exclusions, or strict timestamp assertion requires a reviewed policy and validator change in the same pull request. No hardening exception is granted through runtime configuration.
