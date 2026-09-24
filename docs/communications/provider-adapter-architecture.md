# Provider adapter architecture

The provider adapter layer is a provider-neutral boundary over the existing
notification command journal. It does not create a second command, attempt,
event, audit, or reconciliation store.

`NullProviderAdapter` is the default and rejects every external operation.
`SyntheticSinkAdapter` accepts only `TEST` records whose destination is
classified `APPROVED_SYNTHETIC`. It derives deterministic provider identifiers,
keeps its test observations in memory, and contains no HTTP, SMTP, socket, or
provider SDK integration.

Provider-specific stubs contain only a provider name. They have no endpoint,
account, credential, or dispatch implementation and report not-ready.

The contracts store opaque destination and content references. Raw provider
credentials, complete message bodies, and unrestricted destination data are
outside this layer.

All production delivery gates remain false:

- `ENABLE_EXTERNAL_DELIVERY=false`
- `ALLOW_LIVE_EMAIL=false`
- `ALLOW_LIVE_SMS=false`
- `PRODUCTION_N8N_ENABLED=false`
- `N8N_PRODUCTION_WORKFLOWS_ENABLED=false`
