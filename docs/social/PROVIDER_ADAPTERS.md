# Provider adapters

Adapters implement health, capabilities, accounts, post lifecycle, media, comments/messages, analytics and webhook methods. Unsupported functions raise `SOCIAL_PROVIDER_CAPABILITY_UNSUPPORTED`. The registry validates enum names, disabled state and capabilities before dispatch.

New adapters must normalize networks, statuses, errors and events; keep credentials in secret files; never expose raw responses; and add provider-switch and idempotency tests.
