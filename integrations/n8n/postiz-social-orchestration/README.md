# Postiz social orchestration workflows

These inactive exports use n8n's built-in HTTP Request node to call Codestra
Middleware only. They never contain a Postiz URL, provider credential, Odoo
node, database node, or Redis operation. Import requires an authenticated
middleware credential and remains disabled until a separately reviewed
synthetic validation.

Required middleware routes:

- `/api/v1/integrations/postiz/health`
- `/api/v1/integrations/postiz/channels`
- `/api/v1/integrations/postiz/media`
- `/api/v1/integrations/postiz/posts`
- `/api/v1/integrations/postiz/results`
- `/api/v1/integrations/postiz/errors`

`CUSTOM_POSTIZ_NODE_REQUIRED=NO`
`POSTIZ_PUBLISH_ENABLED=false`
