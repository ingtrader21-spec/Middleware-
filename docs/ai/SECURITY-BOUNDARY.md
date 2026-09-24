# Security boundary

The browser, n8n, Odoo, and VICIdial never reach Qwen, LiteLLM, or Ollama. Middleware validates JWT tenant claims for public commands and mTLS/HMAC for workers. The worker cannot fabricate certificate identity headers. Prompts, outputs, secrets, keys, credentials, and full certificates are excluded from logs. All production/business dispatch remains disabled.
