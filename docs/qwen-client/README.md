# Qwen private middleware client contract

Do not replace the base URL placeholder until both private vSwitch addresses and the TLS identity are verified. Qwen must receive only its middleware HMAC secret; it must never receive Odoo, n8n, VICIdial, or Postly credentials.

For each request, send `X-Service-ID`, Unix-seconds `X-Timestamp`, a unique 16+ character `X-Nonce`, and `X-Signature`. The signature is lowercase HMAC-SHA256 over six newline-separated values: HTTP method, exact URL path, service ID, timestamp, nonce, and lowercase SHA-256 of the exact body bytes. Mutating requests also require `X-Correlation-ID` and `Idempotency-Key`.

The middleware implementation is deliberately mock-only and default-off. Downstream adapters do not open network connections.
