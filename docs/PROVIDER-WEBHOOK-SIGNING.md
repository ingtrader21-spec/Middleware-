# Provider webhook signing (VICIdial call results, Telnexa inbound SMS)

Routes: `POST /webhooks/vicidial/call-result/` and `POST /webhooks/sms/inbound/`
(`app/api/v1/provider_webhooks.py`). Both sides of these integrations are
operated by us, so the sender must implement exactly this scheme.

## Request

| Header | VICIdial | Telnexa | Value |
| --- | --- | --- | --- |
| `Content-Type` | required | required | `application/json` (415 otherwise) |
| timestamp | `X-VICIdial-Timestamp` | `X-Telnexa-Timestamp` | Unix seconds, integer |
| signature | `X-VICIdial-Signature` | `X-Telnexa-Signature` | `sha256=<hex>` or bare hex |

Signature: `HMAC-SHA256(secret, "{timestamp}." + raw_body)` — the timestamp is
part of the MAC, so a captured request cannot be replayed with a fresh
timestamp. The body is signed byte-for-byte as sent; do not re-serialize.
Same canonical form as `/api/v1/events/vicidial`.

Rejections: 503 when the secret is not configured; 403 for a bad signature, a
non-integer timestamp, or a timestamp outside `signature_ttl_seconds`
(default 300 s); 413 when the body exceeds `request_max_bytes`.

## Response

`202` with `{"accepted": true, "event_id": "<provider>:<external_id>",
"duplicate": false, "odoo_write": "pending"|"disabled"}`. A retry with the same
`call_id`/`message_id` and identical body returns the original response; the
same id with a different body is `409`.

## Example (Python)

```python
import hashlib, hmac, json, time
body = json.dumps(payload, separators=(",", ":")).encode()
ts = str(int(time.time()))
sig = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
headers = {"Content-Type": "application/json",
           "X-VICIdial-Timestamp": ts, "X-VICIdial-Signature": f"sha256={sig}"}
```
