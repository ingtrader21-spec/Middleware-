# Worker protocol

The worker uses only `https://middleware.internal.codestra.agency` resolved to `10.40.0.1`. Every request uses the established client certificate and exact HMAC canonical string `METHOD\nPATH\nSERVICE_ID\nTIMESTAMP\nNONCE\nBODY_SHA256`. Identity and scopes are server-bound. Worker operations cover registration, heartbeat, claim, lease heartbeat, cancellation check, completion, failure, release, and safe configuration discovery.
