# Fixture 6198 controlled replay v3

This package replays a sealed gateway outbox selection to the RC4 lifecycle
ingress. It fixes the PR14 failure by making the target endpoint explicit and
by refusing legacy or unverified middleware runtimes.

The input must contain exactly three outbox rows whose `payload` values are the
canonical `started`, `connected`, and `ended` envelopes. The tool never changes
an envelope. It submits those three envelopes and one byte-identical replay of
the ended envelope.

Dry-run is the default. Execution additionally requires:

- `--execute`;
- exactly one running Compose service `compose/middleware-event-gateway`;
- the exact approved RC4 image digest and internal `codestra_backend` network;
- strict `/healthz` and `/readyz` responses from the derived internal address;
- a protected HMAC secret file;
- an empty, newly created response log;
- explicit confirmation of a four-request limit.

`TEST_EVIDENCE_ID` is not accepted as an argument and is never placed in an
HTTP request. Keep it solely in the external operator evidence manifest.

The target URL is never accepted from the operator. It is derived from the
single approved Compose container after its labels, immutable image digest,
internal-only network, private address, health, and readiness all pass.
Redirects, public and loopback targets, ambiguous candidates, extra health
fields, and the legacy monolith identity are rejected.

The PR14 HTTP 422 was not caused by the gateway envelope. The replay command
ran inside the legacy `codestra-middleware-1` monolith and posted to that
container's loopback listener. That image predates lifecycle envelopes: its
strict schema rejects the lifecycle extension fields and does not register
`vicidial.call.started` or `vicidial.call.connected`. The approved RC4 schema
accepts all three sealed envelopes unchanged.

Example dry run:

```sh
python3 replay_v3.py \
  --events /restricted/evidence/gateway-outbox-new-events.json \
  --expected-linked-id 1785200809.1
```

Production execution remains a separate, explicit mission.
