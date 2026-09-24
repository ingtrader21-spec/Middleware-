# Integration fabric branch map

## Dependency order

1. `integration/n8n-control-plane-v2-20260827`
2. `architecture/codestra-integration-fabric-v2`
3. shared persistence and authorization primitives
4. `platform/nats-jetstream` durable event transport and `platform/temporal` critical workflow primitives
5. one adapter branch per product
6. matching product-repository contract
7. matching n8n workflow pack
8. Kong route and Keycloak client changes
9. observability and negative tests
10. staging no-effect certification
11. immutable release and separate capability canary

## Focused implementation branches

```text
feat/tenant-onboarding-api-v1
feat/capability-registry-v1
feat/command-operation-api-v1
feat/webhook-inbox-v1
feat/transactional-outbox-v1
feat/event-delivery-ledger-v1
feat/dead-letter-replay-v1
platform/nats-jetstream
platform/temporal
integration/kong-cells-v1
integration/keycloak-service-identities-v2
integration/odoo-crm-facade-v1
integration/klyrow-email-v1
integration/telnexa-sms-v1
integration/postly-social-v1
integration/kyqra-crawler-v1
integration/vicidial-telephony-v1
integration/beyvra-nonfinancial-v1
integration/provisioning-service-v1
```

No branch is an environment. Do not force-update or delete existing historical branches. Cleanup requires a separate reachability and dependency review.

`platform/rabbitmq` is legacy provider-inventory only. RabbitMQ remains inside the Telnexa/Klyrow product boundary and must not be used as the Codestra central event bus.
