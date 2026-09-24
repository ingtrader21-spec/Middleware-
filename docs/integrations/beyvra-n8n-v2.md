# Beyvra non-financial automation boundary

The Beyvra integration is split into two repositories:

```text
appolon1908-hue/beyvra-backend
appolon1908-hue/beyvra-frontend
```

The backend is the domain authority and the only Beyvra application that may participate in Middleware automation commands. The frontend is a browser UI and never authenticates as an n8n or Middleware machine client.

```text
workflow_family = product.beyvra-nonfinancial
client          = n8n-product-automation
command_prefix  = beyvra.operations.
```

Allowed orchestration is limited to onboarding, compliance reminders, support tasks, internal alerts, report readiness, notification delivery and signed-webhook reconciliation. Trading, orders, wallets, ledgers, deposits, withdrawals, transfers, payments, custody, balances, broker credentials and provider credentials are excluded, including demo-order submission.

Dependencies:

```text
beyvra-backend PR #52
beyvra-frontend PR #24
N8N automation/beyvra-operations-v2-20260827
N8N PR #9
Keycloak PR #10
Middleware PR #15
```

Current state:

```text
SOURCE_ONLY=YES
FINANCIAL_EFFECTS_ALLOWED=NO
FRONTEND_MACHINE_CLIENT=NO
LIVE_SERVER_CHANGED=NO
PRODUCTION_DEPLOYED=NO
```
