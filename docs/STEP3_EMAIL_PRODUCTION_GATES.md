# Step 3 Email Production Gates

Date: 2026-08-30

Step 3 can become source-complete without production activation.

## Step 3 Source Exit Gate

SMS source implementation may proceed only after all of the following are true on the unchanged final Middleware head:

- exact source-head validation passes;
- exact merge-result validation passes;
- runtime and test image builds pass;
- disposable PostgreSQL/Redis integration passes;
- NATS JetStream integration passes;
- Temporal unknown-outcome, bounded reconciliation read-back, and no-resubmission evidence passes;
- synthetic no-effect E2E passes;
- container security passes;
- Production route contract passes with every provider-effect flag disabled;
- Klyrow provider CI remains green at its pinned Step 3 head;
- exact Middleware/Klyrow/SDK SHAs and GitHub run IDs are posted to PR #52 and PR #47.

Passing this gate authorizes only continued source development for Step 4 SMS. It does not authorize deployment or delivery.

## Must Pass Before Production Email Sending

- Durable Communications read-model migration and rollback evidence.
- Keycloak to Kong to Middleware live auth matrix.
- Klyrow authenticated staging canary with safe-mode proof.
- SMTP/DNS/domain readiness evidence from Klyrow.
- Live Klyrow provider read-back canary using the reviewed private API and OAuth2 plus mTLS.
- Isolated unknown-outcome and duplicate-send prevention test against the staging Klyrow runtime.
- Backup and restore evidence for communication state.
- Observability alerts for command failures, provider degradation, bounce/complaint spikes, and reconciliation backlog.
- Explicit approval to enable production delivery flags.

## Prohibited In This Branch

- No live Postal/Mautic sending.
- No production DNS activation.
- No Keycloak/Kong/Caddy deployment changes.
- No n8n or Odoo live side effects.
- No email or SMS capability activation.
- No provider credentials or client secrets in Git.
