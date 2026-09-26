# Middleware Single-Lane Agent Contract

This file is mandatory authority for every human, Claude, Codex, Copilot, CI, or other automation acting on this repository.

## Entry gate

Before reading mission-specific instructions or editing a tracked file, run:

```bash
./scripts/agent_preflight.sh --start --branch "$(git branch --show-current)"
```

A failing preflight is a STOP condition. Do not work around it with another worktree, host, port, route, provider, database path, or Git write path.

## Single writer

- Exactly one worktree/branch may be declared as the active write lane for a mission.
- Every other checkout is preserved read-only reconciliation/evidence until its unique semantics are proven reachable or deliberately migrated.
- Never start a second agent on the same repository/worktree while a writer is active.
- Never reset, clean, stash, discard, rebase, rewrite, force-push, delete branches/worktrees, or overwrite unproven history.
- Never develop directly on `main`, a detached HEAD, a stale branch, or a branch whose upstream differs from its remote head.

## Canonical platform boundaries

- Public request path: Client -> Caddy -> Kong -> Middleware `:8095`.
- Do not introduce alternative canonical Middleware ports such as `:8080` or `:8096`.
- Preserve the repository's approved route authorities; do not create parallel aliases or direct-provider shortcuts.
- `/metrics` and `/internal/*` stay private and must not be exposed as public application routes.
- Preserve the canonical request metadata contracts: authentication/tenant context, `X-Correlation-ID`, `X-Causation-ID` where applicable, and `Idempotency-Key` on effect-capable commands.
- Do not introduce direct provider writes, direct Odoo database authority, direct SMTP delivery, or bypass the durable command/ledger/outbox authority.

## Production safety

Production/provider effects remain fail-closed unless a separately approved release mission explicitly authorizes them. An agent must not enable live email/SMS/calling, payment/money movement, direct production database writes, or provider mutations as a side effect of implementation or testing.

## Certification and publication

Before publication:

```bash
./scripts/agent_preflight.sh --certify --branch "$(git branch --show-current)"
```

Then immediately before a normal non-force push, perform a remote-head compare-and-swap:

```bash
branch="$(git branch --show-current)"; local_head="$(git rev-parse HEAD)"; upstream_head="$(git rev-parse "@{u}")"; remote_head="$(git ls-remote origin "refs/heads/$branch" | awk '{print $1}')"; test "$local_head" = "$upstream_head" && test "$remote_head" = "$upstream_head"
```

If that comparison fails, STOP. Fetch and reconcile on the owning workstation; never force-push or publish through a different write path.

The mission handoff must record host, worktree, branch, local HEAD, upstream SHA, remote SHA, dirty state, tests/validators run, and the exact next command.
