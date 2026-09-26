# Single-Lane Development Handoff

## Authority

Every new Middleware agent starts with `AGENTS.md` and `scripts/agent_preflight.sh`. A mission may have only one write-enabled worktree. All other worktrees remain preserved reconciliation/evidence until their unique semantics are proven superseded.

## Current publication lane

- Repository: `ingtrader21-spec/Middleware-`
- Current PR: #355
- Branch: `mission/mcr-c-completion-safe-20260924`
- Certified/pushed head at governance handoff: `d03f7099e05b7bb7888ca8631cdbc10401cc72bb`
- Ubuntu review worktree: `/home/codestra/Worktrees/Middleware-/mcr-c-completion-safe`
- Production/provider effects: fail-closed

## Current convergence lane

`/home/codestra/Worktrees/Middleware-/mcr-c-final-convergence` is preserved at `7d713735e46a0d0efc437808ad34f42ecdc41c6c`. Duplicate Claude/Codex writers were stopped on 2026-09-26. Do not restart a convergence agent until PR #355 required CI is independently green or a documented remediation is required.

## One-line continuation

Ubuntu inspection:

```bash
cd /home/codestra/Worktrees/Middleware-/mcr-c-completion-safe && ./scripts/agent_preflight.sh --start --branch mission/mcr-c-completion-safe-20260924
```

Pre-publication certificate:

```bash
cd /home/codestra/Worktrees/Middleware-/mcr-c-completion-safe && ./scripts/agent_preflight.sh --certify --branch mission/mcr-c-completion-safe-20260924
```

Appolon PowerShell review path (read/check before publication; never overwrite a newer remote):

```powershell
cd C:\Users\agent\Documents\GitHub\Middleware-; git fetch origin; git status --short --branch; git ls-remote origin refs/heads/mission/mcr-c-completion-safe-20260924
```

## Publication rule

Immediately before every normal non-force push, compare local HEAD, upstream HEAD, and `git ls-remote` for the exact intended branch. Any mismatch is a STOP condition.

## Historical lanes

Do not delete, reset, clean, or repurpose old worktrees merely because a newer lane exists. Reconcile unique commits/patches first; then mark the checkout read-only/preserved. Worktree removal is a separate maintenance action only after provenance is recorded.
