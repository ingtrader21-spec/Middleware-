#!/usr/bin/env bash
set -euo pipefail

mode="start"
expected_branch=""
while (($#)); do
  case "$1" in
    --start) mode="start" ;;
    --certify) mode="certify" ;;
    --ci) mode="ci" ;;
    --branch) shift; expected_branch="${1:-}" ;;
    *) echo "agent_preflight: unknown argument: $1" >&2; exit 64 ;;
  esac
  shift
done

fail() { echo "AGENT_PREFLIGHT=FAIL $*" >&2; exit 1; }
pass() { echo "AGENT_PREFLIGHT=PASS $*"; }

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "not_in_git_worktree"
root="$(git rev-parse --show-toplevel)"
cd "$root"

branch="$(git branch --show-current)"
[[ -n "$branch" ]] || fail "detached_head"
[[ "$branch" != "main" && "$branch" != "master" ]] || fail "protected_main_development"
if [[ -n "$expected_branch" && "$branch" != "$expected_branch" ]]; then
  fail "wrong_branch expected=$expected_branch actual=$branch"
fi

upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
[[ -n "$upstream" ]] || fail "missing_upstream branch=$branch"
[[ "$upstream" == "origin/$branch" ]] || fail "wrong_upstream expected=origin/$branch actual=$upstream"

if [[ "$mode" == "start" || "$mode" == "certify" ]]; then
  [[ -z "$(git status --porcelain)" ]] || fail "dirty_worktree"
fi

local_head="$(git rev-parse HEAD)"
upstream_head="$(git rev-parse '@{u}')"
[[ "$local_head" == "$upstream_head" ]] || fail "local_upstream_mismatch local=$local_head upstream=$upstream_head"

remote_head="$(git ls-remote origin "refs/heads/$branch" | awk 'NR==1{print $1}')"
[[ -n "$remote_head" ]] || fail "remote_branch_missing branch=$branch"
[[ "$remote_head" == "$upstream_head" ]] || fail "stale_remote upstream=$upstream_head remote=$remote_head"

base_ref="${GITHUB_BASE_REF:-main}"
if git show-ref --verify --quiet "refs/remotes/origin/$base_ref"; then
  diff_range="origin/$base_ref...HEAD"
else
  diff_range="@{u}...HEAD"
fi

added="$(git diff --unified=0 "$diff_range" -- '*.py' '*.ts' '*.tsx' '*.js' '*.mjs' '*.sh' '*.yml' '*.yaml' '*.json' '*.toml' '*.conf' '*.md' 2>/dev/null | sed -n 's/^+//p' | grep -v '^+++' || true)"

if grep -Eiq '(^|[^0-9])(:?8080|:8096)([^0-9]|$)' <<<"$added"; then
  fail "forbidden_alternate_middleware_port"
fi
if grep -Eiq 'public.*(/metrics|/internal/)|(/metrics|/internal/).*public' <<<"$added"; then
  fail "forbidden_public_private_route"
fi
if grep -Eq 'X-Correlation-Id|X-Tenant-Id|IdempotencyKey|X-Idempotency-Key' <<<"$added"; then
  fail "forbidden_header_variant"
fi
if grep -Eiq '(direct[ _-]?(smtp|provider|odoo[ _-]?db)|bypass[ _-]?(outbox|ledger|middleware)|provider[ _-]?shortcut)' <<<"$added"; then
  fail "forbidden_direct_effect_path"
fi
if grep -Eiq '(production[_ -]?(effects?|enabled|authorized)[[:space:]]*[:=][[:space:]]*(true|1|yes)|live[_ -]?(email|sms|calling)[[:space:]]*[:=][[:space:]]*(true|1|yes))' <<<"$added"; then
  fail "forbidden_production_effect_activation"
fi

if [[ "$mode" == "certify" || "$mode" == "ci" ]]; then
  git diff --check "$diff_range"
  for f in AGENTS.md .github/copilot-instructions.md scripts/agent_preflight.sh; do
    [[ -s "$f" ]] || fail "missing_governance_file file=$f"
  done
  grep -q 'X-Correlation-ID' AGENTS.md || fail "missing_correlation_header_authority"
  grep -q 'Idempotency-Key' AGENTS.md || fail "missing_idempotency_header_authority"
  grep -q 'X-Tenant-ID\|tenant' AGENTS.md || fail "missing_tenant_authority"
fi

pass "mode=$mode branch=$branch head=$local_head upstream=$upstream_head remote=$remote_head"
