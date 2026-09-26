#!/usr/bin/env bash
# Verify the repair candidate branch under Linux with the exact CI commands.
set -Eeuo pipefail
cd ~/pas179/infra
SP=$HOME/pas179/bin
BASE=c288723b040871782f3829d99d205a5bbcd4d54c
git status --porcelain
echo "HEAD=$(git rev-parse HEAD) on $(git rev-parse --abbrev-ref HEAD)"
export GITHUB_REPOSITORY=ingtrader21-spec/Infustruction-repo
export GITHUB_REPOSITORY_ID=1350724865
export GITHUB_EVENT_NAME=pull_request
export GITHUB_REF=refs/pull/127/merge
export GITHUB_SHA=$(git rev-parse HEAD)
export EXPECTED_SHA=$GITHUB_SHA
export COMPARISON_SHA=$BASE
export RUNNER_TEMP=$HOME/pas179/runner-temp-repair
rm -rf "$RUNNER_TEMP"; mkdir -p "$RUNNER_TEMP"
export GITHUB_ENV=$RUNNER_TEMP/github.env; : > "$GITHUB_ENV"
export GITHUB_OUTPUT=$RUNNER_TEMP/github.output; : > "$GITHUB_OUTPUT"
PY=~/pas179/venv/bin/python
declare -A RESULT
run_check() { local name=$1; shift; echo; echo "################ $name"; if "$@"; then RESULT[$name]=PASS; else RESULT[$name]="FAIL($?)"; fi; }

orch() { env -u GITHUB_REPOSITORY python3 .codestra/validate-production-orchestrator-contract.py && git diff --check "$COMPARISON_SHA" "$EXPECTED_SHA"; }
run_check "production-orchestrator-contract" orch
rist() { ( cd ~/pas179/infra && env -u GITHUB_REPOSITORY python3 .codestra/validate-release-intent.py --self-test ); }
run_check "release-intent-self-test" rist
run_check "test-upstream-signing-identity" $PY -m unittest discover -s tests -p test_upstream_signing_identity.py
rpt() { $PY -m unittest discover -s tests -p test_release_policy_review.py -v && $PY -m unittest discover -s tests -p test_release_check_identity.py; }
run_check "release-policy-review-tests" rpt
drb() { $PY -m unittest discover -s tests -p test_deploy_readiness_build_context.py && $PY -m pytest -q tests/test_reusable_deploy_readiness_container_contract.py && $PY -m pytest -q tests/test_deploy_readiness_release_assets.py; }
run_check "test-deploy-readiness-build-context" drb
sam() {
  $PY scripts/validate_production_source_authority_matrix.py
  $PY -m unittest discover -s tests -p test_pr30_evidence_authority.py
  mkdir -p "${RUNNER_TEMP}/tracked-source"; git archive HEAD | tar -x -C "${RUNNER_TEMP}/tracked-source"
  (cd "${RUNNER_TEMP}/tracked-source" && ~/pas179/gitleaks dir --config .gitleaks.toml --no-banner --redact --exit-code 1 . 2>&1 | tail -2)
  $PY scripts/test_gitleaks_policy.py ~/pas179/gitleaks
}
run_check "source-authority-matrix" sam
ccp() { export CONTRACT_DIGEST=b39cdffe56a8185c91174228f0423df68b1137f34875f6ee52f9914f904bf724 CONTRACT_AUTHORITY='appolon1908-hue/codestra-production-platform#257' CONTRACT_ROLE=deployment; $PY "$SP/calling_contract_check.py" && git diff --check; }
run_check "calling-contract-pin" ccp
prov() { $PY "$SP/provenance_generate.py" && $PY -m pytest -q tests/test_reusable_provenance.py; }
run_check "test-provenance-integrity(python-parts)" prov
rna() { $PY scripts/validate_repository_name_aliases.py && $PY scripts/validate_repository_name_transition.py && $PY -m unittest discover -s tests -p 'test_repository_name_*.py'; }
run_check "repository-name-authority" rna

# Independent release policy review with the REPAIRED validator (as it will run from main after merge):
# synthetic open PR JSON bound to the post-transfer repository + a kazan555 approval of the exact head.
rpr_repaired() {
  local head; head=$(git rev-parse HEAD)
  git worktree remove --force "$RUNNER_TEMP/policy" 2>/dev/null || true
  git worktree add -q --detach "$RUNNER_TEMP/policy" "$head"
  git worktree remove --force "$RUNNER_TEMP/candidate" 2>/dev/null || true
  git worktree add -q --detach "$RUNNER_TEMP/candidate" "$head"
  $PY - "$RUNNER_TEMP" "$head" <<'PYX'
import json, sys
temp, head = sys.argv[1], sys.argv[2]
pr = {"number": 127, "state": "open", "draft": False, "user": {"id": 268651787},
      "base": {"ref": "main", "sha": head, "repo": {"id": 1350724865, "full_name": "ingtrader21-spec/Infustruction-repo"}},
      "head": {"sha": head}}
json.dump(pr, open(f"{temp}/policy-pr.json", "w")); json.dump(pr, open(f"{temp}/policy-pr-final.json", "w"))
json.dump([[{"id": 1, "user": {"id": 77101516}, "state": "APPROVED", "commit_id": head, "author_association": "COLLABORATOR"}]], open(f"{temp}/policy-reviews.json", "w"))
PYX
  ( cd "$RUNNER_TEMP" && GITHUB_SHA=$head PR_NUMBER=127 BASE_SHA=$head python3 -I policy/scripts/validate_release_policy_review.py --base-root policy --base-sha "$head" --pr-number 127 --pr "$RUNNER_TEMP/policy-pr.json" --prepare ) && cat "$GITHUB_OUTPUT"
  ( cd "$RUNNER_TEMP" && GITHUB_SHA=$head PR_NUMBER=127 BASE_SHA=$head python3 -I policy/scripts/validate_release_policy_review.py --base-root policy --base-sha "$head" --pr-number 127 --pr "$RUNNER_TEMP/policy-pr.json" --head-sha "$head" --candidate-root candidate --reviews "$RUNNER_TEMP/policy-reviews.json" --final-pr "$RUNNER_TEMP/policy-pr-final.json" )
  echo "## negative: repository ID env mismatch must fail"
  if ( cd "$RUNNER_TEMP" && GITHUB_REPOSITORY_ID=1 GITHUB_SHA=$head python3 -I policy/scripts/validate_release_policy_review.py --base-root policy --base-sha "$head" --pr-number 127 --pr "$RUNNER_TEMP/policy-pr.json" --prepare ) 2>"$RUNNER_TEMP/neg.log"; then echo "UNEXPECTED PASS"; return 1; else tail -1 "$RUNNER_TEMP/neg.log"; fi
  echo "## negative: pre-transfer slug in env must fail"
  if ( cd "$RUNNER_TEMP" && GITHUB_REPOSITORY=appolon1908-hue/Infustruction-repo GITHUB_SHA=$head python3 -I policy/scripts/validate_release_policy_review.py --base-root policy --base-sha "$head" --pr-number 127 --pr "$RUNNER_TEMP/policy-pr.json" --prepare ) 2>"$RUNNER_TEMP/neg2.log"; then echo "UNEXPECTED PASS"; return 1; else tail -1 "$RUNNER_TEMP/neg2.log"; fi
}
run_check "independent-release-policy-review(repaired)" rpr_repaired

echo; echo "=================== SUMMARY on $(git rev-parse HEAD)"
for k in "${!RESULT[@]}"; do printf "%-48s %s\n" "$k" "${RESULT[$k]}"; done | sort
