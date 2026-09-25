#!/usr/bin/env bash
# Local Linux re-execution of every PR-triggered workflow of ingtrader21-spec/Infustruction-repo
# on exact head 60eff4c3ea848a202561412610728000de299f29, mirroring the workflow env.
#
# Inputs: PAS179_ROOT (default ~/pas179) holds infra/ (a clean Infustruction-repo clone at HEAD),
# venv/ and gitleaks; POLICY_PR_JSON is the GitHub API JSON of PR #126
# (gh api repos/ingtrader21-spec/Infustruction-repo/pulls/126).
set -Eeuo pipefail
SP=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
W=${PAS179_ROOT:-$HOME/pas179}
POLICY_PR_JSON=$(realpath "${POLICY_PR_JSON:?PR #126 API JSON is required}")
cd "$W/infra"
HEAD=60eff4c3ea848a202561412610728000de299f29
BASE=9d32d421c8272ef33b7a442ac81617bea6d16897
test "$(git rev-parse HEAD)" = "$HEAD"
test -z "$(git status --porcelain)"
export GITHUB_REPOSITORY=ingtrader21-spec/Infustruction-repo
export GITHUB_REPOSITORY_ID=1350724865
export GITHUB_EVENT_NAME=pull_request
export GITHUB_REF=refs/pull/126/merge
export GITHUB_SHA=$HEAD
export EXPECTED_SHA=$HEAD
export COMPARISON_SHA=$BASE
export RUNNER_TEMP=$W/runner-temp
rm -rf "$RUNNER_TEMP"; mkdir -p "$RUNNER_TEMP"
export GITHUB_ENV=$RUNNER_TEMP/github.env; : > "$GITHUB_ENV"
export GITHUB_OUTPUT=$RUNNER_TEMP/github.output; : > "$GITHUB_OUTPUT"
if [ ! -x "$W"/venv/bin/python ]; then
  python3 -m venv "$W"/venv
  "$W"/venv/bin/pip install -q --disable-pip-version-check PyYAML==6.0.3 pytest==8.4.2
fi
PY="$W"/venv/bin/python
$PY --version
declare -A RESULT
run_check() { # name, command...
  # errexit is suspended for a function called as an `if` condition, so the check runs in a
  # plain subshell with errexit re-armed: any failing command fails the check, not only the last.
  local name=$1 rc; shift
  echo; echo "################ $name"
  set +e; ( set -Eeuo pipefail; "$@" ); rc=$?; set -e
  if [ "$rc" -eq 0 ]; then RESULT[$name]=PASS; else RESULT[$name]="FAIL($rc)"; fi
}

# 1 Validate upstream signing identity
run_check "test-upstream-signing-identity" $PY -m unittest discover -s tests -p test_upstream_signing_identity.py -v

# 2 Production orchestrator contract (exact CI command incl. the env -u wrapper from the head's workflow)
orch() {
  env -u GITHUB_REPOSITORY $PY .codestra/validate-production-orchestrator-contract.py
  git diff --check "$COMPARISON_SHA" "$EXPECTED_SHA"
}
run_check "production-orchestrator-contract" orch

# 2b negative: the pre-transfer invocation (without env -u) must still be the failure observed on 09703be
echo; echo "######## negative: orchestrator without env -u (expect: outside the protected catalog identity map)"
if $PY .codestra/validate-production-orchestrator-contract.py > "$RUNNER_TEMP/orch-neg.log" 2>&1; then
  RESULT[orchestrator-no-wrapper-negative]="UNEXPECTED_PASS"
else
  tail -2 "$RUNNER_TEMP/orch-neg.log"
  RESULT[orchestrator-no-wrapper-negative]="FAILS_AS_EXPECTED"
fi

# 3 Release policy review tests
rpt() {
  $PY -m unittest discover -s tests -p test_release_policy_review.py -v
  $PY -m unittest discover -s tests -p test_release_check_identity.py -v
}
run_check "release-policy-review-tests" rpt

# 4 Deploy readiness build context regression
drb() {
  $PY -m unittest discover -s tests -p test_deploy_readiness_build_context.py -v
  $PY -m pytest -q tests/test_reusable_deploy_readiness_container_contract.py
  $PY -m pytest -q tests/test_deploy_readiness_release_assets.py
}
run_check "test-deploy-readiness-build-context" drb

# 5 source-authority-matrix
sam() {
  test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"
  $PY scripts/validate_production_source_authority_matrix.py
  $PY -m unittest discover -s tests -p test_pr30_evidence_authority.py -v
  local GITLEAKS_VERSION=8.30.1
  local GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
  local archive="${RUNNER_TEMP}/gitleaks.tar.gz"
  if [ ! -x "$W"/gitleaks ]; then
    curl --fail --silent --show-error --location "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" --output "${archive}"
    echo "${GITLEAKS_SHA256}  ${archive}" | sha256sum --check -
    tar -xzf "${archive}" -C "$W" gitleaks
  fi
  cp "$W"/gitleaks "${RUNNER_TEMP}/gitleaks"
  mkdir -p "${RUNNER_TEMP}/tracked-source"
  git archive HEAD | tar -x -C "${RUNNER_TEMP}/tracked-source"
  (cd "${RUNNER_TEMP}/tracked-source" && "${RUNNER_TEMP}/gitleaks" dir --config .gitleaks.toml --no-banner --redact --exit-code 1 . 2>&1 | tail -4)
  $PY scripts/test_gitleaks_policy.py "${RUNNER_TEMP}/gitleaks"
}
run_check "source-authority-matrix" sam

# 6 calling-contract-pin (verify-head + verify-merge-result bodies)
ccp() {
  export CONTRACT_DIGEST=b39cdffe56a8185c91174228f0423df68b1137f34875f6ee52f9914f904bf724
  export CONTRACT_AUTHORITY='appolon1908-hue/codestra-production-platform#257'
  export CONTRACT_ROLE=deployment
  test "$(git rev-parse HEAD)" = "${EXPECTED_SHA}"
  test -z "$(git status --porcelain)"
  $PY "$SP/calling_contract_check.py"
  git diff --check
}
run_check "calling-contract-pin" ccp

# 7 Provenance integrity regression (Python parts; the Go round-trip needs sigstore/cosign@193d2153 + Go toolchain)
prov() {
  test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"
  $PY "$SP/provenance_generate.py"
  $PY -m pytest -q tests/test_reusable_provenance.py
}
run_check "test-provenance-integrity(python-parts)" prov

# 8 Repository Name Authority
rna() {
  $PY scripts/validate_repository_name_aliases.py
  $PY scripts/validate_repository_name_transition.py
  $PY -m unittest discover -s tests -p 'test_repository_name_*.py'
}
run_check "repository-name-authority" rna

# 9 Independent release policy review — pull_request_target: validator executes FROM MAIN (base),
#   so reproduce with main's copy against the real PR #126 JSON
rpr() {
  git worktree remove --force "$RUNNER_TEMP/policy" 2>/dev/null || true
  git worktree add -q --detach "$RUNNER_TEMP/policy" "$BASE"
  cp "$POLICY_PR_JSON" "$RUNNER_TEMP/policy-pr.json"
  ( cd "$RUNNER_TEMP" && GITHUB_SHA=$BASE PR_NUMBER=126 BASE_SHA=$BASE python3 -I policy/scripts/validate_release_policy_review.py --base-root policy --base-sha "$BASE" --pr-number 126 --pr "$RUNNER_TEMP/policy-pr.json" --prepare )
}
run_check "independent-release-policy-review" rpr

echo; echo "=================== SUMMARY on $HEAD"
for k in "${!RESULT[@]}"; do printf "%-45s %s\n" "$k" "${RESULT[$k]}"; done | sort
