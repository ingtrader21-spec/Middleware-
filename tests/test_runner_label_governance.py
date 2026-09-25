"""Runner-label governance for the persistent self-hosted Middleware runner.

``codestra-ubuntu-middleware`` (labels ``self-hosted, Linux, X64,
middleware-ci``) is a persistent operator host, not an ephemeral VM. Only the
required Middleware CI gates may target it, only for trusted events, and only
without host-level side effects. Release, signing and publishing workflows stay
on GitHub-hosted runners because release provenance is verified with
``--deny-self-hosted-runners``.
"""

from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
MIDDLEWARE_CI = WORKFLOWS / "middleware-ci.yml"
REQUIRED_CI = WORKFLOWS / "required-ci.yml"

GOVERNED_LABELS = ("self-hosted", "Linux", "X64", "middleware-ci")
GOVERNED_RUNS_ON = (
    "${{ (github.event_name == 'push' || "
    "github.event.pull_request.head.repo.full_name == github.repository) && "
    "fromJSON('[\"self-hosted\",\"Linux\",\"X64\",\"middleware-ci\"]') || "
    "'ubuntu-24.04' }}"
)
SELF_HOSTED_WORKFLOWS = frozenset({"middleware-ci.yml"})
# Branch-protection contexts plus the push-only main gate. Rerouting must not
# rename, drop or add a job.
MIDDLEWARE_CI_JOB_NAMES = {
    "source-head-validation": "Validate middleware source head",
    "merge-result-validation": "Validate middleware merge result",
    "main-validation": "Validate middleware main push",
    "docker-runtime-build": "docker-runtime-build",
    "docker-test-build": "docker-test-build",
    "connector-runtime-build": "connector-runtime-build",
    "container-security": "container-security",
    "runtime-integration": "Disposable PostgreSQL Redis integration",
    "nats-jetstream-integration": "Disposable NATS JetStream integration",
    "temporal-workflow-integration": "Temporal critical workflow integration",
    "synthetic-acceptance-e2e": "Synthetic no-effect acceptance E2E",
    "required-validation": "validate",
}


def load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def triggers(workflow: dict[str, Any]) -> Any:
    # PyYAML resolves the bare ``on`` key to boolean True.
    return workflow.get("on", workflow.get(True))


def runner_labels(runs_on: Any) -> set[str]:
    if isinstance(runs_on, str):
        return {runs_on}
    if isinstance(runs_on, list):
        return {str(label) for label in runs_on}
    if isinstance(runs_on, dict):
        labels = runs_on.get("labels", [])
        return runner_labels(labels) | {str(runs_on.get("group", ""))}
    return set()


def targets_self_hosted(runs_on: Any) -> bool:
    text = " ".join(sorted(runner_labels(runs_on)))
    return "self-hosted" in text or "middleware-ci" in text


def all_jobs() -> list[tuple[str, str, dict[str, Any]]]:
    jobs = []
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        for job_id, job in (load(path).get("jobs") or {}).items():
            jobs.append((path.name, job_id, job))
    return jobs


def test_governed_expression_uses_exact_labels_and_hosted_fork_fallback() -> None:
    assert '["self-hosted","Linux","X64","middleware-ci"]' in GOVERNED_RUNS_ON
    assert list(GOVERNED_LABELS) == ["self-hosted", "Linux", "X64", "middleware-ci"]
    assert "github.event.pull_request.head.repo.full_name == github.repository" in GOVERNED_RUNS_ON
    assert GOVERNED_RUNS_ON.endswith("|| 'ubuntu-24.04' }}")


def test_every_middleware_ci_job_uses_the_governed_fork_safe_selector() -> None:
    jobs = load(MIDDLEWARE_CI)["jobs"]
    assert set(jobs) == set(MIDDLEWARE_CI_JOB_NAMES)
    for job_id, job in jobs.items():
        assert job["runs-on"] == GOVERNED_RUNS_ON, job_id
        assert job["name"] == MIDDLEWARE_CI_JOB_NAMES[job_id], job_id


def test_required_aggregate_still_fails_closed_on_every_gate() -> None:
    job = load(MIDDLEWARE_CI)["jobs"]["required-validation"]
    assert job["if"] == "always()"
    assert set(job["needs"]) == set(MIDDLEWARE_CI_JOB_NAMES) - {"required-validation"}
    script = job["steps"][0]["run"]
    assert 'test "$result" = success' in script
    assert 'test "$MAIN_RESULT" = skipped' in script
    assert 'test "$MAIN_RESULT" = success' in script


def test_self_hosted_workflow_only_runs_for_trusted_event_types() -> None:
    on = triggers(load(MIDDLEWARE_CI))
    assert set(on) == {"pull_request", "push"}
    assert on["push"] == {"branches": ["main"]}
    for name in SELF_HOSTED_WORKFLOWS:
        assert set(triggers(load(WORKFLOWS / name))) <= {"pull_request", "push"}, name


def test_self_hosted_workflow_keeps_least_privilege_and_no_persisted_credentials() -> None:
    workflow = load(MIDDLEWARE_CI)
    assert workflow["permissions"] == {"contents": "read"}
    for job_id, job in workflow["jobs"].items():
        assert "permissions" not in job, job_id
        for step in job.get("steps", []):
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False, job_id


def test_self_hosted_jobs_do_not_mutate_the_host_or_bind_fixed_ports() -> None:
    source = MIDDLEWARE_CI.read_text(encoding="utf-8")
    for forbidden in ("sudo", "iptables", "127.0.0.1:5432", "127.0.0.1:6379"):
        assert forbidden not in source, forbidden
    for job_id, job in load(MIDDLEWARE_CI)["jobs"].items():
        for service_name, service in (job.get("services") or {}).items():
            for port in service.get("ports", []):
                assert ":" not in str(port), f"{job_id}.{service_name} binds a fixed host port"
    runtime = load(MIDDLEWARE_CI)["jobs"]["runtime-integration"]["steps"][-1]["env"]
    assert "${{ job.services.postgres.ports[5432] }}" in runtime["DATABASE_URL"]
    assert "${{ job.services.redis.ports[6379] }}" in runtime["REDIS_URL"]


@pytest.mark.parametrize(
    ("workflow", "job_id", "job"),
    [pytest.param(*entry, id=f"{entry[0]}:{entry[1]}") for entry in all_jobs()],
)
def test_no_other_workflow_targets_a_self_hosted_runner(
    workflow: str, job_id: str, job: dict[str, Any]
) -> None:
    if workflow in SELF_HOSTED_WORKFLOWS:
        assert job["runs-on"] == GOVERNED_RUNS_ON
        return
    assert not targets_self_hosted(job.get("runs-on")), f"{workflow}:{job_id}"


def test_required_exact_sha_ci_stays_hosted_while_it_mutates_the_host_firewall() -> None:
    # required-ci.yml inserts REJECT rules into the runner's OUTPUT/FORWARD
    # chains. On a persistent host those rules would outlive the job, so the
    # workflow may only move after its egress deny becomes job-scoped.
    source = REQUIRED_CI.read_text(encoding="utf-8")
    assert "sudo -n iptables" in source
    for job_id, job in load(REQUIRED_CI)["jobs"].items():
        assert not targets_self_hosted(job["runs-on"]), job_id
