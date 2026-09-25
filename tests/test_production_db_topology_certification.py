"""PAS-95 (DB-18) production-shaped database topology certification.

Static tests bind the disposable topology spec to the repository authorities
it claims to mirror, pin the harness safety guards, and validate the recorded
evidence. The live run (Docker, locally built RC image) is opt-in:

    PAS95_LIVE_DB_TOPOLOGY=1 PAS95_RC_IMAGE=<local rc tag> pytest tests/test_production_db_topology_certification.py
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import certify_production_db_topology as harness_module
from scripts.production_migration_authority import validate_authority

ROOT = Path(__file__).resolve().parents[1]
TOPOLOGY = ROOT / "scripts" / "production_db_topology"
SPEC = json.loads((TOPOLOGY / "topology.v1.json").read_text(encoding="utf-8"))
EVIDENCE_DIR = ROOT / "docs" / "evidence" / "pas95-production-db-topology-20260924"
EVIDENCE_PATH = EVIDENCE_DIR / "certification-run.v1.json"
BACKUP_SCRIPT = ROOT / SPEC["backup"]["script"]


def _profiles() -> dict[str, dict]:
    data = json.loads((ROOT / "config" / "runtime-profiles.v1.json").read_text(encoding="utf-8"))
    return {item["profile_id"]: item for item in data["profiles"]}


def _evidence() -> dict:
    return json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))


# ------------------------------------------------------------ spec bindings


def test_spec_binds_the_locked_production_profile():
    profile = _profiles()[SPEC["runtime_profile_id"]]
    database = profile["database"]
    assert profile["environment"] == "production"
    assert profile["production_activation_allowed"] is True
    assert SPEC["database"]["host"] == database["host"]
    assert SPEC["database"]["port"] == database["port"]
    assert SPEC["database"]["name"] == database["name"]
    assert SPEC["roles"]["api"] == database["username"]
    assert database["sslmode"] == "verify-full"
    assert SPEC["secret_mounts"]["prefix"] == profile["secret_path_prefix"]
    for key in ("database_url", "ca_certificate", "client_certificate", "client_key"):
        assert SPEC["secret_mounts"][key].startswith(profile["secret_path_prefix"])


def test_spec_negative_aliases_include_the_canary_compose_host():
    compose = _profiles()[SPEC["compose_profile_id"]]["database"]
    assert compose["host"] in SPEC["database"]["network_aliases_for_negative_checks"]
    assert compose["sslmode"] is None  # PAS-78 F-03, exercised by the live run


def test_spec_release_candidate_matches_migration_authority():
    expected, _graph, _digest = validate_authority(ROOT)
    rc = SPEC["release_candidate"]
    assert rc["schema_head"] == expected
    assert rc["core_sql_receipts"] == len(list((ROOT / "migrations").glob("[0-9][0-9][0-9][0-9]_*.sql")))
    assert rc["automation_sql_receipts"] == len(
        list((ROOT / "migrations" / "automation").glob("[0-9][0-9][0-9][0-9]_*.sql"))
    )
    canary = (ROOT / SPEC["canary_compose"]).read_text(encoding="utf-8")
    assert f"SCHEMA_HEAD: {rc['schema_head']}" in canary
    dockerfile = (ROOT / rc["dockerfile"]).read_text(encoding="utf-8")
    assert f"FROM runtime-common AS {rc['target']}" in dockerfile
    assert f"USER {rc['runtime_user']}" in dockerfile
    assert f'user: "{rc["runtime_user"]}"' in canary


def test_spec_pools_match_the_rc_code():
    from app.core import runtime
    from app.core.config import Settings

    pools = SPEC["pools"]
    assert pools["asyncpg_pool"] == {
        "min_size": runtime.SHARED_POOL_MIN_SIZE,
        "max_size": runtime.SHARED_POOL_MAX_SIZE,
        "command_timeout_seconds": runtime.SHARED_POOL_COMMAND_TIMEOUT_SECONDS,
    }
    fields = Settings.model_fields
    engine = pools["sqlalchemy_engine"]
    assert engine["pool_size"] == fields["database_pool_size"].default
    assert engine["max_overflow"] == fields["database_max_overflow"].default
    assert engine["pool_timeout_seconds"] == fields["database_pool_timeout_seconds"].default
    assert engine["pool_recycle_seconds"] == fields["database_pool_recycle_seconds"].default
    assert engine["command_timeout_seconds"] == fields["database_command_timeout_seconds"].default
    canary = (ROOT / SPEC["canary_compose"]).read_text(encoding="utf-8")
    assert f"--workers={pools['api_uvicorn_workers']}" in canary


def test_spec_monitoring_matches_repository_exporter_and_rules():
    monitoring = SPEC["monitoring"]
    compose = (ROOT / monitoring["exporter_compose"]).read_text(encoding="utf-8")
    assert f"image: {monitoring['exporter_image']}" in compose
    rules = (ROOT / monitoring["rules_file"]).read_text(encoding="utf-8")
    for alert in monitoring["alerts"]:
        assert f"alert: {alert}" in rules


def test_spec_rls_tables_match_the_forcing_migration():
    source = (ROOT / "migrations" / "versions" / "0052_callback_rls_hardening.py").read_text(encoding="utf-8")
    assert "FORCE ROW LEVEL SECURITY" in source
    for table in SPEC["rls"]["forced_tables"]:
        assert f'"{table}"' in source


def test_spec_effect_counters_are_zero():
    assert SPEC["effects"] == {
        "PRODUCTION_DATABASE_MUTATIONS": 0,
        "PROVIDER_EFFECTS": 0,
        "PRODUCTION_EFFECTS": 0,
    }


# ------------------------------------------------------- topology artefacts


def test_pg_hba_admits_only_certificate_bound_tls_logins():
    lines = [
        line.split()
        for line in (TOPOLOGY / "pg_hba.conf").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    hostssl_users = set()
    for fields in lines:
        kind = fields[0]
        assert "trust" not in fields and "password" not in fields and "md5" not in fields
        if kind == "local":
            assert fields[2] == "postgres" and fields[3] == "peer"
        elif kind == "hostssl":
            assert fields[1] == SPEC["database"]["name"]
            assert fields[4:] == ["scram-sha-256", "clientcert=verify-full", "clientname=CN"]
            hostssl_users.add(fields[2])
        else:
            assert kind == "host" and fields[-1] == "reject", fields
    assert hostssl_users == set(SPEC["roles"]["login"])
    assert "postgres" not in hostssl_users
    # Rejection lines come last so no network path precedes them.
    assert [fields[0] for fields in lines][-2:] == ["host", "host"]


def test_bootstrap_roles_are_least_privilege_and_carry_no_passwords():
    sql = (TOPOLOGY / "bootstrap_roles.sql").read_text(encoding="utf-8")
    statements = re.findall(r"CREATE ROLE (\w+) (.*?);", sql, flags=re.S)
    created = {name: " ".join(body.split()) for name, body in statements}
    for role in SPEC["roles"]["login"]:
        body = created[role]
        assert "LOGIN" in body and "NOSUPERUSER" in body and "NOBYPASSRLS" in body
        assert "NOCREATEDB" in body and "NOCREATEROLE" in body and "NOREPLICATION" in body
        assert f"PASSWORD :'pw_{role}'" in body
    for role in (*SPEC["roles"]["migration_grant_roles"], SPEC["roles"]["runtime_grant_role"]):
        assert "NOLOGIN" in created[role] and "NOBYPASSRLS" in created[role]
    for role in SPEC["roles"]["runtime"]:
        assert SPEC["roles"]["runtime_grant_role"] in created[role]
    assert f"OWNER {SPEC['roles']['migration']}" in sql
    assert "PASSWORD '" not in sql


def test_runtime_grants_are_dml_only():
    sql = (TOPOLOGY / "grant_runtime.sql").read_text(encoding="utf-8")
    body = "\n".join(line for line in sql.splitlines() if not line.lstrip().startswith("--"))
    for forbidden in ("TRUNCATE", "REFERENCES", "TRIGGER", "ALL PRIVILEGES", "OWNER TO", "BYPASSRLS", "SUPERUSER"):
        assert forbidden not in body
    assert "SET ROLE middleware_migration;" in body and "RESET ROLE;" in body


def test_probe_carries_the_pas96_role_isolation_query():
    probe = (TOPOLOGY / "rc_probe.py").read_text(encoding="utf-8")
    for column in (
        "elevated_role_memberships",
        "owned_public_tables",
        "owned_rls_tables_without_force",
        "forced_rls_tables",
        "public_schema_create",
    ):
        assert f"AS {column}" in probe
    for verb in ("INSERT", "UPDATE ", "DELETE", "ALTER", "DROP", "GRANT"):
        start = probe.index("ROLE_ISOLATION_QUERY = ")
        query = probe[start : probe.index('"""', probe.index('"""', start) + 3)]
        assert verb not in query.upper().replace("'CREATE'", "")


# ------------------------------------------------------------ harness safety


def _harness(tmp_path, monkeypatch) -> harness_module.Harness:
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    args = argparse.Namespace(
        rc_image="unused", source_sha=None, postgres_image=None,
        backup_helper_image="unused", output=tmp_path / "out.json",
    )
    return harness_module.Harness(args)


def test_harness_rejects_any_connection_target_outside_its_resources(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    try:
        assert harness.target(SPEC["database"]["host"]) == SPEC["database"]["host"]
        for foreign in ("codestra-postgres-1.example.com", "10.0.0.5", "postgresql.middleware-staging.svc.cluster.local", "localhost"):
            with pytest.raises(harness_module.HarnessError):
                harness.target(foreign)
    finally:
        shutil.rmtree(harness.workdir, ignore_errors=True)


def test_harness_refuses_remote_docker_and_database_variables(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    try:
        monkeypatch.setenv("DOCKER_HOST", "tcp://10.0.0.5:2376")
        with pytest.raises(harness_module.HarnessError, match="local unix socket"):
            harness.assert_local_docker()
        monkeypatch.delenv("DOCKER_HOST")
        monkeypatch.setattr(
            harness, "docker",
            lambda *a, **k: subprocess.CompletedProcess(a, 0, b"unix:///var/run/docker.sock\n", b""),
        )
        monkeypatch.setenv("DATABASE_URL", "postgresql://x@production/db")
        with pytest.raises(harness_module.HarnessError, match="DATABASE_URL"):
            harness.assert_local_docker()
    finally:
        shutil.rmtree(harness.workdir, ignore_errors=True)


def test_harness_source_never_publishes_ports_or_uses_egress_networks():
    source = (ROOT / "scripts" / "certify_production_db_topology.py").read_text(encoding="utf-8")
    assert '"network", "create", "--internal"' in source
    assert '"-p"' not in source and "--publish" not in source
    assert '"--network", "host"' not in source
    assert "docker push" not in source and '"push"' not in source
    # Every created resource carries the run label that teardown selects on.
    creations = re.findall(r'self\.docker\(\s*"(?:run"|volume",\s*"create"|network",\s*"create")[^)]*', source)
    assert len(creations) >= 8
    for create in creations:
        assert "self.labels" in create, create


def test_evidence_scrubber_refuses_secret_material():
    with pytest.raises(harness_module.HarnessError):
        harness_module.assert_evidence_clean('{"x": "abc123secret"}', ["abc123secret"])
    with pytest.raises(harness_module.HarnessError):
        harness_module.assert_evidence_clean("-----BEGIN PRIVATE KEY-----", [])
    harness_module.assert_evidence_clean('{"ok": true}', ["abc123secret"])


# ----------------------------------------------------------------- evidence


def test_recorded_run_holds_every_effect_at_zero_and_left_nothing_behind():
    evidence = _evidence()
    assert evidence["issue"] == "PAS-95" and evidence["gate"] == "DB-18"
    assert evidence["harness_error"] is None
    assert evidence["effects"] == SPEC["effects"]
    assert evidence["residual"] == {"containers": 0, "volumes": 0, "networks": 0, "pki_workdir": 0}
    statuses = {check["id"]: check["status"] for check in evidence["checks"]}
    assert statuses["effects.network_has_no_egress"] == "PASS"
    assert statuses["effects.connection_targets_disposable"] == "PASS"
    assert statuses["effects.no_row_changes_during_runtime_phase"] == "PASS"
    assert statuses["effects.canary_flags_off"] == "PASS"
    assert statuses["effects.teardown_residual_zero"] == "PASS"


def test_recorded_run_is_bound_to_the_current_spec_and_rc():
    evidence = _evidence()
    spec_bytes = (TOPOLOGY / "topology.v1.json").read_bytes()
    import hashlib

    assert evidence["topology_spec_sha256"] == hashlib.sha256(spec_bytes).hexdigest()
    rc = evidence["observations"]["release_candidate"]
    assert rc["oci_revision"] == rc["source_sha"]
    assert re.fullmatch(r"[0-9a-f]{40}", rc["source_sha"])
    # Local build, never pushed: no digest may name a registry.
    assert not any("/" in digest.split("@", 1)[0] for digest in rc["registry_digests"])


def test_recorded_run_statuses_are_consistent_and_explained():
    evidence = _evidence()
    blockers = {item[1] for item in harness_module.RUNTIME_ONLY_BLOCKERS}
    order = {"PASS": 0, "INFO": 0, "BLOCKED": 1, "FAIL": 2}
    summary: dict[str, str] = {}
    for check in evidence["checks"]:
        assert check["status"] in harness_module.STATUSES
        if check["status"] in {"FAIL", "BLOCKED"}:
            assert check.get("note") or check["id"] in blockers, check["id"]
        current = summary.get(check["area"], "PASS")
        summary[check["area"]] = max(current, check["status"], key=order.__getitem__)
    assert summary == evidence["area_summary"]
    assert blockers <= {check["id"] for check in evidence["checks"]}
    expected = "FAIL" if "FAIL" in summary.values() else "BLOCKED" if "BLOCKED" in summary.values() else "PASS"
    assert evidence["verdict"] == expected


def test_recorded_run_contains_no_credentials():
    text = EVIDENCE_PATH.read_text(encoding="utf-8")
    assert "PRIVATE KEY" not in text
    assert not re.search(r"postgres(?:ql)?(?:\+asyncpg)?://[^\s\"'/]*:[^\s\"'@/]+@", text.replace(":placeholder@", "@"))
    assert not re.search(r"\b[0-9a-f]{48}\b", text)  # generated passwords are 48 hex chars


def test_recorded_run_proves_the_production_shaped_security_model():
    statuses = {check["id"]: check["status"] for check in _evidence()["checks"]}
    for role in SPEC["roles"]["login"]:
        assert statuses[f"mtls.accept.{role}"] == "PASS"
        assert statuses[f"isolation.{role}"] == "PASS"
    for rejected in (
        "plaintext_sslmode_disable",
        "tls_without_client_certificate",
        "client_certificate_cn_of_another_role",
        "client_certificate_from_untrusted_ca",
        "expired_client_certificate",
        "server_hostname_not_in_certificate",
        "superuser_over_network",
        "compose_profile_as_shipped_dsn",
    ):
        assert statuses[f"reject.{rejected}"] == "PASS"
    for check_id in (
        "migration.apply_1",
        "migration.apply_2_idempotent",
        "migration.verify_only",
        "receipts.readback",
        "roles.runtime_role_cannot_migrate",
        "rls.other_tenant_isolated",
        "rls.cross_tenant_insert_rejected",
        "rls.schema_owner_subject_to_force",
        "api.readiness",
        "api.no_mutation_routes",
        "monitoring.exporter_mtls_scrape",
        "restore.table_and_row_parity",
    ):
        assert statuses[check_id] == "PASS", check_id


# ------------------------------------------------ defects pinned by this lane


@pytest.mark.xfail(strict=True, reason="PAS-95 F-A: backup script passes '-' to pg_restore (opened as a file)")
def test_backup_script_reads_the_dump_from_stdin():
    script = BACKUP_SCRIPT.read_text(encoding="utf-8")
    assert "pg_restore --list - <" not in script
    assert not re.search(r"^\s+- <\"\$final_path\"", script, flags=re.M)


def test_backup_corrections_match_the_recorded_defect_exactly_once():
    script = BACKUP_SCRIPT.read_bytes()
    for old, _new in harness_module.Harness.STDIN_CORRECTIONS:
        assert script.count(old) in {0, 1}


@pytest.mark.xfail(strict=True, reason="PAS-78 F-01/F-02: locked profile rejects every mTLS-capable DSN")
def test_production_profile_admits_a_client_certificate_dsn():
    from app.core.config import Settings

    database = _profiles()[SPEC["runtime_profile_id"]]["database"]
    prefix = SPEC["secret_mounts"]["prefix"]
    dsn = (
        f"postgresql://{database['username']}:x@{database['host']}:{database['port']}/{database['name']}"
        f"?sslmode=verify-full&sslrootcert={prefix}db-ca.crt&sslcert={prefix}db-client.crt&sslkey={prefix}db-client.key"
    )
    Settings.model_construct(database_url=dsn)._validate_database_profile(database)


# --------------------------------------------------------------- live (opt-in)


@pytest.mark.skipif(
    os.environ.get("PAS95_LIVE_DB_TOPOLOGY") != "1" or not os.environ.get("PAS95_RC_IMAGE"),
    reason="live disposable topology run is opt-in (Docker + locally built RC image)",
)
def test_live_disposable_topology_run(tmp_path):
    output = tmp_path / "run.json"
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "certify_production_db_topology.py"),
         "--rc-image", os.environ["PAS95_RC_IMAGE"], "--output", str(output)],
        capture_output=True, text=True, timeout=1800,
    )
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert evidence["effects"] == SPEC["effects"]
    assert not any(evidence["residual"].values())
