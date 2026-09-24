from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "collect_staging_migration_evidence.sh"


def bash_executable() -> str:
    found = shutil.which("bash")
    if found:
        return found
    for candidate in (
        os.path.join(os.environ.get("LOCALAPPDATA", r"C:\Users\Default\AppData\Local"), "Programs", "Git", "bin", "bash.exe"),
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ):
        if os.path.exists(candidate):
            return candidate
    return "bash"


def source() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_shell_syntax_is_valid() -> None:
    subprocess.run([bash_executable(), "-n", str(SCRIPT)], check=True)


def test_default_revision_and_output_are_safe() -> None:
    value = source()
    assert "0053_callback_worker_grants" in value
    assert "OUTPUT_DIR:-/tmp/codestra-migration-evidence-" in value
    assert "umask 077" in value


def test_collector_does_not_query_or_mutate_database() -> None:
    value = source().lower()
    prohibited = [
        "psql ",
        "alembic ",
        "select version_num",
        "update alembic_version",
        "insert into alembic_version",
        "delete from alembic_version",
        "drop table",
        "alter table",
    ]
    for token in prohibited:
        assert token not in value
    assert "database_queries=no" in value


def test_collector_uses_only_read_only_docker_commands() -> None:
    value = source()
    prohibited_patterns = [
        r"\bdocker\s+exec\b",
        r"\bdocker\s+(?:rm|kill|restart|stop|start|pause|unpause|update|commit|cp)\b",
        r"\bdocker\s+compose\s+(?:up|down|restart|stop|start|rm|run|exec)\b",
        r"\bdocker\s+container\s+(?:rm|kill|restart|stop|start|update)\b",
        r"\bdocker\s+image\s+(?:rm|prune|push|pull|tag)\b",
    ]
    for pattern in prohibited_patterns:
        assert re.search(pattern, value) is None, pattern
    assert "docker inspect" in value
    assert "docker image inspect" in value
    assert "docker ps" in value
    assert "CONTAINERS_CHANGED=NO" in value
    assert "CONTAINER_FILES_CHANGED=NO" in value


def test_collector_does_not_dump_container_environment_or_file_contents() -> None:
    value = source()
    assert "docker inspect \"$container\" --format '{{range .Config.Env}}" not in value
    assert "docker exec" not in value
    assert "cat \"$candidate\"" not in value
    assert "grep -IlF" in value
    assert "sha256sum \"$file\"" in value


def test_search_scope_is_operator_bounded_and_discovers_nested_repositories() -> None:
    value = source()
    assert 'SEARCH_ROOTS="${SEARCH_ROOTS:-}"' in value
    assert 'append_search_root "$compose_workdir"' in value
    assert "find \"$root\" -xdev -type f" in value
    assert "discover_git_repositories" in value
    assert "-type d -name .git" in value
    assert "-type f -name .git" in value
    assert 'append_git_repository "$repository"' in value
    assert "DEEP_GIT_SEARCH" in value
    assert "rev-list --all" in value


def test_deep_git_search_treats_status_one_as_normal_no_match() -> None:
    value = source()
    assert 'grep_status=$?' in value
    assert 'if [[ "$grep_status" -ne 1 ]]' in value
    assert 'matches=""' in value
    assert "git grep failed for repository=" in value


def test_evidence_summary_records_no_effect_guarantees() -> None:
    value = source()
    for statement in (
        "DATABASE_QUERIES=NO",
        "CONTAINERS_CHANGED=NO",
        "CONTAINER_FILES_CHANGED=NO",
        "NETWORK_CHANGED=NO",
        "EVIDENCE_OUTPUT_ONLY=YES",
    ):
        assert statement in value
