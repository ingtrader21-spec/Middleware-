from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKUP_SCRIPT = ROOT / "scripts" / "server-a-backup-legacy-middleware-images.sh"


def test_family_operations_are_not_wrapped_in_failure_aggregation_lists() -> None:
    """Bash suppresses errexit inside functions invoked from an ``||`` list."""

    text = BACKUP_SCRIPT.read_text(encoding="utf-8")
    loop = text.split("processed=0", 1)[1]

    assert "failures=0" not in loop
    assert "failures=$((failures + 1))" not in loop
    assert "archive_family" in loop
    assert "mirror_family" in loop
    assert "verify_image_and_workloads" in loop

    # The reviewed implementation invokes each family operation directly so
    # global ``set -Eeuo pipefail`` applies throughout every function body.
    for command in (
        "verify_image_and_workloads",
        "archive_family",
        "mirror_family",
    ):
        assert f"{command} \\" in loop


def test_backup_script_retains_immediate_fail_closed_controls() -> None:
    text = BACKUP_SCRIPT.read_text(encoding="utf-8")

    assert "set -Eeuo pipefail" in text
    assert "MISSING_EXPECTED_WORKLOADS" in text
    assert 'fail "processed_image_family_count_mismatch"' in text
    assert "sha256sum --check --strict SHA256SUMS" in text
