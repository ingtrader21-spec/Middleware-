import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations/versions/0021_async_comm_contract.py"
REQUIRED_CI = ROOT / ".github/workflows/required-ci.yml"


def test_async_communication_migration_chain_and_revision_width():
    tree = ast.parse(MIGRATION.read_text(encoding="utf-8"))
    values = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in {"revision", "down_revision"}
    }
    assert values == {
        "revision": "0021_async_comm_contract",
        "down_revision": "0020_registry_runtime_grants",
    }
    assert len(values["revision"]) <= 32


def test_async_communication_migration_is_provider_neutral_and_fail_closed():
    source = MIGRATION.read_text(encoding="utf-8")
    for field in (
        "command_type",
        "customer_id",
        "destination_token",
        "destination_classification",
        "policy_version",
        "quiet_hours_policy",
        "rate_limit_bucket",
        "cost_limit_bucket",
        "pii_classification",
        "template_variables",
    ):
        assert f'"{field}"' in source
    for state in ("DEFERRED", "BOUNCED", "COMPLAINED", "UNSUBSCRIBED", "UNDELIVERED"):
        assert f'"{state}"' in source
    assert "smtp" not in source.lower()
    assert "twilio" not in source.lower()


def test_required_ci_asserts_the_repository_head_not_a_stale_revision():
    workflow = REQUIRED_CI.read_text(encoding="utf-8")
    assert 'expected_migration_head="$(alembic heads' in workflow
    assert '"0020_registry_runtime_grants"' not in workflow
