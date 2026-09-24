from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_normal_beyvra_email_startup_cannot_mutate_schema() -> None:
    runtime = (ROOT / "app/email/runtime.py").read_text()
    assert "create_all" not in runtime
    assert "seed_templates" not in runtime
    assert '@app.on_event("startup")' not in runtime


def test_schema_mutation_is_one_shot_and_backup_gated() -> None:
    schema = (ROOT / "app/email/schema.py").read_text()
    assert schema.count("Base.metadata.create_all(engine)") == 1
    assert 'BEYVRA_EMAIL_MIGRATION_AUTHORIZED' in schema
    assert 'BEYVRA_EMAIL_PREDEPLOY_BACKUP_ID' in schema
    assert 'inspect(engine).get_table_names()' in schema
    assert 'BEYVRA_EMAIL_ONE_SHOT_MIGRATION=PASS' in schema


def test_compose_keeps_migration_out_of_normal_startup() -> None:
    compose = (ROOT / "deploy/beyvra-email/compose.yaml").read_text()
    migration = compose.split("  migrate:\n", 1)[1].split("secrets:\n", 1)[0]
    assert "profiles: [migration]" in migration
    assert 'restart: "no"' in migration
    assert "command: [python, -m, app.email.schema]" in migration
    assert "BEYVRA_EMAIL_MIGRATION_AUTHORIZED:-false" in migration
    assert "BEYVRA_EMAIL_PREDEPLOY_BACKUP_ID:-" in migration
