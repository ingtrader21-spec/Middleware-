from scripts import reconcile_staging_schema_contract as target


def test_reconciler_is_exactly_bounded_to_four_known_constraints():
    assert target.TARGET_DATABASE == "middleware_staging"
    assert target.TARGET_HEAD == "0067_service_catalog_monitoring_state"
    assert target.CONSTRAINTS == (
        (
            "campaign_design_current",
            "ck_campaign_current_lifecycle",
            "lifecycle_state IN ('approval_pending','approved')",
        ),
        (
            "campaign_design_failure",
            "ck_campaign_failure_status",
            "status IN ('retry','dead_letter')",
        ),
        (
            "campaign_design_revision",
            "ck_campaign_design_approval",
            "approval_state IN ('preview','approved')",
        ),
        (
            "campaign_event_inbox",
            "ck_campaign_inbox_state",
            "processing_state IN ('processing','completed')",
        ),
    )


def test_default_mode_is_non_mutating_by_contract():
    source = open(target.__file__, encoding="utf-8").read()
    assert 'parser.add_argument("--apply", action="store_true")' in source
    assert "if not apply:" in source
    assert "STAGING_SCHEMA_CONTRACT_APPLY=NO" in source
    assert "ALEMBIC_HEAD_UNCHANGED=" in source
