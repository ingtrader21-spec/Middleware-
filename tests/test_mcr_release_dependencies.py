"""MCR-M convergence tests: evidence cannot pass before upstream lanes are integrated."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_mcr_dependency_artifacts_are_integrated() -> None:
    required = (
        "agent_desktop/src/features/lead/LeadJourney.tsx",
        "contracts/campaign-recycling/odoo-handoff-authority.v1.json",
        "contracts/campaign-recycling/post-acceptance-automation.v1.json",
        "docs/operations/mcr-observability.md",
    )
    missing = [path for path in required if not (ROOT / path).is_file()]
    assert not missing, f"MCR dependency artifacts not integrated: {missing}"


def test_mcr_lead_journey_ui_states_are_integrated() -> None:
    path = ROOT / "agent_desktop/src/features/lead/LeadJourney.tsx"
    assert path.is_file(), "MCR-B Lead Journey UI is not integrated"
    text = path.read_text(encoding="utf-8")
    for marker in (
        "Loading lead journey",
        "Retry journey",
        "Next action unavailable",
        "No channel-health evidence",
        "No lifecycle or exposure history",
        "Read-only decision; no outreach is triggered",
    ):
        assert marker in text


def test_mcr_rollback_readback_is_integrated() -> None:
    path = ROOT / "docs/operations/mcr-observability.md"
    assert path.is_file(), "MCR-L rollback/readback runbook is not integrated"
    text = path.read_text(encoding="utf-8").lower()
    assert "rollback" in text
    assert "readback" in text
