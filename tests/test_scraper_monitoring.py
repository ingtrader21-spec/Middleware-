from pathlib import Path


def test_scraper_alerts_have_threshold_owner_and_runbook() -> None:
    alerts = Path("monitoring/middleware-alerts.yaml").read_text()
    for name in (
        "CodestraScraperInboxBacklog",
        "CodestraScraperOldestPending",
        "CodestraScraperDeadLetter",
        "CodestraScraperAuthenticationFailures",
        "CodestraScraperRedisErrors",
    ):
        block = alerts.split(f"alert: {name}", 1)[1].split("- alert:", 1)[0]
        assert "for:" in block
        assert "owner:" in block
        assert "environment: production-readiness" in block
        assert "runbook_url:" in block


def test_scraper_alert_transition_matrix_is_present() -> None:
    matrix = Path("monitoring/scraper-alerts.test.yaml").read_text()
    for name in (
        "CodestraScraperInboxBacklog",
        "CodestraScraperOldestPending",
        "CodestraScraperDeadLetter",
        "CodestraScraperAuthenticationFailures",
        "CodestraScraperRedisErrors",
    ):
        matching = [
            block.split("- eval_time:", 1)[0]
            for block in matrix.split(f"alertname: {name}")[1:]
        ]
        assert len(matching) == 2, name
        assert any("exp_alerts:\n          -" in block for block in matching), name
        assert any("exp_alerts: []" in block for block in matching), name
