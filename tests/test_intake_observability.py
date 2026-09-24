from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families

from app.main import create_app
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.storage import MemoryInboxStore


class IntakeAndMonitoringTokenVerifier:
    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        from app.security import AuthenticationError

        allowed = {
            ("sdk-intake", "leads.write"): "Bearer intake-lead-token",
            ("sdk-intake", "surveys.write"): "Bearer intake-survey-token",
            ("monitoring-readonly", "metrics.read"): "Bearer metrics-token",
        }
        if allowed.get((expected_client_id, required_scope)) != authorization:
            raise AuthenticationError("invalid test token")
        return {
            "azp": expected_client_id,
            "scope": required_scope,
            "aud": "middleware-api",
            "tenant_id": "tenant-1",
            "sub": expected_client_id,
        }

    async def ready(self) -> bool:
        return True


def _sample_value(
    text: str,
    name: str,
    required_labels: dict[str, str],
) -> float:
    for family in text_string_to_metric_families(text):
        for sample in family.samples:
            if sample.name != name:
                continue
            if all(
                sample.labels.get(key) == value
                for key, value in required_labels.items()
            ):
                return float(sample.value)
    raise AssertionError(f"missing sample {name} with labels {required_labels}")


def _runtime(test_settings) -> Runtime:
    return Runtime(
        settings=test_settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=IntakeAndMonitoringTokenVerifier(),
    )


def _lead_payload(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "tenantId": "tenant-1",
        "siteId": "landing-001",
        "submittedAt": "2026-08-30T11:00:00+00:00",
        "source": "landing_page",
        "formId": "credit-repair-lead-never-a-label",
        "campaignId": "campaign-never-a-label",
        "name": "Private Contact Name",
        "email": "private-contact@example.test",
        "phone": "+18095550123",
        "message": "Private form message that must never enter metrics.",
        "consent": {
            "marketing": True,
            "sms": False,
            "email": True,
            "privacyPolicyVersion": "2026-08-30",
        },
    }
    value.update(updates)
    return value


def _survey_payload(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "tenantId": "tenant-1",
        "siteId": "landing-001",
        "submittedAt": "2026-08-30T11:01:00+00:00",
        "source": "form",
        "surveyId": "nps-private-survey-id",
        "surveyVersion": "1.0",
        "surveyCategory": "nps",
        "anonymous": True,
        "answers": {
            "score": 9,
            "free_text": "Private survey answer that must never enter metrics.",
        },
    }
    value.update(updates)
    return value


def _headers(token: str, scope: str, key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": "tenant-1",
        "X-Correlation-ID": f"correlation-{scope}",
        "Idempotency-Key": key,
        "Content-Type": "application/json",
    }


def test_metrics_report_real_intake_outcomes_and_aggregate_backlog(
    test_settings,
) -> None:
    app = create_app(settings=test_settings, runtime=_runtime(test_settings))
    lead_headers = _headers("intake-lead-token", "lead", "lead-metrics-key-001")
    survey_headers = _headers(
        "intake-survey-token",
        "survey",
        "survey-metrics-key-001",
    )

    with TestClient(app) as client:
        accepted_lead = client.post(
            "/v1/intake/leads",
            json=_lead_payload(),
            headers=lead_headers,
        )
        duplicate_lead = client.post(
            "/v1/intake/leads",
            json=_lead_payload(),
            headers=lead_headers,
        )
        invalid_headers = {
            **lead_headers,
            "Idempotency-Key": "lead-metrics-key-002",
        }
        invalid_lead = client.post(
            "/v1/intake/leads",
            json=_lead_payload(unexpected=True),
            headers=invalid_headers,
        )
        accepted_survey = client.post(
            "/v1/intake/surveys/responses",
            json=_survey_payload(),
            headers=survey_headers,
        )
        duplicate_survey = client.post(
            "/v1/intake/surveys/responses",
            json=_survey_payload(),
            headers=survey_headers,
        )
        metrics = client.get(
            "/metrics",
            headers={"Authorization": "Bearer metrics-token"},
        )

    assert accepted_lead.status_code == 202
    assert duplicate_lead.status_code == 200
    assert invalid_lead.status_code == 400
    assert accepted_survey.status_code == 202
    assert duplicate_survey.status_code == 200
    assert metrics.status_code == 200

    base = {
        "codestra_business": "platform",
        "application": "integration",
        "service": "middleware-api",
        "environment": "test",
    }
    lead = {**base, "channel": "landing_page", "form_kind": "configured"}
    survey = {
        **base,
        "channel": "form",
        "survey_kind": "nps",
        "anonymous": "true",
    }
    assert _sample_value(
        metrics.text,
        "lead_submissions_total",
        {**lead, "result": "accepted"},
    ) == 1
    assert _sample_value(
        metrics.text,
        "lead_submissions_total",
        {**lead, "result": "duplicate"},
    ) == 1
    assert _sample_value(
        metrics.text,
        "lead_duplicates_total",
        lead,
    ) == 1
    assert _sample_value(
        metrics.text,
        "lead_validation_failures_total",
        {
            **base,
            "channel": "unknown",
            "form_kind": "unknown",
            "reason": "invalid_contract",
        },
    ) == 1
    assert _sample_value(
        metrics.text,
        "survey_responses_total",
        {**survey, "result": "accepted"},
    ) == 1
    assert _sample_value(
        metrics.text,
        "survey_responses_total",
        {**survey, "result": "duplicate"},
    ) == 1
    assert _sample_value(metrics.text, "intake_inbox_backlog", base) == 2
    assert _sample_value(
        metrics.text,
        "intake_outbox_backlog",
        {**base, "delivery_target": "nats-jetstream"},
    ) == 2
    assert _sample_value(
        metrics.text,
        "intake_backlog_collection_success",
        base,
    ) == 1

    forbidden_values = (
        "tenant-1",
        "credit-repair-lead-never-a-label",
        "campaign-never-a-label",
        "Private Contact Name",
        "private-contact@example.test",
        "+18095550123",
        "Private form message",
        "nps-private-survey-id",
        "Private survey answer",
    )
    assert all(value not in metrics.text for value in forbidden_values)


def test_metrics_endpoint_remains_private(test_settings) -> None:
    app = create_app(settings=test_settings, runtime=_runtime(test_settings))
    with TestClient(app) as client:
        missing = client.get("/metrics")
        wrong_identity = client.get(
            "/metrics",
            headers={"Authorization": "Bearer intake-lead-token"},
        )

    assert missing.status_code == 401
    assert wrong_identity.status_code == 401
