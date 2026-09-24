from __future__ import annotations

import pytest

from app.security import RequestValidationError
from app.webhook_api import route_for_connector_endpoint


def test_kyqra_result_and_progress_endpoints_keep_explicit_contracts() -> None:
    results = route_for_connector_endpoint("kyqra", "results")
    progress = route_for_connector_endpoint("kyqra", "progress")

    assert results.producer_client_id == "kyqra-gateway"
    assert results.required_scope == "crawler.results.publish"
    assert results.event_types == frozenset(
        {
            "codestra.crawler.job.completed",
            "codestra.crawler.result.available",
            "codestra.crawler.result.review_required",
        }
    )

    assert progress.producer_client_id == "kyqra-gateway"
    assert progress.required_scope == "crawler.progress.publish"
    assert progress.event_types == frozenset(
        {
            "codestra.crawler.job.failed",
            "codestra.crawler.job.progress",
        }
    )
    assert "codestra.crawler.job.completed" not in progress.event_types
    assert "codestra.crawler.result.review_required" not in progress.event_types


@pytest.mark.parametrize(
    ("connector", "endpoint"),
    [
        ("kyqra", "events"),
        ("kyqra", "unknown"),
        ("unknown", "results"),
        ("", "results"),
    ],
)
def test_unknown_connector_endpoint_pairs_fail_closed(
    connector: str,
    endpoint: str,
) -> None:
    with pytest.raises(RequestValidationError):
        route_for_connector_endpoint(connector, endpoint)


def test_single_endpoint_connectors_remain_addressable() -> None:
    odoo = route_for_connector_endpoint("odoo", "events")
    telnexa = route_for_connector_endpoint("telnexa", "events")

    assert odoo.producer_client_id == "odoo-integration"
    assert telnexa.producer_client_id == "telnexa-gateway"
