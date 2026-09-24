"""Registry-backed Odoo delivery client.

This adapter owns Odoo endpoint contracts only; URL, credential, TLS, retry,
and idempotency policy remain owned by the common service client and registry.
"""

from dataclasses import dataclass
from typing import Any

import httpx

from app.core.endpoint_registry import ResolutionRequest
from app.core.service_client import CommonServiceClient


ODOO_SERVICE_KEY = "odoo"
ODOO_ENDPOINTS = {
    "outbox.claim": "odoo.outbox.claim",
    "outbox.read": "odoo.outbox.read",
    "outbox.renew": "odoo.outbox.renew",
    "outbox.acknowledge": "odoo.outbox.acknowledge",
    "outbox.fail": "odoo.outbox.fail",
    "outbox.release": "odoo.outbox.release",
    "results.create": "odoo.results.create",
    "results.read": "odoo.results.read",
    "results.by_delivery": "odoo.results.by_delivery",
    "automation_results.apply": "odoo.automation_results.apply",
    "provider_activities.create": "odoo.provider_activities.create",
    "campaign.actual_state.write": "odoo.campaign.actual_state.write",
    "desired_state.read": "odoo.desired_state.read",
    "agents.read": "odoo.agents.read",
    "leads.read": "odoo.leads.read",
    "campaigns.read": "odoo.campaigns.read",
    "traces.read": "odoo.traces.read",
    "telephony.projections.read": "odoo.telephony.projections.read",
    "telephony.mappings.read": "odoo.telephony.mappings.read",
    "reconciliation.runs.read": "odoo.reconciliation.runs.read",
    "reconciliation.drifts.read": "odoo.reconciliation.drifts.read",
    "sales.lookup": "odoo.sales.lookup",
    "sales.verification.read": "odoo.sales.verification.read",
    "observability.kpis.create": "odoo.observability.kpis.create",
    "observability.incidents.upsert": "odoo.observability.incidents.upsert",
    "observability.kpis.read": "odoo.observability.kpis.read",
    "observability.incidents.read": "odoo.observability.incidents.read",
    "observability.sync.read": "odoo.observability.sync.read",
}

ODOO_READ_OPERATIONS = frozenset(
    {
        "outbox.read",
        "results.read",
        "results.by_delivery",
        "desired_state.read",
        "agents.read",
        "leads.read",
        "campaigns.read",
        "traces.read",
        "telephony.projections.read",
        "telephony.mappings.read",
        "reconciliation.runs.read",
        "reconciliation.drifts.read",
        "sales.lookup",
        "sales.verification.read",
        "observability.kpis.read",
        "observability.incidents.read",
        "observability.sync.read",
    }
)


class OdooDeliveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class OdooDeliveryClient:
    service_client: CommonServiceClient
    environment: str
    organization_public_id: str = ""
    business_unit_public_id: str = ""
    campaign_public_id: str = ""

    async def aclose(self) -> None:
        await self.service_client.aclose()

    async def request(
        self,
        operation: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str,
        request_id: str,
        correlation_id: str,
        causation_id: str,
        traceparent: str,
        tracestate: str = "",
    ) -> httpx.Response:
        endpoint_key = ODOO_ENDPOINTS.get(operation)
        if endpoint_key is None:
            raise OdooDeliveryError("unknown Odoo endpoint operation")
        route = ResolutionRequest(
            environment=self.environment,
            service_key=ODOO_SERVICE_KEY,
            endpoint_key=endpoint_key,
            api_version="v1",
            organization_public_id=self.organization_public_id,
            business_unit_public_id=self.business_unit_public_id,
            campaign_public_id=self.campaign_public_id,
            mutation=operation not in ODOO_READ_OPERATIONS,
        )
        return await self.service_client.request(
            route,
            payload,
            idempotency_key=idempotency_key,
            request_id=request_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            traceparent=traceparent,
            tracestate=tracestate,
        )
