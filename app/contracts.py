from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config" / "api-webhook-contracts.json"


@dataclass(frozen=True)
class WebhookRoute:
    producer_client_id: str
    required_scope: str
    path: str
    event_types: frozenset[str]


def load_webhook_routes() -> tuple[WebhookRoute, ...]:
    raw = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    routes = []
    for item in raw["webhooks"]:
        routes.append(
            WebhookRoute(
                producer_client_id=item["producerClientId"],
                required_scope=item["requiredScope"],
                path=item["path"],
                event_types=frozenset(item["eventTypes"]),
            )
        )
    return tuple(routes)


WEBHOOK_ROUTES = load_webhook_routes()
ROUTE_BY_PATH = {route.path: route for route in WEBHOOK_ROUTES}
