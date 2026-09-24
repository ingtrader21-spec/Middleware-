from dataclasses import dataclass


@dataclass(frozen=True)
class WebSocketScope:
    user_id: str
    business_unit: str
    campaigns: frozenset[str]
    session_id: str


def authorized(scope: WebSocketScope, *, user_id: str, business_unit: str,
               campaign: str, session_id: str) -> bool:
    return (
        scope.user_id == user_id
        and scope.business_unit == business_unit
        and campaign in scope.campaigns
        and scope.session_id == session_id
    )
