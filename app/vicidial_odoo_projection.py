from __future__ import annotations

from .vicidial_odoo_projection_config import ProjectionSettings, parse_bool
from .vicidial_odoo_projection_errors import (
    DeterministicRejection,
    KnownNotDelivered,
    OutcomeUnknown,
    ProjectionConfigurationError,
    ProjectionConflict,
    ProjectionError,
)
from .vicidial_odoo_projection_models import (
    AMBIGUOUS_STATUSES,
    CALL_EVENT_PATH,
    CALL_EVENT_STATUS_PATH,
    LIFECYCLE_EVENT_MAP,
    OdooCallEvent,
    canonical_event_body,
    project_envelope,
    sign_call_event,
)
from .vicidial_odoo_projection_state import ProjectionState
from .vicidial_odoo_projection_transport import OdooCallEventDispatcher

__all__ = [
    "AMBIGUOUS_STATUSES",
    "CALL_EVENT_PATH",
    "CALL_EVENT_STATUS_PATH",
    "DeterministicRejection",
    "KnownNotDelivered",
    "LIFECYCLE_EVENT_MAP",
    "OdooCallEvent",
    "OdooCallEventDispatcher",
    "OutcomeUnknown",
    "ProjectionConfigurationError",
    "ProjectionConflict",
    "ProjectionError",
    "ProjectionSettings",
    "ProjectionState",
    "canonical_event_body",
    "parse_bool",
    "project_envelope",
    "sign_call_event",
]
