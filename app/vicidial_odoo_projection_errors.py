from __future__ import annotations


class ProjectionError(RuntimeError):
    pass


class ProjectionConfigurationError(ProjectionError):
    pass


class ProjectionConflict(ProjectionError):
    pass


class OutcomeUnknown(ProjectionError):
    pass


class KnownNotDelivered(ProjectionError):
    pass


class DeterministicRejection(ProjectionError):
    pass
