from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

from .storage import MemoryInboxStore, PostgresInboxStore, StorageError


CODESTRA_BUSINESS: Final = "platform"
APPLICATION: Final = "integration"
SERVICE: Final = "middleware-api"
INTAKE_EVENT_TYPES: Final = (
    "codestra.events.lead_submitted",
    "codestra.events.survey_response_submitted",
)
ALLOWED_CHANNELS: Final = {
    "form",
    "landing_page",
    "chat",
    "voice",
    "api",
    "other",
}
ALLOWED_SURVEY_KINDS: Final = {
    "csat",
    "nps",
    "post_call",
    "post_service",
    "qualification",
    "nonprofit_impact",
    "other",
}
SURVEY_KIND_ALIASES: Final = {
    "customer_satisfaction": "csat",
    "customer_satisfaction_score": "csat",
    "net_promoter_score": "nps",
    "postcall": "post_call",
    "postservice": "post_service",
    "non_profit_impact": "nonprofit_impact",
}
ALLOWED_DESTINATIONS: Final = {
    "nats-jetstream",
    "odoo-19",
    "analytics",
    "other",
}


@dataclass(frozen=True)
class IntakeBacklogSnapshot:
    inbox_backlog: int
    outbox_backlog: dict[str, int]
    oldest_pending_seconds: dict[str, float]


def _bounded_channel(value: str) -> str:
    return value if value in ALLOWED_CHANNELS else "unknown"


def _bounded_form_kind(value: str) -> str:
    return value if value in {"configured", "generic"} else "unknown"


def _bounded_survey_kind(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    normalized = SURVEY_KIND_ALIASES.get(normalized, normalized)
    return normalized if normalized in ALLOWED_SURVEY_KINDS else "other"


def _bounded_anonymous(value: str) -> str:
    return value if value in {"true", "false"} else "unknown"


def _bounded_destination(value: str) -> str:
    return value if value in ALLOWED_DESTINATIONS else "other"


async def collect_intake_backlog(inbox: object) -> IntakeBacklogSnapshot:
    """Read aggregate intake queue state without tenant or customer dimensions."""

    if isinstance(inbox, MemoryInboxStore):
        count = sum(
            1
            for record in inbox.ledger_records
            if record.payload.get("event_type") in INTAKE_EVENT_TYPES
        )
        return IntakeBacklogSnapshot(
            inbox_backlog=count,
            outbox_backlog={"nats-jetstream": count},
            oldest_pending_seconds={"inbox": 0.0, "outbox:nats-jetstream": 0.0},
        )

    if not isinstance(inbox, PostgresInboxStore):
        return IntakeBacklogSnapshot(
            inbox_backlog=0,
            outbox_backlog={},
            oldest_pending_seconds={"inbox": 0.0},
        )

    try:
        async with inbox.pool.acquire() as conn:
            inbox_row = await conn.fetchrow(
                """
                SELECT count(*)::bigint AS pending,
                       COALESCE(
                         GREATEST(
                           EXTRACT(EPOCH FROM (now() - min(received_at))),
                           0
                         ),
                         0
                       )::double precision AS oldest_seconds
                FROM middleware_inbox
                WHERE event_type = ANY($1::text[])
                  AND processed_at IS NULL
                  AND status IN ('accepted', 'processing', 'failed')
                """,
                list(INTAKE_EVENT_TYPES),
            )
            outbox_rows = await conn.fetch(
                """
                SELECT destination,
                       count(*)::bigint AS pending,
                       COALESCE(
                         GREATEST(
                           EXTRACT(EPOCH FROM (now() - min(created_at))),
                           0
                         ),
                         0
                       )::double precision AS oldest_seconds
                FROM middleware_outbox
                WHERE event_type = ANY($1::text[])
                  AND completed_at IS NULL
                  AND dead_lettered_at IS NULL
                GROUP BY destination
                ORDER BY destination
                """,
                list(INTAKE_EVENT_TYPES),
            )
    except Exception as exc:
        raise StorageError("intake backlog metrics are unavailable") from exc

    outbox: dict[str, int] = {}
    oldest: dict[str, float] = {
        "inbox": float(inbox_row["oldest_seconds"] if inbox_row else 0.0),
    }
    for row in outbox_rows:
        destination = _bounded_destination(str(row["destination"]))
        outbox[destination] = outbox.get(destination, 0) + int(row["pending"])
        oldest[f"outbox:{destination}"] = max(
            oldest.get(f"outbox:{destination}", 0.0),
            float(row["oldest_seconds"]),
        )
    return IntakeBacklogSnapshot(
        inbox_backlog=int(inbox_row["pending"] if inbox_row else 0),
        outbox_backlog=outbox,
        oldest_pending_seconds=oldest,
    )


class IntakeMetrics:
    """Low-cardinality form and survey metrics owned by Middleware."""

    def __init__(self, registry: CollectorRegistry, environment: str) -> None:
        base_labels = ("codestra_business", "application", "service", "environment")
        self._base = (CODESTRA_BUSINESS, APPLICATION, SERVICE, environment)
        self.lead_submissions = Counter(
            "lead_submissions_total",
            "Canonical lead intake requests by bounded outcome.",
            (*base_labels, "channel", "form_kind", "result"),
            registry=registry,
        )
        self.lead_duplicates = Counter(
            "lead_duplicates_total",
            "Canonical duplicate lead submissions.",
            (*base_labels, "channel", "form_kind"),
            registry=registry,
        )
        self.lead_validation_failures = Counter(
            "lead_validation_failures_total",
            "Lead requests rejected by the canonical intake contract.",
            (*base_labels, "channel", "form_kind", "reason"),
            registry=registry,
        )
        self.lead_processing_duration = Histogram(
            "lead_processing_duration_seconds",
            "End-to-end Middleware lead request duration.",
            (*base_labels, "channel", "form_kind"),
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
            registry=registry,
        )
        self.lead_odoo_delivery = Counter(
            "lead_odoo_delivery_total",
            "Odoo intake delivery outcomes recorded by the governed worker.",
            (*base_labels, "result"),
            registry=registry,
        )
        self.lead_odoo_delivery_failures = Counter(
            "lead_odoo_delivery_failures_total",
            "Odoo intake delivery failures by bounded reason.",
            (*base_labels, "reason"),
            registry=registry,
        )
        self.survey_responses = Counter(
            "survey_responses_total",
            "Canonical survey-response requests by bounded outcome.",
            (*base_labels, "channel", "survey_kind", "result", "anonymous"),
            registry=registry,
        )
        self.survey_validation_failures = Counter(
            "survey_validation_failures_total",
            "Survey responses rejected by the canonical contract.",
            (*base_labels, "channel", "survey_kind", "reason"),
            registry=registry,
        )
        self.survey_processing_duration = Histogram(
            "survey_processing_duration_seconds",
            "End-to-end Middleware survey-response duration.",
            (*base_labels, "channel", "survey_kind"),
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
            registry=registry,
        )
        self.inbox_backlog = Gauge(
            "intake_inbox_backlog",
            "Unprocessed durable intake inbox rows.",
            base_labels,
            registry=registry,
        )
        self.outbox_backlog = Gauge(
            "intake_outbox_backlog",
            "Pending durable intake outbox rows by bounded destination.",
            (*base_labels, "delivery_target"),
            registry=registry,
        )
        self.oldest_pending = Gauge(
            "intake_oldest_pending_seconds",
            "Age in seconds of the oldest pending intake item.",
            (*base_labels, "queue"),
            registry=registry,
        )
        self.backlog_collection_success = Gauge(
            "intake_backlog_collection_success",
            "Whether the latest aggregate backlog collection succeeded.",
            base_labels,
            registry=registry,
        )
        self.rate_limit_rejections = Counter(
            "intake_rate_limit_rejections_total",
            "Intake requests rejected by an approved rate-limit boundary.",
            (*base_labels, "channel"),
            registry=registry,
        )
        self.spam_rejections = Counter(
            "intake_spam_rejections_total",
            "Intake requests rejected by bounded abuse controls.",
            (*base_labels, "channel", "reason"),
            registry=registry,
        )
        self._outbox_targets: set[str] = set()
        self._queues: set[str] = {"inbox"}
        self.inbox_backlog.labels(*self._base).set(0)
        self.oldest_pending.labels(*self._base, "inbox").set(0)
        self.backlog_collection_success.labels(*self._base).set(0)
        self.lead_submissions.labels(
            *self._base, "unknown", "unknown", "accepted"
        ).inc(0)
        self.lead_duplicates.labels(*self._base, "unknown", "unknown").inc(0)
        self.lead_validation_failures.labels(
            *self._base, "unknown", "unknown", "invalid_contract"
        ).inc(0)
        self.lead_processing_duration.labels(*self._base, "unknown", "unknown")
        self.survey_responses.labels(
            *self._base, "unknown", "unknown", "accepted", "unknown"
        ).inc(0)
        self.survey_validation_failures.labels(
            *self._base, "unknown", "unknown", "invalid_contract"
        ).inc(0)
        self.survey_processing_duration.labels(*self._base, "unknown", "unknown")
        self.lead_odoo_delivery.labels(*self._base, "success").inc(0)
        self.lead_odoo_delivery_failures.labels(*self._base, "unknown").inc(0)
        self.rate_limit_rejections.labels(*self._base, "unknown").inc(0)
        self.spam_rejections.labels(*self._base, "unknown", "unknown").inc(0)

    def record_http_outcome(
        self,
        operation: str,
        status_code: int,
        elapsed: float,
        context: dict[str, str] | None = None,
    ) -> None:
        safe_context = context or {}
        if operation == "/v1/intake/leads":
            channel = _bounded_channel(safe_context.get("channel", "unknown"))
            form_kind = _bounded_form_kind(
                safe_context.get("form_kind", "unknown")
            )
            self.lead_processing_duration.labels(
                *self._base, channel, form_kind
            ).observe(max(elapsed, 0.0))
            if status_code == 202:
                self.lead_submissions.labels(
                    *self._base, channel, form_kind, "accepted"
                ).inc()
            elif status_code == 200:
                self.lead_submissions.labels(
                    *self._base, channel, form_kind, "duplicate"
                ).inc()
                self.lead_duplicates.labels(*self._base, channel, form_kind).inc()
            elif status_code == 409:
                self.lead_submissions.labels(
                    *self._base, channel, form_kind, "conflict"
                ).inc()
            elif status_code in {400, 413}:
                reason = (
                    "payload_too_large" if status_code == 413 else "invalid_contract"
                )
                self.lead_validation_failures.labels(
                    *self._base, channel, form_kind, reason
                ).inc()
            elif status_code == 429:
                self.rate_limit_rejections.labels(*self._base, channel).inc()
            elif status_code >= 500:
                self.lead_submissions.labels(
                    *self._base, channel, form_kind, "failure"
                ).inc()
            return

        if operation == "/v1/intake/surveys/responses":
            channel = _bounded_channel(safe_context.get("channel", "unknown"))
            survey_kind = _bounded_survey_kind(
                safe_context.get("survey_kind", "unknown")
            )
            anonymous = _bounded_anonymous(
                safe_context.get("anonymous", "unknown")
            )
            self.survey_processing_duration.labels(
                *self._base, channel, survey_kind
            ).observe(max(elapsed, 0.0))
            if status_code == 202:
                result = "accepted"
            elif status_code == 200:
                result = "duplicate"
            elif status_code == 409:
                result = "conflict"
            elif status_code in {400, 413}:
                reason = (
                    "payload_too_large" if status_code == 413 else "invalid_contract"
                )
                self.survey_validation_failures.labels(
                    *self._base, channel, survey_kind, reason
                ).inc()
                return
            elif status_code == 429:
                self.rate_limit_rejections.labels(*self._base, channel).inc()
                return
            elif status_code >= 500:
                result = "failure"
            else:
                return
            self.survey_responses.labels(
                *self._base, channel, survey_kind, result, anonymous
            ).inc()

    def record_odoo_delivery(self, *, result: str, reason: str = "unknown") -> None:
        bounded_result = result if result in {"success", "failure"} else "failure"
        self.lead_odoo_delivery.labels(*self._base, bounded_result).inc()
        if bounded_result == "failure":
            bounded_reason = reason if reason in {
                "timeout",
                "authentication",
                "authorization",
                "validation",
                "dependency",
                "reconciliation",
            } else "unknown"
            self.lead_odoo_delivery_failures.labels(
                *self._base, bounded_reason
            ).inc()

    def record_spam_rejection(self, *, channel: str, reason: str) -> None:
        bounded_channel = _bounded_channel(channel)
        bounded_reason = reason if reason in {
            "captcha",
            "velocity",
            "reputation",
            "content",
            "policy",
        } else "unknown"
        self.spam_rejections.labels(
            *self._base, bounded_channel, bounded_reason
        ).inc()

    def set_backlog(self, snapshot: IntakeBacklogSnapshot) -> None:
        self.inbox_backlog.labels(*self._base).set(max(snapshot.inbox_backlog, 0))
        current_targets = {
            _bounded_destination(item) for item in snapshot.outbox_backlog
        }
        for target in self._outbox_targets - current_targets:
            self.outbox_backlog.labels(*self._base, target).set(0)
        for target, value in snapshot.outbox_backlog.items():
            bounded = _bounded_destination(target)
            self.outbox_backlog.labels(*self._base, bounded).set(max(value, 0))
        self._outbox_targets |= current_targets

        current_queues = set(snapshot.oldest_pending_seconds)
        for queue in self._queues - current_queues:
            self.oldest_pending.labels(*self._base, queue).set(0)
        for queue, age_seconds in snapshot.oldest_pending_seconds.items():
            bounded_queue = (
                queue
                if queue == "inbox" or queue.startswith("outbox:")
                else "other"
            )
            self.oldest_pending.labels(*self._base, bounded_queue).set(
                max(age_seconds, 0.0)
            )
        self._queues |= current_queues
        self.backlog_collection_success.labels(*self._base).set(1)

    def record_backlog_failure(self) -> None:
        self.backlog_collection_success.labels(*self._base).set(0)
