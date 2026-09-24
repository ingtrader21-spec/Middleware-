from prometheus_client import Counter, Gauge, Histogram

created = Counter("email_created_total", "Email notifications created")
queued = Counter("email_queued_total", "Email notifications queued")
sent = Counter("email_sent_total", "Email notifications submitted or sent")
delivered = Counter("email_delivered_total", "Email notifications delivered")
failed = Counter("email_failed_total", "Email notifications permanently failed")
bounced = Counter("email_bounced_total", "Email notifications bounced", ["kind"])
complaints = Counter("email_complaint_total", "Email complaints")
suppressed = Counter("email_suppressed_total", "Email notifications suppressed")

outbox_depth = Gauge("outbox_depth", "Queued email outbox records")
oldest_outbox_age = Gauge("oldest_outbox_age_seconds", "Age of oldest queued email")
retry_count = Gauge("retry_count", "Cumulative attempts on queued email")
dead_letter_count = Gauge("dead_letter_count", "Email dead letters")
klyrow_latency = Histogram("klyrow_latency_seconds", "Klyrow request latency")
postal_latency = Histogram("postal_latency_seconds", "Postal event processing latency")
