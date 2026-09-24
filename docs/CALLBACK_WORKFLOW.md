# Callback Workflows

`CallbackScheduledV1` distributes a versioned schedule event. `CallbackReminderV1` requests internal email at 24 hours and one hour. `CallbackDueV1` requests the 15-minute warning and due popup. `CallbackMissedV1` marks a callback missed after the campaign grace period. `CallbackEscalationV1` notifies the supervisor and missed queue. `CallbackCompletedV1` cancels all older pending deliveries. Consumers reject any event whose version differs from the aggregate version.
