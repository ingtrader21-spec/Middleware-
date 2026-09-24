# Job lifecycle

External states map to durable lower-case database states. Submission is idempotent per tenant/workspace/key. Claims use `FOR UPDATE SKIP LOCKED`, bounded leases, and monotonically increasing fencing tokens. Expired leases retry within the attempt bound and otherwise dead-letter. Deadlines expire without deleting jobs. Completion is unique and cancellation races are fenced.
