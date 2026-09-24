# Campaign activation

States: DRAFT, IDENTITY_RESERVED, PROVISIONED_DISABLED, SECURITY_REVIEW,
BUSINESS_APPROVAL, ACTIVATION_READY, ACTIVE, PAUSED, SUSPENDED, RETIRED.

Activation is a serializable transaction bound to an immutable activation ID
and canonical policy SHA-256. It verifies registry identity, non-overlapping
extensions, disabled-ready VICIdial records, closed dialplan, exact groups and
scope, compliance, monitoring, evidence, rollback and kill switches. Any
missing gate aborts without partial activation.

Proposed database models are campaign_registry, campaign_parent,
campaign_extension_block, identity_sequence, lead_identity,
campaign_activation, campaign_feature_activation, lifecycle_scope_policy,
search_alias and immutable_campaign_audit. Unique constraints cover campaign
number/code/public/VICIdial IDs, aliases and active extension/user ownership.
An integer-range exclusion constraint prevents block overlap. No migration is
applied by this policy PR.
