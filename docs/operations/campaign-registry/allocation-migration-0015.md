# Campaign extension allocation migration 0015

Middleware PostgreSQL is the authoritative extension-allocation store. Odoo,
VICIdial, Asterisk, Redis and WebRTC are projections or consumers and may not
allocate numbers independently.

Migration file `0015_campaign_extension_allocation.py` follows
`0014_telephony_call_lifecycle`; its database revision identifier is
`0015_campaign_ext_allocation`, shortened to fit the existing Alembic
`varchar(32)` version column.

The migration preserves the existing `telephony_extension_pool` rows while
raising their ceiling to 9999. It adds the immutable
`campaign_extension_allocation` ledger with inclusive generated `int4range`,
disabled `PROPOSED` default, unique campaign/public identities and an all-row
GiST exclusion constraint. RETIRED rows remain covered. A trigger prohibits
deleting an allocation or changing its campaign, public identity, range,
policy hash or change ID.

Downgrade is allowed only when the campaign allocation ledger is empty and no
existing role pool exceeds the former 6999 ceiling. This prevents silent data
loss. The migration creates no campaign, reservation, endpoint, credential,
phone, user, list, WebRTC assignment or delivery activation.

Known database constraints translate only by exact constraint name:
`EXTENSION_RANGE_OVERLAP`, `EXTENSION_OUT_OF_SUPPORTED_RANGE`,
`EXTENSION_RANGE_INVALID`, `CAMPAIGN_ALLOCATION_ALREADY_EXISTS`, and
`HISTORICAL_RANGE_REUSE_PROHIBITED`. Unrelated integrity errors are re-raised.
