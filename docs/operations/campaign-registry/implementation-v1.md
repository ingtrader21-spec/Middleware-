# Campaign registry identity implementation v1

The middleware PostgreSQL database is the canonical identity authority.
Odoo, VICIdial, Asterisk, WebRTC and n8n consume projections and must not
allocate campaign or lead identifiers independently.

Migration 0016 creates immutable registry, object-identity, search-alias,
feature-gate and activation-audit structures. A PostgreSQL sequence issues
non-reusable values: sequence advancement is not rolled back, so failed
transactions leave safe gaps.

Migration 0017 reserves the eight approved permanent campaign identities and
their non-overlapping extension blocks. Every registry row is
`PROPOSED_DISABLED`, every extension block is `PROPOSED`, and all eight
downstream feature gates are `DISABLED`.

The seed revision is intentionally irreversible. Campaign numbers, codes,
public IDs and extension blocks are permanent and cannot be erased for reuse.

Identity creation is separate from dialing:

- object identity defaults to `ID_ASSIGNED`;
- dialing state defaults to `NOT_ELIGIBLE`;
- no activation routine exists in these migrations;
- call direction and destination policy remain unresolved and therefore
  cannot authorize production.

Search accepts exact canonical identifiers only. Telephone numbers, wildcards
and path-like inputs are rejected. Callers must supply a trusted,
server-derived campaign permission set to the scoped search function; browser
headers are not an authorization source.

The legacy `vicidial_campaign_registry` remains a staging projection. Its
legacy `TRX` code and eight-character physical-ID constraint are not silently
rewritten or treated as canonical `TRD` identity.
