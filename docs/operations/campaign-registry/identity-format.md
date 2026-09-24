# Immutable identity formats

- Campaign: `CMP-<campaign_number>-<campaign_code>`
- Lead compact: `<campaign_number>-L-<8-digit-sequence>`
- Lead alias: `<campaign_code>-<campaign_number>-L-<8-digit-sequence>`
- Agent: `<campaign_number>-A-<extension>`
- Call: `<campaign_number>-C-<YYYYMMDD>-<6-digit-sequence>`
- Callback: `<campaign_number>-CB-<8-digit-sequence>`
- Transfer: `<campaign_number>-XF-<8-digit-sequence>`
- List: `<campaign_number>-LST-<4-digit-sequence>`
- Activation: `<campaign_number>-ACT-<YYYYMMDD>-<3-digit-sequence>`
- Import: `<campaign_number>-IMP-<YYYYMMDD>-<3-digit-sequence>`

Sequences are rows keyed by campaign, identity type, and date partition where
applicable. Allocation uses a database transaction and row lock or atomic
`UPDATE ... RETURNING`; gaps are allowed and reuse is prohibited. Public IDs
and aliases are globally unique and immutable. External/VICIdial IDs are
aliases, never substitutes for the canonical ID.
