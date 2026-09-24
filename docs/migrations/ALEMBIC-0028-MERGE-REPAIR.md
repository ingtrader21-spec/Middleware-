# Alembic 0028 merge repair

Middleware main acquired two valid Alembic heads when the independently
developed Lead Automation and recording migrations were merged. Both revisions
descend from `0027_telephony_command_journal`; neither parent migration is
individually defective.

`0029_merge_lead_recording_heads` joins
`0028_lead_automation_v1` and `0028_recording_api` as a topology-only merge
point. Its upgrade and downgrade functions execute no DDL and mutate no data.
Upgrading from either branch applies the other branch and then records the
single merge head. Downgrading the merge point restores the two parent heads;
normal supported downgrade targets can then be selected explicitly.

Validation must show one head, connected ancestry through both parents, a clean
empty-database upgrade, branch-to-head upgrades, downgrade/re-upgrade, and the
full Middleware test suite. Rollback is source-only: revert the repair merge
before deployment if validation fails. Do not stamp or alter a deployed
database as part of this repair.

Production deployment remains prohibited. This repair does not modify either
existing migration, recording behavior, Lead Automation behavior, or runtime
defaults.
