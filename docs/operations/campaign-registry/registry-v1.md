# Campaign registry v1

Campaign numbers, codes, public IDs, VICIdial IDs, extension blocks, groups and
contexts in `registry-v1.yaml` are immutable identities. Numbers are never
reused; the next campaign receives the next unused multiple of 100.

Read-only scans found no assignments in 7100–7899 across loaded Asterisk
endpoints, VICIdial phones/users, Odoo extension models, middleware
reservations/sagas, Redis provisioning keys, or WebRTC assignments. Static
mentions of 7200 and 7500 were timer/frequency values, not extensions.

The ranges remain proposed. Current middleware database checks restrict pools
to 6100–6999, so a reviewed migration must expand the ceiling before any
reservation. No migration or record change is part of this package.

Calderon Farm (800) is a child of Moy Logistics (300). The parent relationship
does not permit shared IDs, extensions, groups, contexts, data access, or
activation state.
