# Extension allocation

Each campaign owns one non-overlapping 100-extension half-open-free block as
listed in the registry. Offset 00 is a non-login anchor; 01–09 supervisors and
administrators; 10–59 regular agents; 60–69 closers/senior agents; 70–79 QA and
support; 80–89 separately approved callbacks, queues, and service endpoints;
90–94 controlled internal tests; 95–99 reserved.

One extension belongs to one campaign and one active user. Database exclusion
constraints prevent overlapping integer ranges. Partial unique indexes prevent
more than one live reservation per extension or employee. Allocation locks the
campaign block and sequence transactionally. Released extensions enter
cooldown and retain immutable history; cross-campaign reuse is forbidden.
Extensions 6110 and 6198 are globally excluded.
