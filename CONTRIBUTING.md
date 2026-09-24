# Contributing to Codestra Middleware

All changes use a short-lived branch and a pull request into `main`. Direct pushes,
force pushes, stacked production branches, mutable image tags, and undocumented
contract changes are prohibited.

A pull request must:

1. identify the canonical contract and affected W-code;
2. preserve tenant authority, exact scope resolution, idempotency, and durable
   acknowledgement ordering;
3. add negative authorization and replay tests;
4. keep all live-write switches false;
5. include measured evidence in `docs/evidence/<gate>/GATE.md`;
6. pass the exact source-head and merge-result validations.

Consumer and Middleware contracts may not be silently weakened to make a test
pass. Record an R6 decision when two authoritative contracts disagree.
