# Isolated connector contracts

Each file in `config/connectors/` belongs to exactly one Middleware workstream and source repository. Connectors never share a Keycloak client ID or secret reference. Base URLs and secrets are environment-variable references, not values committed to Git.

New contracts are deliberately fail closed: runtime activation and external effects are disabled, runtime status is unconfirmed, and deployment evidence records that no deployment occurred. Activating a connector requires reviewed endpoint ownership, credentials outside Git, exact-commit staging tests, rollback evidence, and separate deployment approval.

Run `python3 scripts/validate_connector_contracts.py` or the complete `scripts/run_ci.sh` suite before pushing a connector branch.
