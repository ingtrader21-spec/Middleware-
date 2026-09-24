# Runtime inventory reconciliation

Issues #38 and #109 require current observations to be distinguished from old captures. `scripts/reconcile_runtime_inventory.py` compares a checksum-bound observation with a separately prepared expected inventory. It runs offline and never contacts a host, changes a route, starts a container, or accepts a production release.

The expected file uses `schema_version: "1.0"` and a nonempty `workloads` array. Each entry has exactly `name`, `source_repository` (an explicit GitHub repository URL), `source_revision` (a full commit), and `image_reference` (repository plus SHA-256 digest). Populate these from the reviewed candidate and its workload ownership bindings. Do not generate this expectation from the observed containers: doing so would conceal missing workloads and competing owners.

The observation has a timezone-qualified `observed_at` and a nonempty `workloads` array. Each observed entry includes the same four identity fields plus Docker `status` and `health`. Additional captured fields are not copied into the report. Capture and expected-file checksums must be supplied by the evidence handoff; a checksum proves byte identity, not provenance or authorization.

```sh
python3 scripts/reconcile_runtime_inventory.py \
  --inventory /private/evidence/observed.json \
  --inventory-sha256 "$OBSERVATION_SHA256" \
  --expected /private/evidence/expected.json \
  --expected-sha256 "$EXPECTED_INVENTORY_SHA256" \
  --output /private/evidence/reconciliation.json
```

Exit 0 means the inventory observations match; exit 2 means rejected input or unresolved differences. Reports are written atomically. Invalid input replaces any previous success report with a rejected result when the output is writable. Always check the exit status; an unwritable output cannot be refreshed. Inputs cannot also be the output.

- `CURRENT`: a fresh, running, healthy observation matches its expected repository, source and immutable image.
- `UNKNOWN`: an observed workload has no expected ownership binding.
- `REQUIRES_RUNTIME_READBACK`: an expected workload is absent, unhealthy, stopped, mutable, or has an identity mismatch.
- `HISTORICAL`: the observation exceeds the age limit (one hour by default). Underlying differences remain recorded.

The tool does not infer `SUPERSEDED` from a different digest: an older image may be a required rollback artifact or a distinct worker. That disposition needs separately reviewed release/predecessor evidence. Empty inventories, duplicate workload names, duplicate JSON members, future dates and ambiguous timestamps are rejected.

Every report retains `runtime_certified: false` and `deployment_authorized: false`, including a matching inventory. Schema/configuration/queue/network/secret-reference readback, signed release admission, backup and restore, rollback, gateway/authentication checks, and zero-effect runtime counters remain required under #118/#134. Staging intake and automation acceptance (#65/#74) run through `Infustruction-repo`'s protected controller. W0 governance (#68) has its own live settings verification and tag acceptance. This report satisfies none of those gates by itself.
