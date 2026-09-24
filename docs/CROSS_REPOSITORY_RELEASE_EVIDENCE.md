# Cross-Repository Release Evidence

## Purpose

Codestra repositories release independently. There is no central release-authority repository and no shared mutable deployment branch.

For a feature that spans more than one repository, `ingtrader21-spec/Middleware-` owns only the **combined release-evidence note** because Middleware is the cross-system command/write boundary. This documentation responsibility does not authorize Middleware to merge, deploy or activate another repository.

## Required evidence before a multi-repository change is called released

Create one note under `docs/releases/` with:

- change/release ID;
- scope and capability flags;
- every participating repository;
- exact accepted commit SHA for each repository;
- immutable image digest/artifact digest where applicable;
- contract/schema version shared across the repositories;
- required CI run IDs and conclusions;
- staging acceptance evidence;
- backup/restore or rollback evidence when durable state changes;
- runtime read-back/reconciliation evidence;
- production approval reference, if production activation is in scope;
- explicit list of capability flags enabled and flags still false.

## Merge/release order

Default dependency order for a cross-system feature:

```text
contract
-> migration/shared primitive
-> product/provider implementation
-> Middleware adapter
-> Odoo module/service method
-> n8n workflow (inactive first)
-> Keycloak desired state
-> Kong route/edge policy
-> Caddy edge source
-> observability
-> integration/staging acceptance
-> release-evidence note
-> separately approved production activation
```

A repository may merge earlier when its source is independently safe, but the combined feature must not be declared released until all required repositories are represented by exact accepted identities.

## No floating references

Do not record only branch names, `latest`, mutable tags or GitHub PR numbers. The final note must use immutable commit SHAs and image/artifact digests.

## Safety

Creating a release-evidence note never enables a capability. Live SMS, email, dialing, crawler/provider writes, Odoo writes, provisioning writes and replay remain controlled by their independent fail-closed flags and launch gates.
