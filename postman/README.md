# Middleware Postman authority

The generated collection is derived from the canonical OpenAPI with scripts/generate_postman.py. The database certification collection is a read-only overlay for PAS-102. Exported environments contain no tokens or production secrets. The --check flag fails on generated collection drift.

Production-safe mode never enables database mutations, raw SQL, migration apply, backup shell execution, or provider/business effects.
