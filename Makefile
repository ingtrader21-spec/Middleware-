.PHONY: inventory backup format-check lint typecheck test test-integration security verify build deploy-internal rollback report

PYTHON ?= python3
ROOT := $(CURDIR)
RUFF_VERSION := 0.12.10
MYPY_VERSION := 1.17.1

define require_python_tool_version
	@$(PYTHON) -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else "Python 3.12 required")'
	@actual="$$($(PYTHON) -m $(1) --version 2>/dev/null | awk '{print $$2}')"; \
	test "$$actual" = "$(2)" || { \
		echo '$(1) $(2) required; install the pinned development dependencies' >&2; \
		exit 2; \
	}
endef

inventory:
	@printf 'repository=%s\n' "$(ROOT)"
	@git status --short --branch 2>/dev/null || true

backup:
	@stamp=$$(date +%Y%m%d-%H%M%S); dir=/opt/codestra/backups/middleware/$$stamp; mkdir -p "$$dir"; tar --exclude='.git' --exclude='__pycache__' -czf "$$dir/source.tgz" -C /opt/codestra middleware; sha256sum "$$dir/source.tgz"

format-check:
	$(call require_python_tool_version,ruff,$(RUFF_VERSION))
	@$(PYTHON) -m ruff format --check app migrations tests

lint:
	$(call require_python_tool_version,ruff,$(RUFF_VERSION))
	@$(PYTHON) -m ruff check app migrations tests

typecheck:
	$(call require_python_tool_version,mypy,$(MYPY_VERSION))
	@$(PYTHON) -m mypy app

test:
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m pytest -q tests

test-integration:
	@echo 'Integration tests require an explicitly provisioned isolated PostgreSQL/Redis test environment'; exit 2

security:
	@! git grep -nE '(BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|github_pat_[A-Za-z0-9_]{40,}|gh[opusr]_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_live_[A-Za-z0-9]{20,})'

verify: format-check lint typecheck test security

build:
	@python3 -m compileall -q -f app

deploy-internal:
	@echo 'Deployment intentionally disabled; requires separate approval.'; exit 2

rollback:
	@echo 'Rollback is documented only; no runtime changes were made.'

report:
	@test -f reports/phase1-outbox-build-report.md
