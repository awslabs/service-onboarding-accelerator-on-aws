# Service Approval — convenience targets over install.sh + sync-ide-configs.py
#
# Prefer these for day-to-day use. Each wraps a shell script with the same
# behaviour as running the script directly.

.PHONY: install sync update check test test-sync test-install verify enable-auto-sync clean-staging help

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-22s %s\n", $$1, $$2}'

install:  ## Detect installed clients and wire them up (run once after clone)
	@./install.sh

sync:  ## Re-copy Kiro files + regenerate per-client manifests from manifest.yaml
	@./install.sh --sync

update:  ## git pull, then sync
	@./install.sh --update

check:  ## Dry-run — report what would be installed, no changes
	@./install.sh --check

enable-auto-sync:  ## Wire .githooks/post-merge so `git pull` auto-syncs
	@git config core.hooksPath .githooks
	@echo "Auto-sync enabled. Every 'git pull' will now run install.sh --sync."

test:  ## Run the Python test suite (validators + evidence module)
	@python3 -m pytest tools/validate/ tools/evidence/ -q

test-sync:  ## Verify no drift between manifest.yaml and generated client configs (incl. agent mirrors)
	@python3 tools/sync-ide-configs.py --check
	@python3 tools/generate-kiro-agents.py --check

test-install:  ## Verify install.sh --check completes without error
	@./install.sh --check >/dev/null && echo "install.sh --check: OK"

verify: test test-sync test-install  ## Run all verification steps (CI-equivalent)
	@echo ""
	@echo "All verification checks passed."

clean-staging:  ## Remove stale _staging/ directories (older than 24 hours)
	@echo "Cleaning stale _staging/ directories (>24h old)..."
	@if [ -d .service-approval/_staging ]; then \
		find .service-approval/_staging -mindepth 1 -maxdepth 1 -type d -mtime +0 -exec echo "  Removing: {}" \; -exec rm -rf {} \; ; \
		echo "Done."; \
	else \
		echo "  No _staging/ directory found."; \
	fi
