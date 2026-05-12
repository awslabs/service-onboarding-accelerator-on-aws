# Service Approval — convenience targets over install.sh + sync-ide-configs.py
#
# Prefer these for day-to-day use. Each wraps a shell script with the same
# behaviour as running the script directly.

.PHONY: install sync update check test test-sync test-install verify enable-auto-sync help

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

test:  ## Run the Python test suite (205 tests)
	@python3 -m pytest tools/validate/ -q

test-sync:  ## Verify no drift between manifest.yaml and generated client configs
	@python3 tools/sync-ide-configs.py --check

test-install:  ## Verify install.sh --check completes without error
	@./install.sh --check >/dev/null && echo "install.sh --check: OK"

verify: test test-sync test-install  ## Run all verification steps (CI-equivalent)
	@echo ""
	@echo "All verification checks passed."
