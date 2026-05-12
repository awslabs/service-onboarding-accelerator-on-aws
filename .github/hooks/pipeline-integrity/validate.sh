#!/usr/bin/env bash
# Service Approval — Copilot sessionEnd hook.
#
# Runs after every Copilot coding-agent session. Invokes the shared pipeline
# integrity validator that enforces the 7 hard rules (no shortcut runs,
# MCP verification, no templated notes, parameterized IaC, SCP safety,
# verdict consistency). Exit code 2 signals failure; Copilot surfaces this
# to the user.
#
# This is the same script Kiro's Stop hook and Claude Code's Stop hook
# invoke — one source of truth across clients.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

if [ ! -d ".service-approval/state" ]; then
  # No pipeline state — nothing to validate. Not a failure.
  exit 0
fi

exec python3 tools/validate/hook_stop.py
