#!/usr/bin/env bash
# Service Approval — Copilot sessionEnd hook.
#
# Runs after every Copilot coding-agent session. Invokes the shared pipeline
# integrity validator that enforces the hard rules (no shortcut runs,
# MCP verification, no templated notes, reference-anchored controls, citation
# coverage, SCP safety, verdict consistency). Exit code 2 signals failure;
# Copilot surfaces this to the user.
#
# This is the same script Kiro's Stop hook and Claude Code's Stop hook
# invoke — one source of truth across clients.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

# Check if any service directories exist (skip _staging/ and plans/)
if [ ! -d ".service-approval" ]; then
  exit 0
fi

# Look for any service directory with phase subdirs
has_services=false
for dir in .service-approval/*/; do
  [ -d "$dir" ] || continue
  # Skip _staging/ and plans/
  case "$(basename "$dir")" in
    _*|plans) continue ;;
  esac
  # Check if it has phase directories (0N-*)
  if ls -d "$dir"0*-*/ 2>/dev/null | grep -q .; then
    has_services=true
    break
  fi
done

if [ "$has_services" = "false" ]; then
  # No pipeline state — nothing to validate. Not a failure.
  exit 0
fi

exec python3 tools/validate/hook_stop.py
