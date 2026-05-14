#!/usr/bin/env bash
# Service Approval plugin installer — detects installed AI clients and wires them up.
#
# Modes:
#   ./install.sh              Initial install (runs sync afterward)
#   ./install.sh --sync       Re-sync only (safe after git pull; copies Kiro files,
#                             regenerates client manifests from manifest.yaml)
#   ./install.sh --update     git pull + --sync (one-shot "get latest")
#   ./install.sh --check      Dry-run — report what would be installed/synced
#   ./install.sh --quiet      Suppress non-error output
#
# Update flow:
#   - Symlinked installs (Kiro CLI `power install --local`)
#     auto-update on git pull.
#   - Copy-based installs (Kiro IDE — which reads .kiro/agents/*.md, .kiro/hooks/
#     *.kiro.hook, .kiro/settings/mcp.json) need --sync to re-copy.
#   - Enable auto-sync on git pull:
#       git config core.hooksPath .githooks
#     .githooks/post-merge fires --sync automatically.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
MODE="install"
QUIET=0

for arg in "$@"; do
  case "$arg" in
    --check)  MODE="check" ;;
    --sync)   MODE="sync" ;;
    --update) MODE="update" ;;
    --quiet)  QUIET=1 ;;
    -h|--help)
      sed -n '2,20p' "$0"
      exit 0
      ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

log() { [ "$QUIET" -eq 0 ] && echo "$@"; }
ok()  { log "  ✓ $*"; }
skip(){ log "  · $*"; }
warn(){ echo "  ! $*" >&2; }

# ---------------------------------------------------------------------------
# --update: git pull first, then fall through to --sync
# ---------------------------------------------------------------------------
if [ "$MODE" = "update" ]; then
  log ""
  log "Pulling latest changes..."
  git -C "$REPO_DIR" pull --ff-only || {
    warn "git pull failed — fix conflicts and rerun"
    exit 1
  }
  MODE="sync"
fi

log ""
log "Service Approval ${MODE}er"
log "Repo: $REPO_DIR"
log ""

# ---------------------------------------------------------------------------
# sync_kiro_ide: copy Power files into .kiro/ workspace paths.
# Kiro IDE reads .kiro/agents/*.md, .kiro/hooks/*.kiro.hook, .kiro/steering/*.md,
# .kiro/settings/mcp.json. The Power bundle at powers/service-approval/ide/
# is the source; this function promotes those files into the workspace-scoped
# .kiro/ dir so the IDE picks them up.
# ---------------------------------------------------------------------------
sync_kiro_ide() {
  local src="$REPO_DIR/powers/service-approval"
  local dst_kiro="$REPO_DIR/.kiro"

  if [ ! -d "$src" ]; then
    skip "powers/service-approval/ missing — Kiro IDE sync skipped"
    return 0
  fi

  mkdir -p "$dst_kiro/agents" "$dst_kiro/hooks" "$dst_kiro/steering" "$dst_kiro/settings"

  # Steering — every *.md from powers/.../steering/
  if [ -d "$src/steering" ]; then
    cp "$src/steering"/*.md "$dst_kiro/steering/" 2>/dev/null || true
  fi

  # IDE agents (.md) — from powers/.../ide/agents/ if present (dual-format)
  # Fallback: skip silently until Step 3 lands the generator.
  if [ -d "$src/ide/agents" ]; then
    cp "$src/ide/agents"/*.md "$dst_kiro/agents/" 2>/dev/null || true
  fi

  # IDE hooks (.kiro.hook) — from powers/.../ide/hooks/ if present
  if [ -d "$src/ide/hooks" ]; then
    cp "$src/ide/hooks"/*.kiro.hook "$dst_kiro/hooks/" 2>/dev/null || true
  fi

  # MCP config — merge source is powers/.../mcp.json; workspace target is
  # .kiro/settings/mcp.json. Always overwrite (source of truth is the manifest).
  if [ -f "$src/mcp.json" ]; then
    cp "$src/mcp.json" "$dst_kiro/settings/mcp.json"
  fi
}

# ---------------------------------------------------------------------------
# sync_configs: regenerate client-specific manifests from manifest.yaml AND
# regenerate Kiro CLI/IDE agent mirrors from powers/service-approval/agents-src/*.yaml.
# ---------------------------------------------------------------------------
sync_configs() {
  if [ ! -f "$REPO_DIR/manifest.yaml" ]; then
    skip "manifest.yaml missing — skipping config sync"
    return 0
  fi
  if ! python3 -c "import yaml" >/dev/null 2>&1; then
    warn "PyYAML not installed — run: pip3 install pyyaml"
    return 1
  fi
  python3 "$REPO_DIR/tools/sync-ide-configs.py" || return $?
  python3 "$REPO_DIR/tools/generate-kiro-agents.py" || return $?
}

# ===========================================================================
# Sync mode — copy Kiro IDE files, regenerate client manifests, stop.
# ===========================================================================
if [ "$MODE" = "sync" ]; then
  log "Kiro IDE sync"
  sync_kiro_ide
  ok "workspace .kiro/ synced from powers/service-approval/"

  log ""
  log "Client manifest sync"
  sync_configs && ok "manifests + agent mirrors regenerated from manifest.yaml + agents-src/"

  log ""
  log "Done. Re-run any time after editing manifest.yaml, agents-src/*.yaml, powers/, or steering."
  log "Enable auto-sync on git pull: git config core.hooksPath .githooks"
  exit 0
fi

# ===========================================================================
# Install / check mode — detect clients, wire them up.
# ===========================================================================

# ---------------------------------------------------------------------------
# Claude Code — auto-discovers via .claude-plugin/plugin.json. Nothing to do.
# ---------------------------------------------------------------------------
log "Claude Code"
if [ -f "$REPO_DIR/.claude-plugin/plugin.json" ]; then
  ok "plugin.json present — Claude Code will auto-load on session start"
else
  warn ".claude-plugin/plugin.json missing (expected in repo)"
fi

# ---------------------------------------------------------------------------
# GitHub Copilot (VS Code) — auto-discovers .github/copilot-instructions.md,
# .github/agents/, .github/prompts/, .github/skills/. Nothing to install.
# ---------------------------------------------------------------------------
log ""
log "GitHub Copilot"
if [ -d "$REPO_DIR/.github" ]; then
  ok ".github/ present — VS Code + Copilot auto-discovers"
else
  warn ".github/ missing"
fi

# ---------------------------------------------------------------------------
# Kiro CLI 2.0 — install the Power (symlink) AND copy IDE files to .kiro/.
# ---------------------------------------------------------------------------
log ""
log "Kiro CLI"
if command -v kiro-cli >/dev/null 2>&1; then
  if [ -d "$REPO_DIR/powers/service-approval" ]; then
    if [ "$MODE" = "check" ]; then
      skip "would run: kiro-cli power install --local $REPO_DIR/powers/service-approval"
    else
      if kiro-cli power install --local "$REPO_DIR/powers/service-approval" >/dev/null 2>&1; then
        ok "Power installed (symlink — git pull auto-updates)"
      else
        skip "Power already installed"
      fi
    fi
  else
    skip "powers/service-approval/ missing"
  fi
else
  skip "kiro-cli not installed — see https://kiro.dev/docs/cli"
fi

# ---------------------------------------------------------------------------
# Kiro IDE — manual UI install, but we pre-copy workspace files to .kiro/
# so the IDE picks them up on open.
# ---------------------------------------------------------------------------
log ""
log "Kiro IDE"
if [ -d "/Applications/Kiro.app" ] || [ -d "$HOME/.kiro" ]; then
  if [ "$MODE" = "check" ]; then
    skip "would copy powers/service-approval/{steering,ide/*} → .kiro/"
  else
    sync_kiro_ide
    ok "workspace .kiro/ populated — open Kiro and Powers → Add from Local Path"
    ok "                              → select $REPO_DIR/powers/service-approval"
  fi
else
  skip "Kiro IDE not detected (install from https://kiro.dev)"
fi

# ---------------------------------------------------------------------------
# Run sync after install so everything's wired up
# ---------------------------------------------------------------------------
if [ "$MODE" = "install" ]; then
  log ""
  log "Running sync to regenerate client manifests + agent mirrors..."
  sync_configs >/dev/null 2>&1 && ok "manifests + agent mirrors in sync with sources"
fi

log ""
log "Done. Update with: ./install.sh --update  (or: git pull && ./install.sh --sync)"
log "Auto-sync on git pull: git config core.hooksPath .githooks"
