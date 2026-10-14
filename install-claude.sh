#!/usr/bin/env bash
# Install the service-approval plugin for Claude Code — no manual steps required.
# Run from the repo root: ./install-claude.sh
#
# This script does NOT hand-write MCP configs or server allowlists. It runs
# tools/sync-ide-configs.py against manifest.yaml, which is the canonical
# source of truth for every MCP server, license metadata, and per-client
# config layout. Hand-writing those values here drifts every time a new
# server lands in the manifest (mitre-attack was missed pre-fix).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Installing service-approval plugin for Claude Code..."

# 1. Ensure .claude/commands/ exists with symlink to the slash command
mkdir -p "$REPO_DIR/.claude/commands"
if [ ! -e "$REPO_DIR/.claude/commands/service-approval.md" ]; then
  ln -s ../../commands/service-approval.md "$REPO_DIR/.claude/commands/service-approval.md"
  echo "  ✓ Slash command /service-approval linked"
else
  echo "  · Slash command already in place"
fi

# 2. Sync .vscode/mcp.json + .mcp.json + powers/.../mcp.json from manifest.yaml.
# These are the canonical MCP-server lists; hand-writing them here would
# drift every time manifest.yaml gains a server (e.g., mitre-attack).
if command -v python3 >/dev/null 2>&1 && python3 -c "import yaml" >/dev/null 2>&1; then
  python3 "$REPO_DIR/tools/sync-ide-configs.py" >/dev/null
  echo "  ✓ MCP configs regenerated from manifest.yaml"
else
  echo "  ⚠ python3 + PyYAML required for manifest sync; skipping. Run:"
  echo "    pip3 install pyyaml && python3 tools/sync-ide-configs.py"
fi

# 3. Write .claude/settings.json — render the MCP allowlist from the
# manifest's keys instead of hardcoding it. The allowlist must include
# every entry generated above (or Claude Code blocks the server even
# when its config exists).
ENABLED_SERVERS=$(python3 - "$REPO_DIR" <<'PY'
import sys, yaml, json
manifest = yaml.safe_load(open(f"{sys.argv[1]}/manifest.yaml"))
servers = list(manifest.get("mcp_servers", {}).keys())
print(json.dumps(servers))
PY
)

cat > "$REPO_DIR/.claude/settings.json" <<EOF
{
  "permissions": {
    "allow": [
      "Bash(ls ./input/)",
      "Bash(ls .service-approval/*/)",
      "Bash(mkdir -p .service-approval/*)",
      "Bash(mkdir -p .service-approval/*/0[0-8]-*)",
      "Bash(touch .service-approval/*/mcp-calls.log)",
      "Bash(touch .service-approval/*/pipeline.log)",
      "Bash(python3 -m json.tool .service-approval/*)",
      "Bash(python3 -m tools.validate.check_phase_complete *)",
      "Bash(python3 -m tools.validate.log *)"
    ]
  },
  "enabledMcpjsonServers": ${ENABLED_SERVERS},
  "enabledPlugins": {
    "service-approval@service-approval": true
  }
}
EOF
echo "  ✓ .claude/settings.json written (MCP allowlist from manifest.yaml; ${ENABLED_SERVERS} servers)"

# 4. Register the repo as a local marketplace so the plugin is available
# from any working directory (not just when you open this repo).
echo ""
echo "Registering plugin marketplace..."
if command -v claude >/dev/null 2>&1; then
  if claude plugin marketplace add "$REPO_DIR" 2>/dev/null; then
    echo "  ✓ Marketplace registered — plugin available from any directory"
    claude plugin install service-approval@service-approval --scope user 2>/dev/null && \
      echo "  ✓ Plugin installed (user scope)" || \
      echo "  · Plugin may already be installed"
  else
    echo "  ⚠ Marketplace registration failed — plugin works only when repo is open"
  fi
else
  echo "  ⚠ claude CLI not found — open Claude Code in this repo and run:"
  echo "    /plugin marketplace add ./"
  echo "    /plugin install service-approval@service-approval"
fi

# 5. Check prerequisites
echo ""
echo "Checking prerequisites..."

if command -v uv >/dev/null 2>&1; then
  echo "  ✓ uv found (required for aws-documentation + mitre-attack MCP servers)"
else
  echo "  ⚠ uv not found — install: curl -LsSf https://astral.sh/uv/install.sh | sh"
fi

if command -v python3 >/dev/null 2>&1; then
  echo "  ✓ python3 found (required for pipeline tooling + validators)"
else
  echo "  ⚠ python3 not found — pipeline tooling and validation won't work"
fi

echo ""
echo "Done. Start Claude Code from any working directory and run:"
echo "  /service-approval --service=<name>"
echo ""
echo "Or with custom input files:"
echo "  /service-approval ./input --service=<name>"
