# Testing the service-approval Power in Kiro

> **Update (2026-05-18):** the Kiro CLI 2.0 install code path was removed
> from `install.sh`. The `kiro-cli power install --local` references below
> describe a runtime path that is no longer wired automatically; for
> current install guidance, see [`docs/INSTALL.md`](INSTALL.md). Whether
> Kiro CLI 2.0 stays as a manually-installed runtime is being re-evaluated;
> the Kiro IDE (desktop) flow is the supported path today.

Step-by-step guide to install, verify, and troubleshoot the Power in both Kiro IDE (desktop) and Kiro CLI 2.0.

## Prerequisites

1. Kiro IDE or Kiro CLI 2.0 installed. Kiro IDE: https://kiro.dev. CLI: `curl -fsSL https://cli.kiro.dev/install | bash`.
2. **`uv` on PATH** (required for `uvx`-backed MCP servers: `aws-documentation`, `iam`):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   uv --version   # verify
   ```

   **macOS gotcha:** the installer puts `uv` and `uvx` in `~/.local/bin`, which is on your shell PATH but **not** on macOS GUI-app PATH. Kiro IDE launched from Finder/Dock spawns MCP servers without your shell's `~/.zshrc` loaded, so it'll error with `spawn uvx ENOENT` even though `which uvx` works in Terminal.

   Fix once:
   ```bash
   # Symlink into a dir that GUI apps always see
   sudo ln -s ~/.local/bin/uvx /usr/local/bin/uvx
   sudo ln -s ~/.local/bin/uv  /usr/local/bin/uv

   # Teach macOS GUI apps about ~/.local/bin permanently
   launchctl setenv PATH "$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
   ```

   Then fully quit Kiro (Cmd+Q) and reopen.
3. **AWS profile `delegated-admin`** configured in `~/.aws/credentials` (needed for `kb-search` and `iam` MCPs, plus optional Tier 2 policy validation).
4. Python 3.9+ with `mcp>=1.0.0` and `boto3>=1.35.0`:
   ```bash
   pip3 install -r tools/kb-search-mcp/requirements.txt
   ```

### Kiro-specific prerequisites (first-time users)

Kiro's security model requires approving env-var template variables before expansion. The `kb-search` MCP server uses `${workspaceRoot}` in its command path. Until you approve it, the server will fail with `Connection closed`.

**Approve `${workspaceRoot}` once:**
- Open Kiro Settings
- Navigate to **MCP → Approved Environment Variables**
- Add `workspaceRoot`
- Save and reload Kiro

Or when Kiro shows the security warning toast, click **Approve**.

### Clean up any stale user-level MCP config

Before installing, check `~/.kiro/settings/mcp.json` for leftover entries from other plugins or old installs:

```bash
cat ~/.kiro/settings/mcp.json | jq '.mcpServers | keys'
```

If you see any leftover MCP entries that predate the canonical awslabs/mcp endpoints, remove them (they will fail). In particular:
- Any deprecated IaC-focused MCP server no longer used by this Power
- Any `aws-documentation` with an `"url": "https://..."` field — old guesses, not real endpoints. Replace with the canonical `uvx` config:
  ```json
  "aws-documentation": {
    "command": "uvx",
    "args": ["awslabs.aws-documentation-mcp-server@latest"],
    "env": {"FASTMCP_LOG_LEVEL": "ERROR", "AWS_DOCUMENTATION_PARTITION": "aws"}
  }
  ```

## Install

From a local clone of this repo:

```bash
cd /path/to/service-onboarding-accelerator-on-aws
./install.sh
```

The installer:
- Detects Kiro CLI and runs `kiro-cli power install --local powers/service-approval` (symlink install — `git pull` updates it)
- Detects Kiro IDE and copies `powers/service-approval/steering/*.md` to `.kiro/steering/`, `powers/service-approval/ide/agents/*.md` to `.kiro/agents/`, `powers/service-approval/ide/hooks/*.kiro.hook` to `.kiro/hooks/`, and `powers/service-approval/mcp.json` to `.kiro/settings/mcp.json`

After `install.sh`:
- **Kiro IDE users**: open the IDE → Powers panel (ghost-with-lightning icon) → **Add power from Local Path** → select `<repo>/powers/service-approval/`. This registers the Power's manifest. The `.kiro/*` workspace files are already in place.
- **Kiro CLI users**: already registered via the installer.

## Verify the install

### 1. Power registered

**Kiro IDE**: Powers panel → scroll to custom Powers → "AWS Service Security Controls Generator" should be listed.

**Kiro CLI**:
```bash
kiro-cli power list
```
Expect `service-approval` in the output.

### 2. `.kiro/` populated

```bash
ls .kiro/agents/         # should list sa-*.md files (matches powers/service-approval/ide/agents/)
ls .kiro/hooks/          # should list *.kiro.hook files (matches powers/service-approval/ide/hooks/)
ls .kiro/steering/       # should list *.md files (matches powers/service-approval/steering/)
cat .kiro/settings/mcp.json | jq 'keys'   # should list the configured MCP servers
```

If any is empty, re-run `./install.sh --sync`.

### 3. MCP servers reachable

In Kiro Chat, ask:
```
list my MCP servers and tools
```

Expect these servers: `aws-documentation`, `awsknowledge`, `kb-search`, `iam`.

If servers show "connection failed":
- `aws-documentation` — missing `uv`. Run `curl -LsSf https://astral.sh/uv/install.sh | sh`, then reload Kiro.
- `kb-search` — requires `AWS_PROFILE=delegated-admin` valid AWS creds.
- `iam` — requires `awslabs.iam-mcp-server` binary on PATH.

### 4. Power activates on keywords

In Kiro Chat:
```
run service approval for s3 --dry-run
```

Expected: the chat trace should note "Service Approval Power activated" (or similar wording from Kiro). The agent then reads `skills/service-approval/SKILL.md` and starts Phase 0 (Assess).

If keywords don't trigger, check `powers/service-approval/POWER.md` frontmatter `keywords:` list. Add more variants if needed.

### 5. Hooks fire

After a full run (remove `--dry-run`):

```bash
# PostToolUse hook should have logged schema errors (if any) during the run
ls .service-approval/<slug>/

# Stop hook should have written mcp-calls.log with >=10 entries
wc -l .service-approval/<slug>/mcp-calls.log
```

If `mcp-calls.log` is missing or <10 lines, integrity rule P1 will fail and the verdict will be `REQUIRES REMEDIATION` — hooks are working.

## Test the full pipeline

Create an `./input/` folder with a minimal AWS service input (at least `sar-slugs.json` pointing at a service), then:

```
run service approval for s3 --dry-run
```

The agent should run the Intake precursor plus all 6 numbered phases. Watch for:
- Intake writes `.service-approval/_staging/<ts>/00-intake/intake-manifest.json` before Phase 0
- Phase 1 (Research) spawns 4 parallel subagents
- Phase 3 (Map) spawns 2 early + 2 sequential
- Phase 4 (Recommended Guidance) spawns 2 parallel families
- Phase 5 (Summarize) writes `.service-approval/<service-slug>/06-summarize/SUMMARY-REPORT.md`

End state should be a completed `SUMMARY-REPORT.md` (the report issues no approve/deny verdict), not silence.

## Update the Power

```bash
cd /path/to/service-onboarding-accelerator-on-aws
git pull
./install.sh --sync        # re-copy .kiro/ files
```

If you enabled auto-sync (`make enable-auto-sync`), `git pull` alone is enough — `.githooks/post-merge` runs `install.sh --sync` automatically.

## Uninstall

**Kiro IDE**: Powers panel → service-approval → Uninstall. Then manually:
```bash
rm -rf .kiro/
```

**Kiro CLI**:
```bash
kiro-cli power uninstall service-approval
rm -rf .kiro/
```

## Troubleshooting

### `Failed to connect to MCP server "aws-documentation": fetch failed`

**Cause**: old config used unreachable HTTP URL. Fixed in May 2026 to stdio via `uvx`.
**Fix**: `git pull` then `./install.sh --sync`. Install `uv` if not present.

### `Failed to connect to MCP server "<deprecated-server>": Connection closed`

**Cause**: a deprecated MCP server is NOT in this plugin's config. Left over from a prior Kiro install in `~/.kiro/settings/mcp.json` (user-level) or somewhere else.
**Fix**: edit `~/.kiro/settings/mcp.json` and remove the stale entry. The service-approval Power uses `aws-documentation` and `awsknowledge` instead.

### `Security Warning: MCP configuration contains environment variables that have not been approved: workspaceRoot`

**Cause**: Kiro's security gate requires you to whitelist template variables before expansion. `${workspaceRoot}` is used by the `kb-search` MCP server for the local Python script path.
**Fix**: accept the Kiro security prompt when it appears. If the prompt doesn't appear, go to Kiro Settings → MCP → Approved Environment Variables and add `workspaceRoot`.

### Agent reports "(No tools available)" for all MCPs

Check the actual Kiro MCP logs before accepting the agent's claim:

```bash
LATEST=$(ls -t ~/Library/Application\ Support/Kiro/logs/ | head -1)
cat "$HOME/Library/Application Support/Kiro/logs/$LATEST/window1/exthost/kiro.kiroAgent/Kiro - MCP Logs.log"
```

Look for `Successfully connected and synced tools and resources`. If you see those lines, the MCPs are up — the agent is hallucinating a degraded state. Tell it explicitly: **"MCPs are connected. Use awsknowledge and aws-documentation MCPs. Do NOT fall back to web search."**

If you see `MCP connection closed successfully` for every server, the Power was uninstalled or the workspace closed. Reimport the Power and retry.

The agent falling back to web search violates hard rule 2 (no training-data values) and will be blocked by the Stop hook (P1: mcp-calls.log <10 entries).

### Power doesn't appear in Powers panel after Local Path install

**Cause**: missing `POWER.md` at the root of the selected directory, or the frontmatter doesn't parse.
**Fix**: confirm `powers/service-approval/POWER.md` starts with `---\nname: service-approval\n...\n---`. Validate with:
```bash
python3 -c "import yaml; print(yaml.safe_load(open('powers/service-approval/POWER.md').read().split('---')[1]))"
```

### Keyword activation doesn't fire

**Cause**: Kiro keyword matching is word-boundary sensitive. "run service approval" works, "serviceapproval" doesn't.
**Fix**: either use explicit invocation ("use the service-approval Power for Amazon S3") or add more keyword variants to `POWER.md` frontmatter and run `./install.sh --sync`.

### `.kiro/agents/` is empty after install

**Cause**: `powers/service-approval/ide/agents/` is empty (generator hasn't run yet).
**Fix**: `python3 tools/generate-kiro-agents.py && ./install.sh --sync`.

### Agent runs but MCP calls aren't logged

**Cause**: agents aren't invoking MCP tools (falling back on training data, violates rule 2).
**Fix**: ensure `.kiro/settings/mcp.json` has all configured servers and they're "connected" in Kiro's MCP panel. Restart Kiro. Confirm the workspace is trusted (`.kiro/` files require trusted workspace).
