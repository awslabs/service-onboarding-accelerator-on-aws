# Installation Guide

Short version: `git clone && cd && ./install.sh`. That's it for most clients.

## Quick install

```bash
git clone https://github.com/awslabs/service-onboarding-accelerator-on-aws.git
cd service-onboarding-accelerator-on-aws
./install.sh
```

Windows:
```powershell
git clone https://github.com/awslabs/service-onboarding-accelerator-on-aws.git
cd service-onboarding-accelerator-on-aws
.\install.ps1
```

The installer detects which CLIs you have installed and wires each one up. Re-run
anytime. Idempotent.

## Per-client install detail

### Claude Code — scripted install (recommended)

From the repo root:

```bash
./install-claude.sh
```

This creates the `.claude/commands/` symlink, writes `.claude/settings.json` (MCP
servers, permissions, plugin enablement), and writes `.vscode/mcp.json`. After
running, open the repo in Claude Code and invoke:

```
/service-approval ./input --service=<name>
```

### Claude Code — manual install (alternative)

If you prefer to install the plugin manually without the script:

1. **Add the repo as a local marketplace.** From within Claude Code, run:

   ```
   /plugin marketplace add ./
   ```

2. **Install the plugin.** Run:

   ```
   /plugin install service-approval@service-approval
   ```

   Choose **Project scope** when prompted (installs for all collaborators on this repo).

3. **Reload plugins.** Run:

   ```
   /reload-plugins
   ```

4. **Verify.** The `/service-approval` slash command should now appear. Run:

   ```
   /service-approval ./input --service=<name>
   ```

> **Note:** The manual approach does not configure MCP servers. You will need to
> approve MCP server connections (aws-documentation, awsknowledge, etc.)
> when prompted on first use, or run `./install-claude.sh` afterward to write the
> MCP config.

### GitHub Copilot (VS Code) — zero install

Open the repo in VS Code. Copilot auto-discovers:
- `.github/copilot-instructions.md` (repo-wide rules)
- `.github/agents/service-approval.agent.md` (the agent)
- `.github/prompts/service-approval.prompt.md` (the slash command)
- `.github/skills/` (skill bundles)

Invoke from Copilot Chat in Agent mode: `@service-approval ./input --service=<name>`.

### Kiro — manual Power install via IDE

1. Open **Kiro** IDE
2. Open the **Powers** panel
3. Click **Add power from local path**
4. Select `powers/service-approval/` from this repo

Invoke via keyword match in chat ("run service approval for S3"), or explicitly
ask Kiro to use the power.


## Verifying the install

Run the check mode:

```bash
./install.sh --check
# or Windows:
.\install.ps1 -Check
```

Prints what would be installed without making changes. Use to confirm detection
worked before a real install.

## Updating

```bash
git pull
```

Auto-discovered clients (Claude Code, Copilot) read the latest files every session.
Kiro reads from the Power path — re-add the Power if you move the repo.

If an IDE caches configs, restart the client after a pull that changes MCP servers
or top-level manifests.

## Uninstall

Delete the repo. Optionally remove the Power from Kiro first:

1. Open **Kiro** IDE → **Powers** panel
2. Remove **service-approval**

Neither is strictly required — with the repo gone, the clients stop discovering it.

## Kiro-specific testing and troubleshooting

See [`docs/TESTING-KIRO.md`](TESTING-KIRO.md) for a step-by-step Kiro IDE + CLI 2.0 testing guide, including MCP connection errors (`fetch failed`, `Connection closed`), the `workspaceRoot not approved` security warning, and keyword activation debugging.

## Troubleshooting

**`install.sh: Permission denied`**
```bash
chmod +x install.sh
```

**Kiro doesn't show the Power**
Re-add via Powers panel → Add power from local path → select `powers/service-approval/`.

**Copilot doesn't see the agent**
1. Confirm Copilot Chat is in Agent mode (not Ask mode)
2. Restart VS Code after opening the repo
3. Check `.github/agents/service-approval.agent.md` exists

**Kiro doesn't activate the Power**
Keyword-triggered. Mention "service approval" or the specific AWS service name in
your chat, OR explicitly ask Kiro to use the power.
