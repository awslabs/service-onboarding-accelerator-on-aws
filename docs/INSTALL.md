# Installation Guide

Short version: `git clone && cd && ./install.sh`. That's it for most clients.

## Quick install

```bash
git clone https://gitlab.aws.dev/lightninglane/service-onboarding.git
cd service-onboarding
./install.sh
```

Windows:
```powershell
git clone https://gitlab.aws.dev/lightninglane/service-onboarding.git
cd service-onboarding
.\install.ps1
```

The installer detects which CLIs you have installed and wires each one up. Re-run
anytime. Idempotent.

## Per-client install detail

### Claude Code — zero install

Open the repo in Claude Code. `.claude-plugin/plugin.json` is auto-discovered.
Invoke: `/service-approval ./input --service=<name>`.

### GitHub Copilot (VS Code) — zero install

Open the repo in VS Code. Copilot auto-discovers:
- `.github/copilot-instructions.md` (repo-wide rules)
- `.github/agents/service-approval.agent.md` (the agent)
- `.github/prompts/service-approval.prompt.md` (the slash command)
- `.github/skills/` (skill bundles)

Invoke from Copilot Chat in Agent mode: `@service-approval ./input --service=<name>`.

### Kiro CLI 2.0 — one install command

Requires `kiro-cli` on PATH. `install.sh` runs:

```bash
kiro-cli power install --local /path/to/service-onboarding/powers/service-approval
```

Symlinked, so `git pull` updates the Power. Invoke via keyword match in chat
("run service approval for S3"), or explicitly ask Kiro to use the power.

Alternative (GUI): Kiro app → Powers panel → Add power from local path → select
`powers/service-approval/`.


## Windows Developer Mode

Symlink installs need Developer Mode on Windows (one-time toggle):

1. Open **Settings** (Win + I)
2. **Update & Security** (Windows 10) or **Privacy & Security** (Windows 11)
3. **For developers**
4. Turn **Developer Mode** ON
5. Reboot not required

Without Developer Mode, symlinks need an elevated terminal. The alternative is
copying files instead of linking, which breaks auto-update via `git pull`.

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

Symlinked clients (Kiro) reflect changes on next session. Auto-discovered
clients (Claude Code, Copilot) read the latest files every session.

If an IDE caches configs, restart the client after a pull that changes MCP servers
or top-level manifests.

## Uninstall

Delete the repo. Optionally unlink from Kiro first:

```bash
kiro-cli power uninstall service-approval
```

Neither is strictly required — with the repo gone, symlinks dangle and the clients
stop discovering them.

## Kiro-specific testing and troubleshooting

See [`docs/TESTING-KIRO.md`](TESTING-KIRO.md) for a step-by-step Kiro IDE + CLI 2.0 testing guide, including MCP connection errors (`fetch failed`, `Connection closed`), the `workspaceRoot not approved` security warning, and keyword activation debugging.

## Troubleshooting

**`install.sh: Permission denied`**
```bash
chmod +x install.sh
```

**`kiro-cli: command not found`**
Install via `curl -fsSL https://cli.kiro.dev/install | bash`.

**Copilot doesn't see the agent**
1. Confirm Copilot Chat is in Agent mode (not Ask mode)
2. Restart VS Code after opening the repo
3. Check `.github/agents/service-approval.agent.md` exists

**Kiro doesn't activate the Power**
Keyword-triggered. Mention "service approval" or the specific AWS service name in
your chat, OR explicitly ask Kiro to use the power.
