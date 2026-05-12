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

### Cursor — zero install

Cursor reads `AGENTS.md` at the repo root. Ask it to run the service-approval workflow.

### Codex CLI — zero install

Codex reads `AGENTS.md`. Start a session in the repo dir.

### Gemini CLI — one install command

Requires `gemini` on PATH. `install.sh` runs:

```bash
gemini extensions link /path/to/service-onboarding/gemini-extension
```

This creates a symlink from Gemini's extensions directory to this repo. `git pull`
auto-updates the extension on next session. Invoke: `/service-approval`.

### Kiro CLI 2.0 — one install command

Requires `kiro-cli` on PATH. `install.sh` runs:

```bash
kiro-cli power install --local /path/to/service-onboarding/powers/service-approval
```

Symlinked, so `git pull` updates the Power. Invoke via keyword match in chat
("run service approval for S3"), or explicitly ask Kiro to use the power.

Alternative (GUI): Kiro app → Powers panel → Add power from local path → select
`powers/service-approval/`.

### Amazon Q Developer — zero install

Amazon Q reads `.amazonq/instructions.md` if present. Low-fidelity support; no
hooks, no enforcement. Run the validate step manually after generation.

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

Symlinked clients (Gemini CLI, Kiro) reflect changes on next session. Auto-discovered
clients (Claude Code, Copilot, Cursor, Codex) read the latest files every session.

If an IDE caches configs, restart the client after a pull that changes MCP servers
or top-level manifests.

## Uninstall

Delete the repo. Optionally unlink from Gemini / Kiro first:

```bash
gemini extensions unlink service-approval
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

**`gemini: command not found`**
Install Gemini CLI per https://geminicli.com. The installer skips Gemini if it's
not on PATH.

**`kiro-cli: command not found`**
Install via `curl -fsSL https://cli.kiro.dev/install | bash`.

**Copilot doesn't see the agent**
1. Confirm Copilot Chat is in Agent mode (not Ask mode)
2. Restart VS Code after opening the repo
3. Check `.github/agents/service-approval.agent.md` exists

**Kiro doesn't activate the Power**
Keyword-triggered. Mention "service approval" or the specific AWS service name in
your chat, OR explicitly ask Kiro to use the power.

**Gemini extension not loading**
Run `gemini extensions list` — confirm `service-approval` is listed. If not, rerun
`./install.sh`. If it's listed but tools aren't available, restart the Gemini session.
