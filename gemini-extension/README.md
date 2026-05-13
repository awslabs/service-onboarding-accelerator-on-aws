# Service Approval — Gemini CLI Extension

Generates AWS security controls for any AWS service via an 8-phase pipeline. Packaged as a Gemini CLI extension with MCP server config, a custom slash command (`/service-approval`), and context via `GEMINI.md`.

Bundles the same 18 skills that Claude Code, Copilot, and Kiro use — via shared files in `../skills/` (agentskills.io format).

## Install

From this repo:

```bash
cd /path/to/service-onboarding
./install.sh
```

The installer runs `gemini extensions link` under the hood, creating a symlink so `git pull` auto-updates the extension.

Direct install:

```bash
gemini extensions link /path/to/service-onboarding/gemini-extension
```

Or from GitHub (when published):

```bash
gemini extensions install https://gitlab.aws.dev/lightninglane/service-onboarding \
  --path gemini-extension
```

## Verify

```bash
gemini extensions list
```

Should show `service-approval` with version `1.0.0`.

## Usage

### Via slash command

```
/service-approval --service=s3 --env=my-profile
/service-approval ./input --service=kms --dry-run
/service-approval --service=bedrock-agentcore-control --skip-test
```

### Via natural language

```
run service approval for s3
generate AWS security controls for kms using my-profile
service approval ./input --service=lambda --skip-test
```

## What happens on activation

1. Gemini CLI loads `gemini-extension.json` — registers 5 MCP servers (aws-documentation, awsknowledge, awsiac, terraform, kb-search)
2. `GEMINI.md` loads into context — contains the extension's rules and pipeline overview
3. The `/service-approval` slash command is registered
4. When invoked, the agent reads `../skills/service-approval/SKILL.md` and runs the 8-phase pipeline

## Repo layout

```
gemini-extension/
├── gemini-extension.json    Manifest: MCP servers, contextFileName
├── GEMINI.md                Context: rules, pipeline, MCP server list
├── commands/
│   └── service-approval.toml   /service-approval slash command
└── README.md                (this file)
```

Note: skills live in `../skills/` (real repo root directory), not in this extension dir. Gemini CLI discovers them via the `.agents/skills/` alias at repo root.

## Hard rules

Enforced at `AfterAgent` via `hooks/hooks.json`:

```json
{
  "hooks": [
    {
      "event": "AfterAgent",
      "command": "python3 ${extensionPath}/../tools/validate/hook_stop.py",
      "timeout_ms": 60000
    }
  ]
}
```

Exit 0 = integrity passed; exit 2 = REQUIRES REMEDIATION and the agent retries.
Same `hook_stop.py` script Claude Code and Kiro invoke — one source of truth.

## Update

```bash
cd /path/to/service-onboarding
git pull
```

Symlinked install — changes reflect on next Gemini session.

## Uninstall

```bash
gemini extensions uninstall service-approval
```

## Why no bundled skills in this dir?

Gemini CLI supports discovery from `.agents/skills/` (the agentskills.io alias) at workspace root. This repo has a symlink at `/.agents/skills/` → `/skills/`, so all 18 skills are discoverable without duplicating files inside the extension.

If you want to use this extension on a different repo, either:
1. Copy `../skills/` into `gemini-extension/skills/` so they ship with the extension
2. Or publish them as separate skill packages via `gemini skills install`

Shared-file approach is chosen here so skill updates apply across all clients (Claude Code, Copilot, Kiro, Cursor, Codex) from a single source.
