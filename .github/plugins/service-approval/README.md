# Service Approval — Copilot Plugin

Bundled GitHub Copilot plugin that generates AWS security controls for any AWS service via a 9-phase pipeline.

## What's in the bundle

| Path | Purpose |
|------|---------|
| `../../agents/service-approval.agent.md` | Chat-mode agent (Copilot Chat in Agent mode) |
| `../../prompts/service-approval.prompt.md` | `/service-approval` slash command |
| `../../skills/*/SKILL.md` | 20 skills the agent loads progressively |
| `../../hooks/pipeline-integrity/` | sessionEnd hook — runs integrity checks |
| `../../copilot-instructions.md` | Repo-wide rules (always-applied) |

The plugin references existing files via relative paths — nothing is duplicated. Updates to the shared files (skills, hooks) automatically apply to all clients that discover them.

## Install

Copilot auto-discovers `.github/` contents when the repo is opened in VS Code with Copilot Chat in Agent mode. Nothing to install.

For clean activation:
1. Open the repo in VS Code
2. Open Copilot Chat (Ctrl+Alt+I)
3. Switch to **Agent mode** (not Ask mode)
4. Verify the agent is available: `@service-approval /help` should show the agent

## Usage

```
@service-approval ./input --service=s3 --env=my-profile
@service-approval --service=kms --dry-run
```

Or via slash command:

```
/service-approval --service=bedrock-agentcore-control --skip-test
```

## Hard rules

Enforced at `sessionEnd` via `.github/hooks/pipeline-integrity/validate.sh`:

1. No one-shot generator scripts — every phase runs through its `SKILL.md`
2. Every capability/API/condition-key MCP-verified (no training-data values)
3. `mcp-calls.log` ≥10 entries
4. `validated.json` verification notes unique
5. IaC parameterized — no hardcoded accounts / ARNs
6. SCPs have ≥1 `Deny`; `StringEquals`/`StringNotEquals` target same key
7. Verdict matches integrity — no false `APPROVED`

## MCP servers

Registered via `.vscode/mcp.json` (workspace-scoped):

- `aws-documentation` — service docs, feature references
- `awsknowledge` — SAR queries, condition keys
- `awsiac` — IaC lookups (CFN, CDK, TF)
- `terraform` — Terraform provider details (Docker stdio)

Create `.vscode/mcp.json` if missing:

```json
{
  "servers": {
    "aws-documentation": {
      "type": "stdio",
      "command": "uvx",
      "args": ["awslabs.aws-documentation-mcp-server@latest"],
      "env": {
        "FASTMCP_LOG_LEVEL": "ERROR",
        "AWS_DOCUMENTATION_PARTITION": "aws"
      }
    },
    "awsknowledge": {
      "type": "http",
      "url": "https://knowledge-mcp.global.api.aws"
    },
    "awsiac": {
      "type": "stdio",
      "command": "uvx",
      "args": ["awslabs.aws-iac-mcp-server@latest"],
      "env": {
        "FASTMCP_LOG_LEVEL": "ERROR"
      }
    },
    "terraform": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "hashicorp/terraform-mcp-server:0.5.1"]
    }
  }
}
```

## Layout

```
.github/
├── copilot-instructions.md            Repo-wide rules (always-applied)
├── agents/
│   └── service-approval.agent.md      Agent in Agent mode
├── prompts/
│   └── service-approval.prompt.md     Slash command
├── skills/                            symlink → /skills/
├── hooks/
│   └── pipeline-integrity/
│       ├── hooks.json                 sessionEnd trigger
│       ├── validate.sh                wraps tools/validate/hook_stop.py
│       └── README.md
└── plugins/
    └── service-approval/
        ├── .github/plugin/plugin.json Bundle manifest (this)
        └── README.md                  (this file)
```

## Output

- `.service-approval/<slug>/07-summarize/SUMMARY-REPORT.md` — Summary Report + CCMv4 matrix
- `.service-approval/<slug>/05-recommended-guidance/` — all 78–111 generated artifacts
- `.service-approval/<slug>/` — pipeline state files per phase + mcp-calls.log

## Update

```bash
git pull
```

Skills / hooks / instructions are all file-based — Copilot re-reads them every session. No re-install.

## License

MIT
