---
name: service-approval
description: Orchestrate all 5 service-approval agents to generate AWS security controls and compliant resource templates for any AWS service
disable-model-invocation: false
argument-hint: "[./input-folder] [--service=<name>] [--env=<profile>] [--skip-test] [--dry-run] [--timeout=<minutes>] [--keep] [--include-unverified] [--clean]"
---

# Service Approval — Orchestrator

Coordinate the 5 service-approval agents to produce a complete set of AWS security controls
and a compliant resource template for any AWS service.

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `./input-folder` | Path to folder with input files (.md, .json, .xlsx, .pdf, .docx) | None (MCP-only mode) |
| `--service=<name>` | AWS service ID (e.g., `bedrock-agentcore-control`) | Required if no folder |
| `--env=<profile>` | AWS CLI profile for Tester | None (skips Tester) |
| `--skip-test` | Skip Tester agent | false |
| `--dry-run` | Lint artifacts, do not deploy | false |
| `--timeout=<minutes>` | Security Hub polling timeout | 30 |
| `--keep` | Keep deployed test resources | false |
| `--include-unverified` | Allow unverified items in generation | false |
| `--clean` | Delete existing .service-approval/ state before run | false |

## Prerequisites

### MCP Pre-flight Check

Before doing anything else, verify all required MCP servers are available. Run this check
automatically — do not ask the user. Install any that are missing.

Required MCPs (all from https://github.com/awslabs/mcp):

| Name | Transport | Endpoint / Command |
|------|-----------|-------------------|
| `awsknowledge` | HTTP | `https://knowledge-mcp.global.api.aws` |
| `aws-documentation` | HTTP | `https://mcp.awsdocs.amazon.com` |
| `awsiac` | HTTP | `https://iac-mcp.global.api.aws` |
| `aws-cdk-mcp-server` | stdio | `npx -y @aws/cdk-mcp-server@latest` |

**Step 1 — Detect environment** (reuse the same logic as Environment Detection below):
- `Agent` tool in tool list → Claude Code
- `KIRO_AGENT` env var set → Kiro
- Otherwise → Generic

**Step 2 — Check and install missing MCPs:**

**Claude Code:**
```bash
INSTALLED=$(claude mcp list 2>/dev/null)
for MCP in awsknowledge aws-documentation awsiac aws-cdk-mcp-server; do
  echo "$INSTALLED" | grep -q "$MCP" && echo "OK: $MCP" || echo "MISSING: $MCP"
done
```
For each MISSING entry, run the corresponding add command:
```bash
claude mcp add --transport http awsknowledge https://knowledge-mcp.global.api.aws
claude mcp add --transport http aws-documentation https://mcp.awsdocs.amazon.com
claude mcp add --transport http awsiac https://iac-mcp.global.api.aws
claude mcp add aws-cdk-mcp-server -- npx -y @aws/cdk-mcp-server@latest
```
After adding any MCP, inform the user: "Added missing MCP servers: <list>. They are now active."

**Kiro:**
```bash
cat ~/.kiro/settings/mcp.json 2>/dev/null || echo "{}"
```
For each missing MCP, add it to `~/.kiro/settings/mcp.json` using this structure:
```json
{
  "mcpServers": {
    "awsknowledge":       { "type": "http", "url": "https://knowledge-mcp.global.api.aws" },
    "aws-documentation":  { "type": "http", "url": "https://mcp.awsdocs.amazon.com" },
    "awsiac":             { "type": "http", "url": "https://iac-mcp.global.api.aws" },
    "aws-cdk-mcp-server": { "command": "npx", "args": ["-y", "@aws/cdk-mcp-server@latest"] }
  }
}
```
Merge (do not overwrite existing entries). Write back the updated file.
After writing, inform the user: "Added missing MCP servers to ~/.kiro/settings/mcp.json: <list>. Restart Kiro if this is the first time adding them."

**Generic (GitHub Copilot, Amazon Q, other):**
Print instructions for each missing MCP and continue — do not block execution:
```
⚠ Missing MCP servers detected. Add these to your IDE's MCP configuration:
  awsknowledge:       { "type": "http", "url": "https://knowledge-mcp.global.api.aws" }
  aws-documentation:  { "type": "http", "url": "https://mcp.awsdocs.amazon.com" }
  awsiac:             { "type": "http", "url": "https://iac-mcp.global.api.aws" }
  aws-cdk-mcp-server: { "command": "npx", "args": ["-y", "@aws/cdk-mcp-server@latest"] }
See: https://github.com/awslabs/mcp
Continuing with degraded MCP coverage — some steps may fall back to web search.
```

- [ ] If `--clean` was passed:
  ```bash
  rm -rf .service-approval/state .service-approval/controls .service-approval/APPROVAL-REPORT.md
  ```

- [ ] Create state directory and log file:
  ```bash
  mkdir -p .service-approval/state
  touch .service-approval/state/mcp-calls.log
  ```

- [ ] Validate required input:
  If no `./input-folder` AND no `--service`, ask the user: "What AWS service should I analyze? (e.g., bedrock-agentcore-control, s3, kms)"

## Environment Detection

Detect execution environment to choose parallelism strategy:

```bash
env | grep -E 'GITHUB_COPILOT|AMAZON_Q_CONTEXT|KIRO_AGENT' 2>/dev/null
```

Additionally: check whether the `Agent` tool appears in your available tool list.
If it does, treat this as Claude Code regardless of env var results.

Decision logic:
- `Agent` tool available in tool list → **Claude Code — use Parallel Mode** (see below)
- `KIRO_AGENT` env var set → **Kiro Sequential Mode** (Kiro does not support multi-agent dispatch from within a skill; run sequentially with file-state handoffs)
- `GITHUB_COPILOT` or `AMAZON_Q_CONTEXT` env var set → **Sequential Mode**
- No signals detected → **Sequential Mode** (safe default)

## Sequential Mode (default for all non-Claude-Code clients)

Run each agent in order. Pass all relevant flags through to each agent.

### Phase 1: Research
Follow ALL instructions in `skills/research/SKILL.md` exactly.
Pass: input folder path, `--service` flag.
When done: verify `.service-approval/state/research.json` exists before proceeding.

### Phase 2: Validate
Follow ALL instructions in `skills/validate/SKILL.md` exactly.
When done: verify `.service-approval/state/validated.json` exists before proceeding.

### Phase 3: Generate
Follow ALL instructions in `skills/generate/SKILL.md` exactly.
Pass: `--include-unverified` if set.
When done: verify `.service-approval/controls/` directory has files before proceeding.

### Phase 4: Test
If `--skip-test` OR `--dry-run` OR no `--env` provided: skip this phase entirely.
Otherwise: follow ALL instructions in `skills/test/SKILL.md` exactly.
Pass: `--env`, `--keep`, `--dry-run`, `--timeout` flags.

### Phase 5: Summarize
Follow ALL instructions in `skills/summarize/SKILL.md` exactly.
Report the final verdict to the user.

## Parallel Mode (Claude Code only — Agent tool available)

IMPORTANT: "Parallel" means Phase 1 runs as a background subagent while the orchestrator
monitors for its output. Phases 2-5 have strict sequential dependencies and run one at a time.
This is NOT bulk parallelism — only Phase 1 benefits from background dispatch.

Execution:
1. Dispatch Researcher as background subagent using the Agent tool.
   Provide the full text of `skills/research/SKILL.md` as the prompt plus input folder and flags.
   Poll `.service-approval/state/research.json` every 10s while other work continues.
2. When `research.json` appears: dispatch Validator as subagent (foreground).
   Provide full text of `skills/validate/SKILL.md` as prompt.
   Wait for `validated.json`.
3. When `validated.json` appears: dispatch Generator as subagent (foreground).
   Provide full text of `skills/generate/SKILL.md` as prompt.
   Wait for `controls/` to be populated.
4. When `controls/` is populated and test not skipped: dispatch Tester as subagent (foreground).
   Provide full text of `skills/test/SKILL.md` as prompt plus `--env` and flags.
   Wait for `test-results.json`.
5. Dispatch Summarizer as subagent (foreground).
   Provide full text of `skills/summarize/SKILL.md` as prompt.
   Wait for `APPROVAL-REPORT.md`.

If polling exceeds `--timeout` minutes for any phase, proceed to Summarizer with partial results.
Summarizer marks the timed-out agent as INCOMPLETE in the report.

## Final Output

```
Service Approval complete.
Report: .service-approval/APPROVAL-REPORT.md
Controls: .service-approval/controls/
Verdict: <APPROVED|APPROVED WITH EXCEPTIONS|REQUIRES REMEDIATION>
```

## Verify frontmatter
```bash
head -5 skills/service-approval/SKILL.md
```
Expected: starts with `---` and contains `name: service-approval`.

## Commit
```bash
cd "/Users/hardikvt/Library/CloudStorage/OneDrive-amazon.com/Hackathon/service-approval-plugin"
git add skills/service-approval/SKILL.md
git commit -m "feat: add orchestrator skill — wires all 5 agents with environment-aware dispatch"
```

Report: Status DONE + commit SHA.
