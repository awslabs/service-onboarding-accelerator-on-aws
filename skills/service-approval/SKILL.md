---
name: service-approval-v3
description: Orchestrate all 7 service-approval agents (Assess → Research → Validate → Map → Generate → Test → Summarize) to generate AWS security controls and compliant resource templates for any AWS service
disable-model-invocation: false
argument-hint: '[./input-folder] [--service=<name>] [--env=<profile>] [--skip-test] [--questions=<file>] [--dry-run] [--timeout=<minutes>] [--keep] [--include-unverified] [--clean] [--framework=<ccmv4|nist|cis|iso>] [--framework-file=<path>]'
---

# Service Approval — Orchestrator v3

Coordinate the service-approval agents to produce a complete set of AWS security controls
and a compliant resource template for any AWS service.

**Pipeline**: Assess → Research (3 sub-skills) → Validate → Map (4 sub-skills) → Generate (3 sub-skills) → Test → Summarize

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `./input-folder` | Path to folder with input files (.md, .json, .xlsx, .pdf, .docx) | None (MCP-only mode) |
| `--service=<name>` | AWS service ID (e.g., `bedrock-agentcore`) | Required if no folder |
| `--env=<profile>` | AWS CLI profile for Tester | None (skips Tester) |
| `--skip-test` | Skip Tester agent | false |
| `--dry-run` | Lint artifacts, do not deploy | false |
| `--timeout=<minutes>` | Config evaluation timeout | 30 |
| `--keep` | Keep deployed test resources | false |
| `--include-unverified` | Allow unverified items in generation | false |
| `--questions=<file>` | Path to SITCO Bar Questions file (.docx or .txt) — passed to Phase 0 | None |
| `--clean` | Delete existing .service-approval/ state before run | false |
| `--framework=<type>` | Control framework type (ccmv4, nist, cis, iso) — passed to Map phase | auto-detect |
| `--framework-file=<path>` | Explicit path to framework file — passed to Map phase | auto-detect from input folder |

## Agnosticism Guardrails (apply to every sub-skill)

This pipeline is explicitly **AWS-service-agnostic** and **control-framework-agnostic**. Every
skill, sub-skill, validator, and generated artifact MUST honor these rules. They are binding
on all agents executing any phase of the pipeline.

### Service agnosticism

1. **No hardcoded service names in generic skills.** The service name (`Amazon ECS`,
   `AWS Lambda`, `Amazon S3`, etc.) is ALWAYS a runtime argument passed via `--service=<name>`.
   It never appears as a literal in skill files, validator code, or rule descriptions — only
   in examples explicitly labeled as illustrative (e.g., "e.g. `ecs:Create*`"). Service
   prefixes in rule bodies must come from `validated.json` / `sar-facts.json`, not assumption.

2. **Service-specific data belongs in data files, not code.** Lookup tables (`sar-slugs.json`,
   consumer specs, CFN prefixes) MUST live as JSON/YAML data files that any service can
   extend. Code that iterates these files must emit a WARNING on an unknown key — never
   silently skip.

3. **Sub-skills must read service identifiers from state.** `validated.json` has `service`
   and `capabilities.iam.service_prefix`. Sub-skills must read both from there, not infer
   them. The SAR page is the ground truth for any service-specific fact.

### Framework agnosticism

1. **No hardcoded framework names or objective IDs in generic skills.** Framework domain
   names (`CEK-03`, `IAM-04`, `AC-2`, `CIS 1.1`) appear ONLY in `map-parse-framework` and
   `map-framework-mapping` skills, which dispatch on the `--framework=<type>` argument. Never
   in `generate-*` skills, never in validators.

2. **Customer framework is supplied at runtime.** Every pipeline run takes
   `--framework-file=<path>` pointing at a customer-provided file (xlsx/json/md). No
   framework ships bundled except as a schema/parser reference.

### No service-specific helper scripts

Agents executing any phase MUST NOT create service-specific helper scripts in `scripts/`,
`.service-approval/state/`, or `service-approval-plugin/`. If a one-off computation is
needed:
- Keep it inline in the agent's task (Python `python3 -c "..."` or Bash)
- Or write it under `/tmp/` for the duration of the run
- Never commit or persist a file named `build-<service>-*.py`, `fix-<service>-*.sh`, or
  similar. Durable tooling belongs in the plugin's own `tools/` tree and must be generic
  across services.

### Enforcement

- Every generic skill in this pipeline MUST state its agnosticism in its own header if it
  adds any consumer/service logic. If it cannot be generic (e.g., `map-parse-framework`
  for CCMv4), it MUST be a dedicated sub-skill that dispatches on argument.
- If an agent notices a rule, table, or validator check that would need rewriting to run
  on a different AWS service or a different framework, flag it as a CONTRADICTS-AGNOSTICISM
  finding and stop until resolved.

---

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
- `GEMINI_CLI_VERSION` env var set → Gemini CLI
- `AMAZON_Q_CONTEXT` or `Q_DEVELOPER_CLI` env var set → Amazon Q Developer
- `CURSOR_TRACE_ID` env var set → Cursor
- `WINDSURF_EXTENSION_ID` or `CODEIUM_API_KEY` env var set → Windsurf
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

**Step 3 — Handle MCPs that are registered but failing to connect:**
If any MCP is listed but shows "Failed to connect" or is unreachable, warn the user:
```
MCP degraded coverage:
  aws-documentation UNREACHABLE — Research and Validate will fall back to web search.
  awsiac UNREACHABLE — Generate will use best-effort generation.
```
Do NOT block execution — continue with degraded coverage and note it in the final report.

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

**Gemini CLI:**
```bash
cat ~/.gemini/settings.json 2>/dev/null || echo "{}"
```
For each missing MCP, add it to `~/.gemini/settings.json` under `mcpServers`:
```json
{
  "mcpServers": {
    "awsknowledge":       { "httpUrl": "https://knowledge-mcp.global.api.aws" },
    "aws-documentation":  { "httpUrl": "https://mcp.awsdocs.amazon.com" },
    "awsiac":             { "httpUrl": "https://iac-mcp.global.api.aws" },
    "aws-cdk-mcp-server": { "command": "npx", "args": ["-y", "@aws/cdk-mcp-server@latest"] }
  }
}
```
Merge (do not overwrite existing entries). Write back the updated file.

**Amazon Q Developer:**
```bash
cat ~/.aws/amazonq/mcp.json 2>/dev/null || echo "{}"
```
For each missing MCP, add it to `~/.aws/amazonq/mcp.json`:
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
Merge and write back. Inform the user to restart Amazon Q Developer if MCPs were added.

**Cursor:**
```bash
cat ~/.cursor/mcp.json 2>/dev/null || cat .cursor/mcp.json 2>/dev/null || echo "{}"
```
For each missing MCP, add it to `~/.cursor/mcp.json` (or workspace `.cursor/mcp.json`):
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
Merge and write back.

**Windsurf:**
```bash
cat ~/.codeium/windsurf/mcp_config.json 2>/dev/null || echo "{}"
```
For each missing MCP, add it to `~/.codeium/windsurf/mcp_config.json`:
```json
{
  "mcpServers": {
    "awsknowledge":       { "serverUrl": "https://knowledge-mcp.global.api.aws" },
    "aws-documentation":  { "serverUrl": "https://mcp.awsdocs.amazon.com" },
    "awsiac":             { "serverUrl": "https://iac-mcp.global.api.aws" },
    "aws-cdk-mcp-server": { "command": "npx", "args": ["-y", "@aws/cdk-mcp-server@latest"] }
  }
}
```
Merge and write back.

**Generic (GitHub Copilot, Aider, Continue, other):**
Print instructions for each missing MCP and continue — do not block execution:
```
Missing MCP servers detected. Add these to your IDE's MCP configuration:
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

- [ ] Check for stale state — if `.service-approval/state/` exists AND `--clean` was NOT passed:
  Tell the user: "Existing state found in .service-approval/. Use --clean to start fresh, or I'll
  run all phases again and overwrite. Proceeding with fresh run."
  Then continue — NEVER silently read or report from old state files.

- [ ] Create state directory and log file:
  ```bash
  mkdir -p .service-approval/state
  touch .service-approval/state/mcp-calls.log
  ```

- [ ] Validate required input:
  If no `./input-folder` AND no `--service`, ask the user:
  "What AWS service should I analyze? (e.g., bedrock-agentcore, s3, kms)"
  Do NOT proceed until the user provides a service name or input folder.

## Environment Detection

Detect execution environment to choose parallelism strategy:

```bash
env | grep -E 'KIRO_AGENT|GEMINI_CLI_VERSION|AMAZON_Q_CONTEXT|Q_DEVELOPER_CLI|CURSOR_TRACE_ID|WINDSURF_EXTENSION_ID|CODEIUM_API_KEY|GITHUB_COPILOT' 2>/dev/null
```

Additionally: check whether the `Agent` tool appears in your available tool list.
If it does, treat this as Claude Code regardless of env var results.

Decision logic:
- `Agent` tool available in tool list → **Claude Code — use Parallel Mode** (see below)
- `KIRO_AGENT` env var set → **Kiro — Sequential Mode**
- `GEMINI_CLI_VERSION` env var set → **Gemini CLI — Sequential Mode**
- `AMAZON_Q_CONTEXT` or `Q_DEVELOPER_CLI` env var set → **Amazon Q Developer — Sequential Mode**
- `CURSOR_TRACE_ID` env var set → **Cursor — Sequential Mode**
- `WINDSURF_EXTENSION_ID` or `CODEIUM_API_KEY` env var set → **Windsurf — Sequential Mode**
- `GITHUB_COPILOT` env var set → **GitHub Copilot — Sequential Mode**
- No signals detected → **Sequential Mode** (safe default)

---

## Sequential Mode (default for all non-Claude-Code clients)

Run each phase in order. Pass all relevant flags through.

### Phase 0: Assess (Mandatory)
Follow ALL instructions in `skills/assess/SKILL.md` exactly.
Pass: input folder path, `--service` flag, `--questions` flag if provided.
When done: verify these files exist before proceeding:
- `.service-approval/state/sar-facts.json`
- `.service-approval/state/checkpoint-results.json`
- `.service-approval/state/assessment-summary.md`

**Skip condition**: Phase 0 is skipped ONLY if all three assessment artifacts already
exist (from a previous `/assess` run). There is no flag to skip assessment.

### Phase 1: Research (3+1 sub-skills, sequential in this mode)

**Step 1a — Mitigations:**
Follow ALL instructions in `skills/research-mitigations/SKILL.md`.
Pass: `./input-folder`, `--service`.
Wait for `.service-approval/state/research-mitigations.json`.

**Step 1b — Capabilities:**
Follow ALL instructions in `skills/research-capabilities/SKILL.md`.
Pass: `--service`.
Wait for `.service-approval/state/research-capabilities.json`.

**Step 1c — API Surface:**
Follow ALL instructions in `skills/research-api-surface/SKILL.md`.
Pass: `--service`.
Wait for `.service-approval/state/research-api-surface.json`.

**Step 1d — ATT&CK Attack Surface (optional):**
Follow ALL instructions in `skills/research-attack-surface/SKILL.md`.
Pass: `--service`.
Wait for `.service-approval/state/research-attack-surface.json`.
Skip this step if ATT&CK enrichment is not needed (no customer threat model input).

**Step 1e — Merge:**
Run the merge step from `skills/research/SKILL.md` → "Merge Step" section.
Verify `.service-approval/state/research.json` exists and has `schema_version: "3.0"`.

### Phase 2: Validate
Follow ALL instructions in `skills/validate/SKILL.md` exactly.
When done: verify `.service-approval/state/validated.json` exists before proceeding.

### Phase 3: Map (4 sub-skills, sequential in this mode)

**Step 3a — Parse Framework:**
Follow ALL instructions in `skills/map-parse-framework/SKILL.md`.
Pass: `--framework` and `--framework-file` flags if provided.
Wait for `.service-approval/state/map-framework-parsed.json`.

**Step 3b — Generate Controls:**
Follow ALL instructions in `skills/map-generate-controls/SKILL.md`.
Pass: `--service`.
Wait for `.service-approval/state/map-controls-generated.json`.

**Step 3c — Framework Mapping:**
Follow ALL instructions in `skills/map-framework-mapping/SKILL.md`.
Wait for `.service-approval/state/map-framework-mapped.json`.

**Step 3d — Assemble:**
Follow ALL instructions in `skills/map-assemble/SKILL.md`.
Verify these files exist before proceeding:
- `.service-approval/state/mapping-results.json`
- `.service-approval/state/controls-catalog.md`
- `.service-approval/state/framework-mapping.md`

### Phase 4: Generate (3 sub-skills, sequential in this mode)

**Step 4a — Preventive/Proactive:**
Follow ALL instructions in `skills/generate-preventive/SKILL.md`.
Pass: `--service`, `--include-unverified` if set.
Wait for `controls/preventive/` and `controls/proactive/` to be populated.

**Step 4b — Detective/Corrective:**
Follow ALL instructions in `skills/generate-detective/SKILL.md`.
Pass: `--service`, `--include-unverified` if set.
Wait for `controls/detective/` and `controls/remediation/` to be populated.

**Step 4c — IaC Templates:**
Follow ALL instructions in `skills/generate-iac/SKILL.md`.
Pass: `--service`, `--include-unverified` if set.
Wait for `controls/iac/` to have all 4 formats.

**Step 4d — Final Validation:**
Run the final validation from `skills/generate/SKILL.md` → "Final Validation" section.

### Phase 5: Test
If `--skip-test` OR `--dry-run` OR no `--env` provided: skip this phase entirely.
Otherwise: follow ALL instructions in `skills/test/SKILL.md` exactly.
Pass: `--env`, `--keep`, `--dry-run`, `--timeout` flags.

### Phase 6: Summarize
Follow ALL instructions in `skills/summarize/SKILL.md` exactly.
Report the final verdict to the user.

---

## Parallel Mode (Claude Code only — Agent tool available)

Leverage the Agent tool to parallelize independent sub-skills within each phase.

### Phase 0: Assess (Mandatory)
If all 3 assessment artifacts already exist, skip (previous `/assess` run).
Otherwise: dispatch Assessor as foreground subagent.
Wait for all 3 assessment artifacts.

### Phase 1: Research (3+1 sub-skills in parallel)

Dispatch all 4 research sub-skills simultaneously as background subagents:

```
Agent 1: research-mitigations (background)
  Prompt: Full text of skills/research-mitigations/SKILL.md + input folder + --service flag
  Output: research-mitigations.json

Agent 2: research-capabilities (background)
  Prompt: Full text of skills/research-capabilities/SKILL.md + --service flag
  Output: research-capabilities.json

Agent 3: research-api-surface (background)
  Prompt: Full text of skills/research-api-surface/SKILL.md + --service flag
  Output: research-api-surface.json

Agent 4: research-attack-surface (background, optional)
  Prompt: Full text of skills/research-attack-surface/SKILL.md + --service flag
  Output: research-attack-surface.json
  Note: Always dispatch — runs fast and enriches controls with threat traceability.
  If it fails, pipeline continues without it (backward compatible).
```

**IMPORTANT:** Dispatch all 4 in a single message with 4 Agent tool calls.
Do NOT set `model` parameter — let subagents inherit the caller's model.

When all 4 complete (or 3 complete + Agent 4 fails gracefully), run the merge step
from `skills/research/SKILL.md`:
- Combine the 3 required partial JSONs into `research.json`
- If `research-attack-surface.json` exists, merge its data into `attack_surface`
- Run the validation script
- If CRITICAL cross-reference errors exist (actions missing from both operations[] and
  permission_only_actions[]), re-dispatch the api-surface agent with the missing action list

### Phase 2: Validate
Dispatch Validator as foreground subagent.
Provide full text of `skills/validate/SKILL.md`.
Wait for `validated.json`.

### Phase 3: Map (4 sub-skills, 2 parallel + 2 sequential)

**Steps 3a+3b: Parallel dispatch**

Dispatch both independent sub-skills simultaneously as background subagents:

```
Agent 3a: map-parse-framework (background)
  Prompt: Full text of skills/map-parse-framework/SKILL.md + framework flags
  Output: map-framework-parsed.json

Agent 3b: map-generate-controls (background)
  Prompt: Full text of skills/map-generate-controls/SKILL.md + --service flag
  Output: map-controls-generated.json
```

**IMPORTANT:** Dispatch both in a single message with 2 Agent tool calls.

**Step 3c: Framework mapping (foreground, after 3a+3b complete)**

When both complete, dispatch as foreground subagent:

```
Agent 3c: map-framework-mapping (foreground)
  Prompt: Full text of skills/map-framework-mapping/SKILL.md
  Input: map-framework-parsed.json + map-controls-generated.json
  Output: map-framework-mapped.json
```

This is the most reasoning-heavy step — MUST run in foreground to ensure quality gates pass.

**Step 3d: Assembly (foreground, after 3c completes)**

Dispatch as foreground subagent:

```
Agent 3d: map-assemble (foreground)
  Prompt: Full text of skills/map-assemble/SKILL.md
  Input: All 3 intermediate files + validated.json
  Output: mapping-results.json + controls-catalog.md + framework-mapping.md
```

Wait for `mapping-results.json`, `controls-catalog.md`, `framework-mapping.md`.

### Phase 4: Generate (3 sub-skills in parallel)

Dispatch all 3 generate sub-skills simultaneously as background subagents:

```
Agent 4: generate-preventive (background)
  Prompt: Full text of skills/generate-preventive/SKILL.md + --service + --include-unverified
  Output: controls/preventive/ + controls/proactive/

Agent 5: generate-detective (background)
  Prompt: Full text of skills/generate-detective/SKILL.md + --service + --include-unverified
  Output: controls/detective/ + controls/remediation/

Agent 6: generate-iac (background)
  Prompt: Full text of skills/generate-iac/SKILL.md + --service + --include-unverified
  Output: controls/iac/
```

**IMPORTANT:** Dispatch all 3 in a single message with 3 Agent tool calls.

When all 3 complete, run the final validation from `skills/generate/SKILL.md`.
If any IaC templates are missing, re-dispatch the generate-iac agent.

### Phase 5: Test
If not skipped: dispatch Tester as foreground subagent.

### Phase 6: Summarize
Dispatch Summarizer as foreground subagent.
Wait for `APPROVAL-REPORT.md`.

### Parallelism Summary

```
Phase 0: Assess          (1 agent, foreground)
Phase 1: Research         (4 agents in parallel, then merge)
  1a: Mitigations         (background) ─┐
  1b: Capabilities        (background) ─┤
  1c: API Surface         (background) ─┤
  1d: ATT&CK Surface      (background) ─┤
                                        └─ 1e: Merge (foreground)
Phase 2: Validate         (1 agent, foreground)
Phase 3: Map              (2 agents in parallel, then 2 sequential)
  3a: Parse Framework     (background) ─┐
  3b: Generate Controls   (background) ─┤
                                        ├─ 3c: Framework Mapping (foreground)
                                        └─ 3d: Assemble          (foreground)
Phase 4: Generate         (3 agents in parallel, then validate)
Phase 5: Test             (1 agent, foreground)
Phase 6: Summarize        (1 agent, foreground)
```

Total agents: up to 14 (vs 7 in monolithic mode), but with 3 parallelization windows
that significantly reduce wall-clock time.

If any agent exceeds `--timeout` minutes, proceed to Summarizer with partial results.
Summarizer marks the timed-out agent as INCOMPLETE in the report.

---

## Final Output

```
Service Approval complete.
Report: .service-approval/APPROVAL-REPORT.md
Controls: .service-approval/controls/
Verdict: <APPROVED|APPROVED WITH EXCEPTIONS|REQUIRES REMEDIATION>
```
