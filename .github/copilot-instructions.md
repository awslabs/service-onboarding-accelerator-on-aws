# Service Approval — GitHub Copilot Instructions

## How to invoke
Type: `@service-approval [./input-folder] [--service=<name>] [--framework=<ccmv4|nist|cis|iso>]`

Examples:
- `@service-approval ./Hackathon --service=bedrock-agentcore-control`
- `@service-approval --service=s3`

Flags can also be expressed in natural language:
- "run service approval for bedrock agentcore"
- "map controls for s3"

## What it does
Read the skill at `skills/service-approval/SKILL.md` and follow it step by step.
Run 6 phases: Intake → Assess → Research → Validate → Map → Summarize.
All state is written to `.service-approval/<service-slug>/` (per-service layout) in the current working directory.

## MCP servers
Registered via `.vscode/mcp.json`. Confirm these are reachable before starting the skill:
- `aws-documentation` (HTTP)
- `awsknowledge` (HTTP)
- `awsiac` (HTTP)

## Output
- Final report: `.service-approval/<service-slug>/05-summarize/APPROVAL-REPORT.md`
- State files: `.service-approval/<service-slug>/` (per-phase subdirectories)

## Agent mode required
This skill writes files and runs multi-step workflows. Use Copilot Chat in **Agent mode**,
not Ask mode.

## Hard rules — no shortcuts
1. Never write a one-shot generator script that hardcodes state or controls. Run the
   6-phase pipeline (Intake, Assess, Research, Validate, Map, Summarize) as described
   in `skills/service-approval/SKILL.md`.
2. Every capability claim, API parameter, and condition key must be verified via MCP
   (`awsknowledge`, `aws-documentation`, `awsiac`). Hardcoded values from training data
   are banned.
3. Log every MCP call to `.service-approval/<service-slug>/mcp-calls.log`. The Stop hook enforces
   a minimum of 10 logged calls.
4. Every item in `validated.json` must have a unique `verification_note` specific to that
   item. Templated or duplicated notes fail integrity checks.
5. Verdict must match integrity. If any pipeline integrity check fails, the verdict is
   `REQUIRES REMEDIATION`, not `APPROVED`.

The Stop hook runs `validate_pipeline_integrity.py` and blocks on any rule above.
