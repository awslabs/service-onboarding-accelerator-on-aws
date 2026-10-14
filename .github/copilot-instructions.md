# Service Approval — GitHub Copilot Instructions

## How to invoke
Type: `@service-approval [./input-folder] [--service=<name>] [--framework=<ccmv4|nist|cis|iso>] [--dry-run]`

Examples:
- `@service-approval ./Hackathon --service=bedrock-agentcore-control`
- `@service-approval --service=s3 --framework=ccmv4`

Flags can also be expressed in natural language:
- "run service approval for bedrock agentcore"
- "generate controls for s3 against CCMv4"

## What it does
Read the skill at `skills/service-approval/SKILL.md` and follow it step by step.
Run the pipeline: Intake → Assess → Research → Validate → Map → Recommended Guidance → Summarize.
It recommends controls; you deploy them yourself.
Every run requires a published AWS Threat Model retrieved from the latest release.
Run the canonical Intake fetch gate before MCP/assessment/research. Missing
services or retrieval failures stop the run; local files cannot substitute.
Resume checks the latest release with `--refresh`; changed models require a fresh
Intake and regeneration. See `docs/THREAT-MODELS.md`.
All state is written to `.service-approval/<service-slug>/` (per-service layout) in the current working directory.

## MCP servers
Registered via `.vscode/mcp.json`. Confirm these are reachable before starting the skill:
- `aws-documentation` (stdio, via `uvx`)
- `awsknowledge` (HTTP)
- `mitre-attack` (stdio, via `uvx`; falls back to bundled `data/attack-cloud-matrix.json`)

The pipeline can also run without any MCP servers — pass `--no-mcp` and facts are
verified over the web instead. See the "Running without MCP" section of
`docs/USAGE-COPILOT.md`.

## Output
- Final report: `.service-approval/<service-slug>/06-summarize/SUMMARY-REPORT.md`
- All controls: `.service-approval/<service-slug>/05-recommended-guidance/`
- State files: `.service-approval/<service-slug>/` (per-phase subdirectories)

## Agent mode required
This skill writes files and runs multi-step workflows. Use Copilot Chat in **Agent mode**,
not Ask mode.

## Hard rules — no shortcuts
1. Never write a one-shot generator script that hardcodes state or controls. Run the
   pipeline (Intake, Assess, Research, Validate, Map, Recommended Guidance, Summarize) as described
   in `skills/service-approval/SKILL.md`.
2. Every capability claim, API parameter, and condition key must be verified via MCP
   (`awsknowledge`, `aws-documentation`). Hardcoded values from training data
   are banned.
3. Log every MCP call to `.service-approval/<service-slug>/mcp-calls.log`. The Stop hook enforces
   a minimum of 10 logged calls.
4. Every item in `validated.json` must have a unique `verification_note` specific to that
   item. Templated or duplicated notes fail integrity checks.
5. SCPs must contain at least one `Deny` statement. `StringEquals` and `StringNotEquals`
   in the same Condition must target the same key or the statement cannot fire.
6. Verdict must match integrity. If any pipeline integrity check fails, the verdict is
   `REQUIRES REMEDIATION`, not `APPROVED`.

The Stop hook runs `validate_pipeline_integrity.py` and blocks on any rule above.
