# Service Approval — GitHub Copilot Instructions

## How to invoke
Type: `@service-approval [./input-folder] [--service=<name>] [--env=<profile>] [--skip-test] [--dry-run]`

Examples:
- `@service-approval ./Hackathon --service=bedrock-agentcore-control --skip-test`
- `@service-approval --service=s3 --env=my-dev-profile`

Flags can also be expressed in natural language:
- "run service approval for bedrock agentcore skipping the test phase"
- "generate controls for s3 using the dev aws profile"

## What it does
Read the skill at `skills/service-approval/SKILL.md` and follow it step by step.
Run 9 phases: Intake → Assess → Research → Validate → Map → Generate → Test → Summarize → Evidence.
All state is written to `.service-approval/<service-slug>/` (per-service layout) in the current working directory.

## MCP servers
Registered via `.vscode/mcp.json`. Confirm these are reachable before starting the skill:
- `aws-documentation` (HTTP)
- `awsknowledge` (HTTP)
- `awsiac` (HTTP)
- `terraform` (stdio via Docker — `hashicorp/terraform-mcp-server:0.5.1`)

Note: the `aws-cdk` MCP server was removed from this plugin. CDK/CDKTF construct lookups
should use `aws-documentation` and `awsiac` instead. If the skill instructs you to use
`aws-cdk-mcp-server`, fall back to those two.

## Output
- Final report: `.service-approval/<service-slug>/07-summarize/SUMMARY-REPORT.md`
- All controls: `.service-approval/<service-slug>/05-recommended-guidance/`
- State files: `.service-approval/<service-slug>/` (per-phase subdirectories)
- Evidence: `.service-approval/<service-slug>/08-evidence/` (if Phase 7 runs)

## Agent mode required
This skill writes files and runs multi-step workflows. Use Copilot Chat in **Agent mode**,
not Ask mode.

## Hard rules — no shortcuts
1. Never write a one-shot generator script that hardcodes state or controls. Run the
   9-phase pipeline (Intake, Assess, Research, Validate, Map, Generate, Test, Summarize, Evidence) as described
   in `skills/service-approval/SKILL.md`.
2. Every capability claim, API parameter, and condition key must be verified via MCP
   (`awsknowledge`, `aws-documentation`, `awsiac`). Hardcoded values from training data
   are banned.
3. Log every MCP call to `.service-approval/<service-slug>/mcp-calls.log`. The Stop hook enforces
   a minimum of 10 logged calls.
4. Every item in `validated.json` must have a unique `verification_note` specific to that
   item. Templated or duplicated notes fail integrity checks.
5. IaC templates must be parameterized. No hardcoded account IDs (`123456789012`) or
   placeholder ARNs.
6. SCPs must contain at least one `Deny` statement. `StringEquals` and `StringNotEquals`
   in the same Condition must target the same key or the statement cannot fire.
7. Verdict must match integrity. If any pipeline integrity check fails, the verdict is
   `REQUIRES REMEDIATION`, not `APPROVED`.

The Stop hook runs `validate_pipeline_integrity.py` and blocks on any rule above.
