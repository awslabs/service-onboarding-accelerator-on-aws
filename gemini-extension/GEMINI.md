# Service Approval — Gemini CLI Extension

You are running the `service-approval` extension. It generates AWS security controls and compliant IaC for any AWS service.

## How to invoke

Say any of:
- "run service approval for <service-name>"
- "generate AWS security controls for <service-name>"
- "service approval ./input --service=<name>"

Or use the slash command: `/service-approval` (with args after).

## Entry point

**Read `${extensionPath}/../skills/service-approval/SKILL.md` in full.** That file is the authoritative orchestrator. Follow every step — don't deviate.

The extension bundles 18 skills total in `${extensionPath}/../skills/`. Each has its own `SKILL.md` with frontmatter and instructions. The agentskills.io format — identical to Claude Code and GitHub Copilot, so the same skill files serve all three clients.

## Pipeline (7 phases, 19 sub-skills)

```
Phase 0 Assess       → state/sar-facts.json, state/checkpoint-results.json
Phase 1 Research     → state/research.json (4 parallel sub-skills merged)
Phase 2 Validate     → state/validated.json
Phase 3 Map          → state/mapping-results.json + framework-mapping.md
Phase 4 Generate     → controls/ (78–111 files)
Phase 5 Test         → state/test-results.json (optional, needs AWS creds)
Phase 6 Summarize    → APPROVAL-REPORT.md
```

All output goes to `.service-approval/` in the working directory.

## Parameters

| Parameter | Description |
|-----------|-------------|
| `service` | AWS service ID (e.g., `s3`, `kms`, `bedrock-agentcore-control`). Required unless input folder is given. |
| input folder | Customer docs (.md, .json, .xlsx, .pdf, .docx). Optional. |
| `env` | AWS CLI profile for Phase 5 Test. Optional — skips Test if absent. |
| `framework` | `ccmv4`, `nist`, `cis`, or `iso`. Auto-detected from input. |
| `skip-test` | Skip deployment validation. |
| `dry-run` | Lint only, no deployment. |

## Hard rules — no shortcuts

Enforced by the `AfterAgent` hook at `${extensionPath}/hooks/hooks.json` which
runs `tools/validate/hook_stop.py`. Exit code 2 blocks the agent turn and forces
a retry or the verdict `REQUIRES REMEDIATION`.

1. Never write a one-shot generator script that hardcodes state or controls. Run every phase through its `SKILL.md`.
2. Every capability claim, API parameter, and condition key must be verified via MCP (`awsknowledge`, `aws-documentation`, `awsiac`). Hardcoded values from training data are banned.
3. Log every MCP call to `.service-approval/state/mcp-calls.log`. Minimum 10 entries.
4. Every item in `validated.json` must have a unique `verification_note` specific to that item. Templated notes fail integrity check.
5. IaC templates must be parameterized. No hardcoded account IDs (`123456789012`) or placeholder ARNs.
6. SCPs must contain at least one `Deny` statement. `StringEquals` and `StringNotEquals` in the same Condition must target the same key.
7. Verdict matches integrity. Any integrity failure → verdict is `REQUIRES REMEDIATION`, not `APPROVED`.

## MCP servers available

Registered in `gemini-extension.json`:

| Server | Purpose |
|--------|---------|
| `aws-documentation` | Service docs, feature references, IAM key semantics |
| `awsknowledge` | SAR queries, condition keys, service capabilities |
| `awsiac` | IaC lookups: CFN, CDK, Terraform provider schema |
| `terraform` | Terraform provider details (stdio via Docker) |
| `kb-search` | Amazon Bedrock KB — customer-specific mitigations (optional) |

Start every capability / condition-key / API-param lookup with one of these. Don't rely on training data.

## Parallelization

Gemini CLI supports parallel sub-agent runs. Three phases benefit:

**Phase 1 Research (4 parallel):**
- `skills/research-mitigations/`
- `skills/research-capabilities/`
- `skills/research-api-surface/`
- `skills/research-attack-surface/` (optional)

**Phase 3 Map (2 parallel, then 2 sequential):**
- `skills/map-parse-framework/`
- `skills/map-generate-controls/`
- then `skills/map-framework-mapping/` → `skills/map-assemble/`

**Phase 4 Generate (3 parallel):**
- `skills/generate-preventive/`
- `skills/generate-detective/`
- `skills/generate-iac/`

## Output

- `.service-approval/APPROVAL-REPORT.md` — final report + CCMv4 coverage matrix
- `.service-approval/controls/` — all generated artifacts
- `.service-approval/state/` — pipeline state files + mcp-calls.log

## Install notes

This extension is symlink-installed (`gemini extensions link`). `git pull` in the parent repo auto-updates the extension on next Gemini session.

If Gemini reports "extension not loading", run `gemini extensions list` to confirm it's registered. If the MCP servers aren't available, restart the Gemini session.

## Debugging

- `gemini extensions list` — confirm extension is loaded
- `gemini extensions config service-approval` — inspect settings
- Check `.service-approval/state/mcp-calls.log` mid-run to confirm MCP calls happening
- If a sub-skill produces empty output, the MCP server is probably unreachable — check network / Docker (for terraform MCP)
