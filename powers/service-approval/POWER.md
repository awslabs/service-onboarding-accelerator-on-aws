---
name: service-approval
displayName: AWS Service Security Controls Generator
description: Generate AWS security controls and compliant IaC for any AWS service. Runs a 9-phase pipeline (Intake, Assess, Research, Validate, Map, Generate, Test, Summarize, Evidence) mapped to CCMv4 / NIST 800-53 / CIS / ISO frameworks.
keywords:
- aws
- security
- controls
- compliance
- ccmv4
- nist-800-53
- cis
- iso-27001
- scp
- rcp
- config-rules
- cfn-guard
- checkov
- opa
- terraform
- cloudformation
- cdk
- cdktf
- mitre-attack
- preventive-controls
- detective-controls
- proactive-controls
- responsive-controls
author: GFS PACE
version: 1.0.0
---

# AWS Service Security Controls Generator

## Overview

This Power drives a 9-phase pipeline that generates AWS security controls for any AWS service. It reads customer inputs (mitigation reports, threat models, framework spreadsheets), researches the service via AWS knowledge MCP servers, maps every capability to a control framework (CCMv4, NIST 800-53, CIS, ISO), and produces a full set of deployable artifacts.

**Key capabilities:**
- **9-phase pipeline** — Intake → Assess → Research → Validate → Map → Generate → Test → Summarize → Evidence, with 20 sub-skills
- **Parallel execution** — 4 research sub-skills, 3 generate sub-skills run concurrently via Kiro's `/spawn` command
- **MCP-driven verification** — every capability claim, API parameter, and condition key is verified via `awsknowledge`, `aws-documentation`, and `awsiac` MCPs. Hardcoded values from training data are banned.
- **Full artifact coverage** — SCPs, RCPs, Config rules + Lambda handlers, CFN Guard rules, OPA policies, Checkov custom policies, CFN Hooks, CDK/CDKTF/Terraform/CloudFormation templates
- **Integrity-enforced** — the Stop hook runs `validate_pipeline_integrity.py` and blocks shortcut runs

## Prerequisites

1. **Python 3.9+**: `python3 --version`
2. **MCP servers** registered in `mcp.json` (auto-loaded by this Power):
   - `aws-documentation` (HTTP)
   - `awsknowledge` (HTTP)
   - `awsiac` (HTTP)
   - `terraform` (stdio via Docker — `hashicorp/terraform-mcp-server:0.5.1`)
3. **AWS CLI profile** (optional, for Phase 5 Test) — passed via `--env=<profile>`

## How to invoke

Triggered by keyword match. Say any of:
- "run service approval for <service-name>"
- "generate AWS security controls for <service-name>"
- "service approval ./input --service=<name>"
- "run the 9-phase pipeline on <service-name>"

Explicit invocation: ask Kiro to *"use the service-approval Power for Amazon S3"*.

### Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| `service` | AWS service ID (e.g., `s3`, `kms`, `bedrock-agentcore-control`) | Yes (unless input folder provided) |
| input folder | Customer docs (.md, .json, .xlsx, .pdf, .docx) | No |
| `env` | AWS CLI profile for Phase 5 | No (skips Test if absent) |
| `framework` | `ccmv4`, `nist`, `cis`, `iso` | Auto-detected |
| `skip-test` | Skip deployment validation | No |
| `dry-run` | Lint only, no deployment | No |

## Pipeline

```
Phase Intake         → _staging/<ts>/00-intake/intake-manifest.json (promoted to <slug>/00-intake/ in Phase 0)
Phase 0 Assess       → <slug>/01-assess/sar-facts.json, checkpoint-results.json, iac-support.json
Phase 1 Research     → <slug>/02-research/research.json (4 parallel sub-skills merged)
Phase 2 Validate     → <slug>/03-validate/validated.json
Phase 3 Map          → <slug>/04-map/mapping-results.json + framework-mapping.md
Phase 4 Generate     → <slug>/05-generate/{preventive, proactive, detective, responsive, iac}/
Phase 5 Test         → <slug>/06-test/test-results.json + deployed-resources.json (needs --env)
Phase 6 Summarize    → <slug>/07-summarize/APPROVAL-REPORT.md
Phase 7 Evidence     → <slug>/08-evidence/attestation-report.md + <slug>/attestation.md (runs after Phase 5 Test)
```

**Parallelization windows** (use `/spawn` at these points):
- Window 1 — Research (Phase 1a–1d): 4 subagents
- Window 2 — Map (Phase 3a–3b): 2 subagents, then 3c and 3d sequential
- Window 3 — Generate (Phase 4a–4c): 3 subagents

All output lands in `.service-approval/` in the working directory.

## How to execute

Read `steering/pipeline.md` in full — that file is the authoritative phase-by-phase
guide. For deep dives into specific phases, `steering/phase-*.md` loads contextually
when Kiro routes the task.

Agent definitions for each sub-skill live in `agents/sa-*.json`. Kiro CLI 2.0 loads
these from `.kiro/agents/` at workspace scope after this Power is installed.

## Hard rules — no shortcuts

The Stop hook (`hooks/stop.json`) runs `tools/validate/hook_stop.py` which invokes
`validate_pipeline_integrity.py`. The hook blocks the Stop event (exit code 2) on
any of these violations:

1. Never write a one-shot generator script that hardcodes state or controls. Run every phase through its `SKILL.md`.
2. Every capability claim, API parameter, and condition key must be verified via MCP. Hardcoded values from training data are banned.
3. Log every MCP call to `.service-approval/<slug>/mcp-calls.log`. Minimum 10 entries enforced.
4. Every item in `validated.json` must have a unique `verification_note` specific to that item. Templated notes fail integrity checks.
5. IaC templates must be parameterized. No hardcoded account IDs (`123456789012`) or placeholder ARNs.
6. SCPs must contain at least one `Deny` statement. `StringEquals` and `StringNotEquals` in the same Condition must target the same key.
7. Verdict matches integrity. Any integrity failure → verdict is `REQUIRES REMEDIATION`, not `APPROVED`.

## Output

- `.service-approval/APPROVAL-REPORT.md` — final report + CCMv4 coverage matrix
- `.service-approval/<slug>/05-generate/` — all generated artifacts (85+ files)
- `.service-approval/<slug>/` — pipeline state files per phase (01-assess/, 02-research/, 03-validate/, 04-map/, 05-generate/, 06-test/)
- `.service-approval/ARTIFACT-FLOW-MATRIX.md` — per-artifact input/output dependency graph

## Troubleshooting

### `mcp-calls.log missing` (P1 hook failure)
Every subagent must call `@awsknowledge`, `@aws-documentation`, or `@awsiac` at least once and log to `.service-approval/<slug>/mcp-calls.log`. Check the Research and Validate phases — these are where calls are concentrated.

### `validated.json verification notes duplicated` (P2)
Every `verification_note` must be item-specific. If Kiro is templating notes, re-run Validate with stricter prompting: *"write a unique verification note citing the exact MCP call result for each item."*

### Verdict mismatch (P6)
If `APPROVED` appears despite integrity failures, the Stop hook will force `REQUIRES REMEDIATION`. Fix upstream integrity issues, rerun from the failing phase.

### Headless mode

For CI integration, set `KIRO_API_KEY` and invoke:
```bash
kiro-cli --no-interactive --trust-tools="aws-documentation,awsknowledge,awsiac,terraform" \
  "run service approval for s3"
```
See `steering/headless.md` for the full CI recipe.

## Resources

- Agent Skills spec: https://agentskills.io
- Kiro CLI docs: https://kiro.dev/docs/cli
- CCMv4 reference: https://cloudsecurityalliance.org/research/cloud-controls-matrix

---

**License:** MIT
