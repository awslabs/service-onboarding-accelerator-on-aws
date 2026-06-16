---
name: service-approval
displayName: AWS Service Security Controls Generator
description: Generate AWS security controls and compliant IaC for any AWS service. Runs a 9-phase pipeline (Intake, Assess, Research, Validate, Map, Generate, Test, Summarize, Evidence) mapped to CCMv4 (other frameworks deferred).
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
author: Service Onboarding on AWS Team
version: 1.0.0
---

# AWS Service Security Controls Generator

## Overview

This Power drives a 9-phase pipeline that generates AWS security controls for any AWS service. It reads customer inputs (mitigation reports, threat models, framework spreadsheets), researches the service via AWS knowledge MCP servers, maps every capability to CCMv4 (other frameworks are deferred), and produces a full set of deployable artifacts.

**Key capabilities:**
- **9-phase pipeline** — Intake → Assess → Research → Validate → Map → Generate → Test → Summarize → Evidence, with 26 sub-skills
- **Parallel execution** — 4 research sub-skills and 3 generate families run concurrently via Kiro's `/spawn` command; the preventive family runs a gated sub-pipeline (recommend → reference-anchored authors → root-cause critic)
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
| `service` | AWS service ID (e.g., `s3`, `kms`, `bedrock-agentcore-control`) | Asked during Intake if not supplied as a flag |
| input folder | Customer docs (.md, .json, .xlsx, .pdf, .docx) | No (Intake creates `./input/` if missing) |
| `env` | AWS CLI profile for Phase 5 | Asked during Intake if Testing mode is `full-deploy` or `dry-run` |
| `framework` | `ccmv4` for both Kiro Power and Claude Code (interactive intake is CCMv4-only). Multi-framework parsing remains available via the `--framework=<type>` CLI flag for advanced operators. | Asked during Intake if not supplied as a flag. **Not auto-detected silently.** |
| `skip-test` | Skip deployment validation (equivalent to Testing mode `skip`) | Asked during Intake if not supplied as a flag |
| `dry-run` | Lint only, no deployment (equivalent to Testing mode `dry-run`) | Asked during Intake if not supplied as a flag |

### Intake is mandatory — defaults are NOT silently applied

Intake's framework prompt and testing-mode prompt MUST run on every
invocation unless the corresponding CLI flag was supplied (`--framework=`,
`--skip-test`, `--dry-run`, `--from-intake=`). The absence of a flag is
NOT permission to apply the documented default — it is a signal to ASK
the user.

The Power's intake agent (`agents-src/sa-intake.yaml`) is the source of
truth for prompt behavior. It pins Branch B turn-taking (one question
per turn, `>>> WAITING FOR YOUR REPLY` marker, no further tool calls in
the same turn) because Kiro lacks an `AskUserQuestion`-style blocking
primitive.

Documented defaults (this file, `skills/intake/defaults.yaml`, the
orchestrator's flag table) apply ONLY when the user's interactive reply
to a specific prompt is literally empty/blank — never as a substitute
for the prompt itself.

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

Agent definitions live in `cli/agents/sa-*.json` (CLI format) and
`ide/agents/sa-*.md` (IDE format), both generated from `agents-src/*.yaml`.
Kiro IDE loads `.md` files from `.kiro/agents/`; the CLI consumes the `.json`
form. Run `python3 tools/generate-kiro-agents.py` to regenerate after editing
the source YAML.

## Hard rules — no shortcuts

The Stop hook (`ide/hooks/stop.kiro.hook`) runs `tools/validate/hook_stop.py` which invokes
`validate_pipeline_integrity.py`. The hook blocks the Stop event (exit code 2) on any of
these P1–P7 failure signals (mirrors `validate_pipeline_integrity.py` module docstring):

- **P1** — `pipeline.log` / `mcp-calls.log` missing or too few MCP calls (≥10 required, exempted by `[pipeline:complete:<VERDICT>]` terminal sentinel for finalized runs).
- **P2** — `validated.json` has templated or empty verification notes (≥50% uniqueness required).
- **P3** — IAM policy logic errors (mismatched `StringEquals`/`StringNotEquals` keys, broad Allow on `Resource:*` without Condition, SCP without Deny).
- **P4** — IaC templates contain placeholder account IDs (`123456789012`, `000000000000`, `111111111111`) or placeholder ARNs.
- **P5** — framework coverage below 15% with no per-objective rationale.
- **P6** — verdict mismatch (`APPROVED` emitted despite integrity failures).
- **P7** — phase-output completeness: every phase dir on disk must contain its declared outputs (`mapping-results.json`, `controls-catalog.md`, `framework-mapping.md`, etc.) at min-size thresholds.

Cultural rules (skill-based execution, no one-shot generator scripts) live in
[`steering/service-approval-enforcement.md`](steering/service-approval-enforcement.md), not in this list.

## Output

- `.service-approval/APPROVAL-REPORT.md` — final report + CCMv4 coverage matrix
- `.service-approval/<slug>/05-generate/` — all generated artifacts (per-service; see `steering/pipeline.md` for per-category ranges)
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

For CI integration, run the Power through the Kiro IDE's headless harness or
through Claude Code's CLI. See `steering/headless.md` for the full CI recipe.

## Resources

- Agent Skills spec: https://agentskills.io
- Kiro docs: https://kiro.dev/docs
- CCMv4 reference: https://cloudsecurityalliance.org/research/cloud-controls-matrix

---

**License:** Apache-2.0
