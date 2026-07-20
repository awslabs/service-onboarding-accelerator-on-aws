# Service Approval — Kiro Power

Kiro Power that generates AWS security controls for any AWS service via an Intake + 6-phase pipeline. Produces SCPs, Config rules, CFN Guard rules, Checkov policies, OPA policies, and compliant Terraform/CloudFormation/CDK/CDKTF templates, all mapped to CCMv4 (other frameworks deferred).

## Install

From a local checkout (this repo):

```bash
cd /path/to/service-onboarding-accelerator-on-aws
./install.sh
```

The installer copies the Power's IDE files (agents, hooks, steering, MCP config) into your workspace `.kiro/` so the Kiro IDE picks them up on open. Re-run `./install.sh` after `git pull` to refresh.

From GitHub (Kiro desktop app):
1. Open the **Powers** panel
2. Click **Add power from GitHub**
3. Paste `https://github.com/awslabs/service-onboarding-accelerator-on-aws` and choose `/powers/service-approval` as the path

## Prerequisites

1. **Kiro IDE** — https://kiro.dev
2. **Python 3.9+** — required for validators and hooks
3. **Docker** — required for `terraform` MCP server
4. **MCP servers** — registered in `mcp.json`, loaded automatically when the Power activates

## Usage

Once installed, Kiro activates this Power when you mention any of:

- "run service approval for <service-name>"
- "generate AWS security controls for <service-name>"
- "service approval ./input --service=<name>"
- explicit: "use the service-approval Power for Amazon S3"

Full parameter reference is in [`POWER.md`](POWER.md).

## What this Power does

1. Reads customer inputs (`./input/` folder with .md, .json, .xlsx, .pdf, .docx)
2. Runs an Intake + 6-phase pipeline (Intake, Assess, Research, Validate, Map, Recommended Guidance, Summarize)
3. Writes state and artifacts to `.service-approval/<service-slug>/` (per-service layout) in the working directory
4. Produces `SUMMARY-REPORT.md` with a framework-coverage matrix. It recommends controls + compliant IaC that the customer deploys themselves.

## Pipeline

```
Intake               → _staging/<ts>/00-intake/intake-manifest.json (promoted to <slug>/00-intake/ in Phase 0)
Phase 0 Assess       → <slug>/01-assess/sar-facts.json, checkpoint-results.json, iac-support.json
Phase 1 Research     → <slug>/02-research/research.json (4 parallel sub-skills)
Phase 2 Validate     → <slug>/03-validate/validated.json (cross-MCP verification)
Phase 3 Map          → <slug>/04-map/mapping-results.json (+ framework-mapping.md)
Phase 4 Recommended Guidance → <slug>/05-recommended-guidance/ (78–111 files across preventive/proactive/detective/responsive/iac)
Phase 5 Summarize    → <slug>/06-summarize/SUMMARY-REPORT.md
```

Uses Kiro IDE's `/spawn` (Kiro CLI 2.0 also supports it; runtime path is being re-evaluated) for parallel execution in Phases 1, 3, and 4.

## Repository layout

```
powers/service-approval/
├── POWER.md                              Manifest + body (keywords, invocation, pipeline)
├── README.md                             (this file)
├── mcp.json                              MCP server registrations
├── steering/                             Always-on + fileMatch-loaded guidance
│   ├── product.md                        What and why (always-on)
│   ├── tech.md                           Stack + validators (always-on)
│   ├── structure.md                      Layout + conventions (always-on)
│   ├── pipeline.md                       Full phase-by-phase guide
│   ├── phase-research.md                 Loads for research state files
│   ├── phase-validate.md                 Loads for validated.json
│   ├── phase-map.md                      Loads for map-* state files
│   ├── phase-generate.md                 Loads for 05-recommended-guidance/ artifacts
│   ├── headless.md                       CI / headless invocation recipe
│   └── service-approval-enforcement.md   Skill-based execution guardrail
├── agents-src/                           Source-of-truth YAML — one sa-<slug>.yaml per agent
│   └── sa-*.yaml                         (one per sub-skill)
├── cli/agents/                           Generated CLI format (JSON)
│   └── sa-*.json                         (run tools/generate-kiro-agents.py to regenerate)
└── ide/                                  Generated IDE artifacts
    ├── agents/sa-*.md                    (markdown agents the IDE loads)
    └── hooks/                            (Kiro IDE Stop / PostToolUse / PreToolUse hooks)
        ├── stop.kiro.hook                Runs pipeline integrity checks
        ├── post-tool-use.kiro.hook       Validates state files on write
        └── block-direct-state-writes.kiro.hook   Enforces skill-based execution
```

## Hard rules

The Stop hook (`ide/hooks/stop.kiro.hook`) runs `tools/validate/hook_stop.py` which invokes `validate_pipeline_integrity.py`. Exit code 2 blocks on any P1–P7 failure signal:

- **P1** — too few MCP calls (≥10 required; exempted for finalized runs by the `[pipeline:complete:<VERDICT>]` terminal sentinel)
- **P2** — `validated.json` notes templated or empty (≥50% uniqueness required)
- **P3** — IAM policy logic errors (mismatched `StringEquals`/`StringNotEquals` keys, broad Allow on `Resource:*` without Condition, SCP without Deny)
- **P4** — IaC templates contain placeholder account IDs or placeholder ARNs
- **P5** — framework coverage below 15% with no per-objective rationale
- **P6** — verdict mismatch (`APPROVED` despite integrity failures)
- **P7** — phase-output completeness (every phase dir produces its declared outputs)

Cultural rules (skill-based execution, no one-shot generator scripts) live in [`steering/service-approval-enforcement.md`](steering/service-approval-enforcement.md). Full list and validator implementation in [`tools/validate/validate_pipeline_integrity.py`](../../tools/validate/validate_pipeline_integrity.py).

## Headless / CI

> **Note (2026-05-18):** Kiro CLI 2.0 headless mode is no longer wired by
> `install.sh`. The recipe in `steering/headless.md` requires installing
> `kiro-cli` separately and is being re-evaluated; for new CI pipelines,
> consider Claude Code CLI (`install-claude.sh`).

Kiro CLI 2.0 headless mode works with this Power when `kiro-cli` is installed manually. Set `KIRO_API_KEY`, pass `--no-interactive --trust-tools="aws-documentation,awsknowledge,awsiac,terraform,kb-search"`. Full recipe in [`steering/headless.md`](steering/headless.md).

## Updating

```bash
cd /path/to/service-onboarding-accelerator-on-aws
git pull
```

Re-run `./install.sh` to refresh the Power's IDE files in your workspace `.kiro/`.

## Uninstalling

Kiro app → Powers panel → service-approval → Uninstall. To remove the workspace files, delete the `.kiro/` directory in your repo.

## Testing and troubleshooting

Full testing guide at [`docs/TESTING-KIRO.md`](../../docs/TESTING-KIRO.md). Covers:
- Verifying the install populated `.kiro/agents/`, `.kiro/hooks/`, `.kiro/steering/`
- Confirming MCP servers connect (requires `uv` on PATH for `aws-documentation` and `awsiac`)
- Keyword activation tests
- Hook-fire verification via `.service-approval/<slug>/mcp-calls.log`
- Fixes for "fetch failed", "aws-cdk-mcp-server Connection closed", and the "workspaceRoot not approved" security warning

## License

Apache-2.0
