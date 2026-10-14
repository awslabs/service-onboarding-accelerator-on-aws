---
name: tech
description: Stack, tools, MCP servers, and technical constraints
alwaysApply: true
---

# Service Approval — Technical Context

## Runtime

- **Python 3.9+** for validators, hooks, and pipeline tooling
- **AWS CLI** optional — required only for Tier 2 policy validation (Access Analyzer)

## MCP servers

All registered in `mcp.json`. Auto-loaded when the Power activates:

| Server | Transport | Purpose |
|--------|-----------|---------|
| `aws-documentation` | stdio | Service docs, feature references, IAM key semantics |
| `awsknowledge` | HTTP | SAR (Service Authorization Reference) queries, condition keys |
| `mitre-attack` | stdio | ATT&CK technique and tactic lookups, with a bundled snapshot fallback |

P1 enforces a minimum count (≥10) of MCP calls per pipeline run; the strict expectation that every capability claim, API parameter, and condition key is MCP-verified lives in `service-approval-enforcement.md`.

## Tools used by agents

Each agent — both CLI (`cli/agents/sa-*.json`) and IDE (`ide/agents/sa-*.md`)
formats, generated from `agents-src/sa-*.yaml` — declares:
- `tools: ["*"]` — access to all standard Kiro tools
- `allowedTools: ["fs_read", "fs_write", "execute_bash"]` — explicit allowlist
- `includeMcpJson: true` — sees workspace MCP config

## State file layout

```
.service-approval/
├── _staging/<ts>/                  ← intake landing zone before slug is known (Phase 0 promotes)
│   └── 00-intake/intake-manifest.json
└── <slug>/                          ← per-service root (e.g. awslambda/, awss3/)
    ├── mcp-calls.log                ← every MCP call appended here (service-scoped)
    ├── 00-intake/intake-manifest.json
    ├── 01-assess/
    │   ├── sar-facts.json
    │   ├── checkpoint-results.json
    │   └── assessment-summary.md
    ├── 02-research/
    │   ├── research.json            ← merged from 4 sub-skills
    │   ├── research-mitigations.json
    │   ├── research-capabilities.json
    │   ├── research-api-surface.json
    │   └── research-attack-surface.json
    ├── 03-validate/validated.json
    ├── 04-map/
    │   ├── map-framework-parsed.json
    │   ├── map-controls-generated.json
    │   ├── map-framework-mapped.json
    │   ├── mapping-results.json
    │   ├── controls-catalog.md
    │   └── framework-mapping.md
    ├── 05-recommended-guidance/
    │   ├── preventive/              (SCPs, RCPs, resource policies)
    │   ├── proactive/               (CFN Guard, OPA, Checkov, CFN Hooks)
    │   ├── detective/               (Config rules + Lambda handlers, EventBridge)
    │   └── responsive/              (Lambda remediators, SSM runbooks)
    └── 06-summarize/
        ├── SUMMARY-REPORT.md
        └── ARTIFACT-FLOW-MATRIX.md
```

## Schema contracts

Every pipeline state file has a matching `schemas/<name>.schema.json` enforcing its shape. The helper at `/tools/validate/_schemas.py` wraps them via `schema_errors(doc, schema_name)`. Wired into `validate_state.py`.

## Validators

| Script | Scope |
|--------|-------|
| `tools/validate/validate_state.py` | Schema + cross-file integrity for state files |
| `tools/validate/validate_controls.py` | Generated artifact checks (SCP format, policy parameterization) |
| `tools/validate/validate_pipeline_integrity.py` | Stop-hook enforcement of the pipeline integrity checks |
| `tools/validate/validate_kms_consumers.py` | KMS key policy ↔ consumer resource cross-check |

## CLI 2.0 features used

- `/spawn` — parallel subagent execution for Research (4), Map (2), Generate (2)
- Hooks with `${workspaceRoot}` — paths work regardless of install location (symlink vs copy)
- Headless mode — `--no-interactive` + `KIRO_API_KEY` for CI runs

## Forbidden patterns

- Hardcoded account IDs (`123456789012`, `000000000000`). `validate_controls.py` blocks.
- Placeholder ARNs (`arn:aws:kms:us-east-1:123456789012:key/example`). `validate_controls.py` blocks.
- `StringEquals` and `StringNotEquals` on different keys in the same `Condition`. Validator P3 blocks (conditions AND together, so this never fires).
- SCPs without a `Deny` statement. Safety rule enforced.
- `APPROVED` verdict with integrity failures. Validator P6 blocks.
