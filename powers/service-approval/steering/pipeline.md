---
name: pipeline
description: Phase-by-phase execution guide for the service-approval pipeline
inclusion: fileMatch
fileMatchPattern: "**/.service-approval/**"
---

# Pipeline — 8 phases (Intake + 7), 20 sub-skills

## Hard rules (re-stated)

1. Never write a one-shot generator script. Run every phase through its `SKILL.md`.
2. Every capability claim, API parameter, and condition key must be verified via MCP.
3. Log every MCP call to `.service-approval/state/mcp-calls.log`. Minimum 10 entries.
4. Every `validated.json` item needs a unique `verification_note`.
5. IaC templates must be parameterized — no hardcoded accounts or ARNs.
6. SCPs need at least one `Deny`. `StringEquals`/`StringNotEquals` must target the same key.
7. Verdict = integrity. Any failure → `REQUIRES REMEDIATION`.

## Entry point

Read `skills/service-approval/SKILL.md` in full. That file is the authoritative
orchestrator; do not deviate from the steps it prescribes.

## Intake — Precursor

**Sub-skill:** `skills/intake/SKILL.md`
**Agent:** `sa-intake`
**Inputs:** `--service`, `--from-intake=<file>`, `--interactive`, plus any
orchestrator-level CLI flags (`--env`, `--framework`, `--framework-file`,
`--skip-test`, `--dry-run`, `--keep`, `--timeout`)
**Outputs:**
- `state/intake-manifest.json` — service identity, input folder, framework
  selection, testing intent (`full-deploy`/`dry-run`/`skip`/`manual-cli`)

Runs before Phase 0. Deployment intent is captured here and consumed by Phase 5
via the orchestrator's flag-resolution rules. IaC format selection is NOT done
here — that happens in Phase 0 (Assess) Step 2b.

## Phase 0 — Assess

**Sub-skill:** `skills/assess/SKILL.md`
**Agent:** `sa-assess`
**Inputs:** input folder (customer docs), `data/sar-slugs.json`, framework file
**Outputs:**
- `state/sar-facts.json` — SAR extraction (actions, condition keys, resource types)
- `state/checkpoint-results.json` — CAF security assessment per domain
- `state/assessment-summary.md`
- `state/iac-support.json` — per-format IaC provider support for the service
  (CloudFormation, Terraform hashicorp/awscc, CDK, CDKTF); consumed by Phase 4

Runs sequentially. Loads `sar-slugs.json` from `data/` to resolve the service's
SAR URL. Calls `@awsknowledge` for condition keys, `@aws-documentation` for
service descriptions, and runs the IaC Provider Discovery step that populates
`iac-support.json`.

## Phase 1 — Research (parallel)

**Sub-skills:** 4 parallel + 1 merge
**Agents:** `sa-research-mitigations`, `sa-research-capabilities`, `sa-research-api-surface`, `sa-research-attack-surface` (optional)

Use Kiro CLI 2.0 `/spawn` to run these in parallel:

```
/spawn sa-research-mitigations    (reads input mitigation docs)
/spawn sa-research-capabilities   (queries awsknowledge for service capabilities)
/spawn sa-research-api-surface    (queries awsknowledge + awsiac for API operations)
/spawn sa-research-attack-surface (optional — queries ATT&CK enrichment data)
```

After all complete, merge into `state/research.json` per the Phase 1e recipe in
`skills/research/SKILL.md`.

**Phase 1 cannot run until Phase 0 is complete** — the merge depends on sar-facts.

## Phase 2 — Validate

**Sub-skill:** `skills/validate/SKILL.md`
**Agent:** `sa-validate`

Cross-references every claim in `state/research.json` against MCP responses.
Every item in the output `validated.json` must have a unique `verification_note`
citing the specific MCP call and result. Items flagged `UNVERIFIED` must not
reach Phase 4.

Runs sequentially. This is the gate — Phase 3 reads `validated.json`, not
`research.json`.

## Phase 3 — Map

**Sub-skills:** 4 (2 parallel, then 2 sequential)

```
/spawn sa-map-parse-framework     → state/map-framework-parsed.json
/spawn sa-map-generate-controls   → state/map-controls-generated.json
```

After both complete:
```
sa-map-framework-mapping  → state/map-framework-mapped.json   (sequential)
sa-map-assemble           → state/mapping-results.json         (sequential)
                          → controls-catalog.md
                          → framework-mapping.md
```

`mapping-results.json` is the richest state file — it has every control, every
mitigation, every framework objective, the coverage matrix, and the
threat → mitigation → control traceability. Phase 4 reads it.

## Phase 4 — Generate (parallel)

**Sub-skills:** 3 in parallel

```
/spawn sa-generate-preventive  → controls/preventive/, controls/proactive/
/spawn sa-generate-detective   → controls/detective/, controls/responsive/
/spawn sa-generate-iac         → controls/iac/ (4 formats + TF modules)
```

Each generator reads `mapping-results.json` and emits artifacts to the right
`controls/` subdirectory. Artifact count ranges:
- Preventive: 9–12 files
- Proactive: 12–15 files
- Detective: 34–47 files
- Responsive: 6 files
- IaC: 17–31 files

Total: 78–111 files depending on service surface area.

## Phase 5 — Test (optional)

**Sub-skill:** `skills/test/SKILL.md`
Runs only if `--env=<profile>` is provided. Two tiers:
- Tier 1 (always): static validation via cfn-lint, tflint, cfn-guard parse, OPA check
- Tier 2 (with creds): AWS API — cfn validate-template, Access Analyzer validate-policy

Output: `state/test-results.json`.

## Phase 6 — Summarize

**Sub-skill:** `skills/summarize/SKILL.md`

Produces:
- `.service-approval/APPROVAL-REPORT.md` — the customer-facing verdict
- `.service-approval/ARTIFACT-FLOW-MATRIX.md` — per-artifact dependency graph

The verdict is one of:
- `APPROVED` — all integrity checks passed, framework coverage above threshold
- `APPROVED (with exceptions)` — coverage gaps have rationale, no integrity failures
- `REQUIRES REMEDIATION` — any integrity check failed

The Stop hook (`hooks/stop.json`) enforces rule 7: if integrity failed, the
verdict MUST be `REQUIRES REMEDIATION`. An `APPROVED` verdict with failures is
rewritten by the hook.
