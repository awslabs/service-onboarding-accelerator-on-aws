---
name: pipeline
description: Phase-by-phase execution guide for the service-approval pipeline
inclusion: fileMatch
fileMatchPattern: "**/.service-approval/**"
---

# Pipeline — 9 service-approval agents (1 precursor + 8 numbered phases), 21 sub-skills

The pipeline runs as 9 agents total: an unnumbered **Intake** precursor that
gathers customer inputs and writes a candidate slug to a staging directory,
followed by 8 numbered phases (0 Assess → 7 Evidence). Phase 0 (Assess) atomically
promotes the staging dir to `.service-approval/<slug>/` after deriving the
canonical service slug from SAR.

## Hard rules (re-stated)

1. Never write a one-shot generator script. Run every phase through its `SKILL.md`.
2. Every capability claim, API parameter, and condition key must be verified via MCP.
3. Log every MCP call to `.service-approval/<service-slug>/pipeline.log` (the consolidated debugging artifact, with `[mcp:<server>:call]` source tags). Lines are mirrored to `mcp-calls.log` for backward compatibility, but `pipeline.log` is the source of truth. Minimum 10 entries enforced by the Stop hook's P1 check.
4. Every `validated.json` item needs a unique `verification_note`.
5. IaC templates must be parameterized — no hardcoded accounts or ARNs.
6. SCPs need at least one `Deny`. `StringEquals`/`StringNotEquals` must target the same key.
7. Verdict = integrity. Any failure → `REQUIRES REMEDIATION`.

## Entry point

Read `skills/service-approval/SKILL.md` in full. That file is the authoritative
orchestrator; do not deviate from the steps it prescribes.

## Precursor — Intake

**Sub-skill:** `skills/intake/SKILL.md`
**Agent:** `sa-intake`
**Inputs:** `--service`, `--from-intake=<file>`, `--interactive`, plus any
orchestrator-level CLI flags (`--env`, `--framework`, `--framework-file`,
`--skip-test`, `--dry-run`, `--keep`, `--timeout`)
**Outputs:**
- `.service-approval/_staging/<timestamp>/00-intake/intake-manifest.json` — service identity, input folder, framework
  selection, testing intent (`full-deploy`/`dry-run`/`skip`/`manual-cli`),
  `service.candidate_slug`, `staging_timestamp`

Intake runs BEFORE the canonical service slug is known — that slug is derived
in Phase 0 (Assess) from the SAR `service_prefix`. Therefore intake writes to a
timestamped staging directory (`_staging/<ts>/`) rather than directly into the
canonical `<slug>/` tree. Phase 0 atomically promotes the staging directory
to `.service-approval/<slug>/` after slug derivation; see Phase 0 Step 0b.

Deployment intent (`testing.mode`) is captured here and consumed by Phase 5 via
the orchestrator's flag-resolution rules. IaC format selection is NOT done here —
that happens in Phase 0 (Assess) Step 2b and lands in `iac-support.json`.

If the user has an existing `./service-approval-intake.yaml` (the per-user
config they fill in from `skills/intake/intake-template.yaml`), the intake
skill auto-discovers it, renders a summary, and prompts: `[U]se as-is /
[E]dit a field` (case-insensitive). To start over, the user deletes the
file or passes `--interactive`; there is no in-prompt "fresh start"
option by design.

The intake skill is the source of truth for that flow — see
`skills/intake/SKILL.md` "Existing Intake Flow" section. Don't
re-implement it here.



## Phase 0 — Assess

**Sub-skill:** `skills/assess/SKILL.md`
**Agent:** `sa-assess`
**Inputs:** input folder (customer docs), `data/sar-slugs.json`, framework file, staging manifest from Intake
**Outputs (after slug promotion):**
- `<slug>/01-assess/sar-facts.json` — SAR extraction (actions, condition keys, resource types)
- `<slug>/01-assess/checkpoint-results.json` — CAF security assessment per domain
- `<slug>/01-assess/assessment-summary.md`
- `<slug>/01-assess/iac-support.json` — per-format IaC provider matrix (CloudFormation, Terraform hashicorp/awscc, CDK, CDKTF); consumed by Phase 4

Runs sequentially. Loads `sar-slugs.json` from `data/` to resolve the service's
SAR URL. Step 0b derives the canonical slug via `tools/slug.py` and atomically
moves `_staging/<ts>/` → `<slug>/`. Calls `@awsknowledge` for condition keys,
`@aws-documentation` for service descriptions, and runs the IaC Provider Discovery
step that populates `iac-support.json`.

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

After all complete, merge into `<slug>/02-research/research.json` per the
Phase 1e recipe in `skills/research/SKILL.md`.

**Phase 1 cannot run until Phase 0 is complete** — the merge depends on sar-facts.

## Phase 2 — Validate

**Sub-skill:** `skills/validate/SKILL.md`
**Agent:** `sa-validate`

Cross-references every claim in `<slug>/02-research/research.json` against MCP
responses. Every item in the output `<slug>/03-validate/validated.json` must
have a unique `verification_note` citing the specific MCP call and result. Items
flagged `UNVERIFIED` must not reach Phase 4.

Runs sequentially. This is the gate — Phase 3 reads `validated.json`, not
`research.json`.

## Phase 3 — Map

**Sub-skills:** 4 (2 parallel, then 2 sequential)

```
/spawn sa-map-parse-framework     → <slug>/04-map/map-framework-parsed.json
/spawn sa-map-generate-controls   → <slug>/04-map/map-controls-generated.json
```

After both complete:
```
sa-map-framework-mapping  → <slug>/04-map/map-framework-mapped.json   (sequential)
sa-map-assemble           → <slug>/04-map/mapping-results.json         (sequential)
                          → <slug>/04-map/controls-catalog.md
                          → <slug>/04-map/framework-mapping.md
```

`mapping-results.json` is the richest state file — it has every control, every
mitigation, every framework objective, the coverage matrix, and the
threat → mitigation → control traceability. Phase 4 reads it.

## Phase 4 — Generate (parallel)

**Sub-skills:** 3 in parallel

```
/spawn sa-generate-preventive  → <slug>/05-generate/preventive/, <slug>/05-generate/proactive/
/spawn sa-generate-detective   → <slug>/05-generate/detective/, <slug>/05-generate/responsive/
/spawn sa-generate-iac         → <slug>/05-generate/iac/ (4 formats + TF modules)
```

Each generator reads `<slug>/04-map/mapping-results.json` and emits artifacts to
the right `<slug>/05-generate/` subdirectory. Artifact count ranges:
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

Output: `<slug>/06-test/test-results.json` plus `<slug>/06-test/deployed-resources.json` (stack ID + ARNs consumed by Phase 7) and `<slug>/06-test/deploy-logs/*.log`.

**Stack lifecycle:** When Phase 7 is in scope (default), Phase 5 leaves the
deployed CFN stack alive (`smoke-deploy-test.sh --keep`) and records
`teardown_status: "deferred_to_phase_7"` in `test-results.json`. Phase 7 owns
teardown. When invoked with `--no-evidence`, Phase 5 reverts to the legacy
deploy-and-teardown behavior.

## Phase 6 — Summarize

**Sub-skill:** `skills/summarize/SKILL.md`

Produces:
- `<slug>/07-summarize/APPROVAL-REPORT.md` — the customer-facing verdict
- `<slug>/07-summarize/ARTIFACT-FLOW-MATRIX.md` — per-artifact dependency graph

The verdict is one of:
- `APPROVED` — all integrity checks passed, framework coverage above threshold
- `APPROVED (with exceptions)` — coverage gaps have rationale, no integrity failures
- `REQUIRES REMEDIATION` — any integrity check failed

The Stop hook (`hooks/stop.json`) enforces rule 7: if integrity failed, the
verdict MUST be `REQUIRES REMEDIATION`. An `APPROVED` verdict with failures is
rewritten by the hook.

## Phase 7 — Evidence (optional, requires AWS credentials)

**Sub-skill:** `skills/evidence/SKILL.md`
**Agent:** `sa-evidence`

Runs AWS CLI probes against deployed resources from Phase 5 Test to prove each
mapped control is actually enforced at runtime. Produces:
- `<slug>/08-evidence/attestation-report.md` — control × verdict matrix
- `<slug>/08-evidence/attestation-results.json` — machine-readable results
- `<slug>/08-evidence/cli-outputs/*.log` — raw stdout/stderr per probe
- `<slug>/attestation.md` — reviewer's audit guide

**Preconditions:**
- Phase 5 Test must have run successfully with `--env=<profile>`
- `<slug>/06-test/deployed-resources.json` must exist with stack ID + resource ARNs

**Skip condition:** Phase 7 is skipped if Phase 5 was not run or failed.

**Teardown ownership:** Phase 7 Step 11 tears down the deployed CFN stack at
the end of evidence collection. The stack ARN is read from
`06-test/deployed-resources.json.stack_id`. If
`intake-manifest.json.testing.keep == true`, teardown is skipped and the stack
remains alive (intended for manual debugging — operator must clean up
manually). The outcome is recorded in
`08-evidence/attestation-results.json.teardown_status` (one of: `completed`,
`skipped_keep_true`, `failed`, `not_attempted`).

Runs sequentially after Phase 6. Uses service-agnostic CLI synthesis rules (6 families)
to map each control in `mapping-results.json` to an AWS CLI probe. Controls that
cannot be CLI-validated (e.g., IaC-time-only CFN Guard rules) are marked as
`NOT_CLI_VALIDATABLE` with supplemental evidence from `iac-time-evidence/`.
