---
name: pipeline
description: Phase-by-phase execution guide for the service-approval pipeline
inclusion: fileMatch
fileMatchPattern: "**/.service-approval/**"
---

# Pipeline — service-approval agents (1 precursor + 6 numbered phases)

The pipeline runs an unnumbered **Intake** precursor that gathers customer
inputs and writes a candidate slug to a staging directory, followed by 6
numbered phases (0 Assess → 5 Summarize). Phase 0 (Assess) atomically
promotes the staging dir to `.service-approval/<slug>/` after deriving the
canonical service slug from SAR. The pipeline recommends controls that the
customer deploys themselves; it does not deploy, test, or attest against a
live account.

## Hard rules (re-stated)

The Stop hook enforces the following failure signals via `validate_pipeline_integrity.py`:

- **P1** — too few MCP calls. Log every MCP call to `.service-approval/<service-slug>/pipeline.log` (the consolidated debugging artifact, with `[mcp:<server>:call]` source tags); lines are mirrored to `mcp-calls.log` for backward compatibility. Minimum 10 entries enforced. Exempted for finalized runs by the `[pipeline:complete:<VERDICT>]` terminal sentinel.
- **P2** — `validated.json` items need unique `verification_note`s (≥50% uniqueness required).
- **P3** — IAM policy logic errors: mismatched `StringEquals`/`StringNotEquals` keys, broad `Allow` on `Resource:*` without `Condition`, SCP without at least one `Deny`.
- **P5** — framework coverage below 15% with no per-objective rationale.
- **P6** — verdict matches integrity. Any integrity failure → `REQUIRES REMEDIATION`, not `APPROVED`.
- **P7** — phase-output completeness: every phase dir on disk must contain its declared outputs at min-size thresholds.

**Cultural rules** (skill-based execution, no one-shot generator scripts, every claim
MCP-verified) live in [`service-approval-enforcement.md`](service-approval-enforcement.md),
not in the validator's P-check list.

## Entry point

Read `skills/service-approval/SKILL.md` in full. That file is the authoritative
orchestrator; do not deviate from the steps it prescribes.

## Precursor — Intake

Before external work, Intake MUST validate a matching AWS Threat Model JSON
export with `tools/validate/validate_threat_model_input.py`. Record the selected
absolute path as `inputs.threat_model_file`. Revalidate with `--manifest` before
Assess, and with `--slug` before every later/resumed phase. Nonzero exit halts the
pipeline in every mode; MITRE defaults, flags, and cached state cannot replace it.

**Sub-skill:** `skills/intake/SKILL.md`
**Agent:** `sa-intake`
**Inputs:** `--service`, `--from-intake=<file>`, `--interactive`, plus any
orchestrator-level CLI flags (`--framework`, `--framework-file`,
`--include-unverified`, `--dry-run`, `--clean`)
**Outputs:**
- `.service-approval/_staging/<timestamp>/00-intake/intake-manifest.json` — service identity, input folder, framework
  selection, `service.candidate_slug`, `staging_timestamp`

Intake runs BEFORE the canonical service slug is known — that slug is derived
in Phase 0 (Assess) from the SAR `service_prefix`. Therefore intake writes to a
timestamped staging directory (`_staging/<ts>/`) rather than directly into the
canonical `<slug>/` tree. Phase 0 atomically promotes the staging directory
to `.service-approval/<slug>/` after slug derivation; see Phase 0 Step 0b.

**Kiro Power note — this is a chat pane, not Claude Code.** The Power's
`sa-intake` agent uses a trimmed, self-contained prompt: CCMv4 is opt-in,
MITRE ATT&CK is always-on, and the NIST/CIS/ISO menu is hidden. The agent
MUST stop and ask for every field — it must NEVER infer values from the
user's opening prompt, prior chat turns, file contents, environment
variables, or any other source. Branch B turn-taking (the literal
`>>> WAITING FOR YOUR REPLY` marker, one question per turn, no further
tool calls in the same turn) is inlined directly into the agent body
because Kiro lacks an `AskUserQuestion`-style blocking primitive. The
Claude Code interactive path (Branch A) uses the same CCMv4-only narrowing
(see `skills/intake/SKILL.md` Step 2). Multi-framework parsing remains
available behind the `--framework=<type>` CLI flag for advanced operators
who bypass the interactive intake.

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

Runs sequentially. Loads `sar-slugs.json` from `data/` to resolve the service's
SAR URL. Step 0b derives the canonical slug via `tools/slug.py` and atomically
moves `_staging/<ts>/` → `<slug>/`. Calls `@awsknowledge` for condition keys and
`@aws-documentation` for service descriptions.

## Phase 1 — Research (parallel)

**Sub-skills:** 4 parallel + 1 merge
**Agents:** `sa-research-mitigations`, `sa-research-capabilities`, `sa-research-api-surface`, `sa-research-attack-surface`

Use Kiro CLI 2.0 `/spawn` to run these in parallel:

```
/spawn sa-research-mitigations    (reads input mitigation docs)
/spawn sa-research-capabilities   (queries awsknowledge for service capabilities)
/spawn sa-research-api-surface    (queries awsknowledge for API operations)
/spawn sa-research-attack-surface (mandatory — queries MITRE ATT&CK enrichment data)
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

## Phase 4 — Recommended Guidance (2 families in parallel; preventive is a gated sub-pipeline)

**Families:** 2 in parallel. The preventive family runs its sub-skills in order
(recommender gate → reference-anchored authors → root-cause critic).

```
preventive (in order):
  /spawn sa-generate-preventive-recommend → <slug>/05-recommended-guidance/preventive-plan.json (gate)
  /spawn sa-generate-preventive-scp        → <slug>/05-recommended-guidance/preventive/ (GENERATE_SCP)
  /spawn sa-generate-preventive-rcp        → <slug>/05-recommended-guidance/preventive/ (GENERATE_RCP)
  /spawn sa-generate-preventive-iam        → <slug>/05-recommended-guidance/preventive/ (GENERATE_IAM)
  /spawn sa-generate-preventive-rootcause  → prove anchored + enforcing
/spawn sa-generate-detective   → <slug>/05-recommended-guidance/detective/, <slug>/05-recommended-guidance/responsive/
```

Every preventive artifact must carry a reference anchor (`_metadata.reference`)
resolving to `data/reference-repos/index.yaml`, and only enforceable objectives
(a condition key gates the action) are authored; the rest route to detective.
`skills/generate-preventive/SKILL.md` is the shared authoring-rules reference.

Each generator reads `<slug>/04-map/mapping-results.json` and emits artifacts to
the right `<slug>/05-recommended-guidance/` subdirectory. Artifact count ranges:
- Preventive: 9–12 files
- Proactive: 12–15 files
- Detective: 34–47 files
- Responsive: 6 files

Total varies with service surface area.

## Phase 5 — Summarize

**Sub-skill:** `skills/summarize/SKILL.md`

Produces:
- `<slug>/06-summarize/SUMMARY-REPORT.md` — the customer-facing Summary Report
- `<slug>/06-summarize/ARTIFACT-FLOW-MATRIX.md` — per-artifact dependency graph

Summarize issues no approve/deny verdict — it reports coverage, mitigation
traceability, and the artifact inventory so a reviewer can see what was checked.
The Stop hook still enforces the P1–P7 integrity signals on the run's outputs.

## Self-Review Gate (mandatory, runs between Recommended Guidance and Summarize)

Before entering Phase 5 (Summarize), the orchestrator MUST perform a completeness
and correctness review of all Phase 4 (Recommended Guidance) output. This step
exists because the families run in parallel and gaps are easy to miss when
subagents complete independently.

### Checklist

1. **Artifact count** — Count all files in `05-recommended-guidance/` by category. Compare
   against the ranges in `steering/phase-generate.md`. If below minimum for any
   category, re-run that generator sub-skill.

2. **Policy engine coverage** — Every proactive control must exist in ALL THREE
   engines: CFN Guard (`.guard`), OPA (`.rego`), and Checkov (`.py`). A control
   in only one engine is incomplete.

3. **SCP metadata** — Every file in `05-recommended-guidance/preventive/` must have:
   - `_metadata` with control_id, name, ccmv4_objectives, mitre_techniques
   - `_simulation_tests` array with at least one DENY and one ALLOW scenario
   - Control ID in the `Sid` field of each Statement

4. **Control ID annotations** — Spot-check 3 random preventive/proactive policy
   files. Each rule or statement that implements a control must carry the control
   ID (`# CTRL-*` in Guard/rego, `Sid: CTRL-*` in JSON policies).

5. **Integrity pre-check** — Run the P3 check inline:
   - P3: Every SCP has ≥1 Deny statement; no `StringEquals`/`StringNotEquals`
     targeting different keys in the same Condition block

6. **Directory structure** — Verify output matches the layout defined in
   `steering/structure.md` (subdirectories, naming conventions).

### Outcome

- All checks pass → proceed to Phase 5 (Summarize)
- Any check fails → fix the gap, then re-run this gate before proceeding
- Document any fixes made in `pipeline.log` with tag `[self-review:fix]`
