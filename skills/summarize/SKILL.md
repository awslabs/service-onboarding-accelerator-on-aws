---
name: summarize-v3
description: Produce final APPROVAL-REPORT.md with framework coverage matrix, mitigation traceability, and verdict
disable-model-invocation: false
---

> NOTE: Generate-phase outputs are DRAFT artifacts (suffixed `-DRAFT`) embedded with a non-production disclaimer. When summarizing or testing, preserve the DRAFT markers in any references and surface the disclaimer text in any user-facing report. Do NOT strip the `-DRAFT` suffix or the embedded disclaimer.

# Service Approval — Summarizer v3

Read all state files and generate the final approval report at `.service-approval/<slug>/05-summarize/APPROVAL-REPORT.md`.

## Prerequisites

- [ ] **Hard gate — verify the phases summarize depends on:**
  ```bash
  python3 -m tools.validate.check_phase_complete --slug <slug> --phase 01-assess || exit 2
  python3 -m tools.validate.check_phase_complete --slug <slug> --phase 03-validate || exit 2
  python3 -m tools.validate.check_phase_complete --slug <slug> --phase 04-map || exit 2
  ```

## Step 1: Determine verdict

Read `validated.json` for `unverified_count`.

| Condition | Verdict |
|-----------|---------|
| `unverified_count = 0` | APPROVED |
| `unverified_count > 0` | APPROVED WITH EXCEPTIONS |

## Step 2: Build framework coverage matrix

Read `mapping-results.json` `framework_mapping[]`. Build a table:

| {Framework} Objective ID | Title | Domain | Satisfied By | Threat IDs | Coverage |

Where "Satisfied By" = comma-separated control IDs that map to this framework objective.
Where "Threat IDs" = `threat_ids[]` on the objective entry (the native threat IDs from the
input threat model, e.g. `T-0522`, that trace to this objective via its controls). Joined,
comma-separated; render `—` when empty (e.g. objectives covered only by assessment-derived
`M-GAP-*` controls with no source threat link). This puts the customer's native threat IDs on
the central framework matrix itself, so a reviewer can read objective → threat directly without
pivoting through the mitigation traceability table.
Use the framework name dynamically from `mapping-results.json.framework.name`.

## Step 3: Build mitigation traceability matrix

Read `mapping-results.json` `threat_mitigation_map[]`. Build a table:

| Threat ID | Mitigation ID | Statement | Resource Type | Controls | MITRE Techniques | Framework Objectives | Coverage |

Where "Threat ID" = `threat_id` field — the native threat ID from the input threat model
(e.g. `T-0522`). Render `—` when the field is null/absent (e.g. assessment-derived `M-GAP-*`
mitigations with no source threat link).
Where "Statement" = `statement` field.
Where "Controls" = `control_ids[]` from the mitigation entry (joined, comma-separated).
Where "MITRE Techniques" = `attack_techniques[]` from the mitigation entry (joined,
comma-separated). Render `—` when empty. If this field is absent, derive it: for each control
id in the mitigation's `control_ids[]`, look up that control in the top-level `controls[]` and
collect its `attack_techniques[]`. Deduplicate and sort.
Where "Framework Objectives" = `framework_objectives[]` from the mitigation entry. If this field
is absent, derive it: for each control id in the mitigation's `control_ids[]`, look up that control
in the top-level `controls[]` and collect its `framework_objectives[]`. Deduplicate and sort.

This shows end-to-end traceability from the customer's native threat IDs through mitigations,
controls, and MITRE ATT&CK techniques to framework objectives — a single consolidated join.

## Step 4: Write APPROVAL-REPORT.md

**CRITICAL — Terminology rules for the report:**
The APPROVAL-REPORT.md is a customer-facing document. NEVER use internal/pipeline terms:
- NO: "service approval pipeline", "pipeline generated" → YES: "47 security controls were generated"
- NO: "--skip-test flag", "--clean flag" → YES: "Testing was deferred for this assessment"
- NO: "deployment pipeline" → YES: "deployment process"
- NO: MCP tool names, skill names, agent names
- NO: internal file names ("validated.json", "mapping-results.json", "research.json") → YES: "all capabilities were verified"
- NO: "unverified_count = 0" → YES: "all items verified"
- Apply all terminology rules from CLAUDE.md (see Terminology Rules section)

Write `.service-approval/<slug>/05-summarize/APPROVAL-REPORT.md` with these sections.
Section headings are H2 (`##`) — the report's top-level title `# Service Approval
Report — {Service}` is H1, so all section headers under it are H2. Downstream
consumers (`skills/evidence/SKILL.md` awk extraction, `validate_pipeline_integrity.py`
P6 verdict-consistency check) anchor on H2; writing H3 here silently breaks both.

## Verdict
[Verdict string with date, service name, resource count]

## Executive Summary
[Coverage numbers: N controls generated, N framework objectives covered, N mitigations addressed, test result]

## Security Posture Assessment
**Include this section only if `assessment-summary.md` exists.**
- Extract GAPS Summary from assessment-summary.md (total gaps, total customer actions)
- List each domain's gap count: IAM ({N}), LOGGING ({N}), INFRA ({N}), DATA ({N}), INCIDENT ({N})
- For each REQUIREMENT GAP: show whether a control was generated to address it
  (from mapping-results.json controls with `assessment_gap_ids[]`)
- Include checkpoint verification summary from checkpoint-results.json (if available):
  RCP: {Yes/No}, FIPS: {Yes/No}, Declarative Policies: {Yes/No}, RAM: {Yes/No}

## Framework Coverage Matrix ({framework-name})
[Full table from Step 2 — all framework objectives, mapped or N/A]
Use the framework name dynamically from `mapping-results.json.framework.name`:
- Default (no input, interactive intake): "CSA CCMv4 Coverage Matrix"
- Customer NIST file (CLI `--framework=nist` only): "NIST 800-53 Coverage Matrix"
- Customer CIS file (CLI `--framework=cis` only): "CIS Benchmarks Coverage Matrix"
- Customer ISO file (CLI `--framework=iso` only): "ISO 27001 Coverage Matrix"
- Customer custom file: "Custom Framework Coverage Matrix"

> Note: as of 2026-05-16, interactive runs are narrowed to CCMv4 by intake.
> The non-CCMv4 branches above are reachable only when an advanced operator
> bypasses intake with `--framework=<type>`.

## Mitigation Traceability
[Full table from Step 3 — all customer mitigations with control and framework mappings]
Include coverage summary: N/N mitigations fully covered, N partially covered, N uncovered.

## Threat Model Coverage
**Always included** — MITRE ATT&CK analysis is mandatory for every service onboarding.
`mapping-results.json` always contains `attack_coverage`.

This section renders threat model coverage regardless of which threat model was used as input
(MITRE ATT&CK, custom STRIDE model, organizational threat catalog, etc.). The section title
and content adapt based on the `attack_coverage` data:

- Read `attack_coverage.attack_matrix_version` for the threat model version
- Read `attack_coverage.attack_matrix_source` for the source file name (if present)
- Use the threat model name from the source file or default to "Threat Model"

**Section title:** Use the threat model name dynamically (mirrors the 5-case
naming-rules table in `skills/research-attack-surface/SKILL.md`):
- If source contains "MITRE" or "ATT&CK" (or is the default `data/attack-cloud-matrix.json`) → "MITRE ATT&CK Threat Coverage (v{version})"
- If source contains "STRIDE" → "STRIDE Threat Coverage"
- If hybrid (multiple sources merged, e.g. MITRE + STRIDE) → "{combined_name} Threat Coverage" (e.g. "MITRE ATT&CK + STRIDE Threat Coverage")
- If source is a custom file → "Threat Model Coverage ({source_filename})"
- If no threat model source can be identified → "Threat Model Coverage"

Build a tactic/category heat map showing control coverage:

```
| Tactic / Category | Techniques | Covered | Coverage |
|-------------------|-----------|---------|----------|
| Initial Access (TA0001) | 3 | 2 | ██████░░ 67% |
| Execution (TA0002) | 2 | 2 | ████████ 100% |
| Persistence (TA0003) | 3 | 1 | ██░░░░░░ 33% |
[repeat for each tactic/category with applicable techniques]
```

Include a "Threat Gaps" sub-section listing uncovered HIGH-applicability techniques/threats:
- Technique/threat ID, name, and which categories it maps to
- Recommended control type to address the gap
- Priority (based on applicability: HIGH = immediate, MEDIUM = short-term)

**If `customer_stride_profile` exists in `research-attack-surface.json`**, also include a
STRIDE coverage summary showing which STRIDE categories have controls addressing them:

```
| STRIDE Category | Mitigations Referenced | Techniques Mapped | Controls Covering |
|-----------------|----------------------|-------------------|-------------------|
| Spoofing | M-AgentRuntime.0, ... | T1078.004, T1199 | CTRL-005, CTRL-006 |
[repeat for each STRIDE category]
```

## UNVERIFIED Items
[List with reasons, or "None — all items verified" if unverified_count = 0]

## Pipeline-Complete Sentinel

After APPROVAL-REPORT.md is written, emit a terminal-state sentinel to
`pipeline.log`. This signals to the Stop hook (`validate_pipeline_integrity.py`
P1 check) that the run is finalized — the file is frozen, and remediation-only
checks like the MCP-call-count gate cannot be retroactively satisfied.
Without this sentinel, the Stop hook re-fires forever on completed runs that
happen to have a P1 violation in their pipeline.log.

Emit AFTER the report file is closed and AFTER the print summary.

```bash
# Map verdict to sentinel form. Drop any parenthesized qualifier first so
# "APPROVED (test not run)" canonicalizes to "APPROVED" (the qualifier is
# audit-trail metadata, not a distinct verdict — see "Sentinel canonicalization"
# note below). Then uppercase and fold spaces/hyphens to underscores.
VERDICT_TAG=$(echo "<verdict>" \
    | sed -E 's/ *\(.*\)$//' \
    | tr '[:lower:]' '[:upper:]' | tr ' -' '__')
# e.g., "APPROVED with exceptions" -> "APPROVED_WITH_EXCEPTIONS"
# e.g., "APPROVED (test not run)"  -> "APPROVED"

python3 -m tools.validate.log \
    --slug <slug> \
    --phase 05-summarize \
    --source pipeline:complete \
    --verdict "${VERDICT_TAG}" \
    --message "summarize finalized; verdict=${VERDICT_TAG}"
```

**Sentinel canonicalization:** the validator's closed allowlist is
`APPROVED | APPROVED_WITH_EXCEPTIONS | REQUIRES_REMEDIATION`. Parenthesized
qualifiers in the verdict table (e.g., `APPROVED (test not run)`) are
*informational metadata*, not distinct verdicts — they describe which
subset of validation ran, not whether the run was approved. The sentinel
canonicalizes them away so the gate stays binary; consumers needing the
original qualifier read `APPROVAL-REPORT.md` directly, not the sentinel
token. Adding new parenthesized variants does NOT require validator
allowlist changes; adding a new bare verdict (e.g., a hypothetical
`PENDING`) does.

The validator anchors on the literal token `[pipeline:complete:<VERDICT>]`,
where `<VERDICT>` is uppercase letters with underscores. Mid-flight runs
without the sentinel still get the strict P1 check.

Print:
```
Report written: .service-approval/<slug>/05-summarize/APPROVAL-REPORT.md
Verdict: <APPROVED|APPROVED WITH EXCEPTIONS|REQUIRES REMEDIATION>
Framework: {name} — {mapped} / {total} objectives covered
Mitigations: {covered} / {total} addressed
Threat model: {threat_model_name} — {covered} / {total} techniques covered (if attack_coverage present)
```
