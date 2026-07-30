---
name: summarize-v3
description: Produce final SUMMARY-REPORT.md — a brief, service-first report that links out to the companion docs and coverage rollups
disable-model-invocation: false
---

# Service Approval — Summarizer v3

Read the state files and generate the final Summary Report at
`.service-approval/<slug>/06-summarize/SUMMARY-REPORT.md`.

The report is **brief, service-first, and link-out**. It does not restate detail
that already lives in the companion docs and machine-readable rollups — it points
to them. It issues **no** approve/deny verdict.

## Prerequisites

- [ ] **Hard gate — verify the phases summarize depends on:**
  ```bash
  python3 -m tools.validate.check_phase_complete --slug <slug> --phase 01-assess || exit 2
  python3 -m tools.validate.check_phase_complete --slug <slug> --phase 03-validate || exit 2
  python3 -m tools.validate.check_phase_complete --slug <slug> --phase 04-map || exit 2
  test -d .service-approval/<slug>/05-recommended-guidance || { echo "ERROR: run generator first"; exit 2; }
  ```

## Inputs the report reads (never invent — read from state)

| Fact | Source |
|------|--------|
| Service name + friendly name | `validated.json.service`, `sar-facts.json` |
| Service AWS documentation URL | `sar-facts.json.sar_url` (the Service Authorization Reference page) |
| Framework name | `mapping-results.json.framework.name` |
| Per-objective status + **reason** | `mapping-results.json.framework_mapping[]` (`status`, `reason` / `na_reason`) |
| Objective applicability reason | `applicability-matrix.json` (when present) |
| Threat coverage | `mapping-results.json.attack_coverage` |
| Control catalog (4 families) + citations | `05-recommended-guidance/{preventive,proactive,detective,responsive}/` + `citation-coverage.json` |
| Preventive rollup | `05-recommended-guidance/preventive-coverage.json` |
| Unverified count | `validated.json.unverified_count` |

**Coverage grading is computed but NOT shown.** The pipeline still computes the
per-objective coverage level internally (validators read it from
`mapping-results.json`); the report does **not** render a coverage column or a
Fully/Partial/Supportive grade. It shows only `MAPPED` / `N/A` status plus the
reason.

**Terminology rules (customer-facing document):**
- NO internal/pipeline terms: no "pipeline", no MCP/skill/agent names, no internal
  file names (`validated.json`, `mapping-results.json`) in prose. Say "all
  capabilities were verified", "47 controls were generated".
- NO verdict label ("APPROVED", "REQUIRES REMEDIATION", readiness rating).
- NO per-item confidence score or band (validator P11 enforces this).
- Apply all terminology rules from CLAUDE.md.

## Report structure

Write `.service-approval/<slug>/06-summarize/SUMMARY-REPORT.md`. The title is H1
(`# Service Summary Report — {Service}`); every section below is H2 (`##`) —
downstream consumers anchor on H2, so do not use H3 for section headers. **Every
section opens with a 1-2 sentence description of its purpose.** Keep the whole
report short; push detail into the linked companion docs.

Emit the sections in exactly this order:

### 1. Service Overview
> *Describe what this section is: a two-to-three sentence orientation to the
> service and a link to its AWS documentation.*

Two-to-three sentences on what the service does and its security-relevant surface,
followed by a link to its AWS documentation (`sar-facts.json.sar_url`). Example:

```markdown
## Service Overview

This section orients the reader to the service and links to its authoritative AWS
documentation.

{Service} is {one-sentence description}. {One or two sentences on its
security-relevant capabilities — encryption, IAM surface, network posture.}

**AWS documentation:** {sar_url}
```

### 2. Summary of Findings
> *Describe what this section is: an honest one-paragraph recap of what was
> produced and what is covered — no verdict.*

One factual paragraph: date, service, how many controls were generated across the
four families, how many framework objectives are covered, and any open items.
State it plainly. No approve/deny judgment, no readiness rating.

If `validated.json.unverified_count` is 0, add a single line: **"All items
verified."** Only render a list of unverified items if `unverified_count > 0` (id
+ reason per item). Do not ship an empty "UNVERIFIED" section.

### 3. Framework Coverage — {framework-name}
> *Describe what this section is: which framework objectives are supported or not,
> and WHY, with no coverage grade.*

Use the framework name from `mapping-results.json.framework.name` (default "CSA
CCMv4"; `--framework=nist|cis|iso` or a custom file changes it). Render the full
objective table with **status and reason only — no coverage column**:

```markdown
| {Framework} Objective ID | Title | Domain | Status | Why |
|---|---|---|---|---|
| {objective_id} | {title} | {domain} | MAPPED / N/A | {reason} |
```

For **every** objective, the "Why" is pulled verbatim (or lightly reworded to
customer-facing prose) from `mapping-results.json.framework_mapping[].reason` /
`na_reason`, or from `applicability-matrix.json` when the objective is N/A by
applicability. **Do not invent a reason** — if a row has no reason in state, write
"See control catalog" and flag it, do not fabricate a justification. "Satisfied
By" control IDs are not a separate column here; the control catalog (section 5)
carries the control detail.

### 4. Threat Model Coverage
> *Describe what this section is: which adversary techniques the generated controls
> address. Always present (MITRE ATT&CK analysis is mandatory).*

Brief. Read `mapping-results.json.attack_coverage`. Title adapts to the threat
model source (mirrors `skills/research-attack-surface/SKILL.md` naming): "MITRE
ATT&CK Threat Coverage (v{version})" by default; "STRIDE Threat Coverage",
"{combined} Threat Coverage", or "Threat Model Coverage ({source})" per source.

Render a compact tactic heat map and a short list of uncovered HIGH-applicability
techniques with the recommended control type — keep it to the table plus a few
gap lines, not a technique-by-technique essay:

```markdown
| Tactic / Category | Techniques | Covered | Coverage |
|---|---|---|---|
| Initial Access (TA0001) | 3 | 2 | 67% |
```

### 5. Control Catalog
> *Describe what this section is: the index of every generated control artifact,
> grouped by the four families, each with its citation — the renamed "Artifact
> Manifest".*

Group by the four families: **Preventive, Proactive, Detective, Responsive.** For
each family, list its artifacts with the **citation** each carries (repo anchor
`example_id` + URL, or doc anchor title + URL) read from `citation-coverage.json`.
Do not restate policy bodies — link out. Close the section with pointers to the
companion docs rather than duplicating them:

```markdown
| Family | Artifact | Citation |
|---|---|---|
| Preventive | scp-policy.json | {example_id} — {url} |
| Detective | config-rules.json | {managed-rule doc url} |
| Proactive | cfn-guard-rules.guard | {example_id} — {url} |
| Responsive | ssm-runbook-reference.md | AWS-{Runbook} — {runbook doc url} |

Full provenance and per-artifact detail (companion docs in the guidance folder):
[README.md](../05-recommended-guidance/README.md) ·
[PROVENANCE.md](../05-recommended-guidance/PROVENANCE.md) ·
[preventive-coverage.json](../05-recommended-guidance/preventive-coverage.json) ·
[citation-coverage.json](../05-recommended-guidance/citation-coverage.json)

(Link only the companion docs that exist in this run's guidance folder.)
```

Exclude vendored/build directories from any file listing (`node_modules/`,
`.terraform/`, `__pycache__/`, `.git/`, lockfiles) so the catalog stays a
human-readable index, not a dump.

### 6. Preventive Coverage Rollup
> *Describe what this section is: the deterministic accounting of how each
> preventive objective was handled — authored, referred, or routed to detective.*

Read **verbatim** from
`.service-approval/<slug>/05-recommended-guidance/preventive-coverage.json` (built by
`build_preventive_coverage.py`). Do NOT hand-write or estimate the numbers. If the
file is absent (no preventive controls in this run), state that plainly and omit
the table.

```markdown
Of {objectives} preventive objectives: **{authored}** have a policy generated from
a public AWS reference example, **{referred}** point to a reference example the
customer applies, and **{routed_to_detective}** are covered by detective controls
(not preventable at request time).

| Control | Coverage | Mechanism | Reference / Citation | Why |
|---|---|---|---|---|
| {control_id} | {Authored / Referred / Routed to detective} | {mechanism} | {anchor example_id + url, or citation type + id/url} | {reason} |
```

The counts come straight from `totals`; each row from `controls[]`. A reader can
verify every number by following the control id and citation back to the generated
artifacts. Descriptive, not a judgment.

## Pipeline-Complete Sentinel

After SUMMARY-REPORT.md is written, emit a terminal-state sentinel to
`pipeline.log`. This signals to the Stop hook (`validate_pipeline_integrity.py`
P1 check) that the run is finalized — the file is frozen, and remediation-only
checks like the MCP-call-count gate cannot be retroactively satisfied. Without
this sentinel, the Stop hook re-fires forever on completed runs that happen to
have a P1 violation in their pipeline.log.

Emit AFTER the report file is closed and AFTER the print summary. Summarize is the
terminal phase, so it always owns the sentinel.

```bash
# The terminal-state sentinel is verdict-free: it records only that the run
# finalized, freezing the file against retroactive remediation. The fixed token
# FINALIZED closes out the P1 check.
python3 -m tools.validate.log \
    --slug <slug> \
    --phase 06-summarize \
    --source pipeline:complete \
    --verdict FINALIZED \
    --message "summarize finalized"
```

The validator anchors on the literal token `[pipeline:complete:FINALIZED]`.
Mid-flight runs without the sentinel still get the strict P1 check. The sentinel
carries no approve/deny meaning — this report does not adjudicate.

Print:
```
Report written: .service-approval/<slug>/06-summarize/SUMMARY-REPORT.md
Framework: {name} — {mapped} / {total} objectives covered
Threat model: {threat_model_name} — {covered} / {total} techniques covered (if attack_coverage present)
Total control artifacts: N
```
