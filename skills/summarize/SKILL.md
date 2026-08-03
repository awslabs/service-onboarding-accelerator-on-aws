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
| Objective counts (MAPPED / total) | `mapping-results.json.framework_mapping[]` — a **count** for the Summary of Findings; the per-objective table lives in `framework-mapping.md`, not this report |
| Threat coverage | `mapping-results.json.attack_coverage` |
| Control counts (4 families) | `05-recommended-guidance/{preventive,proactive,detective,responsive}/` — counts for the findings paragraph; the per-artifact index lives in `controls-catalog.md` |
| Which deliverables exist | the files present under `04-map/` and `05-recommended-guidance/` — drives the Output Guide |
| Unverified count | `validated.json.unverified_count` |

**Coverage grading is computed but NOT shown, and the per-objective mapping is NOT
re-reported here.** The pipeline still computes per-objective status/coverage
internally (validators read it from `mapping-results.json`), and the full
objective-by-objective table is rendered in `framework-mapping.md`. This report
gives only a **count** ("N of M objectives covered") in Summary of Findings and a
pointer to `framework-mapping.md` — no objective table, no coverage column, no
Fully/Partial/Supportive grade.

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

The Summary Report is a **high-level overview of the whole process** — what was
done, what was found, how to use the results, and what the output files are. It
does **not** re-report the framework mapping (that lives in `framework-mapping.md`)
or recap every artifact/objective. Push all granular detail into the companion
docs and link to them.

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

### 3. What Was Done
> *Describe what this section is: a high-level, customer-facing narrative of the
> process that produced these results — no pipeline/skill/agent names.*

A short paragraph (or a few bullets) describing, at altitude, what the process did:
the service's capabilities were verified against AWS documentation; those
capabilities were mapped to the {framework-name} control framework; preventive,
proactive, detective, and responsive controls were generated, each anchored to a
public AWS reference or a Canopy-cited source; and applicable adversary techniques
were analyzed. **No tables, no per-objective rows, no internal terms** — this is
the "how we got here" orientation, not a re-report. Point the reader to the later
sections and companion docs for detail.

### 4. How to Use These Results (Output Guide)
> *Describe what this section is: a compact guide to the deliverables — what each
> file is and how to use it — so the reader knows where to go for detail.*

A compact table of the deliverables with a one-line "what it is / how to use it"
each. High level, **not** a per-artifact file dump. List only the files this run
actually produced.

```markdown
| Deliverable | What it is / how to use it |
|---|---|
| SUMMARY-REPORT.md | This overview — start here. |
| framework-mapping.md | The full objective-by-objective framework mapping with status and reason. Go here for the complete coverage detail. |
| controls-catalog.md | The catalog of every generated control with its citation. Go here for the per-artifact index. |
| preventive/ proactive/ detective/ responsive/ | The generated control artifacts, one folder per family. Review and adapt the policies/rules before deploying. |
| preventive-coverage.json | Deterministic accounting of how each preventive objective was handled (authored / referred / routed). |
| citation-coverage.json | Every non-preventive artifact's citation (repo anchor, AWS doc, or Canopy alias + link). |
| README.md / PROVENANCE.md | Provenance and how the guidance folder is organized. |
```

For the full objective-by-objective framework detail, point the reader to
`framework-mapping.md` **instead of** rendering the objective table here. Link the
companion docs that exist in this run's guidance folder:

```markdown
Companion docs (in the guidance folder):
[framework-mapping.md](../04-map/framework-mapping.md) ·
[controls-catalog.md](../04-map/controls-catalog.md) ·
[README.md](../05-recommended-guidance/README.md) ·
[PROVENANCE.md](../05-recommended-guidance/PROVENANCE.md) ·
[preventive-coverage.json](../05-recommended-guidance/preventive-coverage.json) ·
[citation-coverage.json](../05-recommended-guidance/citation-coverage.json)
```

Exclude vendored/build directories (`node_modules/`, `.terraform/`, `__pycache__/`,
`.git/`, lockfiles) — the output guide is a reader's map, not a file dump.

### 5. Threat Model Coverage
> *Describe what this section is: which adversary techniques the generated controls
> address. Always present (MITRE ATT&CK analysis is mandatory). Keep it short.*

Brief. Read `mapping-results.json.attack_coverage`. Title adapts to the threat
model source (mirrors `skills/research-attack-surface/SKILL.md` naming): "MITRE
ATT&CK Threat Coverage (v{version})" by default; "STRIDE Threat Coverage",
"{combined} Threat Coverage", or "Threat Model Coverage ({source})" per source.

Render the compact tactic rollup plus a couple of gap lines — the table and a few
lines, not a technique-by-technique essay. Do not expand this section:

```markdown
| Tactic / Category | Techniques | Covered | Coverage |
|---|---|---|---|
| Initial Access (TA0001) | 3 | 2 | 67% |
```

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
