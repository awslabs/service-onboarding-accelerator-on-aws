---
name: map-assemble
description: Deterministic assembly of map sub-skill outputs into final mapping-results.json, controls-catalog.md, and framework-mapping.md. Builds traceability, identifies coverage gaps, and runs comprehensive validation. No LLM reasoning required — pure data assembly.
disable-model-invocation: false
argument-hint: '[--service=<name>]'
---

# Service Approval — Map: Assemble

Deterministic assembly of the 3 map sub-skill outputs into the final mapping state files.
This step builds traceability links, identifies coverage gaps, and produces the markdown
reports. It is largely mechanical — no LLM reasoning about control-objective alignment.

**Inputs:**
- `.service-approval/<slug>/04-map/map-framework-parsed.json` — framework objectives
- `.service-approval/<slug>/04-map/map-controls-generated.json` — controls with metadata
- `.service-approval/<slug>/04-map/map-framework-mapped.json` — framework mappings with quality gates
- `.service-approval/<slug>/03-validate/validated.json` — mitigations and capabilities (for traceability)

**Outputs:**
- `.service-approval/<slug>/04-map/mapping-results.json` — machine-readable mapping state (final)
- `.service-approval/<slug>/04-map/controls-catalog.md` — controls inventory by Category x Scope
- `.service-approval/<slug>/04-map/framework-mapping.md` — framework objective crosswalk

---

## Prerequisites

**Hard gate — halts the run if upstream phases are incomplete.** The
pre-phase precondition CLI verifies that each upstream phase produced
its declared artifacts (with min-size thresholds to catch stub writes).
Exit non-zero from any of these means STOP — do not proceed with assembly.

```bash
python3 -m tools.validate.check_phase_complete --slug <slug> --phase 03-validate || exit 2
# Note: 04-map outputs from upstream sub-skills are checked individually below
# (map-assemble produces controls-catalog.md / framework-mapping.md / mapping-results.json
# which are the outputs OF this skill, so they're validated in Phase 7).
test -f .service-approval/<slug>/04-map/map-framework-parsed.json || { echo "ERROR: map-parse-framework didn't run"; exit 2; }
test -f .service-approval/<slug>/04-map/map-controls-generated.json || { echo "ERROR: map-generate-controls didn't run"; exit 2; }
test -f .service-approval/<slug>/04-map/map-framework-mapped.json || { echo "ERROR: map-framework-mapping didn't run"; exit 2; }
```

After Phase 7 below writes mapping-results.json, controls-catalog.md, and
framework-mapping.md, the Stop hook's P7 check (validate_pipeline_integrity:
check_phase_outputs) re-validates that all 04-map outputs are present and
non-stub-sized. Skipping Phase 5 or Phase 6 of this skill will trip P7
and fail the verdict.

**Audit log — emit start/end events:**

```bash
python3 -m tools.validate.log --slug <slug> --phase 04-map \
    --source skill:map-assemble --verdict start \
    --message "assembling map outputs"
# ... do the work ...
python3 -m tools.validate.log --slug <slug> --phase 04-map \
    --source skill:map-assemble --verdict end \
    --message "wrote mapping-results.json + controls-catalog.md + framework-mapping.md"
```

If the skill halts early (precondition failure, validation error), emit
`--verdict halt` instead of `end` with the reason in `--message`.

---

## Phase 1: Build Reverse Index (controls -> framework objectives)

For each control, collect all framework objectives it maps to:

```python
import json

fw_mapped = json.load(open('.service-approval/<slug>/04-map/map-framework-mapped.json'))
cg = json.load(open('.service-approval/<slug>/04-map/map-controls-generated.json'))

# Build reverse index: control_id -> [objective_ids]
ctrl_to_objs = {}
for f in fw_mapped['framework_mapping']:
    if f.get('status') != 'MAPPED':
        continue
    for c in f.get('controls', []):
        ctrl_to_objs.setdefault(c['control_id'], []).append(f['objective_id'])

# Enrich controls with framework_objectives. Posture + source fields (from Rule C1
# in map-generate-controls) flow through unchanged — they're already on each control
# and will be propagated verbatim into mapping-results.json.controls[]. Every downstream
# generate sub-skill reads ctrl['posture'] to populate _metadata.posture in the
# generated artifact, which CHECK-15 enforces at hook time.
for ctrl in cg['controls']:
    ctrl['framework_objectives'] = sorted(set(ctrl_to_objs.get(ctrl['id'], [])))
    # posture + source: carry forward if present; absence is tolerated for legacy state
    # files generated before Phase C (CHECK-15 only fires when _metadata.posture exists).
```

---

## Phase 2: Build Threat-Mitigation-Control Map

**Canonical implementation:** `scripts/map-assemble.py` →
`build_threat_mitigation_map(mitigations, controls)`. Call the script
rather than reimplementing the logic inline — prior inline pseudocode in
this SKILL drifted from the script (emitted `controls` instead of
`control_ids`, omitted the `layers` sub-object) and caused a downstream
schema mismatch in the `/test` skill's coverage step.

### Emitted shape (one entry per mitigation)

```json
{
  "mitigation_id": "<M-*>",
  "statement": "<mitigation statement from validated.json>",
  "resource_type": "<service-specific resource/asset name>",
  "coverage": "FULL | PARTIAL | NONE",
  "control_ids": ["<CTRL-*>", "..."],
  "framework_objectives": ["<framework-objective-id>", "..."],
  "layers": {
    "preventive": ["<CTRL-*-PRV-*>"],
    "proactive":  ["<CTRL-*-PRO-*>"],
    "detective":  ["<CTRL-*-DET-*>"],
    "responsive": ["<CTRL-*-COR-*>"]
  },
  "residual_gaps": ["<gap-description>", "..."]
}
```

### Coverage rule

See `build_threat_mitigation_map` in `scripts/map-assemble.py` for the
exact implementation. Summary:

- `FULL` — mitigation has both a preventive/proactive AND a detective
  control.
- `PARTIAL` — mitigation has some controls, but not both layers.
- `NONE` — no controls reference this mitigation (`mitigation_ids[]`
  lookup is empty).

### Residual gaps

Emitted for every missing layer (preventive, detective, responsive). The
exact strings live in the script — do NOT hand-author them in downstream
skills; read them from the emitted `residual_gaps` array.

### Consumers

Consumers of `threat_mitigation_map[]` entries:
- `skills/test/SKILL.md` — mitigation coverage calculation reads
  `entry.control_ids` (NOT `entry.controls`).
- `skills/summarize/SKILL.md` — APPROVAL-REPORT coverage matrix reads
  `entry.coverage`, `entry.layers`, and `entry.residual_gaps`.
- Framework mapping UI — reads `entry.framework_objectives`.

When changing the schema, update `scripts/map-assemble.py` first, then
this shape spec, then consumers — in that order.

---

## Phase 2b: Build ATT&CK Coverage Summary (mandatory)

MITRE ATT&CK analysis is mandatory — `validated.json` always contains `attack_surface`.

```python
attack_surface = vj.get('attack_surface')
if not attack_surface:
    raise ValueError("attack_surface missing from validated.json — MITRE ATT&CK analysis is mandatory. Run research-attack-surface first.")

techniques = attack_surface.get('applicable_techniques', [])
technique_ids = {t['technique_id'] for t in techniques}

# Build technique -> controls mapping
tech_to_ctrls = {}
for ctrl in controls:
    for tid in ctrl.get('attack_techniques', []):
        tech_to_ctrls.setdefault(tid, []).append(ctrl['id'])

# Calculate coverage
covered_techniques = [t for t in techniques if t['technique_id'] in tech_to_ctrls]
uncovered_techniques = [t for t in techniques if t['technique_id'] not in tech_to_ctrls]

# Build tactic-level summary
tactic_coverage = {}
for t in techniques:
    tid = t['tactic_id']
    if tid not in tactic_coverage:
        tactic_coverage[tid] = {
            'name': t['tactic_name'],
            'total': 0, 'covered': 0, 'uncovered': 0,
            'techniques_covered': [], 'techniques_uncovered': []
        }
    tactic_coverage[tid]['total'] += 1
    if t['technique_id'] in tech_to_ctrls:
        tactic_coverage[tid]['covered'] += 1
        tactic_coverage[tid]['techniques_covered'].append(t['technique_id'])
    else:
        tactic_coverage[tid]['uncovered'] += 1
        tactic_coverage[tid]['techniques_uncovered'].append(t['technique_id'])

attack_coverage = {
    'total_techniques': len(techniques),
    'covered_by_controls': len(covered_techniques),
    'uncovered': len(uncovered_techniques),
    'uncovered_techniques': [
        {'technique_id': t['technique_id'], 'technique_name': t['technique_name'],
         'applicability': t['applicability']}
        for t in uncovered_techniques
    ],
    'tactic_coverage': tactic_coverage,
    'technique_to_controls': {tid: cids for tid, cids in tech_to_ctrls.items()}
}
```

---

## Phase 3: Identify Coverage Gaps

Detect and classify ALL gap types:

```python
coverage_gaps = []

# 0. posture_gap: forward any (mitigation, posture) gaps produced by Rule C1's
# feasibility filter in map-generate-controls. These are structural gaps — a mitigation
# was intended to produce a preventative-request or reactive-corrective control but the
# parameter's gateable_by / mutability precluded it.
for g in cg.get('coverage_gaps', []):
    coverage_gaps.append({
        "type": "posture_gap",
        "id": g.get('mitigation_id'),
        "description": (
            f"Posture {g.get('posture')!r} not feasible for mitigation "
            f"{g.get('mitigation_id')}: {g.get('reason')}"
        ),
        "recommendation": (
            "Either accept the posture gap (documented), or pick a compensating "
            "mechanism at a different posture (e.g., reactive-detective)."
        ),
        "posture": g.get('posture'),
        "reason": g.get('reason'),
    })

# 1. mitigation_gap: mitigations with NONE coverage
for t in threat_mitigation_map:
    if t['coverage'] == 'NONE':
        coverage_gaps.append({
            "type": "mitigation_gap",
            "id": t['mitigation_id'],
            "description": f"No controls address mitigation {t['mitigation_id']}",
            "recommendation": f"Generate controls for: {t['mitigation_goal'][:100]}"
        })

# 2. single_layer: mitigations with only one control category
for t in threat_mitigation_map:
    if t['coverage'] == 'NONE':
        continue
    ctrl_cats = set()
    for ctrl in controls:
        if ctrl['id'] in t['controls']:
            ctrl_cats.add(ctrl['category'])
    preventive_cats = ctrl_cats & {'PRV', 'PRO'}
    detective_cats = ctrl_cats & {'DET', 'COR'}
    if preventive_cats and not detective_cats:
        coverage_gaps.append({
            "type": "single_layer",
            "id": t['mitigation_id'],
            "description": f"Mitigation {t['mitigation_id']} has only preventive controls, no detective",
            "recommendation": "Add detective control (Config rule or CloudWatch alarm)"
        })
    elif detective_cats and not preventive_cats:
        coverage_gaps.append({
            "type": "single_layer",
            "id": t['mitigation_id'],
            "description": f"Mitigation {t['mitigation_id']} has only detective controls, no preventive",
            "recommendation": "Add preventive control (SCP, IAM policy, or resource policy)"
        })

# 3. partial_parameter_coverage: mitigations where some params uncovered
for t in threat_mitigation_map:
    if t['residual_gaps']:
        for gap in t['residual_gaps']:
            if 'Parameters not controlled' in gap:
                coverage_gaps.append({
                    "type": "partial_parameter_coverage",
                    "id": t['mitigation_id'],
                    "description": gap,
                    "recommendation": "Add controls for uncovered parameters"
                })

# 4. framework_gap: MAPPED objectives with only Supportive Only coverage
for f in fw_mapped['framework_mapping']:
    if f.get('status') == 'MAPPED' and f.get('coverage') == 'Supportive Only':
        coverage_gaps.append({
            "type": "framework_gap",
            "id": f['objective_id'],
            "description": f"Objective {f['objective_id']} has only Supportive controls (no Full or Partial Coverage)",
            "recommendation": "Implement stronger controls directly addressing this objective"
        })

# 5. control_orphan: controls not mapped to any objective
orphaned = fw_mapped.get('quality_gate_results', {}).get('orphaned_controls', [])
for oid in orphaned:
    coverage_gaps.append({
        "type": "control_orphan",
        "id": oid,
        "description": f"Control {oid} does not map to any framework objective",
        "recommendation": "Review if this control addresses any framework requirement"
    })

# 6. attack_technique_gap: HIGH applicability techniques with no controls
# attack_coverage is built from attack_surface above (always present —
# MITRE ATT&CK is mandatory); no guard needed.
for t in attack_coverage.get('uncovered_techniques', []):
    if t['applicability'] == 'HIGH':
        coverage_gaps.append({
            "type": "attack_technique_gap",
            "id": t['technique_id'],
            "description": f"HIGH applicability technique {t['technique_id']} ({t['technique_name']}) has no covering controls",
            "recommendation": "Generate controls targeting this attack technique"
        })
```

---

## Phase 4: Assemble mapping-results.json

Combine all data into the final `mapping-results.json`:

```python
fw_parsed = json.load(open('.service-approval/<slug>/04-map/map-framework-parsed.json'))

# Build control_summary
from collections import Counter
scope_counts = Counter(c['scope'] for c in controls)
cat_counts = Counter(c['category'] for c in controls)
mech_counts = Counter(c['mechanism'] for c in controls)

mapping_results = {
    "schema_version": "1.0",
    "service": cg.get('service', vj.get('service', '')),
    "framework": fw_parsed['framework'],
    "controls": controls,  # enriched with framework_objectives
    "threat_mitigation_map": threat_mitigation_map,
    "framework_mapping": fw_mapped['framework_mapping'],
    "framework_coverage_summary": fw_mapped['framework_coverage_summary'],
    "coverage_gaps": coverage_gaps,
    "attack_coverage": attack_coverage,  # always present — MITRE ATT&CK is mandatory
    "control_summary": {
        "total_controls": len(controls),
        "by_scope": dict(scope_counts),
        "by_category": dict(cat_counts),
        "by_mechanism": dict(mech_counts)
    }
}

with open('.service-approval/<slug>/04-map/mapping-results.json', 'w') as f:
    json.dump(mapping_results, f, indent=2)
```

---

## Phase 5: Write controls-catalog.md

Write `.service-approval/<slug>/04-map/controls-catalog.md`:

```markdown
# Security Controls Catalog — {service-name}

**Service:** {service-name}
**Date Generated:** {date}
**Total Controls:** {count}
**Resources:** {resource-list}
**Mitigations Addressed:** {count}

## Control Categories

| Category | Purpose |
|----------|---------|
| **Preventive** | Designed to prevent an event from occurring |
| **Proactive** | Designed to prevent the creation of noncompliant resources |
| **Detective** | Designed to detect, log, and alert after an event has occurred |
| **Responsive** | Designed to drive remediation of adverse events or deviations from your security baseline |

## Control Matrix Summary

|  | Proactive | Preventive | Detective | Responsive | Total |
|---|---|---|---|---|---|
| **Organisation** | N | N | N | N | N |
| **Account** | N | N | N | N | N |
| **Resource** | N | N | N | N | N |
| **Total** | N | N | N | N | N |

## Organisation-Level Controls

### Proactive

#### {CTRL-ORG-PRO-001} — {Control Title}

- **Resource:** {resource-type}
- **Scope:** Organisation
- **Description:** {what this control does}
- **Enforcement Point:** {mechanism}
- **Implementation:** {how to implement}
- **Parameters Controlled:** {API parameters}
- **Mitigations:** {M-xxx IDs}
- **AWS Doc Reference:** {URL}

[repeat for each control, organized by Scope > Category]

### Preventive
### Detective
### Responsive

## Account-Level Controls

### Proactive
### Preventive
### Detective
### Responsive

## Resource-Level Controls

### Proactive
### Preventive
### Detective
### Responsive
```

Each control entry MUST include a `Mitigations:` line referencing the mitigation IDs it addresses.

**Responsive Controls** MUST be generated for every mitigation that has detective controls.
The responsive control completes the detect-respond loop. Typical responsive mechanisms:
- **Lambda + EventBridge** — auto-tag, notify, or remediate on detection
- **SSM Automation runbook** — manual or scheduled remediation workflow
- **Step Functions workflow** — multi-step orchestration (detect → notify → remediate → verify)
- **Systems Manager OpsItems** — create operational items for manual follow-up

After the Control Matrix Summary, always include the ATT&CK Technique Coverage section:

```markdown
## ATT&CK Technique Coverage

| Tactic | Tactic Name | Techniques | Covered | Uncovered |
|---|---|---|---|---|
| TA0001 | Initial Access | 3 | 2 | 1 |
[repeat for each tactic]

### Uncovered HIGH Techniques

| Technique | Name | Applicability | Recommendation |
|---|---|---|---|
| T1190 | Exploit Public-Facing Application | HIGH | Add VPC endpoint controls |
```

---

## Phase 6: Write framework-mapping.md

Write `.service-approval/<slug>/04-map/framework-mapping.md`.

**Format:** the document is a single flat **Crosswalk** table — one row per
framework objective — with framework, control, threat, and MITRE technique
provenance tagged inline. This replaces the legacy per-domain
`Detailed Mappings by Domain` layout. Reviewers can scan top-to-bottom and
immediately see, for each objective, which controls satisfy it, what threats
those controls counter, and which MITRE ATT&CK techniques apply — together
with a `(source)` tag per cell so they can tell whether the data came from
Canopy, AWS docs, the customer's threat model, or the MITRE MCP.

The document MUST be service-agnostic and framework-agnostic in its
structure. Use `framework.name`, `framework.source`, domain names, and
objective IDs from `map-framework-parsed.json`. Use the service name from
`map-controls-generated.json` and per-control `provenance` from the same
file. Per-mitigation `source` flows from `validated.existing_mitigations[]`
through `threat_mitigation_map[]`. Per-technique `source` flows from
`validated.attack_surface.applicable_techniques[].source`.

### Document outline

```markdown
# Framework Mapping -- {framework_name} x {service}

## Coverage Summary
| Metric | Count |
| ...   | ...   |

## Domain Coverage Summary
| Domain | Total | Mapped | N/A | Coverage % |
| ...   | ...   | ...    | ... | ...        |

## Crosswalk
| Control Objective | Controls (source) | Threats (source) | MITRE Techniques (source) |
| ...               | ...               | ...              | ...                       |

## Unmapped Controls
## Coverage Gaps
   ### Mitigations Without Controls
   ### Single-Layer Coverage
   ### Framework Objectives with SUPPORTS-Only Coverage
   ### Posture Gaps                  ← surfaces canopy_loader.detect_posture_gaps()
## Mitigation Traceability
```

### Crosswalk row contract

One row per objective. Multi-line cells use `<br>` for soft line breaks and
`<br><br>` between distinct entries within a cell. The `_( ... )_` italics
hold the source tag.

```
| **{OBJ-ID}**: {Title}<br>_({framework_source})_ | `{CTRL-ID}` — {name}<br>_({ctrl_provenance})_<br><br>... | `{MIT-ID}`: {statement…}<br>_({mit_source})_<br><br>... | {T-ID} — {name}<br>_({tech_source})_<br><br>... |
```

**Source labels** (rendered values shown in italics inside cells):

| Field             | Source value             | Rendered label   |
|-------------------|--------------------------|------------------|
| Objective         | `customer-upload`        | Customer Upload  |
| Objective         | `ccmv4-default`          | CCMv4 Default    |
| Control           | `canopy`                 | Canopy           |
| Control           | `aws-docs`               | AWS Docs         |
| Threat/Mitigation | `canopy`                 | Canopy           |
| Threat/Mitigation | `customer-threat-model`  | Customer TM      |
| Threat/Mitigation | `mitigation-report`      | Mitigation Report|
| MITRE technique   | `canopy`                 | Canopy           |
| MITRE technique   | `mitre-mcp`              | MITRE MCP        |

**N/A objectives:** the row still appears. The Controls cell holds the
italicized reason (e.g., `_Physical datacenter security is managed by AWS
under the shared responsibility model_`); Threats and MITRE Techniques
cells are empty.

### MITRE branching (where the source tags come from)

The MITRE technique source is set upstream in `research-attack-surface`,
not at render time:

- `canopy` — set when `inputs.canopy_present = true`. Techniques are
  extracted from `canopy.threats[].mappings[type=FRAMEWORK,
  frameworkName="MITRE ATT&CK"]`. The MITRE MCP is NOT called.
- `customer-threat-model` — set when a STRIDE / custom threat catalog is
  parsed (without Canopy).
- `mitre-mcp` — set when the MITRE ATT&CK MCP is queried (no Canopy, no
  customer threat model).

`map-assemble` does NOT re-derive these tags; it copies them from the
control's `attack_techniques[].source` field verbatim.

### Implementation

The renderer lives at `scripts/map-assemble.py::render_crosswalk()` and is
called from `write_framework_mapping()`. It accepts:

- `fw_mapped` — the framework_mapping[] array (every objective, MAPPED + N/A)
- `controls` — controls[] with `provenance` and `attack_techniques[].source` populated
- `threat_mitigation_map` — with `source` populated from validated mitigations
- `framework_source` — from `map-framework-parsed.json::framework.source`
- `technique_names` — derived from `validated.attack_surface.applicable_techniques[].technique_name`

The legacy fields (`controls_catalog → MITRE ATT&CK Threat-to-Controls
Mapping`, per-domain Detailed Mappings, etc.) are intentionally removed.
The same data lives in `mapping-results.json` for downstream consumers
that need machine-readable traceability.

---

## Phase 7: Final Validation

Output validation runs automatically via PostToolUse hook (validate_state.py Check S13).


---

## Print Summary

```
Map (Assemble) complete:
  Inputs:
    - map-framework-parsed.json ({N} objectives)
    - map-controls-generated.json ({N} controls)
    - map-framework-mapped.json ({N} mappings)
  Outputs:
    - mapping-results.json (final state)
    - controls-catalog.md (matrix: {O} org, {A} acc, {R} res x {P} pro, {V} prv, {D} det, {R} res)
    - framework-mapping.md ({mapped} mapped, {na} N/A, MITRE: {covered}/{total} techniques)
  Traceability:
    - Mitigations: {N}/{total} ({pct}%)
    - Framework objectives: {mapped}/{total} mapped, {na} N/A
    - MITRE ATT&CK: {covered}/{total} techniques covered ({pct}%)
    - Coverage gaps: {N}
  Validation: PASS
```
